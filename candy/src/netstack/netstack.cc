// SPDX-License-Identifier: MIT
#include "netstack/netstack.h"

#include "core/client.h"
#include <Poco/Net/SocketAddress.h>
#include <chrono>
#include <spdlog/spdlog.h>
#include <vector>

namespace candy {

namespace {
constexpr size_t kRecvBufSize = 65536;
constexpr uint32_t kUdpFlowMaxAgeMs = 60000;
// Idle wait between lwIP maintenance cycles when no packets arrive. Acts as
// both responsiveness cap and heartbeat for TCP retransmits / proxy I/O.
constexpr auto kLwipIdleWait = std::chrono::milliseconds(20);

uint32_t timestampMs() {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch());
    return (uint32_t)ms.count();
}
} // namespace

Netstack::Netstack() : client(nullptr) {}

Netstack::~Netstack() {
    // Wake any sleeping lwipThread before destroying shared state.
    this->pendingCv.notify_all();

    {
        std::unique_lock lock(this->tcpProxyMutex);
        for (auto &px : this->tcpProxies) {
            if (px.stream)
                px.stream->close();
            if (px.sock) {
                try {
                    px.sock->shutdown();
                } catch (...) {
                }
            }
        }
        this->tcpProxies.clear();
        this->socketMap.clear();
    }

    {
        std::unique_lock lock(this->udpProxyMutex);
        this->udpProxies.clear();
    }

    this->tcpListener.reset();
    this->udpSocket.reset();
    this->ip.reset();
}

int Netstack::run(Client *client) {
    this->client = client;

    Config cfg;
    cfg.mtu = client->getMtu();

    this->ip = IpStack::create(cfg);
    if (!this->ip) {
        spdlog::error("IpStack init failed");
        return -1;
    }

    this->tcpListener = TcpListener::bind(*this->ip, cfg.addr, cfg.listenPort);
    if (!this->tcpListener) {
        spdlog::error("TcpListener bind failed");
        return -1;
    }

    this->udpSocket = UdpSocket::bind(*this->ip, cfg.addr, cfg.listenPort);
    if (!this->udpSocket) {
        spdlog::error("UdpSocket bind failed");
        return -1;
    }

    this->msgThread = std::thread([&] {
        spdlog::debug("start thread: netstack msg");
        try {
            while (getClient().isRunning()) {
                Msg msg = getClient().getNetstackMsgQueue().read();
                if (msg.kind != MsgKind::PACKET)
                    continue;
                {
                    std::unique_lock lock(this->pendingMutex);
                    this->pendingPackets.push_back(std::move(msg));
                }
                this->pendingCv.notify_one();
            }
            getClient().shutdown();
        } catch (const std::exception &e) {
            spdlog::error("netstack msg thread exception: {}", e.what());
            getClient().shutdown();
        }
        spdlog::debug("stop thread: netstack msg");
    });

    this->lwipThread = std::thread([&] {
        spdlog::debug("start thread: netstack lwip");
        try {
            while (getClient().isRunning()) {
                // Phase 1: drain all pending input packets through lwIP.
                {
                    std::unique_lock lock(this->pendingMutex);
                    while (!this->pendingPackets.empty()) {
                        Msg msg = std::move(this->pendingPackets.front());
                        this->pendingPackets.pop_front();
                        lock.unlock();
                        this->handlePacket(std::move(msg));
                        lock.lock();
                    }
                    // Wait for new work or short timeout for maintenance.
                    this->pendingCv.wait_for(lock, kLwipIdleWait,
                                             [this] { return !this->pendingPackets.empty() || !getClient().isRunning(); });
                }

                // Phase 2: periodic maintenance. Must run on this thread since
                // it touches lwIP (checkTimeouts, accept, tcp_write, udp_send).
                checkTimeouts();
                pollProxies();

                // Phase 3: drain any output lwIP produced.
                while (auto pkt = this->ip->recv()) {
                    sendIPIP(*pkt);
                }
            }
            getClient().shutdown();
        } catch (const std::exception &e) {
            spdlog::error("netstack lwip thread exception: {}", e.what());
            getClient().shutdown();
        }
        spdlog::debug("stop thread: netstack lwip");
    });
    return 0;
}

int Netstack::wait() {
    if (this->msgThread.joinable())
        this->msgThread.join();
    if (this->lwipThread.joinable())
        this->lwipThread.join();
    return 0;
}

int Netstack::handlePacket(Msg msg) {
    if (msg.data.size() < sizeof(IP4Header)) {
        spdlog::warn("packet too small: {}", msg.data.size());
        return 0;
    }

    IP4Header *outer = (IP4Header *)msg.data.data();

    if (outer->isIPIP()) {
        this->peerIp = outer->saddr;
        msg.data.erase(0, sizeof(IP4Header));
    } else {
        return 0;
    }

    this->ip->send(msg.data);

    while (auto pkt = this->ip->recv()) {
        sendIPIP(*pkt);
    }

    return 0;
}

void Netstack::sendIPIP(const std::string &innerPkt) {
    std::string buffer;
    buffer.resize(sizeof(IP4Header) + innerPkt.size());
    IP4Header *hdr = (IP4Header *)buffer.data();
    hdr->version_ihl = 0x45;
    hdr->tos = 0;
    hdr->tot_len = hton(sizeof(IP4Header) + innerPkt.size());
    hdr->id = hton(netstack::TAG_RESPONSE);
    hdr->frag_off = 0;
    hdr->ttl = 64;
    hdr->protocol = 0x04;
    hdr->check = 0;
    hdr->saddr = this->client->address();
    hdr->daddr = this->peerIp;
    memcpy(buffer.data() + sizeof(IP4Header), innerPkt.data(), innerPkt.size());
    getClient().getPeerMsgQueue().write(Msg(MsgKind::PACKET, std::move(buffer)));
}

void Netstack::pollProxies() {
    pollTcpProxies();
    pollUdpProxies();
}

Client &Netstack::getClient() {
    return *this->client;
}

void Netstack::pollTcpProxies() {
    if (!this->tcpListener) {
        spdlog::error("pollTcpProxies listener=null");
        return;
    }

    while (auto result = this->tcpListener->accept()) {
        IP4 proxyAddr = result->dstAddr;
        uint16_t proxyPort = result->dstPort;

        TcpProxy proxy;
        proxy.stream = std::move(result->stream);
        proxy.closed = false;

        try {
            Poco::Net::SocketAddress addr(proxyAddr.toString(), proxyPort);
            proxy.sock = std::make_unique<Poco::Net::StreamSocket>();
            proxy.sock->connect(addr);
            proxy.sock->setBlocking(false);
        } catch (const std::exception &e) {
            spdlog::error("tcp proxy connect failed: {}", e.what());
            proxy.stream->close();
            continue;
        }

        {
            std::unique_lock lock(this->tcpProxyMutex);
            this->tcpProxies.push_back(std::move(proxy));
            TcpProxy &ref = this->tcpProxies.back();
            this->pollSet.add(*ref.sock, Poco::Net::PollSet::POLL_READ);
            this->socketMap[ref.sock->impl()] = &ref;
        }
    }

    struct Ready {
        Poco::Net::SocketImpl *impl;
        TcpProxy *tcpProxy;
    };
    std::vector<Ready> readyList;

    {
        std::unique_lock lock(this->tcpProxyMutex);
        try {
            auto ready = this->pollSet.poll(Poco::Timespan(0, 0));
            for (auto &entry : ready) {
                auto it = this->socketMap.find(entry.first.impl());
                if (it == this->socketMap.end())
                    continue;
                for (auto &px : this->tcpProxies) {
                    if (&px == it->second) {
                        readyList.push_back({entry.first.impl(), &px});
                        break;
                    }
                }
            }
        } catch (const std::exception &e) {
            spdlog::error("pollSet error: {}", e.what());
        }
    }

    // Note: readyList holds raw TcpProxy* into tcpProxies. This is safe because
    // (a) std::list<> elements are node-stable (don't relocate on insert/erase),
    // (b) the only writer to tcpProxies is this same lwip thread, and we don't
    //     mutate the list between building readyList and consuming it below.
    for (auto &r : readyList) {
        if (r.tcpProxy->closed)
            continue;
        try {
            std::string data(kRecvBufSize, 0);
            int n = r.tcpProxy->sock->receiveBytes(data.data(), data.size());
            if (n > 0) {
                r.tcpProxy->stream->write(std::string(data.data(), n));
            } else if (n == 0) {
                r.tcpProxy->closed = true;
                r.tcpProxy->stream->close();
            }
        } catch (const std::exception &e) {
            spdlog::error("pollTcp exception: {}", e.what());
        }
    }

    {
        std::unique_lock lock(this->tcpProxyMutex);
        for (auto &px : this->tcpProxies) {
            if (px.closed)
                continue;
            while (auto data = px.stream->read()) {
                if (data->empty()) {
                    px.closed = true;
                    break;
                }
                if (px.sock) {
                    try {
                        px.sock->sendBytes(data->data(), data->size());
                    } catch (const std::exception &e) {
                        spdlog::error("tcp sendBytes failed: {}", e.what());
                    }
                }
            }
            if (px.stream->isClosed())
                px.closed = true;
        }

        for (auto it = this->tcpProxies.begin(); it != this->tcpProxies.end();) {
            if (it->closed) {
                if (it->sock) {
                    try {
                        this->pollSet.remove(*it->sock);
                        this->socketMap.erase(it->sock->impl());
                        it->sock->shutdown();
                    } catch (...) {
                    }
                }
                if (it->stream)
                    it->stream->close();
                it = this->tcpProxies.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void Netstack::pollUdpProxies() {
    if (!this->udpSocket) {
        spdlog::error("pollUdpProxies socket=null");
        return;
    }

    while (auto pkt = this->udpSocket->recv()) {

        Poco::Net::DatagramSocket *sock = nullptr;
        {
            std::unique_lock lock(this->udpProxyMutex);
            for (auto &up : this->udpProxies) {
                if (up.srcIp == pkt->srcAddr && up.srcPort == pkt->srcPort && up.dstIp == pkt->dstAddr &&
                    up.dstPort == pkt->dstPort) {
                    sock = up.sock.get();
                    up.lastActive = timestampMs();
                    break;
                }
            }
        }

        if (!sock) {
            try {
                UdpProxy up;
                up.sock = std::make_unique<Poco::Net::DatagramSocket>();
                up.dstIp = pkt->dstAddr;
                up.dstPort = pkt->dstPort;
                up.srcIp = pkt->srcAddr;
                up.srcPort = pkt->srcPort;
                up.lastActive = timestampMs();
                {
                    std::unique_lock lock(this->udpProxyMutex);
                    this->udpProxies.push_back(std::move(up));
                    // Capture the raw socket pointer under the lock; the
                    // element stays alive because std::list nodes are stable
                    // and the only mutator of udpProxies is this same thread.
                    sock = this->udpProxies.back().sock.get();
                }
            } catch (const std::exception &e) {
                spdlog::error("udp proxy create failed: {}", e.what());
                continue;
            }
        }

        try {
            Poco::Net::SocketAddress dest(pkt->dstAddr.toString(), pkt->dstPort);
            sock->sendTo(pkt->data.data(), pkt->data.size(), dest);
        } catch (const std::exception &e) {
            spdlog::error("udp sendTo failed: {}", e.what());
        }
    }

    {
        std::unique_lock lock(this->udpProxyMutex);
        for (auto &up : this->udpProxies) {
            try {
                if (up.sock->poll(0, Poco::Net::Socket::SELECT_READ)) {
                    std::string data(kRecvBufSize, 0);
                    Poco::Net::SocketAddress sender;
                    int n = up.sock->receiveFrom(data.data(), data.size(), sender);
                    if (n > 0) {
                        this->udpSocket->send(std::string(data.data(), n), up.dstIp, up.dstPort, up.srcIp, up.srcPort);
                        up.lastActive = timestampMs();
                    }
                }
            } catch (const std::exception &e) {
                spdlog::error("pollUdp error: {}", e.what());
            }
        }
    }

    {
        std::unique_lock lock(this->udpProxyMutex);
        uint32_t now = timestampMs();
        for (auto it = this->udpProxies.begin(); it != this->udpProxies.end();) {
            if (now - it->lastActive > kUdpFlowMaxAgeMs)
                it = this->udpProxies.erase(it);
            else
                ++it;
        }
    }

    // Mirror the proxy-table eviction into the lwIP flow-PCB cache; otherwise
    // flowPcbs grows without bound for long-lived clients talking to many
    // distinct UDP destinations.
    if (this->udpSocket)
        this->udpSocket->sweep(kUdpFlowMaxAgeMs);
}

} // namespace candy

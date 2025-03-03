// SPDX-License-Identifier: MIT
#include "peer/manager.h"
#include "core/client.h"
#include "core/message.h"
#include "core/net.h"
#include "peer/message.h"
#include "utility/time.h"
#include <Poco/Net/NetException.h>
#include <Poco/Net/NetworkInterface.h>
#include <Poco/Timespan.h>
#include <Poco/URI.h>
#include <openssl/sha.h>
#include <shared_mutex>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

namespace Candy {

int PeerManager::setPassword(const std::string &password) {
    this->password = password;
    return 0;
}

int PeerManager::setStun(const std::string &stun) {
    this->udpStun.uri = stun;
    return 0;
}

int PeerManager::setDiscoveryInterval(int interval) {
    return 0;
}

int PeerManager::setForwardCost(int cost) {
    return 0;
}

int PeerManager::setPort(int port) {
    if (port > 0 && port <= UINT16_MAX) {
        this->listenPort = port;
    }
    return 0;
}

int PeerManager::setLocalhost(const std::string &ip) {
    this->localhost.fromString(ip);
    return 0;
}

int PeerManager::setTransport(const std::vector<std::string> &transport) {
    this->transport = transport;
    return 0;
}

int PeerManager::run(Client *client) {
    this->client = client;
    this->localP2PDisabled = false;

    if (this->localhost.empty()) {
        try {
            for (const auto &iface : Poco::Net::NetworkInterface::list()) {
                if (iface.supportsIPv4() && !iface.isLoopback() && !iface.isPointToPoint() &&
                    iface.type() != iface.NI_TYPE_OTHER) {
                    auto firstAddress = iface.firstAddress(Poco::Net::IPAddress::IPv4);
                    memcpy(&this->localhost, firstAddress.addr(), sizeof(this->localhost));
                    spdlog::debug("localhost: {}", this->localhost.toString());
                    break;
                }
            }
        } catch (std::exception &e) {
            spdlog::warn("local ip failed: {}", e.what());
        }
    }

    if (this->initSocket()) {
        Candy::shutdown(this->client);
        return -1;
    }

    this->msgThread = std::thread([&] {
        while (getClient().running) {
            handlePeerQueue();
        }
    });
    this->tickThread = std::thread([&] {
        while (getClient().running) {
            auto wake_time = std::chrono::system_clock::now() + std::chrono::seconds(1);
            tick();
            std::this_thread::sleep_until(wake_time);
        }
    });

    return 0;
}

int PeerManager::shutdown() {
    if (this->msgThread.joinable()) {
        this->msgThread.join();
    }
    if (this->tickThread.joinable()) {
        this->tickThread.join();
    }
    if (this->pollThread.joinable()) {
        this->pollThread.join();
    }

    // TODO: 清理 socket 连接

    return 0;
}

std::string PeerManager::getPassword() {
    return this->password;
}

void PeerManager::handlePeerQueue() {
    Msg msg = getClient().peerMsgQueue.read();
    switch (msg.kind) {
    case MsgKind::TIMEOUT:
        break;
    case MsgKind::PACKET:
        handlePacket(std::move(msg));
        break;
    case MsgKind::TUNADDR:
        handleTunAddr(std::move(msg));
        break;
    case MsgKind::SYSRT:
        this->localP2PDisabled = true;
        break;
    case MsgKind::TRYP2P:
        handleTryP2P(std::move(msg));
        break;
    case MsgKind::PUBINFO:
        handlePubInfo(std::move(msg));
        break;
    default:
        spdlog::warn("unexcepted peer message type: {}", static_cast<int>(msg.kind));
        break;
    }
}

int PeerManager::sendPacket(IP4 dst, const Msg &msg) {
    if (!sendPacketDirect(dst, msg)) {
        return 0;
    }
    if (!sendPacketRelay(dst, msg)) {
        return 0;
    }
    return -1;
}

int PeerManager::sendPacketDirect(IP4 dst, const Msg &msg) {
    std::shared_lock ipPeerLock(this->ipPeerMutex);
    auto it = this->ipPeerMap.find(dst);
    if (it != this->ipPeerMap.end()) {
        auto &peer = it->second;
        if (auto connector = peer.findConnector()) {
            return peer.send(PeerMsg::Forward::create(msg.data), connector);
        }
    }
    return -1;
}

int PeerManager::sendPacketRelay(IP4 dst, const Msg &msg) {
    std::shared_lock rtTableLock(this->rtTableMutex);
    auto rt = this->rtTableMap.find(dst);
    if (rt != this->rtTableMap.end()) {
        if (auto connector = rt->second) {
            if (connector->isConnected()) {
                return connector->getPeer().send(PeerMsg::Forward::create(msg.data), connector);
            }
        }
    }
    return -1;
}

int PeerManager::sendPubInfo(CoreMsg::PubInfo info) {
    info.src = getClient().address();
    if (!info.v6 && !info.tcp) {
        if (info.local) {
            info.ip = this->localhost;
            info.port = this->udp4socket.address().port();
        } else {
            info.ip = this->udpStun.ip;
            info.port = this->udpStun.port;
        }
    }
    getClient().wsMsgQueue.write(Msg(MsgKind::PUBINFO, std::string((char *)(&info), sizeof(info))));
    return 0;
}

IP4 PeerManager::getTunIp() {
    return this->tunAddr.Host();
}

void PeerManager::handlePacket(Msg msg) {
    IP4Header *header = (IP4Header *)msg.data.data();
    if (!sendPacket(header->daddr, msg)) {
        return;
    }
    getClient().wsMsgQueue.write(std::move(msg));
}

void PeerManager::handleTunAddr(Msg msg) {
    if (this->tunAddr.fromCidr(msg.data)) {
        spdlog::error("set tun addr failed: {}", msg.data);
        return;
    }

    std::string data;
    data.append(this->password);
    auto leaddr = hton(uint32_t(this->tunAddr.Host()));
    data.append((char *)&leaddr, sizeof(leaddr));

    this->key.resize(SHA256_DIGEST_LENGTH);
    SHA256((unsigned char *)data.data(), data.size(), (unsigned char *)this->key.data());
}

void PeerManager::handleTryP2P(Msg msg) {
    IP4 src(msg.data);

    std::shared_lock ipPeerLock(this->ipPeerMutex);
    auto it = this->ipPeerMap.find(src);
    if (it == this->ipPeerMap.end()) {
        this->ipPeerMutex.unlock_shared();
        {
            std::unique_lock lock(this->ipPeerMutex);
            this->ipPeerMap.emplace(std::piecewise_construct, std::forward_as_tuple(src), std::forward_as_tuple(src, this));
        }
        this->ipPeerMutex.lock_shared();
        it = this->ipPeerMap.find(src);
    }

    if (it == this->ipPeerMap.end()) {
        spdlog::warn("can not find peer: {}", src.toString());
        return;
    }

    it->second.tryConnecct();
}

void PeerManager::handlePubInfo(Msg msg) {
    CoreMsg::PubInfo *info = (CoreMsg::PubInfo *)(msg.data.data());

    if (info->src == getClient().address() || info->dst != getClient().address()) {
        spdlog::warn("invalid public info: src=[{}] dst=[{}]", info->src.toString(), info->dst.toString());
        return;
    }

    std::shared_lock ipPeerLock(this->ipPeerMutex);
    auto it = this->ipPeerMap.find(info->src);
    if (it == this->ipPeerMap.end()) {
        this->ipPeerMutex.unlock_shared();
        {
            std::unique_lock lock(this->ipPeerMutex);
            this->ipPeerMap.emplace(std::piecewise_construct, std::forward_as_tuple(info->src),
                                    std::forward_as_tuple(info->src, this));
        }
        this->ipPeerMutex.lock_shared();
        it = this->ipPeerMap.find(info->src);
    }

    if (!info->v6 && !info->tcp) {
        it->second.handleUdp4Conn(info->ip, info->port, info->local);
    }
}

void PeerManager::tick() {
    {
        std::shared_lock ipPeerLock(this->ipPeerMutex);
        for (auto &[ip, peer] : this->ipPeerMap) {
            peer.tick();
        }
    }

    if (this->udpStun.needed) {
        sendUdpStunRequest();
        this->udpStun.needed = false;
    }
}

int PeerManager::initSocket() {
    using Poco::Net::AddressFamily;
    using Poco::Net::PollSet;
    using Poco::Net::SocketAddress;

    try {
        for (auto &transport : this->transport) {
            if (transport == "UDP4") {
                this->udp4socket.bind(SocketAddress(AddressFamily::IPv4, this->listenPort), true);
                spdlog::debug("IPv4 UDP listen port: {}", this->udp4socket.address().port());
                this->pollSet.add(this->udp4socket, PollSet::POLL_READ);
            } else if (transport == "UDP6") {
                this->udp6socket.bind6(SocketAddress(AddressFamily::IPv6, this->listenPort), true, true, true);
                spdlog::debug("IPv6 UDP listen port: {}", this->udp6socket.address().port());
                this->pollSet.add(this->udp6socket, PollSet::POLL_READ);
            } else if (transport == "TCP4") {
                this->tcp4socket.bind(SocketAddress(AddressFamily::IPv4, this->listenPort), true);
                this->tcp4socket.listen();
                spdlog::debug("IPv4 TCP listen port: {}", this->tcp4socket.address().port());
                this->pollSet.add(this->tcp4socket, PollSet::POLL_READ);
            } else if (transport == "TCP6") {
                this->tcp6socket.bind6(SocketAddress(AddressFamily::IPv6, this->listenPort), true, true);
                this->tcp6socket.listen();
                spdlog::debug("IPv6 TCP listen port: {}", this->tcp6socket.address().port());
                this->pollSet.add(this->tcp6socket, PollSet::POLL_READ);
            }
        }
    } catch (Poco::Net::NetException &e) {
        spdlog::critical("peer init socket failed: {}: {}", e.what(), e.message());
        return -1;
    }

    this->decryptCtx = std::shared_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    this->pollThread = std::thread([&]() {
        while (getClient().running) {
            poll();
        }
    });
    return 0;
}

void PeerManager::sendUdpStunRequest() {
    try {
        Poco::URI uri(this->udpStun.uri);
        if (!uri.getPort()) {
            uri.setPort(3478);
        }
        StunRequest request;
        this->udpStun.address = Poco::Net::SocketAddress(uri.getHost(), uri.getPort());
        if (this->udp4socket.sendTo(&request, sizeof(request), this->udpStun.address) != sizeof(request)) {
            spdlog::warn("the stun request was not completely sent");
        }
    } catch (std::exception &e) {
        spdlog::debug("send stun request failed: {}", e.what());
    }
}

void PeerManager::handleUdpStunResponse(const std::string &buffer) {
    if (buffer.length() < sizeof(StunResponse)) {
        spdlog::debug("invalid stun response length: {}", buffer.length());
        return;
    }
    StunResponse *response = (StunResponse *)buffer.c_str();
    if (ntoh(response->type) != 0x0101) {
        spdlog::debug("invalid stun reponse type: {}", ntoh(response->type));
        return;
    }

    int pos = 0;
    uint32_t ip = 0;
    uint16_t port = 0;
    uint8_t *attr = response->attr;
    while (pos < ntoh(response->length)) {
        // mapped address
        if (ntoh(*(uint16_t *)(attr + pos)) == 0x0001) {
            pos += 6; // 跳过 2 字节类型, 2 字节长度, 1 字节保留, 1 字节IP版本号,指向端口号
            port = ntoh(*(uint16_t *)(attr + pos));
            pos += 2; // 跳过2字节端口号,指向地址
            ip = *(uint32_t *)(attr + pos);
            break;
        }
        // xor mapped address
        if (ntoh(*(uint16_t *)(attr + pos)) == 0x0020) {
            pos += 6; // 跳过 2 字节类型, 2 字节长度, 1 字节保留, 1 字节IP版本号,指向端口号
            port = ntoh(*(uint16_t *)(attr + pos)) ^ 0x2112;
            pos += 2; // 跳过2字节端口号,指向地址
            ip = (*(uint32_t *)(attr + pos)) ^ hton(0x2112a442);
            break;
        }
        // 跳过 2 字节类型,指向属性长度
        pos += 2;
        // 跳过 2 字节长度和用该属性其他内容
        pos += 2 + ntoh(*(uint16_t *)(attr + pos));
    }
    if (!ip || !port) {
        spdlog::warn("stun response parse failed: {:n}", spdlog::to_hex(buffer));
        return;
    }

    memcpy(&this->udpStun.ip, &ip, sizeof(this->udpStun.ip));
    this->udpStun.port = port;

    std::shared_lock lock(this->ipPeerMutex);
    for (auto &[tun, peer] : this->ipPeerMap) {
        peer.handleUdpStunResponse();
    }

    return;
}

void PeerManager::handleUdp4Message(std::string &buffer, const SocketAddress &address) {
    switch (buffer.front()) {
    case PeerMsgKind::HEARTBEAT:
        handleUdp4HeartbeatMessage(buffer, address);
        break;
    case PeerMsgKind::FORWARD:
        handleUdp4ForwardMessage(buffer, address);
        break;
    case PeerMsgKind::DELAY:
        handleUdp4DelayMessage(buffer, address);
        break;
    case PeerMsgKind::ROUTE:
        handleUdp4RouteMessage(buffer, address);
        break;
    default:
        spdlog::info("udp4 unknown message: {}", address.toString());
        break;
    }
}

void PeerManager::handleUdp4HeartbeatMessage(std::string &buffer, const SocketAddress &address) {
    if (buffer.size() < sizeof(PeerMsg::Heartbeat)) {
        spdlog::debug("udp4 heartbeat failed: len {} address {}", buffer.length(), address.toString());
        return;
    }

    PeerMsg::Heartbeat *heartbeat = (PeerMsg::Heartbeat *)buffer.c_str();
    std::shared_lock lock(this->ipPeerMutex);
    auto it = this->ipPeerMap.find(heartbeat->tunip);
    if (it == this->ipPeerMap.end()) {
        spdlog::debug("udp4 heartbeat find peer failed: tun ip {}", heartbeat->tunip.toString());
        return;
    }

    if (auto peer = it->second.Udp4()) {
        peer->handleHeartbeatMessage(address, heartbeat->ack);
    }
}

void PeerManager::handleUdp4ForwardMessage(std::string &buffer, const SocketAddress &address) {
    if (buffer.size() < sizeof(PeerMsg::Forward)) {
        spdlog::warn("invalid forward message: {:n}", spdlog::to_hex(buffer));
        return;
    }
    buffer.erase(0, 1);
    IP4Header *header = (IP4Header *)buffer.data();
    if (header->daddr == getTunIp()) {
        getClient().tunMsgQueue.write(Msg(MsgKind::PACKET, std::move(buffer)));
    } else {
        getClient().peerMsgQueue.write(Msg(MsgKind::PACKET, std::move(buffer)));
    }
}

void PeerManager::handleUdp4DelayMessage(std::string &buffer, const SocketAddress &address) {
    // TODO: handle udp4 delay message
}

void PeerManager::handleUdp4RouteMessage(std::string &buffer, const SocketAddress &address) {
    // TODO: handle udp4 route message
}

void PeerManager::poll() {
    using Poco::Net::PollSet;
    using Poco::Net::Socket;
    using Poco::Net::SocketAddress;

    PollSet::SocketModeMap socketModeMap = this->pollSet.poll(Poco::Timespan(1, 0));
    for (auto &pair : socketModeMap) {
        if (pair.second & PollSet::POLL_READ) {
            if (pair.first == tcp4socket) {
                // TODO: tcp4
            } else if (pair.first == tcp6socket) {
                // TODO: tcp6
            } else if (pair.first == udp4socket) {
                std::string buffer(1500, 0);
                SocketAddress address;
                auto size = udp4socket.receiveFrom(buffer.data(), buffer.size(), address);
                if (size > 0) {
                    buffer.resize(size);
                    if (this->udpStun.address == address) {
                        handleUdpStunResponse(buffer);
                    } else if (auto plaintext = decrypt(buffer)) {
                        handleUdp4Message(*plaintext, address);
                    }
                }
            } else if (pair.first == udp6socket) {
                // TODO: udp6
            } else {
                spdlog::warn("unexpected socket: {}", pair.first.address().toString());
            }
        }
    }
}

std::optional<std::string> PeerManager::decrypt(const std::string &ciphertext) {
    int len = 0;
    int plaintextLen = 0;
    unsigned char *enc = NULL;
    unsigned char plaintext[1500] = {0};
    unsigned char iv[AES_256_GCM_IV_LEN] = {0};
    unsigned char tag[AES_256_GCM_TAG_LEN] = {0};

    if (this->key.size() != AES_256_GCM_KEY_LEN) {
        spdlog::debug("invalid key length: {}", this->key.size());
        return std::nullopt;
    }

    if (ciphertext.size() < AES_256_GCM_IV_LEN + AES_256_GCM_TAG_LEN) {
        spdlog::debug("invalid ciphertext length: {}", ciphertext.size());
        return std::nullopt;
    }

    std::lock_guard lock(this->decryptCtxMutex);
    auto ctx = this->decryptCtx.get();

    if (!EVP_CIPHER_CTX_reset(ctx)) {
        spdlog::debug("decrypt reset cipher context failed");
        return std::nullopt;
    }

    enc = (unsigned char *)ciphertext.data();
    memcpy(iv, enc, AES_256_GCM_IV_LEN);
    memcpy(tag, enc + AES_256_GCM_IV_LEN, AES_256_GCM_TAG_LEN);
    enc += AES_256_GCM_IV_LEN + AES_256_GCM_TAG_LEN;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char *)key.data(), iv)) {
        spdlog::debug("initialize cipher context failed");
        return std::nullopt;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_LEN, NULL)) {
        spdlog::debug("set iv length failed");
        return std::nullopt;
    }
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, enc, ciphertext.size() - AES_256_GCM_IV_LEN - AES_256_GCM_TAG_LEN)) {
        spdlog::debug("decrypt update failed");
        return std::nullopt;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_256_GCM_TAG_LEN, tag)) {
        spdlog::debug("set tag failed");
        return std::nullopt;
    }

    plaintextLen = len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        spdlog::debug("decrypt final failed");
        return std::nullopt;
    }

    plaintextLen += len;

    std::string result;
    result.append((char *)plaintext, plaintextLen);
    return result;
}

std::vector<std::string> PeerManager::getTransport() {
    return this->transport;
}

Client &PeerManager::getClient() {
    return *this->client;
}

} // namespace Candy

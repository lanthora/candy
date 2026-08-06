// SPDX-License-Identifier: MIT
#include "tun/tun.h"
#include "core/client.h"
#include "core/message.h"
#include "core/net.h"
#include "utils/hex.h"
#include "utils/log.h"
#include <Poco/Format.h>
#include <mutex>
#include <shared_mutex>

namespace candy {

int Tun::run(Client *client) {
    this->client = client;
    this->msgThread = std::thread([&] {
        candy::logger().debug("start thread: tun msg");
        try {
            while (getClient().isRunning()) {
                if (handleTunQueue()) {
                    break;
                }
            }
            getClient().shutdown();
        } catch (const std::exception &e) {
            candy::logger().error(Poco::format("tun msg thread exception: %s", std::string(e.what())));
            getClient().shutdown();
        }
        candy::logger().debug("stop thread: tun msg");
    });
    return 0;
}

int Tun::wait() {
    if (this->msgThread.joinable()) {
        this->msgThread.join();
    }
    if (this->tunThread.joinable()) {
        this->tunThread.join();
    }
    {
        std::unique_lock lock(this->sysRtMutex);
        this->sysRtTable.clear();
    }
    return 0;
}

int Tun::handleTunDevice() {
    std::string buffer;
    int error = read(buffer);
    if (error <= 0) {
        return 0;
    }
    if (buffer.length() < sizeof(IP4Header)) {
        return 0;
    }
    IP4Header *header = (IP4Header *)buffer.data();
    if (!header->isIPv4()) {
        return 0;
    }

    if (header->daddr == getIP()) {
        write(buffer);
        return 0;
    }

    IP4 nextHop = [&]() {
        std::shared_lock lock(this->sysRtMutex);
        for (auto const &rt : sysRtTable) {
            if ((header->daddr & rt.mask) == rt.dst) {
                return rt.nexthop;
            }
        }
        return IP4();
    }();

    if (!nextHop.empty()) {
        buffer.insert(0, sizeof(IP4Header), 0);
        header = (IP4Header *)buffer.data();
        header->protocol = 0x04;
        header->saddr = getIP();
        header->daddr = nextHop;
    }

    if (invalidSrcDst(*header)) {
        candy::logger().debug(Poco::format("packet src=%s or dst=%s not in tun network, dropping", header->saddr.toString(),
                                           header->daddr.toString()));
        return 0;
    }

    this->client->getPeerMsgQueue().write(Msg(MsgKind::PACKET, std::move(buffer)));
    return 0;
}

int Tun::handleTunQueue() {
    Msg msg = this->client->getTunMsgQueue().read();
    switch (msg.kind) {
    case MsgKind::TIMEOUT:
        break;
    case MsgKind::PACKET:
        handlePacket(std::move(msg));
        break;
    case MsgKind::TUNADDR:
        if (handleTunAddr(std::move(msg))) {
            return -1;
        }
        break;
    case MsgKind::SYSRT:
        handleSysRt(std::move(msg));
        break;
    default:
        candy::logger().warning(Poco::format("unexcepted tun message type: %d", static_cast<int>(msg.kind)));
        break;
    }
    return 0;
}

int Tun::handlePacket(Msg msg) {
    if (msg.data.size() < sizeof(IP4Header)) {
        candy::logger().warning(Poco::format("invalid IPv4 packet: %s", to_hex(msg.data)));
        return 0;
    }
    IP4Header *header = (IP4Header *)msg.data.data();
    if (header->isIPIP()) {
        msg.data.erase(0, sizeof(IP4Header));
        header = (IP4Header *)msg.data.data();
    }
    write(msg.data);
    return 0;
}

int Tun::handleTunAddr(Msg msg) {
    if (setAddress(msg.data)) {
        return -1;
    }

    if (up()) {
        candy::logger().fatal("tun up failed");
        return -1;
    }

    this->tunThread = std::thread([&] {
        candy::logger().debug("start thread: tun");
        try {
            while (getClient().isRunning()) {
                if (handleTunDevice()) {
                    break;
                }
            }
            getClient().shutdown();
            candy::logger().debug("stop thread: tun");

            if (down()) {
                candy::logger().fatal("tun down failed");
                return;
            }
        } catch (const std::exception &e) {
            candy::logger().error(Poco::format("tun thread exception: %s", std::string(e.what())));
            getClient().shutdown();
        }
    });

    return 0;
}

int Tun::handleSysRt(Msg msg) {
    SysRouteEntry *rt = (SysRouteEntry *)msg.data.data();
    if (rt->nexthop != getIP()) {
        candy::logger().information(
            Poco::format("route: %s/%d via %s", rt->dst.toString(), rt->mask.toPrefix(), rt->nexthop.toString()));
        if (setSysRtTable(*rt)) {
            return -1;
        }
    }
    return 0;
}

int Tun::setSysRtTable(const SysRouteEntry &entry) {
    std::unique_lock lock(this->sysRtMutex);
    this->sysRtTable.push_back(entry);
    return setSysRtTable(entry.dst, entry.mask, entry.nexthop);
}

int Tun::setAddress(const std::string &cidr) {
    Address address;

    if (address.fromCidr(cidr)) {
        return -1;
    }
    candy::logger().information(Poco::format("client address: %s", address.toCidr()));
    this->ip = address.Host();
    this->mask = address.Mask();
    this->tunAddress = cidr;
    return 0;
}

IP4 Tun::getIP() const {
    return this->ip;
}

IP4 Tun::getMask() const {
    return this->mask;
}

bool Tun::inTunNetwork(IP4 addr) const {
    return (addr & this->mask) == (this->ip & this->mask);
}

bool Tun::invalidSrcDst(const IP4Header &header) const {
    if (inTunNetwork(header.saddr) && inTunNetwork(header.daddr)) {
        return false;
    }
    if (header.daddr == IP4("255.255.255.255")) {
        return false;
    }
    if ((header.daddr & IP4("240.0.0.0")) == IP4("224.0.0.0")) {
        return false;
    }
    return true;
}

Client &Tun::getClient() {
    return *this->client;
}

} // namespace candy

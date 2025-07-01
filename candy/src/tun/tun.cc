// SPDX-License-Identifier: MIT
#include "tun/tun.h"
#include "core/client.h"
#include "core/message.h"
#include "core/net.h"
#include <mutex>
#include <shared_mutex>
#include <spdlog/fmt/bin_to_hex.h>

namespace candy {

int Tun::run(Client *client) {
    this->client = client;
    this->msgThread = std::thread([&] {
        spdlog::debug("start thread: tun msg");
        while (getClient().isRunning()) {
            if (handleTunQueue()) {
                break;
            }
        }
        getClient().shutdown();
        spdlog::debug("stop thread: tun msg");
    });
    return 0;
}

int Tun::wait() {
    if (this->tunThread.joinable()) {
        this->tunThread.join();
    }
    if (this->msgThread.joinable()) {
        this->msgThread.join();
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

    if (header->daddr == getIP()) {
        write(buffer);
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
        spdlog::warn("unexcepted tun message type: {}", static_cast<int>(msg.kind));
        break;
    }
    return 0;
}

int Tun::handlePacket(Msg msg) {
    if (msg.data.size() < sizeof(IP4Header)) {
        spdlog::warn("invalid IPv4 packet: {:n}", spdlog::to_hex(msg.data));
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
        spdlog::critical("tun up failed");
        return -1;
    }

    this->tunThread = std::thread([&] {
        spdlog::debug("start thread: tun");
        while (getClient().isRunning()) {
            if (handleTunDevice()) {
                break;
            }
        }
        getClient().shutdown();
        spdlog::debug("stop thread: tun");

        if (down()) {
            spdlog::critical("tun down failed");
            return;
        }
    });

    return 0;
}

int Tun::handleSysRt(Msg msg) {
    SysRouteEntry *rt = (SysRouteEntry *)msg.data.data();
    if (rt->nexthop != getIP()) {
        spdlog::info("route: {}/{} via {}", rt->dst.toString(), rt->mask.toPrefix(), rt->nexthop.toString());
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

Client &Tun::getClient() {
    return *this->client;
}

} // namespace candy

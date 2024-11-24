// SPDX-License-Identifier: MIT
#include "tun/tun.h"
#include "core/client.h"
#include "core/message.h"
#include "core/net.h"
#include <mutex>
#include <shared_mutex>
#include <spdlog/fmt/bin_to_hex.h>

namespace Candy {

int Tun::run(Client *client) {
    this->client = client;
    this->msgThread = std::thread([&] {
        while (this->client->running) {
            handleTunQueue();
        }
    });
    return 0;
}

int Tun::shutdown() {
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

void Tun::handleTunDevice() {
    std::string buffer;
    int error = read(buffer);
    if (error <= 0) {
        return;
    }
    if (buffer.length() < sizeof(IP4Header)) {
        return;
    }
    IP4Header *header = (IP4Header *)buffer.data();
    if ((header->version_ihl >> 4) != 4) {
        return;
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
        return;
    }

    // 流量给 P2P 模块,如果 P2P 模块无法处理,由 P2P 模块转发给 WS 模块
    this->client->peerMsgQueue.write(Msg(MsgKind::PACKET, std::move(buffer)));
}

void Tun::handleTunQueue() {
    Msg msg = this->client->tunMsgQueue.read();
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
        handleSysRt(std::move(msg));
        break;
    default:
        spdlog::warn("unexcepted tun message type: {}", static_cast<int>(msg.kind));
        break;
    }
}

void Tun::handlePacket(Msg msg) {
    if (msg.data.size() < sizeof(IP4Header)) {
        spdlog::warn("invalid IPv4 packet: {:n}", spdlog::to_hex(msg.data));
        return;
    }
    IP4Header *header = (IP4Header *)msg.data.data();
    if (header->protocol == 0x04) {
        msg.data.erase(0, sizeof(IP4Header));
        header = (IP4Header *)msg.data.data();
    }
    write(msg.data);
}

void Tun::handleTunAddr(Msg msg) {
    if (setAddress(msg.data)) {
        Candy::shutdown(this->client);
    }

    this->tunThread = std::thread([&] {
        if (up()) {
            Candy::shutdown(this->client);
            return;
        }
        while (this->client->running) {
            handleTunDevice();
        }
        if (down()) {
            Candy::shutdown(this->client);
            return;
        }
    });
}

void Tun::handleSysRt(Msg msg) {
    SysRouteEntry *rt = (SysRouteEntry *)msg.data.data();
    if (rt->nexthop != getIP()) {
        spdlog::info("route: {}/{} via {}", rt->dst.toString(), rt->mask.toPrefix(), rt->nexthop.toString());
        setSysRtTable(*rt);
    }
}

int Tun::setSysRtTable(const SysRouteEntry &entry) {
    std::unique_lock lock(this->sysRtMutex);
    this->sysRtTable.push_back(entry);
    return setSysRtTable(entry.dst, entry.mask, entry.nexthop);
}

} // namespace Candy

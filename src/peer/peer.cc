// SPDX-License-Identifier: MIT
#include "peer/peer.h"
#include "core/client.h"
#include "core/message.h"
#include "core/net.h"
#include <shared_mutex>
#include <spdlog/spdlog.h>

namespace Candy {

int Peer::setPassword(const std::string &password) {
    return 0;
}

int Peer::setStun(const std::string &stun) {
    return 0;
}

int Peer::setDiscoveryInterval(int interval) {
    return 0;
}

int Peer::setForwardCost(int cost) {
    return 0;
}

int Peer::setPort(int port) {
    return 0;
}

int Peer::setLocalhost(const std::string &ip) {
    return 0;
}

int Peer::run(Client *client) {
    this->client = client;
    this->msgThread = std::thread([&] {
        while (this->client->running) {
            handlePeerQueue();
        }
    });
    return 0;
}

int Peer::shutdown() {
    if (this->msgThread.joinable()) {
        this->msgThread.join();
    }
    return 0;
}

void Peer::handlePeerQueue() {
    Msg msg = this->client->peerMsgQueue.read();
    switch (msg.kind) {
    case MsgKind::TIMEOUT:
        break;
    case MsgKind::PACKET:
        handlePacket(std::move(msg));
        break;
    case MsgKind::TRYP2P:
        handleTryP2P(std::move(msg));
        break;
    default:
        spdlog::warn("unexcepted peer message type: {}", static_cast<int>(msg.kind));
        break;
    }
}

int Peer::sendTo(IP4 dst, const Msg &msg) {
    // 这两个锁同时使用时先给 ipPeerMap 加锁,避免死锁
    std::shared_lock ipPeerLock(this->ipPeerMutex);
    std::shared_lock rtTableLock(this->rtTableMutex);

    auto rt = this->rtTableMap.find(dst);
    if (rt == this->rtTableMap.end()) {
        return -1;
    }
    auto it = this->ipPeerMap.find(rt->second);
    if (it == this->ipPeerMap.end()) {
        return -1;
    }
    auto &info = it->second;
    if (!info.isConnected()) {
        return -1;
    }
    std::string x;
    x.push_back(1);
    x += msg.data;
    return sendTo(info, x);
}

int Peer::sendTo(PeerInfo &info, const std::string &data) {
    return -1;
}

void Peer::handlePacket(Msg msg) {
    IP4Header *header = (IP4Header *)msg.data.data();
    // 尝试 P2P 转发流量
    if (!sendTo(header->daddr, msg)) {
        return;
    }
    // 无法通过 P2P 转发流量,交给 WS 模块通过服务端转发
    this->client->wsMsgQueue.write(std::move(msg));
}

void Peer::handleTryP2P(Msg msg) {
    // TODO: 尝试与特定对端建立直连
    IP4 src(msg.data);
    spdlog::debug("TRYP2P: {}", src.toString());
}

} // namespace Candy

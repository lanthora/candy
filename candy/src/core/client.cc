// SPDX-License-Identifier: MIT
#include "core/client.h"
#include "core/message.h"
#include <Poco/String.h>
#include <chrono>

namespace candy {

Msg MsgQueue::read() {
    std::unique_lock lock(msgMutex);
    if (!msgCondition.wait_for(lock, std::chrono::seconds(1), [this] { return !msgQueue.empty(); })) {
        return Msg(MsgKind::TIMEOUT);
    }

    Msg msg = std::move(msgQueue.front());
    msgQueue.pop();
    return msg;
}

void MsgQueue::write(Msg msg) {
    {
        std::unique_lock lock(this->msgMutex);
        msgQueue.push(std::move(msg));
    }
    msgCondition.notify_one();
}

void MsgQueue::clear() {
    std::unique_lock lock(this->msgMutex);
    while (!msgQueue.empty()) {
        msgQueue.pop();
    }
}

void Client::setName(const std::string &name) {
    this->tunName = name;
    tun.setName(name);
    ws.setName(name);
}

std::string Client::getName() const {
    return this->tunName;
}

std::string Client::getTunCidr() const {
    return ws.getTunCidr();
}

IP4 Client::address() {
    return this->tun.getIP();
}

MsgQueue &Client::getTunMsgQueue() {
    return this->tunMsgQueue;
}

MsgQueue &Client::getPeerMsgQueue() {
    return this->peerMsgQueue;
}

MsgQueue &Client::getWsMsgQueue() {
    return this->wsMsgQueue;
}

void Client::setPassword(const std::string &password) {
    ws.setPassword(password);
    peerManager.setPassword(password);
}

void Client::setWebSocket(const std::string &uri) {
    ws.setWsServerUri(uri);
}

void Client::setTunAddress(const std::string &cidr) {
    ws.setAddress(cidr);
}

void Client::setExptTunAddress(const std::string &cidr) {
    ws.setExptTunAddress(cidr);
}

void Client::setVirtualMac(const std::string &vmac) {
    ws.setVirtualMac(vmac);
}

void Client::setStun(const std::string &stun) {
    peerManager.setStun(stun);
}

void Client::setDiscoveryInterval(int interval) {
    peerManager.setDiscoveryInterval(interval);
}

void Client::setRouteCost(int cost) {
    peerManager.setRouteCost(cost);
}

void Client::setPort(int port) {
    peerManager.setPort(port);
}

void Client::setLocalhost(std::string ip) {
    peerManager.setLocalhost(ip);
}

void Client::setMtu(int mtu) {
    tun.setMTU(mtu);
}

void Client::run() {
    this->running.store(true);

    if (ws.run(this)) {
        return;
    }
    if (tun.run(this)) {
        return;
    }
    if (peerManager.run(this)) {
        return;
    }

    ws.wait();
    tun.wait();
    peerManager.wait();

    wsMsgQueue.clear();
    tunMsgQueue.clear();
    peerMsgQueue.clear();
}

bool Client::isRunning() {
    return this->running.load();
}

void Client::shutdown() {
    this->running.store(false);
}

} // namespace candy

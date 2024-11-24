// SPDX-License-Identifier: MIT
#include "core/client.h"
#include "core/message.h"
#include <chrono>

namespace Candy {

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

void Client::setName(const std::string &name) {
    this->tunName = name;
    tun.setName(name);
}

std::string Client::getName() const {
    return this->tunName;
}

void Client::setPassword(const std::string &password) {
    ws.setPassword(password);
    peer.setPassword(password);
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
    peer.setStun(stun);
}

void Client::setDiscoveryInterval(int interval) {
    peer.setDiscoveryInterval(interval);
}

void Client::setRouteCost(int cost) {
    peer.setForwardCost(cost);
}

void Client::setPort(int port) {
    peer.setPort(port);
}

void Client::setLocalhost(std::string ip) {
    peer.setLocalhost(ip);
}

void Client::setMtu(int mtu) {
    tun.setMTU(mtu);
}

void Client::setTunUpdateCallback(std::function<int(const std::string &)> callback) {
    this->ws.setTunUpdateCallback(callback);
}

void Client::run() {
    this->running = true;
    ws.run(this);
    tun.run(this);
    peer.run(this);
}

void Client::shutdown() {
    this->running = false;
    ws.shutdown();
    tun.shutdown();
    peer.shutdown();
}

} // namespace Candy

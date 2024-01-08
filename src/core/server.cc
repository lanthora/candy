// SPDX-License-Identifier: MIT
#include "core/server.h"
#include "core/common.h"
#include "core/message.h"
#include "utility/address.h"
#include "utility/random.h"
#include "utility/uri.h"
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

namespace Candy {

int Server::setWebSocketServer(const std::string &uri) {
    Uri parser(uri);
    if (!parser.isValid()) {
        spdlog::critical("invalid websocket uri: {}", uri);
        return -1;
    }
    if (parser.scheme() != "ws") {
        spdlog::critical("websocket server only support ws. please use a proxy such as nginx to handle encryption");
        return -1;
    }
    // 服务端必须指定端口号
    if (parser.port().empty()) {
        spdlog::critical("websocket server must specify the listening port");
        return -1;
    }
    // 服务端必须指定 IP 地址和端口号,不能用域名
    Address address;
    if (address.ipStrUpdate(parser.host())) {
        spdlog::critical("invalid websocket server ip: {}", parser.host());
        return -1;
    }
    this->ipStr = address.getIpStr();
    this->port = std::stoi(parser.port());
    return 0;
}

int Server::setPassword(const std::string &password) {
    this->password = password;
    return 0;
}

int Server::setDynamicAddressRange(const std::string &cidr) {
    if (cidr.empty()) {
        return 0;
    }
    if (this->dynamic.cidrUpdate(cidr)) {
        spdlog::critical("dynamic address generator init failed");
        return -1;
    }
    uint32_t randomHost = (~this->dynamic.getMask()) & randomUint32();
    if (this->dynamic.ipMaskUpdate(this->dynamic.getNet() | randomHost, this->dynamic.getMask())) {
        return -1;
    }
    this->dynamicAddrEnabled = true;
    return 0;
}

int Server::run() {
    this->running = true;
    if (startWsThread()) {
        spdlog::critical("start websocket server thread failed");
        Candy::shutdown();
        return -1;
    }
    return 0;
}

int Server::shutdown() {
    if (!this->running) {
        return 0;
    }

    this->running = false;
    this->dynamicAddrEnabled = false;
    if (this->wsThread.joinable()) {
        this->wsThread.join();
    }

    this->ws.stop();
    return 0;
}

int Server::startWsThread() {
    if (this->ws.listen(this->ipStr, this->port)) {
        spdlog::critical("websocket server listen failed");
        return -1;
    }

    if (this->ws.setTimeout(1)) {
        spdlog::critical("websocket server set read write timeout failed");
        return -1;
    }

    this->wsThread = std::thread([&] { this->handleWebSocketMessage(); });
    return 0;
}

void Server::handleWebSocketMessage() {
    int error;
    WebSocketMessage message;

    while (this->running) {
        error = this->ws.read(message);
        if (error == 0) {
            continue;
        }
        if (error < 0) {
            spdlog::error("websocket server read failed: error {}", error);
            Candy::shutdown();
            break;
        }

        if (message.type == WebSocketMessageType::Message) {
            if (message.buffer.front() == MessageType::FORWARD) {
                handleForwardMessage(message);
                continue;
            }
            if (message.buffer.front() == MessageType::VMAC) {
                handleVirtualMacMessage(message);
                continue;
            }
            if (message.buffer.front() == MessageType::AUTH) {
                handleAuthMessage(message);
                continue;
            }
            if (message.buffer.front() == MessageType::DHCP) {
                handleDynamicAddressMessage(message);
                continue;
            }
            if (message.buffer.front() == MessageType::PEER) {
                handlePeerConnMessage(message);
                continue;
            }
            spdlog::warn("unknown message type: {}", (int)message.buffer.front());
            continue;
        }

        if (message.type == WebSocketMessageType::Close) {
            handleCloseMessage(message);
            continue;
        }
        if (message.type == WebSocketMessageType::Error) {
            spdlog::critical("server websocket error: {}", message.buffer);
            Candy::shutdown();
            break;
        }
    }
    return;
}

void Server::handleAuthMessage(WebSocketMessage &message) {
    if (message.buffer.length() < sizeof(AuthHeader)) {
        spdlog::warn("invalid auth message: len {}", message.buffer.length());
        this->ws.close(message.conn);
        return;
    }

    AuthHeader *header = (AuthHeader *)message.buffer.data();
    if (!header->check(this->password)) {
        spdlog::warn("auth header check failed: buffer {:n}", spdlog::to_hex(message.buffer));
        this->ws.close(message.conn);
        return;
    }

    Address address;
    if (address.ipUpdate(Address::netToHost(header->ip))) {
        spdlog::warn("invalid auth ip: buffer {:n}", spdlog::to_hex(message.buffer));
        this->ws.close(message.conn);
        return;
    }
    if (this->ipWsMap.contains(address.getIp())) {
        this->ws.close(this->ipWsMap[address.getIp()]);
        spdlog::debug("client reconnected: {}", address.getIpStr());
    } else {
        spdlog::info("client connected: {}", address.getIpStr());
    }

    this->ipWsMap[address.getIp()] = message.conn;
    this->wsIpMap[message.conn] = address.getIp();
}

void Server::handleForwardMessage(WebSocketMessage &message) {
    if (!this->wsIpMap.contains(message.conn)) {
        spdlog::debug("unauthorized forward websocket client");
        return;
    }

    if (message.buffer.length() < sizeof(ForwardHeader)) {
        spdlog::debug("invalid forawrd message: len {}", message.buffer.length());
        return;
    }

    ForwardHeader *header = (ForwardHeader *)message.buffer.data();
    Address auth, source, destination;
    auth.ipUpdate(this->wsIpMap[message.conn]);
    source.ipUpdate(Address::netToHost(header->iph.saddr));
    destination.ipUpdate(Address::netToHost(header->iph.daddr));

    if (this->wsIpMap[message.conn] != Address::netToHost(header->iph.saddr)) {
        spdlog::debug("forward source address does not match: auth {} source {}", auth.getIpStr(), source.getIpStr());
        return;
    }

    if (this->ipWsMap.contains(Address::netToHost(header->iph.daddr))) {
        message.conn = this->ipWsMap[Address::netToHost(header->iph.daddr)];
        this->ws.write(message);
        return;
    }

    bool isBroadcast = !((~this->dynamic.getMask()) & (Address::netToHost(header->iph.daddr) + 1));
    if (this->dynamicAddrEnabled && isBroadcast) {
        for (auto conn : this->ipWsMap) {
            message.conn = conn.second;
            this->ws.write(message);
        }
        return;
    }

    spdlog::debug("forward dest address not logged in: source {} dest {}", source.getIpStr(), destination.getIpStr());
    return;
}

void Server::handleDynamicAddressMessage(WebSocketMessage &message) {
    if (message.buffer.length() < sizeof(DynamicAddressMessage)) {
        spdlog::warn("invalid dynamic address message: len {}", message.buffer.length());
        this->ws.close(message.conn);
        return;
    }

    DynamicAddressMessage *header = (DynamicAddressMessage *)message.buffer.data();
    if (!header->check(this->password)) {
        spdlog::warn("dynamic address header check failed: buffer {:n}", spdlog::to_hex(message.buffer));
        this->ws.close(message.conn);
        return;
    }

    if (!this->dynamicAddrEnabled) {
        spdlog::warn("the client requests a dynamic address, but the server does not enable this function");
        this->ws.close(message.conn);
        return;
    }

    Address address;
    if (address.cidrUpdate(header->cidr)) {
        spdlog::warn("dynamic address header cidr invalid: buffer {:n}", spdlog::to_hex(message.buffer));
        this->ws.close(message.conn);
        return;
    }

    bool needGenNewAddr = [&]() {
        if (!dynamic.inSameNetwork(address)) {
            return true;
        }
        auto oldWs = this->ipWsMap.find(address.getIp());
        if (oldWs == this->ipWsMap.end()) {
            return false;
        }
        auto newMac = this->wsMacMap.find(message.conn);
        if (newMac == this->wsMacMap.end()) {
            return true;
        }
        auto oldMac = this->wsMacMap.find(oldWs->second);
        if (oldMac == this->wsMacMap.end()) {
            return true;
        }
        if (newMac->second == oldMac->second) {
            return false;
        }
        return true;
    }();

    if (needGenNewAddr) {
        uint32_t oldip = dynamic.getIp();
        uint32_t newip = 0;
        do {
            if (this->dynamic.next()) {
                spdlog::error("unable to get next available address");
                this->ws.close(message.conn);
                return;
            }
            newip = dynamic.getIp();
            if (oldip == newip) {
                spdlog::warn("all addresses in the network are assigned");
                this->ws.close(message.conn);
                return;
            }
        } while (this->ipWsMap.contains(newip));
        address.ipMaskUpdate(dynamic.getIp(), dynamic.getMask());
    }

    header->timestamp = Time::hostToNet(Time::unixTime());
    std::strcpy(header->cidr, address.getCidr().c_str());
    header->updateHash(this->password);

    this->ws.write(message);
}

void Server::handlePeerConnMessage(WebSocketMessage &message) {
    if (!this->wsIpMap.contains(message.conn)) {
        spdlog::debug("unauthorized peer websocket client");
        return;
    }

    if (message.buffer.length() < sizeof(PeerConnMessage)) {
        spdlog::warn("invalid peer message: len {}", message.buffer.length());
        return;
    }

    PeerConnMessage *header = (PeerConnMessage *)message.buffer.data();
    Address auth, source, destination;
    auth.ipUpdate(this->wsIpMap[message.conn]);
    source.ipUpdate(Address::netToHost(header->src));
    if (this->wsIpMap[message.conn] != Address::netToHost(header->src)) {
        spdlog::debug("peer source address does not match: auth {} source {}", auth.getIpStr(), source.getIpStr());
        return;
    }
    if (!this->ipWsMap.contains(Address::netToHost(header->dst))) {
        spdlog::debug("peer dest address not logged in: source {} dest {}", source.getIpStr(), destination.getIpStr());
        return;
    }
    message.conn = this->ipWsMap[Address::netToHost(header->dst)];
    this->ws.write(message);
    return;
}

void Server::handleVirtualMacMessage(WebSocketMessage &message) {
    if (message.buffer.length() < sizeof(VMacMessage)) {
        spdlog::warn("invalid vmac message: len {}", message.buffer.length());
        return;
    }

    VMacMessage *header = (VMacMessage *)message.buffer.data();
    if (!header->check(this->password)) {
        spdlog::warn("vmac message check failed: buffer {:n}", spdlog::to_hex(message.buffer));
        this->ws.close(message.conn);
        return;
    }
    std::string vmac((char *)header->vmac, sizeof(header->vmac));

    this->wsMacMap[message.conn] = vmac;
    return;
}

void Server::handleCloseMessage(WebSocketMessage &message) {
    auto it = this->wsIpMap.find(message.conn);
    if (it != this->wsIpMap.end()) {
        if (this->ipWsMap[it->second] == message.conn) {
            Address address;
            if (!address.ipUpdate(it->second)) {
                spdlog::info("client disconnected: {}", address.getIpStr());
            }
            this->ipWsMap.erase(it->second);
        }
        this->wsIpMap.erase(it);
    }
    this->wsMacMap.erase(message.conn);
}

} // namespace Candy

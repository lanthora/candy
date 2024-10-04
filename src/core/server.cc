// SPDX-License-Identifier: MIT
#include "core/server.h"
#include "core/common.h"
#include "core/message.h"
#include "utility/address.h"
#include "utility/random.h"
#include "utility/time.h"
#include <Poco/URI.h>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>
#include <sstream>

namespace Candy {

int Server::setWebSocketServer(const std::string &uri) {
    try {
        Poco::URI parser(uri);
        if (parser.getScheme() != "ws") {
            spdlog::critical("websocket server only support ws");
            return -1;
        }
        this->host = parser.getHost();
        this->port = parser.getPort();
        return 0;
    } catch (std::exception &e) {
        spdlog::critical("invalid websocket uri: {}: {}", uri, e.what());
        return -1;
    }
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

int Server::setSdwan(const std::string &sdwan) {
    if (sdwan.empty()) {
        return 0;
    }
    std::string route;
    std::stringstream stream(sdwan);
    while (std::getline(stream, route, ';')) {
        std::string addr;
        SysRoute rt;
        std::stringstream ss(route);
        if (!std::getline(ss, addr, ',') || rt.dev.cidrUpdate(addr) || rt.dev.getIp() != rt.dev.getNet()) {
            spdlog::critical("invalid route device: {}", route);
            return -1;
        }
        if (!std::getline(ss, addr, ',') || rt.dst.cidrUpdate(addr) || rt.dst.getIp() != rt.dst.getNet()) {
            spdlog::critical("invalid route dest: {}", route);
            return -1;
        }
        if (!std::getline(ss, addr, ',') || rt.next.ipStrUpdate(addr)) {
            spdlog::critical("invalid route nexthop: {}", route);
            return -1;
        }
        spdlog::info("route: dev={} dst={} next={}", rt.dev.getCidr(), rt.dst.getCidr(), rt.next.getIpStr());
        this->routes.push_back(rt);
    }
    return 0;
}

int Server::run() {
    this->running = true;
    if (startWsThread()) {
        spdlog::critical("start websocket server thread failed");
        Candy::shutdown(this);
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
    this->routes.clear();
    return 0;
}

int Server::startWsThread() {
    if (this->ws.listen(this->host, this->port)) {
        spdlog::critical("websocket server listen failed");
        return -1;
    }

    if (this->ws.setTimeout(1)) {
        spdlog::critical("websocket server set read write timeout failed");
        return -1;
    }

    this->wsThread = std::thread([&] {
        this->handleWebSocketMessage();
        spdlog::debug("websocket server thread exit");
    });
    return 0;
}

void Server::handleWebSocketMessage() {
    int error;
    WebSocketMessage message;

    spdlog::info("listen: {}:{}", this->host, this->port);

    while (this->running) {
        error = this->ws.read(message);
        if (error == 0) {
            continue;
        }
        if (error < 0) {
            spdlog::error("websocket server read failed: error {}", error);
            Candy::shutdown(this);
            break;
        }

        if (message.type == WebSocketMessageType::Message) {
            uint8_t msgType = message.buffer.front();
            switch (msgType) {
            case MessageType::EXPECTED:
                handleExpectedAddressMessage(message);
                break;
            case MessageType::VMAC:
                handleVirtualMacMessage(message);
                break;
            case MessageType::AUTH:
                handleAuthMessage(message);
                break;
            case MessageType::FORWARD:
                handleForwardMessage(message);
                break;
            case MessageType::PEER:
                handlePeerConnMessage(message);
                break;
            case MessageType::DISCOVERY:
                handleDiscoveryMessage(message);
                break;
            case MessageType::GENERAL:
                handleGeneralMessage(message);
                break;
            default:
                spdlog::debug("unknown message: type {}", msgType);
                break;
            }
        }

        if (message.type == WebSocketMessageType::Close) {
            handleCloseMessage(message);
            continue;
        }

        if (message.type == WebSocketMessageType::Error) {
            spdlog::critical("server websocket error: {}", message.buffer);
            Candy::shutdown(this);
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
        spdlog::info("reconnect: {}", address.getIpStr());
    } else {
        spdlog::info("connect: {}", address.getIpStr());
    }

    this->ipWsMap[address.getIp()] = message.conn;
    this->wsIpMap[message.conn] = address.getIp();
    updateClientRoute(message, address.getIp());
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
    uint32_t saddr = Address::netToHost(header->iph.saddr);
    uint32_t daddr = Address::netToHost(header->iph.daddr);
    Address source;
    source.ipUpdate(saddr);

    if (this->wsIpMap[message.conn] != saddr) {
        Address auth;
        auth.ipUpdate(this->wsIpMap[message.conn]);
        spdlog::debug("forward source address does not match: auth {} source {}", auth.getIpStr(), source.getIpStr());
        return;
    }

    if (this->ipWsMap.contains(daddr)) {
        message.conn = this->ipWsMap[daddr];
        this->ws.write(message);
        return;
    }

    bool broadcast = [&] {
        // 多播地址
        if ((daddr & 0xF0000000) == 0xE0000000) {
            return true;
        }
        // 广播
        if (daddr == UINT32_MAX) {
            return true;
        }
        // 服务端没有配置动态分配地址的范围,没法检查是否为定向广播
        if (!this->dynamicAddrEnabled) {
            return false;
        }
        // 网络号不同,不是定向广播
        if ((this->dynamic.getMask() & daddr) != this->dynamic.getNet()) {
            return false;
        }
        // 主机号部分不全为 1,不是定向广播
        if ((~this->dynamic.getMask()) & (daddr + 1)) {
            return false;
        }
        return true;
    }();

    if (broadcast) {
        for (auto conn : this->ipWsMap) {
            if (conn.first != saddr) {
                message.conn = conn.second;
                this->ws.write(message);
            }
        }
        return;
    }

    Address destination;
    destination.ipUpdate(daddr);
    spdlog::debug("forward failed: source {} dest {}", source.getIpStr(), destination.getIpStr());
    return;
}

void Server::handleExpectedAddressMessage(WebSocketMessage &message) {
    if (message.buffer.length() < sizeof(ExpectedAddressMessage)) {
        spdlog::warn("invalid dynamic address message: len {}", message.buffer.length());
        this->ws.close(message.conn);
        return;
    }

    ExpectedAddressMessage *header = (ExpectedAddressMessage *)message.buffer.data();
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
        spdlog::warn("invalid peer conn message: len {}", message.buffer.length());
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

void Server::handleDiscoveryMessage(WebSocketMessage &message) {
    if (!this->wsIpMap.contains(message.conn)) {
        spdlog::debug("unauthorized discovery websocket client");
        return;
    }

    if (message.buffer.length() < sizeof(DiscoveryMessage)) {
        spdlog::debug("invalid discovery message: len {}", message.buffer.length());
        return;
    }

    DiscoveryMessage *header = (DiscoveryMessage *)message.buffer.data();
    uint32_t saddr = Address::netToHost(header->src);
    uint32_t daddr = Address::netToHost(header->dst);

    if (this->wsIpMap[message.conn] != saddr) {
        Address auth, source;
        auth.ipUpdate(this->wsIpMap[message.conn]);
        source.ipUpdate(saddr);
        spdlog::debug("discovery source address does not match: auth {} source {}", auth.getIpStr(), source.getIpStr());
        return;
    }

    if (daddr == BROADCAST_IP) {
        for (auto conn : this->ipWsMap) {
            if (conn.first != saddr) {
                message.conn = conn.second;
                this->ws.write(message);
            }
        }
        return;
    }

    if (this->ipWsMap.contains(daddr)) {
        message.conn = this->ipWsMap[daddr];
        this->ws.write(message);
        return;
    }
}

void Server::handleGeneralMessage(WebSocketMessage &message) {
    if (!this->wsIpMap.contains(message.conn)) {
        spdlog::debug("unauthorized general websocket client");
        return;
    }

    if (message.buffer.length() < sizeof(GeneralHeader)) {
        spdlog::debug("invalid general message: len {}", message.buffer.length());
        return;
    }

    GeneralHeader *header = (GeneralHeader *)message.buffer.data();
    uint32_t saddr = Address::netToHost(header->src);
    uint32_t daddr = Address::netToHost(header->dst);

    if (this->wsIpMap[message.conn] != saddr) {
        Address auth, source;
        auth.ipUpdate(this->wsIpMap[message.conn]);
        source.ipUpdate(saddr);
        spdlog::debug("general source address does not match: auth {} source {}", auth.getIpStr(), source.getIpStr());
        return;
    }

    if (daddr == BROADCAST_IP) {
        for (auto conn : this->ipWsMap) {
            if (conn.first != saddr) {
                message.conn = conn.second;
                this->ws.write(message);
            }
        }
        return;
    }

    if (this->ipWsMap.contains(daddr)) {
        message.conn = this->ipWsMap[daddr];
        this->ws.write(message);
        return;
    }
}

void Server::handleCloseMessage(WebSocketMessage &message) {
    auto it = this->wsIpMap.find(message.conn);
    if (it != this->wsIpMap.end()) {
        if (this->ipWsMap[it->second] == message.conn) {
            Address address;
            if (!address.ipUpdate(it->second)) {
                spdlog::info("disconnect: {}", address.getIpStr());
            }
            this->ipWsMap.erase(it->second);
        }
        this->wsIpMap.erase(it);
    }
    this->wsMacMap.erase(message.conn);
}

void Server::updateClientRoute(WebSocketMessage &message, uint32_t client) {
    message.buffer.resize(sizeof(SysRouteMessage));
    SysRouteMessage *header = (SysRouteMessage *)message.buffer.data();
    memset(header, 0, sizeof(SysRouteMessage));
    header->type = MessageType::ROUTE;

    for (auto rt : this->routes) {
        if ((rt.dev.getMask() & client) == rt.dev.getIp()) {
            SysRouteItem item;
            item.dest = Address::hostToNet(rt.dst.getNet());
            item.mask = Address::hostToNet(rt.dst.getMask());
            item.nexthop = Address::hostToNet(rt.next.getIp());
            message.buffer.append((char *)(&item), sizeof(item));
            header->size += 1;
        }
        // 100 条路由报文大小是 1204 字节,超过 100 条后分批发送
        if (header->size > 100) {
            this->ws.write(message);
            message.buffer.resize(sizeof(SysRouteMessage));
            header->size = 0;
        }
    }

    if (header->size > 0) {
        this->ws.write(message);
    }
}

} // namespace Candy

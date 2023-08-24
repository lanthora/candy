// SPDX-License-Identifier: MIT
#include "core/server.h"
#include "core/common.h"
#include "core/message.h"
#include "utility/address.h"
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
    if (this->dynamic.ipMaskUpdate(this->dynamic.getNet(), this->dynamic.getMask())) {
        return -1;
    }
    this->dynamicAddrEnabled = true;
    return 0;
}

int Server::run() {
    this->running = true;

    if (startWsThread()) {
        spdlog::critical("start websocket server thread failed");
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

    this->wsThread = std::move(std::thread(&Server::handleWebSocketMessage, this));
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
            break;
        }

        if (message.type == WebSocketMessageType::Message) {
            if (message.buffer.front() == MessageType::TYPE_FORWARD) {
                handleForwardMessage(message);
                continue;
            }
            if (message.buffer.front() == MessageType::TYPE_AUTH) {
                handleAuthMessage(message);
                continue;
            }
            if (message.buffer.front() == MessageType::TYPE_DYNAMIC_ADDRESS) {
                handleDynamicAddressMessage(message);
                continue;
            }
            spdlog::warn("unknown message type. type {}", message.buffer.front());
            continue;
        }

        if (message.type == WebSocketMessageType::Close) {
            handleCloseMessage(message);
            continue;
        }
        if (message.type == WebSocketMessageType::Error) {
            spdlog::critical("server websocket error: {}", message.buffer);
            break;
        }
    }
    Candy::shutdown();
    return;
}

void Server::handleAuthMessage(WebSocketMessage &message) {
    if (message.buffer.length() != sizeof(AuthHeader)) {
        spdlog::warn("invalid auth package: len {}", message.buffer.length());
        return;
    }

    AuthHeader *header = (AuthHeader *)message.buffer.data();
    if (!header->check(this->password)) {
        spdlog::warn("auth header check failed: buffer {:n}", spdlog::to_hex(message.buffer));
        return;
    }

    Address address;
    if (address.ipUpdate(Address::netToHost(header->ip))) {
        spdlog::info("invalid auth ip: buffer {:n}", spdlog::to_hex(message.buffer));
        return;
    }
    if (this->ipWsMap.contains(address.getIp())) {
        this->ws.close(this->ipWsMap[address.getIp()]);
        spdlog::info("ip conflict, old connection kicked out: {}", address.getIpStr());
    }

    spdlog::info("new client connected: {}", address.getIpStr());
    this->ipWsMap[address.getIp()] = message.conn;
    this->wsIpMap[message.conn] = address.getIp();
}

void Server::handleForwardMessage(WebSocketMessage &message) {
    if (!this->wsIpMap.contains(message.conn)) {
        spdlog::debug("unauthorized websocket client");
        return;
    }

    if (message.buffer.length() < sizeof(ForwardHeader)) {
        spdlog::warn("invalid forawrd package: len {}", message.buffer.length());
        return;
    }

    ForwardHeader *header = (ForwardHeader *)message.buffer.data();
    Address auth, source, destination;
    auth.ipUpdate(this->wsIpMap[message.conn]);
    source.ipUpdate(Address::netToHost(header->iph.saddr));
    destination.ipUpdate(Address::netToHost(header->iph.daddr));

    if (this->wsIpMap[message.conn] != Address::netToHost(header->iph.saddr)) {
        spdlog::warn("source address does not match authorized address: auth {} source {}", auth.getIpStr(), source.getIpStr());
        return;
    }

    if (!this->ipWsMap.contains(Address::netToHost(header->iph.daddr))) {
        spdlog::warn("destination client not logged in: source {}  destination {}", source.getIpStr(), destination.getIpStr());
        return;
    }

    message.conn = this->ipWsMap[Address::netToHost(header->iph.daddr)];
    this->ws.write(message);
}

void Server::handleDynamicAddressMessage(WebSocketMessage &message) {
    if (message.buffer.length() != sizeof(DynamicAddressHeader)) {
        spdlog::warn("invalid dynamic address package: len {}", message.buffer.length());
        return;
    }

    DynamicAddressHeader *header = (DynamicAddressHeader *)message.buffer.data();
    if (!header->check(this->password)) {
        spdlog::warn("dynamic address header check failed: buffer {:n}", spdlog::to_hex(message.buffer));
        return;
    }

    Address address;
    address.cidrUpdate(header->cidr);

    // 期望使用的地址不在当前网络或已经被分配
    if (!dynamic.inSameNetwork(address) || this->ipWsMap.contains(address.getIp())) {
        if (!this->dynamicAddrEnabled) {
            spdlog::warn("the client requests a dynamic address, but the server does not enable this function");
            return;
        }
        // 生成下一个动态地址并检查是否可用
        uint32_t oldip = dynamic.getIp();
        uint32_t newip = 0;
        do {
            // 获取下一个地址失败,一般不会发生,除非输入的配置错误
            if (this->dynamic.next()) {
                spdlog::error("unable to get next available address");
                return;
            }
            newip = dynamic.getIp();
            if (oldip == newip) {
                spdlog::warn("all addresses in the network are assigned");
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

void Server::handleCloseMessage(WebSocketMessage &message) {
    auto it = this->wsIpMap.find(message.conn);
    if (it == this->wsIpMap.end()) {
        return;
    }

    if (this->ipWsMap[it->second] == message.conn) {
        Address address;
        if (!address.ipUpdate(it->second)) {
            spdlog::info("client disconnected: {}", address.getIpStr());
        }
        this->ipWsMap.erase(it->second);
    }

    this->wsIpMap.erase(it);
}

}; // namespace Candy

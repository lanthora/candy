// SPDX-License-Identifier: MIT
#include "core/client.h"
#include "core/common.h"
#include "core/message.h"
#include "utility/address.h"
#include "utility/time.h"
#include "utility/uri.h"
#include <bit>
#include <functional>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

namespace Candy {

int Client::setName(const std::string &name) {
    this->tunName = name;
    return 0;
}

int Client::setPassword(const std::string &password) {
    this->password = password;
    return 0;
}

int Client::setWebSocketServer(const std::string &uri) {
    Uri parser(uri);
    if (!parser.isValid()) {
        spdlog::critical("client websocket server parser failed");
        return -1;
    }
    if (parser.scheme() != "ws" && parser.scheme() != "wss") {
        spdlog::critical("invalid websocket scheme {}", parser.scheme());
        return -1;
    }
    this->wsUri = uri;
    return 0;
}

int Client::setLocalAddress(const std::string &cidr) {
    this->localAddress = cidr;
    return 0;
}

int Client::setDynamicAddress(const std::string &cidr) {
    this->dynamicAddress = cidr;
    return 0;
}

int Client::setStun(const std::string &stun) {
    this->stun = stun;
    return 0;
}

std::string Client::getAddress() {
    return this->localAddress;
}

int Client::run() {
    this->running = true;
    if (startWsThread()) {
        spdlog::critical("start websocket client thread failed");
        Candy::shutdown();
        return -1;
    }
    return 0;
}

int Client::shutdown() {
    if (!this->running) {
        return 0;
    }

    this->running = false;

    if (this->wsThread.joinable()) {
        this->wsThread.join();
    }
    if (this->tunThread.joinable()) {
        this->tunThread.join();
    }
    if (this->dispatcherThread.joinable()) {
        this->dispatcherThread.join();
    }

    this->dispatcher.shutdown();
    this->tun.down();
    this->ws.disconnect();
    return 0;
}

int Client::startWsThread() {
    if (this->ws.connect(this->wsUri)) {
        spdlog::critical("websocket client connect failed");
        return -1;
    }
    if (this->ws.setTimeout(1)) {
        spdlog::critical("websocket clinet set read write timeout failed");
        return -1;
    }

    // 只需要开 wsThread, 执行过程中会设置 tun 并开 tunThread.
    this->wsThread = std::move(std::thread([&] { this->handleWebSocketMessage(); }));
    return 0;
}

int Client::startTunThread() {
    if (this->tun.setName(this->tunName.empty() ? "candy" : "candy-" + this->tunName)) {
        return -1;
    }
    if (this->tun.setAddress(this->localAddress)) {
        return -1;
    }
    if (this->tun.setMTU(1400)) {
        return -1;
    }
    if (this->tun.setTimeout(1)) {
        return -1;
    }
    if (this->tun.up()) {
        return -1;
    }

    this->tunThread = std::move(std::thread([&] { this->handleTunMessage(); }));

    sendAuthMessage();
    return 0;
}

int Client::startDispatcherThread() {
    if (this->stun.empty()) {
        spdlog::info("stun is empty, peer-to-peer connections are not enabled");
        return 0;
    }
    if (this->dispatcher.setPassword(this->password)) {
        return -1;
    }
    if (this->dispatcher.setStun(this->stun)) {
        return -1;
    }
    if (this->dispatcher.setTunIP(this->tun.getIP())) {
        return -1;
    }
    if (this->dispatcher.run()) {
        return -1;
    }

    this->dispatcherThread = std::move(std::thread([&] { this->handleDispatcherMessage(); }));

    return 0;
}

void Client::handleWebSocketMessage() {
    int error;
    WebSocketMessage message;

    while (this->running) {
        error = this->ws.read(message);

        if (error == 0) {
            continue;
        }
        if (error < 0) {
            spdlog::critical("webSocket client read failed: error {}", error);
            break;
        }
        if (message.type == WebSocketMessageType::Message) {
            // FORWARD, 拆包后转发给 TUN 设备
            if (message.buffer.front() == MessageType::FORWARD) {
                handleForwardMessage(message);
                continue;
            }
            // 收到动态地址响应包,启动 TUN 设备并发送 Auth 包
            if (message.buffer.front() == MessageType::DHCP) {
                handleDynamicAddressMessage(message);
                continue;
            }
            // 收到对端连接请求包
            if (message.buffer.front() == MessageType::PEER) {
                handlePeerConnMessage(message);
                continue;
            }
            spdlog::warn("unknown message: {:n}", spdlog::to_hex(message.buffer));
            continue;
        }

        if (message.type == WebSocketMessageType::Open) {
            if (!this->localAddress.empty()) {
                if (startTunThread()) {
                    spdlog::critical("start tun thread with static address failed");
                    Candy::shutdown();
                    break;
                }
                if (startDispatcherThread()) {
                    spdlog::critical("start dispatcher thread failed");
                    Candy::shutdown();
                    break;
                }
                continue;
            }

            Address address;
            if (this->dynamicAddress.empty() || address.cidrUpdate(this->dynamicAddress)) {
                this->dynamicAddress = "0.0.0.0/0";
                spdlog::warn("invalid dynamic address, set dynamic address to {}", this->dynamicAddress);
            }
            sendDynamicAddressMessage();
            continue;
        }
        // 连接断开,可能是地址冲突,触发正常退出进程的流程
        if (message.type == WebSocketMessageType::Close) {
            spdlog::info("client websocket close: {}", message.buffer);
            break;
        }
        // 通信出现错误,触发正常退出进程的流程
        if (message.type == WebSocketMessageType::Error) {
            spdlog::critical("client websocket error: {}", message.buffer);
            break;
        }
    }
    Candy::shutdown();
    return;
}

void Client::handleTunMessage() {
    int error;

    std::string buffer;
    IPv4Header *header;

    while (this->running) {
        error = this->tun.read(buffer);
        if (error == 0) {
            continue;
        }
        if (error < 0) {
            spdlog::critical("tun read failed. error {}", error);
            break;
        }
        if (buffer.length() < sizeof(IPv4Header)) {
            continue;
        }

        // 仅处理 IPv4
        header = (IPv4Header *)buffer.data();
        if ((header->version_ihl >> 4) != 4) {
            continue;
        }
        // 发包地址必须与登录地址相同
        if (Address::netToHost(header->saddr) != this->tun.getIP()) {
            continue;
        }

        // 获取当前对端状态机的状态
        uint32_t peerIp = Address::netToHost(header->daddr);
        PeerConnState peerState = this->dispatcher.getPeerState(peerIp);

        // 处于连接状态,直接发送,不需要其他操作
        if (peerState == PeerConnState::CONNECTED) {
            this->dispatcher.write(buffer);
            continue;
        }

        // 先发送建连的包
        if (peerState == PeerConnState::INIT || peerState == PeerConnState::SYNCHRONIZING) {
            uint32_t pubIp;
            uint16_t pubPort;
            if (!this->dispatcher.fetchPublicInfo(pubIp, pubPort)) {
                if (peerState == PeerConnState::INIT) {
                    sendPeerConnMessage(this->tun.getIP(), peerIp, pubIp, pubPort, 1);
                } else {
                    sendPeerConnMessage(this->tun.getIP(), peerIp, pubIp, pubPort, 0);
                }
                this->dispatcher.updatePeerState(peerIp);
            } else {
                spdlog::debug("fetch public info failed");
            }
        }

        // 通过 WebSocket 转发
        WebSocketMessage message;
        message.buffer.push_back(MessageType::FORWARD);
        message.buffer.append(buffer);
        ws.write(message);
    }
    Candy::shutdown();
    return;
}

void Client::handleDispatcherMessage() {
    std::string buffer;
    int len;
    while (this->running) {
        len = this->dispatcher.read(buffer);
        if (len == 0) {
            continue;
        }
        if (len < 0) {
            spdlog::error("handle dispatcher message error");
            continue;
        }
        this->tun.write(buffer);
    }
    return;
}

void Client::sendDynamicAddressMessage() {
    Address address;
    if (address.cidrUpdate(this->dynamicAddress)) {
        spdlog::critical("cannot send invalid dynamic address");
        Candy::shutdown();
        return;
    }

    DynamicAddressMessage header(address.getCidr());
    header.updateHash(this->password);

    WebSocketMessage message;
    message.buffer.assign((char *)(&header), sizeof(DynamicAddressMessage));
    this->ws.write(message);
    return;
}

void Client::sendAuthMessage() {
    Address address;
    if (address.cidrUpdate(this->localAddress)) {
        spdlog::critical("cannot send invalid auth address");
        Candy::shutdown();
        return;
    }

    AuthHeader header(address.getIp());
    header.updateHash(this->password);

    WebSocketMessage message;
    message.buffer.assign((char *)(&header), sizeof(AuthHeader));
    this->ws.write(message);
    return;
}

void Client::sendPeerConnMessage(uint32_t src, uint32_t dst, uint32_t pubIp, uint16_t pubPort, uint8_t forceSync) {
    PeerConnMessage header;
    header.tunSrcIp = Address::hostToNet(src);
    header.tunDestIp = Address::hostToNet(dst);
    header.pubIp = Address::hostToNet(pubIp);
    header.pubPort = Address::hostToNet(pubPort);
    header.forceSync = forceSync;

    WebSocketMessage message;
    message.buffer.assign((char *)(&header), sizeof(PeerConnMessage));
    this->ws.write(message);

    spdlog::debug("send peer message: src {:x} dst {:x} ip {:x} port {}", src, dst, pubIp, pubPort);
    return;
}

void Client::handleDynamicAddressMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(DynamicAddressMessage)) {
        spdlog::warn("invalid dynamic address message: len {}", message.buffer.length());
        spdlog::debug("dynamic address buffer: {:n}", spdlog::to_hex(message.buffer));
        return;
    }

    DynamicAddressMessage *header = (DynamicAddressMessage *)message.buffer.c_str();

    Address address;
    if (address.cidrUpdate(header->cidr)) {
        spdlog::warn("invalid dynamic address ip: cidr {}", header->cidr);
        return;
    }

    this->localAddress = address.getCidr();
    if (startTunThread()) {
        spdlog::critical("start tun thread with dynamic address failed");
        Candy::shutdown();
        return;
    }
    if (startDispatcherThread()) {
        spdlog::critical("start dispatcher thread failed");
        Candy::shutdown();
        return;
    }
}

void Client::handleForwardMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(ForwardHeader)) {
        spdlog::warn("invalid forward message: {:n}", spdlog::to_hex(message.buffer));
    }

    const char *src = message.buffer.c_str() + sizeof(ForwardHeader::type);
    const size_t len = message.buffer.length() - sizeof(ForwardHeader::type);
    this->tun.write(std::string(src, len));
}

void Client::handlePeerConnMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(PeerConnMessage)) {
        spdlog::warn("invalid peer conn message: {:n}", spdlog::to_hex(message.buffer));
    }
    PeerConnMessage *header = (PeerConnMessage *)message.buffer.c_str();

    uint32_t tunSrcIp = Address::netToHost(header->tunSrcIp);
    uint32_t tunDestIp = Address::netToHost(header->tunDestIp);
    uint32_t pubIp = Address::netToHost(header->pubIp);
    uint16_t pubPort = Address::netToHost(header->pubPort);
    uint8_t forceSync = header->forceSync;

    if (tunDestIp != this->tun.getIP()) {
        spdlog::warn("peer conn message dest not match: {:n}", spdlog::to_hex(message.buffer));
    }

    this->dispatcher.updatePeerPublicInfo(tunSrcIp, pubIp, pubPort, forceSync);
    return;
}

}; // namespace Candy

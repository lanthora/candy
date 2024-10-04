// SPDX-License-Identifier: MIT
#include "core/client.h"
#include "core/common.h"
#include "core/message.h"
#include "utility/address.h"
#include "utility/time.h"
#include <Poco/Environment.h>
#include <Poco/URI.h>
#include <algorithm>
#include <fmt/core.h>
#include <functional>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <ranges>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>
#include <unistd.h>

namespace {

constexpr std::size_t AES_256_GCM_IV_LEN = 12;
constexpr std::size_t AES_256_GCM_TAG_LEN = 16;
constexpr std::size_t AES_256_GCM_KEY_LEN = 32;

} // namespace

namespace Candy {
// Public
int Client::setName(const std::string &name) {
    this->tunName = name;
    return 0;
}

std::string Client::getName() const {
    return this->tunName;
}

int Client::setWorkers(int number) {
    number = std::min(number, int(Poco::Environment::processorCount()));
    number = std::max(number, 0);
    this->workers = number;
    if (this->workers) {
        spdlog::debug("workers: {}", this->workers);
    }
    return 0;
}

int Client::setPassword(const std::string &password) {
    this->password = password;
    return 0;
}

int Client::setWebSocketServer(const std::string &uri) {
    try {
        Poco::URI parser(uri);
        if (parser.getScheme() != "ws" && parser.getScheme() != "wss") {
            spdlog::critical("invalid websocket scheme {}", parser.getScheme());
            return -1;
        }
        this->wsUri = uri;
        return 0;
    } catch (std::exception &e) {
        spdlog::critical("client websocket server parser failed: {}", e.what());
        return -1;
    }
}

int Client::setTunAddress(const std::string &cidr) {
    this->tunAddress = cidr;
    this->realAddress = cidr;
    return 0;
}

int Client::setExpectedAddress(const std::string &cidr) {
    this->expectedAddress = cidr;
    return 0;
}

int Client::setVirtualMac(const std::string &vmac) {
    if (vmac.length() != 16) {
        Candy::shutdown(this);
        return -1;
    }
    this->virtualMac = vmac;
    return 0;
}

int Client::setStun(const std::string &stun) {
    this->stun.uri = stun;
    return 0;
}

int Client::setDiscoveryInterval(int interval) {
    this->discoveryInterval = interval;
    return 0;
}

int Client::setRouteCost(int cost) {
    if (cost < 0) {
        this->routeCost = 0;
    } else if (cost > 1000) {
        this->routeCost = 1000;
    } else {
        this->routeCost = cost;
    }
    return 0;
}

int Client::setAddressUpdateCallback(std::function<int(const std::string &)> callback) {
    this->addressUpdateCallback = callback;
    return 0;
}

int Client::setUdpBindPort(int port) {
    if (port > 0 && port < UINT16_MAX) {
        this->udpHolder.setPort(port);
    }
    return 0;
}

int Client::setLocalhost(std::string ip) {
    if (ip.empty()) {
        return 0;
    }
    Address addr;
    if (addr.ipStrUpdate(ip)) {
        return 0;
    }
    this->udpHolder.setIP(addr.getIp());
    return 0;
}

int Client::setMtu(int mtu) {
    this->mtu = mtu;
    return 0;
}

int Client::run() {
    std::lock_guard lock(this->runningMutex);
    this->running = true;
    this->localP2PDisabled = false;
    this->sysRtTable.clear();

    if (startWsThread()) {
        spdlog::critical("start websocket client thread failed");
        Candy::shutdown(this);
        return -1;
    }
    if (startTickThread()) {
        spdlog::critical("start tick thread failed");
        Candy::shutdown(this);
        return -1;
    }
    if (startWorkerThreads()) {
        spdlog::critical("start worker threads failed");
        Candy::shutdown(this);
        return -1;
    }
    return 0;
}

int Client::shutdown() {
    std::lock_guard lock(this->runningMutex);

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
    if (this->udpThread.joinable()) {
        this->udpThread.join();
    }
    if (this->tickThread.joinable()) {
        this->tickThread.join();
    }
    stopWorkerThreads();

    this->tun.down();
    this->ws.disconnect();
    return 0;
}

// Common
int Client::startWorkerThreads() {
    for (int i = 0; i < this->workers; ++i) {
        this->udpMsgWorkerThreads.emplace_back([&] {
            while (this->running) {
                UdpMessage message;
                {
                    static const auto timeout = std::chrono::seconds(1);
                    std::unique_lock<std::mutex> lock(this->udpMsgQueueMutex);
                    if (!this->udpMsgQueueCondition.wait_for(lock, timeout, [this] { return !this->udpMsgQueue.empty(); })) {
                        continue;
                    }
                    message = std::move(this->udpMsgQueue.front());
                    this->udpMsgQueue.pop();
                }
                handleUdpMessage(std::move(message));
            }
        });

        this->tunMsgWorkerThreads.emplace_back([&] {
            while (this->running) {
                std::string message;
                {
                    static const auto timeout = std::chrono::seconds(1);
                    std::unique_lock<std::mutex> lock(this->tunMsgQueueMutex);
                    if (!this->tunMsgQueueCondition.wait_for(lock, timeout, [this] { return !this->tunMsgQueue.empty(); })) {
                        continue;
                    }
                    message = std::move(this->tunMsgQueue.front());
                    this->tunMsgQueue.pop();
                }
                handleTunMessage(std::move(message));
            }
        });
    }
    return 0;
}

int Client::stopWorkerThreads() {
    for (std::thread &t : this->udpMsgWorkerThreads) {
        if (t.joinable()) {
            t.join();
        }
    }
    {
        std::unique_lock<std::mutex> lock(this->udpMsgQueueMutex);
        while (!this->udpMsgQueue.empty()) {
            this->udpMsgQueue.pop();
        }
    }
    this->udpMsgWorkerThreads.clear();

    for (std::thread &t : this->tunMsgWorkerThreads) {
        if (t.joinable()) {
            t.join();
        }
    }
    {
        std::unique_lock<std::mutex> lock(this->tunMsgQueueMutex);
        while (!this->tunMsgQueue.empty()) {
            this->tunMsgQueue.pop();
        }
    }
    this->tunMsgWorkerThreads.clear();
    return 0;
}

// WebSocket
std::string Client::hostName() {
    char hostname[64] = {0};
    if (!gethostname(hostname, sizeof(hostname))) {
        return std::string(hostname, strnlen(hostname, sizeof(hostname)));
    }
    return "";
}

int Client::startWsThread() {
    if (this->ws.setTimeout(1)) {
        spdlog::critical("websocket clinet set read write timeout failed");
        return -1;
    }

    if (this->ws.connect(this->wsUri)) {
        spdlog::critical("websocket client connect failed");
        return -1;
    }

    ws.setPingMessage(fmt::format("candy::{}::{}::{}", CANDY_SYSTEM, CANDY_VERSION, hostName()));

    // 只需要开 wsThread, 执行过程中会设置 tun 并开 tunThread.
    this->wsThread = std::thread([&] {
        this->handleWebSocketMessage();
        spdlog::debug("websocket client thread exit");
    });

    sendVirtualMacMessage();

    if (!this->tunAddress.empty()) {
        if (startTunThread()) {
            spdlog::critical("start tun thread with static address failed");
            return -1;
        }
        if (startUdpThread()) {
            spdlog::critical("start udp thread failed");
            return -1;
        }
    } else {
        Address address;
        if (this->expectedAddress.empty() || address.cidrUpdate(this->expectedAddress)) {
            this->expectedAddress = "0.0.0.0/0";
            spdlog::debug("set default expected address");
        }
        sendDynamicAddressMessage();
    }
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
            Candy::shutdown(this);
            break;
        }
        if (message.type == WebSocketMessageType::Message) {
            uint8_t msgType = message.buffer.front();
            switch (msgType) {
            // FORWARD, 拆包后转发给 TUN 设备
            case MessageType::FORWARD:
                handleForwardMessage(message);
                break;

            // 动态地址响应包,启动 TUN 设备并发送 Auth 包
            case MessageType::EXPECTED:
                handleExpectedAddressMessage(message);
                break;

            // 对端连接请求包
            case MessageType::PEER:
                handlePeerConnMessage(message);
                break;

            // 主动发现报文
            case MessageType::DISCOVERY:
                handleDiscoveryMessage(message);
                break;

            // 路由表
            case MessageType::ROUTE:
                handleSysRtMessage(message);
                break;

            // 通用报文
            case MessageType::GENERAL:
                handleGeneralMessage(message);
                break;

            default:
                spdlog::debug("unknown websocket message: type {}", msgType);
                break;
            }
        }
        // 连接断开,可能是地址冲突,触发正常退出进程的流程
        if (message.type == WebSocketMessageType::Close) {
            spdlog::info("client websocket close: {}", message.buffer);
            Candy::shutdown(this);
            break;
        }
        // 通信出现错误,触发正常退出进程的流程
        if (message.type == WebSocketMessageType::Error) {
            spdlog::warn("client websocket error: {}", message.buffer);
            Candy::shutdown(this);
            break;
        }
    }
    return;
}

void Client::recvUdpMessage() {
    while (this->running) {
        UdpMessage message;
        int error = this->udpHolder.read(message);
        if (error == 0) {
            continue;
        }
        if (error < 0) {
            spdlog::critical("udp read failed: error {}", error);
            Candy::shutdown(this);
            break;
        }
        if (!this->workers) {
            handleUdpMessage(std::move(message));
            continue;
        }
        {
            std::unique_lock<std::mutex> lock(this->udpMsgQueueMutex);
            this->udpMsgQueue.emplace(std::move(message));
        }
        this->udpMsgQueueCondition.notify_one();
    }

    this->udpHolder.reset();
}

void Client::handleUdpMessage(UdpMessage message) {
    if (isStunResponse(message)) {
        handleStunResponse(message.buffer);
        return;
    }

    message.buffer = decrypt(selfInfo.getKey(), message.buffer);
    if (message.buffer.empty()) {
        spdlog::debug("invalid peer message: ip {} port {}", Address::ipToStr(message.ip), message.port);
        return;
    }

    if (isHeartbeatMessage(message)) {
        handleHeartbeatMessage(message);
        return;
    }
    if (isPeerForwardMessage(message)) {
        handlePeerForwardMessage(message);
        return;
    }
    if (isDelayMessage(message)) {
        if (routeCost) {
            handleDelayMessage(message);
        }
        return;
    }
    if (isCandyRtMessage(message)) {
        if (routeCost) {
            handleCandyRtMessage(message);
        }
        return;
    }
    spdlog::debug("unknown peer message: type {}", int(message.buffer.front()));
}

void Client::sendForwardMessage(const std::string &buffer) {
    WebSocketMessage message;
    message.buffer.push_back(MessageType::FORWARD);
    message.buffer.append(buffer);
    if (this->ws.write(message)) {
        spdlog::critical("send forward message failed");
        Candy::shutdown(this);
    }
}

void Client::sendVirtualMacMessage() {
    VMacMessage buffer(this->virtualMac);
    buffer.updateHash(this->password);

    WebSocketMessage message;
    message.buffer.assign((char *)(&buffer), sizeof(buffer));
    if (this->ws.write(message)) {
        spdlog::critical("send virtual mac message failed");
        Candy::shutdown(this);
    }
    return;
}

void Client::sendDynamicAddressMessage() {
    Address address;
    if (address.cidrUpdate(this->expectedAddress)) {
        spdlog::critical("cannot send invalid expected address");
        Candy::shutdown(this);
        return;
    }

    ExpectedAddressMessage header(address.getCidr());
    header.updateHash(this->password);

    WebSocketMessage message;
    message.buffer.assign((char *)(&header), sizeof(header));
    if (this->ws.write(message)) {
        spdlog::critical("send expected address message failed");
        Candy::shutdown(this);
    }
    return;
}

void Client::sendAuthMessage() {
    Address address;
    if (address.cidrUpdate(this->realAddress)) {
        spdlog::critical("cannot send invalid auth address");
        Candy::shutdown(this);
        return;
    }

    AuthHeader header(address.getIp());
    header.updateHash(this->password);

    WebSocketMessage message;
    message.buffer.assign((char *)(&header), sizeof(AuthHeader));
    if (this->ws.write(message)) {
        spdlog::critical("send auth message failed");
        Candy::shutdown(this);
    }

    this->ws.sendPingMessage();
    return;
}

void Client::sendPeerConnMessage(const PeerInfo &peer) {
    PeerConnMessage header;
    header.src = Address::hostToNet(this->tun.getIP());
    header.dst = Address::hostToNet(peer.getTun());
    header.ip = Address::hostToNet(this->selfInfo.wide.ip);
    header.port = Address::hostToNet(this->selfInfo.wide.port);

    WebSocketMessage message;
    message.buffer.assign((char *)(&header), sizeof(PeerConnMessage));
    if (this->ws.write(message)) {
        spdlog::critical("send peer conn message failed");
        Candy::shutdown(this);
    }
    return;
}

void Client::sendDiscoveryMessage(uint32_t dst) {
    DiscoveryMessage header;

    header.src = Address::hostToNet(this->tun.getIP());
    header.dst = Address::hostToNet(dst);

    WebSocketMessage message;
    message.buffer.assign((char *)(&header), sizeof(DiscoveryMessage));
    if (this->ws.write(message)) {
        spdlog::critical("send discovery conn message failed");
        Candy::shutdown(this);
    }
    return;
}

void Client::sendLocalPeerConnMessage(const PeerInfo &peer) {
    if (this->localP2PDisabled) {
        return;
    }

    LocalPeerConnMessage header;
    header.ge.subtype = GeSubType::LOCAL_PEER_CONN;
    header.ge.extra = 0;
    header.ge.src = Address::hostToNet(this->tun.getIP());
    header.ge.dst = Address::hostToNet(peer.getTun());
    header.ip = Address::hostToNet(this->selfInfo.local.ip);
    header.port = Address::hostToNet(this->selfInfo.local.port);

    WebSocketMessage message;
    message.buffer.assign((char *)(&header), sizeof(LocalPeerConnMessage));
    if (this->ws.write(message)) {
        spdlog::critical("send peer conn message failed");
        Candy::shutdown(this);
    }
    return;
}

void Client::handleForwardMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(ForwardHeader)) {
        spdlog::warn("invalid forward message: {:n}", spdlog::to_hex(message.buffer));
        return;
    }

    const char *src = message.buffer.c_str() + sizeof(ForwardHeader::type);
    const size_t len = message.buffer.length() - sizeof(ForwardHeader::type);

    const IPv4Header *header = (const IPv4Header *)src;
    if (header->protocol == 0x04) {
        this->tun.write(std::string(src + sizeof(IPv4Header), len - sizeof(IPv4Header)));
    } else {
        this->tun.write(std::string(src, len));
    }

    tryDirectConnection(Address::netToHost(header->saddr));
}

void Client::handleExpectedAddressMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(ExpectedAddressMessage)) {
        spdlog::warn("invalid expected address message: len {}", message.buffer.length());
        spdlog::debug("expected address buffer: {:n}", spdlog::to_hex(message.buffer));
        return;
    }

    ExpectedAddressMessage *header = (ExpectedAddressMessage *)message.buffer.c_str();

    Address address;
    if (address.cidrUpdate(header->cidr)) {
        spdlog::warn("invalid expected address ip: cidr {}", header->cidr);
        return;
    }

    this->realAddress = address.getCidr();
    if (startTunThread()) {
        spdlog::critical("start tun thread with expected address failed");
        Candy::shutdown(this);
        return;
    }
    if (startUdpThread()) {
        spdlog::critical("start udp thread failed");
        Candy::shutdown(this);
        return;
    }
}

void Client::handlePeerConnMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(PeerConnMessage)) {
        spdlog::warn("invalid peer conn message: {:n}", spdlog::to_hex(message.buffer));
        return;
    }
    PeerConnMessage *header = (PeerConnMessage *)message.buffer.c_str();

    uint32_t src = Address::netToHost(header->src);
    uint32_t dst = Address::netToHost(header->dst);
    uint32_t ip = Address::netToHost(header->ip);
    uint16_t port = Address::netToHost(header->port);

    if (dst != this->tun.getIP()) {
        spdlog::warn("peer conn message dest not match: {:n}", spdlog::to_hex(message.buffer));
        return;
    }

    if (src == this->tun.getIP()) {
        spdlog::warn("peer conn message connect to self");
        return;
    }

    std::unique_lock lock(this->ipPeerMutex);
    PeerInfo &peer = this->ipPeerMap[src];

    peer.wide.ip = ip;
    peer.wide.port = port;
    peer.count = 0;
    peer.setTun(src, this->password);

    if (this->stun.uri.empty()) {
        peer.updateState(PeerState::FAILED);
        return;
    }

    if (peer.getState() == PeerState::CONNECTED) {
        return;
    }

    if (peer.getState() == PeerState::SYNCHRONIZING) {
        peer.updateState(PeerState::CONNECTING);
        return;
    }

    if (peer.getState() != PeerState::CONNECTING) {
        peer.updateState(PeerState::PREPARING);
        sendLocalPeerConnMessage(peer);
        return;
    }
}

void Client::handleDiscoveryMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(DiscoveryMessage)) {
        spdlog::warn("invalid discovery message: {:n}", spdlog::to_hex(message.buffer));
        return;
    }

    DiscoveryMessage *header = (DiscoveryMessage *)message.buffer.c_str();

    uint32_t src = Address::netToHost(header->src);
    uint32_t dst = Address::netToHost(header->dst);

    // 收到广播后向发送方回包
    if (dst == BROADCAST_IP) {
        sendDiscoveryMessage(src);
    }

    // 接收方收到广播或发送方收到回包,同时尝试开始直连
    tryDirectConnection(src);
}

void Client::handleSysRtMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(SysRouteMessage)) {
        spdlog::warn("invalid system route message: {:n}", spdlog::to_hex(message.buffer));
        return;
    }
    this->localP2PDisabled = true;
    SysRouteMessage *header = (SysRouteMessage *)message.buffer.c_str();
    SysRouteItem *rt = header->rtTable;
    std::unique_lock lock(this->sysRtTableMutex);
    for (uint8_t idx = 0; idx < header->size; ++idx) {
        SysRouteEntry entry;
        entry.dst = Address::netToHost(rt[idx].dest);
        entry.mask = Address::netToHost(rt[idx].mask);
        entry.next = Address::netToHost(rt[idx].nexthop);

        if (entry.next == this->tun.getIP()) {
            continue;
        }

        std::string dstStr = Address::ipToStr(entry.dst);
        std::string maskStr = Address::ipToStr(entry.mask);
        std::string nextStr = Address::ipToStr(entry.next);
        spdlog::info("system route: dst={} mask={} next={}", dstStr, maskStr, nextStr);

        this->tun.setSysRtTable(entry.dst, entry.mask, entry.next);
        sysRtTable.push_back(entry);
    }
}

void Client::handleGeneralMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(GeneralHeader)) {
        spdlog::warn("invalid general message: {:n}", spdlog::to_hex(message.buffer));
        return;
    }
    GeneralHeader *header = (GeneralHeader *)message.buffer.c_str();
    switch (header->subtype) {
    case GeSubType::LOCAL_PEER_CONN:
        handleLocalPeerConnMessage(message);
        break;
    }
}

void Client::handleLocalPeerConnMessage(WebSocketMessage &message) {
    if (this->localP2PDisabled) {
        return;
    }
    if (message.buffer.size() < sizeof(LocalPeerConnMessage)) {
        spdlog::warn("invalid local peer conn message: {:n}", spdlog::to_hex(message.buffer));
        return;
    }
    LocalPeerConnMessage *header = (LocalPeerConnMessage *)message.buffer.c_str();

    uint32_t src = Address::netToHost(header->ge.src);
    uint32_t dst = Address::netToHost(header->ge.dst);
    uint32_t ip = Address::netToHost(header->ip);
    uint16_t port = Address::netToHost(header->port);

    if (dst != this->tun.getIP()) {
        spdlog::warn("local peer conn message dest not match: {:n}", spdlog::to_hex(message.buffer));
        return;
    }

    if (src == this->tun.getIP()) {
        spdlog::warn("local peer conn message connect to self");
        return;
    }

    std::unique_lock lock(this->ipPeerMutex);
    PeerInfo &peer = this->ipPeerMap[src];

    peer.local.ip = ip;
    peer.local.port = port;
    peer.setTun(src, this->password);

    if (this->stun.uri.empty()) {
        peer.updateState(PeerState::FAILED);
        return;
    }

    if (peer.getState() == PeerState::INIT) {
        peer.updateState(PeerState::PREPARING);
        sendLocalPeerConnMessage(peer);
        return;
    }
}

// 需要确保双方同时调用.
// 1. 收到对方报文时,一般会回包,此时调用
// 2. 收到主动发现报文时,这时一定会回包
void Client::tryDirectConnection(uint32_t ip) {
    std::unique_lock lock(this->ipPeerMutex);
    PeerInfo &peer = this->ipPeerMap[ip];
    peer.setTun(ip, this->password);
    if (this->stun.uri.empty()) {
        peer.updateState(PeerState::FAILED);
        return;
    }
    if (peer.getState() == PeerState::INIT) {
        peer.updateState(PeerState::PREPARING);
        sendLocalPeerConnMessage(peer);
    }
}

// TUN
int Client::startTunThread() {
    if (this->tun.setName(this->tunName)) {
        return -1;
    }
    if (this->tun.setAddress(this->realAddress)) {
        return -1;
    }
    if (this->tun.setMTU(this->mtu)) {
        return -1;
    }
    if (this->tun.setTimeout(1)) {
        return -1;
    }
    if (this->tun.up()) {
        return -1;
    }

    this->tunThread = std::thread([&] {
        this->recvTunMessage();
        spdlog::debug("tun thread exit");
    });

    sendAuthMessage();

    if (addressUpdateCallback) {
        int error = addressUpdateCallback(this->realAddress);
        if (error) {
            spdlog::critical("address update callback failed: {}", error);
            Candy::shutdown(this);
        }
    }

    return 0;
}

void Client::recvTunMessage() {
    while (this->running) {
        std::string buffer;
        int error = this->tun.read(buffer);
        if (error == 0) {
            continue;
        }
        if (error < 0) {
            spdlog::critical("tun read failed. error {}", error);
            Candy::shutdown(this);
            break;
        }
        if (!this->workers) {
            handleTunMessage(std::move(buffer));
            continue;
        }
        {
            std::unique_lock<std::mutex> lock(this->tunMsgQueueMutex);
            this->tunMsgQueue.emplace(std::move(buffer));
        }
        this->tunMsgQueueCondition.notify_one();
    }
    return;
}

void Client::handleTunMessage(std::string buffer) {
    if (buffer.length() < sizeof(IPv4Header)) {
        return;
    }

    // 仅处理 IPv4
    IPv4Header *header = (IPv4Header *)buffer.data();
    if ((header->version_ihl >> 4) != 4) {
        return;
    }
    // 存在路由表项时封装成简单的 IPIP 协议
    uint32_t nextHop = [&]() {
        uint32_t daddr = Address::netToHost(header->daddr);
        std::shared_lock lock(this->sysRtTableMutex);
        for (auto const &rt : sysRtTable) {
            if ((daddr & rt.mask) == rt.dst) {
                return rt.next;
            }
        }
        if (Address::netToHost(header->saddr) != this->tun.getIP()) {
            return daddr;
        }
        return uint32_t(0);
    }();
    if (nextHop) {
        buffer = std::string(sizeof(IPv4Header), 0) + buffer;
        header = (IPv4Header *)buffer.data();
        header->protocol = 0x04;
        header->saddr = Address::hostToNet(this->tun.getIP());
        header->daddr = Address::hostToNet(nextHop);
    }
    // 目的地址是本机,直接回写,在 macos 中遇到了这种情况
    if (Address::netToHost(header->daddr) == this->tun.getIP()) {
        this->tun.write(buffer);
        return;
    }

    // 尝试通过路由或直连发送
    if (!sendPeerForwardMessage(buffer)) {
        return;
    }

    // 通过 WebSocket 转发
    sendForwardMessage(buffer);
}

// P2P
int Client::startUdpThread() {
    if (this->stun.uri.empty()) {
        return 0;
    }
    if (this->udpHolder.init()) {
        spdlog::critical("udpHolder init failed");
        Candy::shutdown(this);
        return -1;
    }
    if (this->selfInfo.setTun(this->tun.getIP(), this->password)) {
        return -1;
    }
    sendStunRequest();
    this->selfInfo.local.ip = udpHolder.IP();
    this->selfInfo.local.port = udpHolder.Port();
    spdlog::debug("localhost: {}", Address::ipToStr(this->selfInfo.local.ip));
    this->udpThread = std::thread([&] {
        recvUdpMessage();
        spdlog::debug("udp thread exit");
    });
    return 0;
}

int Client::startTickThread() {
    if (this->stun.uri.empty()) {
        return 0;
    }
    this->tickThread = std::thread([&] {
        while (this->running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            this->tick();
        }
        spdlog::debug("tick thread exit");
    });
    return 0;
}

void Client::tick() {
    if (discoveryInterval) {
        if (tickTick % discoveryInterval == 0) {
            sendDiscoveryMessage(BROADCAST_IP);
        }
    }

    std::unique_lock lock(this->ipPeerMutex);
    bool needSendStunRequest = false;
    for (auto &[ip, peer] : this->ipPeerMap) {
        switch (peer.getState()) {
        case PeerState::INIT:
            // 收到对方通过服务器转发的数据的时候,会切换为 PREPARING, 这里不做处理
            break;

        case PeerState::PREPARING:
            // 长时间处于 PREPARING 状态,无法获取本机的公网信息,进入失败状态
            if (peer.count > 10) {
                peer.updateState(PeerState::FAILED);
            } else {
                sendHeartbeatMessage(peer);
                needSendStunRequest = true;
            }
            break;

        case PeerState::SYNCHRONIZING:
            // 1.对方版本不支持 2.没有启用对等连接 3.对方无法获取到自己在公网中的信息
            if (peer.count > 10) {
                peer.updateState(PeerState::FAILED);
            } else {
                sendHeartbeatMessage(peer);
            }
            break;

        case PeerState::CONNECTING:
            // 进行超时检测,超时后进入 WAITING 状态,否则发送心跳
            if (peer.count > 10) {
                peer.updateState(PeerState::WAITING);
            } else {
                sendHeartbeatMessage(peer);
            }
            break;

        case PeerState::CONNECTED:
            // 进行超时检测,超时后清空对端信息,否则发送心跳
            if (peer.count > 3) {
                peer.updateState(PeerState::INIT);
                if (routeCost) {
                    updateCandyRtTable(CandyRouteEntry(peer.getTun(), peer.getTun(), DELAY_LIMIT));
                }
            } else {
                sendHeartbeatMessage(peer);
                if (routeCost && peer.tick % 60 == 0) {
                    sendDelayMessage(peer);
                }
            }
            break;

        case PeerState::WAITING:
            // 达到等待时长,重新进入初始状态
            if (peer.count > peer.retry) {
                peer.updateState(PeerState::INIT);
            }
            break;

        case PeerState::FAILED:
            // 两端任意一方不支持或者未启用对等连接功能,进入失败状态,不再主动重连
            break;
        }
        ++peer.count;
        ++peer.tick;
    }
    if (needSendStunRequest) {
        sendStunRequest();
    }
    ++tickTick;
}

std::string Client::encrypt(const std::string &key, const std::string &plaintext) {
    using lock = std::unique_lock<std::mutex>;
    auto guard = this->workers ? lock() : lock(cryptMutex);
    return encryptHelper(key, plaintext);
}
std::string Client::decrypt(const std::string &key, const std::string &ciphertext) {
    using lock = std::unique_lock<std::mutex>;
    auto guard = this->workers ? lock() : lock(cryptMutex);
    return decryptHelper(key, ciphertext);
}

std::string Client::encryptHelper(const std::string &key, const std::string &plaintext) {
    int len = 0;
    int ciphertextLen = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ciphertext[1500] = {0};
    unsigned char iv[AES_256_GCM_IV_LEN] = {0};
    unsigned char tag[AES_256_GCM_TAG_LEN] = {0};

    if (key.size() != AES_256_GCM_KEY_LEN) {
        spdlog::debug("invalid key size: {}", key.size());
        return "";
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        spdlog::debug("create cipher context failed");
        return "";
    }
    if (!RAND_bytes(iv, AES_256_GCM_IV_LEN)) {
        spdlog::debug("generate random iv failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char *)key.data(), iv)) {
        spdlog::debug("initialize cipher context failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_LEN, NULL)) {
        spdlog::debug("set iv length failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext.data(), plaintext.size())) {
        spdlog::debug("encrypt update failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertextLen = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        spdlog::debug("encrypt final failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertextLen += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_LEN, tag)) {
        spdlog::debug("get tag failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    EVP_CIPHER_CTX_free(ctx);

    std::string result;
    result.append((char *)iv, AES_256_GCM_IV_LEN);
    result.append((char *)tag, AES_256_GCM_TAG_LEN);
    result.append((char *)ciphertext, ciphertextLen);
    return result;
}

std::string Client::decryptHelper(const std::string &key, const std::string &ciphertext) {
    int len = 0;
    int plaintextLen = 0;
    unsigned char *enc = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char plaintext[1500] = {0};
    unsigned char iv[AES_256_GCM_IV_LEN] = {0};
    unsigned char tag[AES_256_GCM_TAG_LEN] = {0};

    if (key.size() != AES_256_GCM_KEY_LEN) {
        spdlog::debug("invalid key length: {}", key.size());
        return "";
    }
    if (ciphertext.size() < AES_256_GCM_IV_LEN + AES_256_GCM_TAG_LEN) {
        spdlog::debug("invalid ciphertext length: {}", ciphertext.size());
        return "";
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        spdlog::debug("create cipher context failed");
        return "";
    }

    enc = (unsigned char *)ciphertext.data();
    memcpy(iv, enc, AES_256_GCM_IV_LEN);
    memcpy(tag, enc + AES_256_GCM_IV_LEN, AES_256_GCM_TAG_LEN);
    enc += AES_256_GCM_IV_LEN + AES_256_GCM_TAG_LEN;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char *)key.data(), iv)) {
        spdlog::debug("initialize cipher context failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_LEN, NULL)) {
        spdlog::debug("set iv length failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, enc, ciphertext.size() - AES_256_GCM_IV_LEN - AES_256_GCM_TAG_LEN)) {
        spdlog::debug("decrypt update failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_256_GCM_TAG_LEN, tag)) {
        spdlog::debug("set tag failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintextLen = len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        spdlog::debug("decrypt final failed");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    plaintextLen += len;
    EVP_CIPHER_CTX_free(ctx);

    std::string result;
    result.append((char *)plaintext, plaintextLen);
    return result;
}

int Client::sendStunRequest() {
    struct addrinfo hints = {}, *info = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    try {
        Poco::URI uri(this->stun.uri);
        std::string strPort = uri.getPort() == 0 ? "3478" : std::to_string(uri.getPort());
        if (getaddrinfo(uri.getHost().c_str(), strPort.c_str(), &hints, &info)) {
            spdlog::warn("resolve stun server domain name failed: {}:{}", uri.getHost(), strPort);
            return -1;
        }
    } catch (std::exception &e) {
        spdlog::error("invalid stun uri: {}: {}", this->stun.uri, e.what());
    }

    this->stun.ip = Address::netToHost((uint32_t)((struct sockaddr_in *)info->ai_addr)->sin_addr.s_addr);
    this->stun.port = Address::netToHost((uint16_t)((struct sockaddr_in *)info->ai_addr)->sin_port);

    freeaddrinfo(info);

    UdpMessage message;
    StunRequest request;
    message.ip = this->stun.ip;
    message.port = this->stun.port;
    message.buffer.assign((char *)&request, sizeof(request));
    if (this->udpHolder.write(message) != message.buffer.size()) {
        spdlog::warn("send stun request failed");
    }
    return 0;
}

int Client::sendHeartbeatMessage(const PeerInfo &peer) {
    UdpMessage message;
    PeerHeartbeatMessage heartbeat;
    heartbeat.type = PeerMessageType::HEARTBEAT;
    heartbeat.tun = Address::hostToNet(this->tun.getIP());
    heartbeat.ack = peer.ack;

    if ((peer.getState() == PeerState::CONNECTED) && (peer.real.ip && peer.real.port)) {
        heartbeat.ip = Address::hostToNet(this->selfInfo.real.ip);
        heartbeat.port = Address::hostToNet(this->selfInfo.real.port);
        message.ip = peer.real.ip;
        message.port = peer.real.port;
        message.buffer = encrypt(peer.getKey(), std::string((char *)&heartbeat, sizeof(heartbeat)));
        this->udpHolder.write(message);
    }

    if ((peer.getState() == PeerState::CONNECTING) && (peer.wide.ip && peer.wide.port)) {
        heartbeat.ip = Address::hostToNet(this->selfInfo.wide.ip);
        heartbeat.port = Address::hostToNet(this->selfInfo.wide.port);
        message.ip = peer.wide.ip;
        message.port = peer.wide.port;
        message.buffer = encrypt(peer.getKey(), std::string((char *)&heartbeat, sizeof(heartbeat)));
        this->udpHolder.write(message);
    }

    if ((peer.getState() == PeerState::PREPARING || peer.getState() == PeerState::SYNCHRONIZING ||
         peer.getState() == PeerState::CONNECTING) &&
        (!this->localP2PDisabled && peer.local.ip && peer.local.port)) {
        heartbeat.ip = Address::hostToNet(this->selfInfo.local.ip);
        heartbeat.port = Address::hostToNet(this->selfInfo.local.port);
        message.ip = peer.local.ip;
        message.port = peer.local.port;
        message.buffer = encrypt(peer.getKey(), std::string((char *)&heartbeat, sizeof(heartbeat)));
        this->udpHolder.write(message);
    }

    return 0;
}

int Client::sendPeerForwardMessage(const std::string &buffer) {
    std::shared_lock ipPeerLock(this->ipPeerMutex);
    std::shared_lock rtTableLock(this->candyRtTableMutex);

    IPv4Header *header = (IPv4Header *)buffer.data();
    uint32_t dst = Address::netToHost(header->daddr);

    // 优先尝试最快的路由转发
    if (routeCost) {
        auto route = this->candyRtTable.find(dst);
        if (route != this->candyRtTable.end()) {
            if (!sendPeerForwardMessage(buffer, route->second.next)) {
                return 0;
            }
        }
    }

    // 尝试直连
    return sendPeerForwardMessage(buffer, dst);
}

int Client::sendPeerForwardMessage(const std::string &buffer, uint32_t nextHop) {
    auto it = this->ipPeerMap.find(nextHop);
    if (it == this->ipPeerMap.end()) {
        return -1;
    }

    const auto &peer = it->second;
    if (peer.getState() != PeerState::CONNECTED) {
        return -1;
    }

    UdpMessage message;
    message.ip = peer.real.ip;
    message.port = peer.real.port;
    message.buffer.push_back(PeerMessageType::FORWARD);
    message.buffer.append(buffer);
    message.buffer = encrypt(peer.getKey(), message.buffer);
    this->udpHolder.write(message);
    return 0;
}

bool Client::isStunResponse(const UdpMessage &message) {
    return message.ip == this->stun.ip && message.port == this->stun.port;
}

bool Client::isHeartbeatMessage(const UdpMessage &message) {
    return message.buffer.front() == PeerMessageType::HEARTBEAT;
}

bool Client::isPeerForwardMessage(const UdpMessage &message) {
    return message.buffer.front() == PeerMessageType::FORWARD;
}

int Client::handleStunResponse(const std::string &buffer) {
    if (buffer.length() < sizeof(StunResponse)) {
        spdlog::debug("invalid stun response length: {}", buffer.length());
        return -1;
    }
    StunResponse *response = (StunResponse *)buffer.c_str();
    if (Address::netToHost(response->type) != 0x0101) {
        spdlog::debug("stun not success response");
        return -1;
    }

    int pos = 0;
    uint32_t ip = 0;
    uint16_t port = 0;
    uint8_t *attr = response->attr;
    while (pos < Address::netToHost(response->length)) {
        // mapped address
        if (Address::netToHost(*(uint16_t *)(attr + pos)) == 0x0001) {
            pos += 6; // 跳过 2 字节类型, 2 字节长度, 1 字节保留, 1 字节IP版本号,指向端口号
            port = Address::netToHost(*(uint16_t *)(attr + pos));
            pos += 2; // 跳过2字节端口号,指向地址
            ip = Address::netToHost(*(uint32_t *)(attr + pos));
            break;
        }
        // xor mapped address
        if (Address::netToHost(*(uint16_t *)(attr + pos)) == 0x0020) {
            pos += 6; // 跳过 2 字节类型, 2 字节长度, 1 字节保留, 1 字节IP版本号,指向端口号
            port = Address::netToHost(*(uint16_t *)(attr + pos)) ^ 0x2112;
            pos += 2; // 跳过2字节端口号,指向地址
            ip = Address::netToHost(*(uint32_t *)(attr + pos)) ^ 0x2112a442;
            break;
        }
        // 跳过 2 字节类型,指向属性长度
        pos += 2;
        // 跳过 2 字节长度和用该属性其他内容
        pos += 2 + Address::netToHost(*(uint16_t *)(attr + pos));
    }
    if (!ip || !port) {
        spdlog::warn("stun response parse failed: {:n}", spdlog::to_hex(buffer));
        return -1;
    }

    this->selfInfo.wide.ip = ip;
    this->selfInfo.wide.port = port;

    // 收到 STUN 响应后,向所有 PREPARING 状态的对端发送自己的公网信息,如果当前持有对端公网信息,就将状态调整为 CONNECTING,
    // 否则调整为 SYNCHRONIZING
    std::unique_lock lock(this->ipPeerMutex);
    for (auto &[tun, peer] : this->ipPeerMap) {
        if (peer.getState() == PeerState::PREPARING) {
            if (peer.wide.ip && peer.wide.port) {
                peer.updateState(PeerState::CONNECTING);
            } else {
                peer.updateState(PeerState::SYNCHRONIZING);
            }
            sendPeerConnMessage(peer);
        }
    }

    return 0;
}

int Client::handleHeartbeatMessage(const UdpMessage &message) {
    if (message.buffer.length() < sizeof(PeerHeartbeatMessage)) {
        spdlog::debug("invalid heartbeat length: {}", message.buffer.length());
        return -1;
    }

    // 收到对端的心跳,更新地址和端口
    PeerHeartbeatMessage *heartbeat = (PeerHeartbeatMessage *)message.buffer.c_str();
    std::unique_lock lock(this->ipPeerMutex);
    uint32_t tun = Address::netToHost(heartbeat->tun);
    PeerInfo &peer = this->ipPeerMap[tun];
    if (peer.getState() == PeerState::INIT || peer.getState() == PeerState::WAITING || peer.getState() == PeerState::FAILED) {
        spdlog::debug("heartbeat peer state invalid: {} {}", Address::ipToStr(tun), peer.getStateStr());
        return -1;
    }

    if (!isLocalIp(message.ip)) {
        peer.wide.ip = message.ip;
        peer.wide.port = message.port;
    } else if (!this->localP2PDisabled) {
        peer.local.ip = message.ip;
        peer.local.port = message.port;
    } else {
        return 0;
    }

    if (isLocalIp(message.ip) || !isLocalIp(peer.real.ip)) {
        peer.real.ip = message.ip;
        peer.real.port = message.port;
    }

    // 设置确认标识,下次向对方发送的心跳将携带确认标识
    if (!peer.ack) {
        peer.ack = 1;
    }

    // 对方发来的心跳中包含确认标识,状态更新为 CONNECTED
    if (heartbeat->ack) {
        if (peer.getState() == PeerState::CONNECTED) {
            peer.count = 0;
            return 0;
        }
        peer.updateState(PeerState::CONNECTED);
        if (routeCost) {
            sendDelayMessage(peer);
        }
    }
    return 0;
}

int Client::handlePeerForwardMessage(const UdpMessage &message) {
    if (message.buffer.length() < sizeof(PeerForwardMessage)) {
        spdlog::debug("invalid raw ipv4 length: {}", message.buffer.length());
        return -1;
    }

    PeerForwardMessage *ipv4Message = (PeerForwardMessage *)message.buffer.c_str();
    if (Address::netToHost(ipv4Message->iph.daddr) == this->tun.getIP()) {
        const char *src = message.buffer.c_str() + sizeof(ForwardHeader::type);
        const size_t len = message.buffer.length() - sizeof(ForwardHeader::type);
        if (ipv4Message->iph.protocol == 0x04) {
            this->tun.write(std::string(src + sizeof(IPv4Header), len - sizeof(IPv4Header)));
        } else {
            this->tun.write(std::string(src, len));
        }

        // 可能是转发来的,尝试跟源地址建立直连
        tryDirectConnection(Address::netToHost(ipv4Message->iph.saddr));
        return 0;
    }

    std::shared_lock ipPeerLock(this->ipPeerMutex);
    std::shared_lock rtTableLock(this->candyRtTableMutex);
    auto route = this->candyRtTable.find(Address::netToHost(ipv4Message->iph.daddr));
    if (route == this->candyRtTable.end()) {
        return 0;
    }

    auto peer = this->ipPeerMap.find(route->second.next);
    if (peer == this->ipPeerMap.end() || peer->second.getState() != PeerState::CONNECTED) {
        return 0;
    }

    UdpMessage forward;
    forward.ip = peer->second.real.ip;
    forward.port = peer->second.real.port;
    forward.buffer = encrypt(peer->second.getKey(), message.buffer);
    this->udpHolder.write(forward);
    return 0;
}

bool Client::isLocalIp(uint32_t ip) {
    // 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000) {
        return true;
    }
    // 172.16.0.0/12
    if ((ip & 0xFFF00000) == 0xAC000000) {
        return true;
    }
    // 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000) {
        return true;
    }
    return false;
}

// Route
void Client::showCandyRtChange(const CandyRouteEntry &entry) {
    std::string dstStr = Address::ipToStr(entry.dst);
    std::string nextStr = Address::ipToStr(entry.next);
    std::string delayStr = (entry.delay == DELAY_LIMIT) ? "[deleted]" : std::to_string(entry.delay);
    spdlog::debug("candy route: dst={} next={} delay={}", dstStr, nextStr, delayStr);
}

int Client::updateCandyRtTable(CandyRouteEntry entry) {
    bool isDirect = (entry.dst == entry.next);
    bool isDelete = (entry.delay < 0 || entry.delay > 1000);

    std::unique_lock lock(this->candyRtTableMutex);

    // 到达此目的地址的历史路由,下一跳可能不同
    auto oldEntry = this->candyRtTable.find(entry.dst);

    // 本机检测到连接断开,删除所有以断联设备作为下一跳的路由并广播
    if (isDirect && isDelete) {
        for (auto it = this->candyRtTable.begin(); it != this->candyRtTable.end();) {
            if (it->second.next == entry.next) {
                it->second.delay = DELAY_LIMIT;
                sendCandyRtMessage(it->second.dst, it->second.delay);
                showCandyRtChange(it->second);
                it = this->candyRtTable.erase(it);
                continue;
            }
            ++it;
        }
        return 0;
    }

    // 本机检测到直连设备时延有更新,下一跳相同或者延迟更低时更新并广播
    if (isDirect && !isDelete) {
        if (oldEntry == this->candyRtTable.end() || oldEntry->second.next == entry.next || oldEntry->second.delay > entry.delay) {
            this->candyRtTable[entry.dst] = entry;
            sendCandyRtMessage(entry.dst, entry.delay);
            showCandyRtChange(entry);
        }
        return 0;
    }

    // 收到设备断连广播,删除本机相同的路由并广播
    if (!isDirect && isDelete) {
        if (oldEntry != this->candyRtTable.end() && oldEntry->second.next == entry.next) {
            oldEntry->second.delay = DELAY_LIMIT;
            sendCandyRtMessage(oldEntry->second.dst, oldEntry->second.delay);
            showCandyRtChange(oldEntry->second);
            this->candyRtTable.erase(oldEntry);
        }
        return 0;
    }

    // 收到设备时延更新广播,更新本机相同路由并广播
    if (!isDirect && !isDelete) {
        auto directEntry = this->candyRtTable.find(entry.next);
        if (directEntry == this->candyRtTable.end()) {
            return 0;
        }
        int32_t nowDelay = directEntry->second.delay + entry.delay;
        if (oldEntry == this->candyRtTable.end() || oldEntry->second.next == entry.next || oldEntry->second.delay > nowDelay) {
            entry.delay = nowDelay;
            this->candyRtTable[entry.dst] = entry;
            sendCandyRtMessage(entry.dst, entry.delay);
            showCandyRtChange(entry);
            return 0;
        }
        return 0;
    }
    return 0;
}

int Client::sendDelayMessage(const PeerInfo &peer) {
    PeerDelayMessage delayMessage;
    delayMessage.type = PeerMessageType::DELAY;
    delayMessage.src = Address::hostToNet(this->tun.getIP());
    delayMessage.dst = Address::hostToNet(peer.getTun());
    delayMessage.timestamp = Time::hostToNet(Time::bootTime());
    return sendDelayMessage(peer, delayMessage);
}

int Client::sendDelayMessage(const PeerInfo &peer, const PeerDelayMessage &delay) {
    UdpMessage message;
    message.ip = peer.real.ip;
    message.port = peer.real.port;
    message.buffer = encrypt(peer.getKey(), std::string((char *)&delay, sizeof(delay)));
    this->udpHolder.write(message);
    return 0;
}

int Client::sendCandyRtMessage(uint32_t dst, int32_t delay) {
    PeerRouteMessage routeMessage;
    routeMessage.type = PeerMessageType::ROUTE;
    routeMessage.dst = Address::hostToNet(dst);
    routeMessage.next = Address::hostToNet(this->tun.getIP());
    routeMessage.delay = Time::hostToNet(delay == DELAY_LIMIT ? DELAY_LIMIT : delay + routeCost);

    for (auto &[_, peer] : this->ipPeerMap) {
        if (peer.getState() == PeerState::CONNECTED) {
            UdpMessage message;
            message.ip = peer.real.ip;
            message.port = peer.real.port;
            message.buffer = encrypt(peer.getKey(), std::string((char *)&routeMessage, sizeof(routeMessage)));
            this->udpHolder.write(message);
        }
    }

    return 0;
}

bool Client::isDelayMessage(const UdpMessage &message) {
    return message.buffer.front() == PeerMessageType::DELAY;
}

bool Client::isCandyRtMessage(const UdpMessage &message) {
    return message.buffer.front() == PeerMessageType::ROUTE;
}

int Client::handleDelayMessage(const UdpMessage &message) {
    if (message.buffer.length() < sizeof(PeerDelayMessage)) {
        spdlog::debug("invalid delay message length: {}", message.buffer.length());
        return -1;
    }

    PeerDelayMessage *delayMessage = (PeerDelayMessage *)message.buffer.c_str();
    uint32_t src = Address::netToHost(delayMessage->src);
    uint32_t dst = Address::netToHost(delayMessage->dst);
    int64_t timestamp = Time::netToHost(delayMessage->timestamp);

    std::shared_lock lock(this->ipPeerMutex);

    if (src == this->tun.getIP()) {
        auto it = this->ipPeerMap.find(dst);
        if (it != this->ipPeerMap.end()) {
            int32_t delay = Time::bootTime() - timestamp;
            it->second.delay = delay;
            updateCandyRtTable(CandyRouteEntry(dst, dst, delay));
        }
        return 0;
    }

    if (dst == this->tun.getIP()) {
        auto it = this->ipPeerMap.find(src);
        if (it != this->ipPeerMap.end()) {
            sendDelayMessage(it->second, *delayMessage);
        }
        return 0;
    }

    return 0;
}

int Client::handleCandyRtMessage(const UdpMessage &message) {
    if (message.buffer.length() < sizeof(PeerRouteMessage)) {
        spdlog::debug("invalid route message length: {}", message.buffer.length());
        return -1;
    }

    PeerRouteMessage *routeMessage = (PeerRouteMessage *)message.buffer.c_str();
    uint32_t dst = Address::netToHost(routeMessage->dst);
    uint32_t next = Address::netToHost(routeMessage->next);
    int32_t delay = Time::netToHost(routeMessage->delay);

    if (dst != this->tun.getIP()) {
        updateCandyRtTable(CandyRouteEntry(dst, next, delay));
    }

    return 0;
}

} // namespace Candy

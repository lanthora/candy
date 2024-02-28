// SPDX-License-Identifier: MIT
#include "core/client.h"
#include "core/common.h"
#include "core/message.h"
#include "utility/address.h"
#include "utility/time.h"
#include "utility/uri.h"
#include <algorithm>
#include <bit>
#include <functional>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <ranges>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

namespace {

static constexpr size_t AES_256_GCM_IV_LEN = 12;
static constexpr size_t AES_256_GCM_TAG_LEN = 16;
static constexpr size_t AES_256_GCM_KEY_LEN = 32;

} // namespace

namespace Candy {
// Public
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

int Client::setVirtualMac(const std::string &vmac) {
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

int Client::setupAddressUpdateCallback(std::function<void(const std::string &)> callback) {
    this->addressUpdateCallback = callback;
    return 0;
}

int Client::run() {
    this->running = true;
    if (startWsThread()) {
        spdlog::critical("start websocket client thread failed");
        Candy::shutdown();
        return -1;
    }
    if (startTickThread()) {
        spdlog::critical("start tick thread failed");
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
    if (this->udpThread.joinable()) {
        this->udpThread.join();
    }
    if (this->tickThread.joinable()) {
        this->tickThread.join();
    }

    this->tun.down();
    this->ws.disconnect();
    return 0;
}

// WebSocket
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
    this->wsThread = std::thread([&] { this->handleWebSocketMessage(); });
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
            Candy::shutdown();
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
            // 收到主动发现报文
            if (message.buffer.front() == MessageType::DISCOVERY) {
                handleDiscoveryMessage(message);
                continue;
            }

            spdlog::warn("unknown websocket message: type {}", int(message.buffer.front()));
            continue;
        }

        if (message.type == WebSocketMessageType::Open) {

            sendVirtualMacMessage();

            if (!this->localAddress.empty()) {
                if (startTunThread()) {
                    spdlog::critical("start tun thread with static address failed");
                    Candy::shutdown();
                    break;
                }
                if (startUdpThread()) {
                    spdlog::critical("start udp thread failed");
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
            Candy::shutdown();
            break;
        }
        // 通信出现错误,触发正常退出进程的流程
        if (message.type == WebSocketMessageType::Error) {
            spdlog::critical("client websocket error: {}", message.buffer);
            Candy::shutdown();
            break;
        }
    }
    return;
}

void Client::handleUdpMessage() {
    int error;
    UdpMessage message;

    while (this->running) {
        error = this->udpHolder.read(message);
        if (error == 0) {
            continue;
        }
        if (error < 0) {
            spdlog::critical("udp read failed: error {}", error);
            Candy::shutdown();
            break;
        }
        if (isStunResponse(message)) {
            handleStunResponse(message.buffer);
            continue;
        }

        message.buffer = decrypt(selfInfo.getKey(), message.buffer);
        if (message.buffer.empty()) {
            spdlog::debug("invalid peer message: ip {} port {}", Address::ipToStr(message.ip), message.port);
            continue;
        }

        if (isHeartbeatMessage(message)) {
            handleHeartbeatMessage(message);
            continue;
        }
        if (isPeerForwardMessage(message)) {
            handlePeerForwardMessage(message);
            continue;
        }
        if (isDelayMessage(message)) {
            if (routeCost) {
                handleDelayMessage(message);
            }
            continue;
        }
        if (isRouteMessage(message)) {
            if (routeCost) {
                handleRouteMessage(message);
            }
            continue;
        }
        spdlog::warn("unknown peer message: type {}", int(message.buffer.front()));
    }
}

void Client::sendForwardMessage(const std::string &buffer) {
    WebSocketMessage message;
    message.buffer.push_back(MessageType::FORWARD);
    message.buffer.append(buffer);
    ws.write(message);
}

void Client::sendVirtualMacMessage() {
    VMacMessage buffer(this->virtualMac);
    buffer.updateHash(this->password);

    WebSocketMessage message;
    message.buffer.assign((char *)(&buffer), sizeof(buffer));
    this->ws.write(message);
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
    message.buffer.assign((char *)(&header), sizeof(header));
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

void Client::sendPeerConnMessage(uint32_t src, uint32_t dst, uint32_t ip, uint16_t port) {
    PeerConnMessage header;
    header.src = Address::hostToNet(src);
    header.dst = Address::hostToNet(dst);
    header.ip = Address::hostToNet(ip);
    header.port = Address::hostToNet(port);

    WebSocketMessage message;
    message.buffer.assign((char *)(&header), sizeof(PeerConnMessage));
    this->ws.write(message);
    return;
}

void Client::sendDiscoveryMessage(uint32_t dst) {
    DiscoveryMessage header;

    header.src = Address::hostToNet(this->tun.getIP());
    header.dst = Address::hostToNet(dst);

    WebSocketMessage message;
    message.buffer.assign((char *)(&header), sizeof(DiscoveryMessage));
    this->ws.write(message);
    return;
}

void Client::handleForwardMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(ForwardHeader)) {
        spdlog::warn("invalid forward message: {:n}", spdlog::to_hex(message.buffer));
    }

    const char *src = message.buffer.c_str() + sizeof(ForwardHeader::type);
    const size_t len = message.buffer.length() - sizeof(ForwardHeader::type);
    this->tun.write(std::string(src, len));

    const IPv4Header *header = (const IPv4Header *)src;

    tryDirectConnection(Address::netToHost(header->saddr));
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

    setLocalAddress(address.getCidr());
    if (startTunThread()) {
        spdlog::critical("start tun thread with dynamic address failed");
        Candy::shutdown();
        return;
    }
    if (startUdpThread()) {
        spdlog::critical("start udp thread failed");
        Candy::shutdown();
        return;
    }
}

void Client::handlePeerConnMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(PeerConnMessage)) {
        spdlog::warn("invalid peer conn message: {:n}", spdlog::to_hex(message.buffer));
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

    if (this->stun.uri.empty()) {
        peer.updateState(PeerState::FAILED);
        return;
    }

    peer.ip = ip;
    peer.port = port;
    peer.count = 0;
    peer.setTun(src, this->password);

    if (peer.getState() == PeerState::SYNCHRONIZING) {
        peer.updateState(PeerState::CONNECTING);
        return;
    }

    if (peer.getState() != PeerState::CONNECTING) {
        peer.updateState(PeerState::PREPARING);
        return;
    }
}

void Client::handleDiscoveryMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(DiscoveryMessage)) {
        spdlog::warn("invalid discovery message: {:n}", spdlog::to_hex(message.buffer));
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

// 调用这个函数是需要确保双方同时调用.
// 1. 收到对方报文时,一般会回包,此时调用
// 2. 收到主动发现报文时,这时一定会回包
void Client::tryDirectConnection(uint32_t ip) {
    std::unique_lock lock(this->ipPeerMutex);
    PeerInfo &peer = this->ipPeerMap[ip];
    if (peer.getState() == PeerState::INIT) {
        peer.setTun(ip, this->password);
        peer.updateState(this->stun.uri.empty() ? PeerState::FAILED : PeerState::PREPARING);
    }
}

// TUN
int Client::startTunThread() {
    if (this->tun.setName(this->tunName)) {
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

    this->tunThread = std::thread([&] { this->handleTunMessage(); });

    sendAuthMessage();

    if (addressUpdateCallback) {
        addressUpdateCallback(this->localAddress);
    }

    return 0;
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
            Candy::shutdown();
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
        // 目的地址是本机,直接回写,在 macos 中遇到了这种情况
        if (Address::netToHost(header->daddr) == this->tun.getIP()) {
            this->tun.write(buffer);
            continue;
        }

        // 尝试通过路由或直连发送
        if (!sendPeerForwardMessage(buffer)) {
            continue;
        }

        // 通过 WebSocket 转发
        sendForwardMessage(buffer);
    }
    return;
}

// P2P
int Client::startUdpThread() {
    if (this->stun.uri.empty()) {
        return 0;
    }
    if (this->selfInfo.setTun(this->tun.getIP(), this->password)) {
        return -1;
    }
    sendStunRequest();
    this->udpThread = std::thread([&] { this->handleUdpMessage(); });
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
    });
    return 0;
}

void Client::tick() {
    if (discoveryInterval) {
        if (tickCount % discoveryInterval == 0) {
            sendDiscoveryMessage(BROADCAST_IP);
        }
    }

    std::unique_lock lock(this->ipPeerMutex);
    bool needSendStunRequest = false;
    for (auto &[ip, peer] : this->ipPeerMap) {
        switch (peer.getState()) {
        case PeerState::INIT:
            // 收到对方通过服务器转发的数据的时候,会切换为 PREPARING,这里不做处理
            break;

        case PeerState::PREPARING:
            // 有 PREPARING 状态的元素,在遍历结束后发送一次 STUN 请求
            needSendStunRequest = true;
            break;

        case PeerState::SYNCHRONIZING:
            // 对方版本不支持或者没有启用对等连接,超时后进入 FAILED
            if (peer.count > 10) {
                peer.updateState(PeerState::FAILED);
            }
            break;

        case PeerState::CONNECTING:
            // 进行超时检测,超时后进入 WAITTING 状态,否则发送心跳
            if (peer.count > 10) {
                peer.updateState(PeerState::WAITTING);
            } else {
                if (peer.count == 0) {
                    std::string ip = Address::ipToStr(peer.getTun());
                    std::string saddr = Address::ipToStr(this->selfInfo.ip);
                    std::string daddr = Address::ipToStr(peer.ip);
                    uint16_t sport = this->selfInfo.port;
                    uint16_t dport = peer.port;
                    spdlog::debug("connecting: {} {}:{} => {}:{}", ip, saddr, sport, daddr, dport);
                }
                sendHeartbeatMessage(peer);
            }
            break;

        case PeerState::CONNECTED:
            // 进行超时检测,超时后清空对端信息,否则发送心跳
            if (peer.count > 3) {
                peer.updateState(PeerState::INIT);
                if (routeCost) {
                    updateRouteTable(RouteEntry(peer.getTun(), peer.getTun(), DELAY_LIMIT));
                }
            } else {
                sendHeartbeatMessage(peer);
                if (routeCost && peer.tick % 60 == 0) {
                    sendDelayMessage(peer);
                }
            }
            break;

        case PeerState::WAITTING:
            // 指数退避算法
            if (peer.count > peer.retry) {
                uint32_t next = std::min(peer.retry * 2, 3600U);
                peer.updateState(PeerState::INIT);
                peer.retry = next;
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
    ++tickCount;
}

std::string Client::encrypt(const std::string &key, const std::string &plaintext) {
    if (key.size() != AES_256_GCM_KEY_LEN) {
        spdlog::debug("invalid key size: {}", key.size());
        return "";
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        spdlog::debug("failed to create cipher context");
        return "";
    }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to initialize cipher context");
        return "";
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_LEN, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to set IV length");
        return "";
    }
    unsigned char iv[AES_256_GCM_IV_LEN];
    if (!RAND_bytes(iv, AES_256_GCM_IV_LEN)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to generate random IV");
        return "";
    }
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char *)key.data(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to set key and IV");
        return "";
    }
    int len;
    unsigned char ciphertext[plaintext.size()];
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext.data(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to encrypt plaintext");
        return "";
    }
    int ciphertextLen = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to finalize encryption");
        return "";
    }
    ciphertextLen += len;
    unsigned char tag[AES_256_GCM_TAG_LEN];
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_LEN, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to get tag");
        return "";
    }
    EVP_CIPHER_CTX_free(ctx);

    std::string result;
    result.append((char *)iv, AES_256_GCM_IV_LEN);
    result.append((char *)tag, AES_256_GCM_TAG_LEN);
    result.append((char *)ciphertext, ciphertextLen);
    return result;
}

std::string Client::decrypt(const std::string &key, const std::string &ciphertext) {
    if (key.size() != AES_256_GCM_KEY_LEN) {
        spdlog::debug("invalid key length: {}", key.size());
        return "";
    }
    if (ciphertext.size() < AES_256_GCM_IV_LEN + AES_256_GCM_TAG_LEN) {
        spdlog::debug("invalid ciphertext length");
        return "";
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        spdlog::debug("failed to create cipher context");
        return "";
    }
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to initialize cipher context");
        return "";
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_LEN, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to set IV length");
        return "";
    }

    unsigned char iv[AES_256_GCM_IV_LEN];
    unsigned char tag[AES_256_GCM_TAG_LEN];
    unsigned char *enc = (unsigned char *)ciphertext.data();

    memcpy(iv, enc, AES_256_GCM_IV_LEN);
    memcpy(tag, enc + AES_256_GCM_IV_LEN, AES_256_GCM_TAG_LEN);
    enc += AES_256_GCM_IV_LEN + AES_256_GCM_TAG_LEN;

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char *)key.data(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to set key and IV");
        return "";
    }

    int len;
    unsigned char plaintext[ciphertext.size() - AES_256_GCM_IV_LEN - AES_256_GCM_TAG_LEN];
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, enc, ciphertext.size() - AES_256_GCM_IV_LEN - AES_256_GCM_TAG_LEN)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to decrypt ciphertext");
        return "";
    }

    int plaintextLen = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_256_GCM_TAG_LEN, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to set tag");
        return "";
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::debug("failed to finalize decryption");
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

    Uri uri(this->stun.uri);
    if (!uri.isValid()) {
        spdlog::error("invalid stun uri: {}", this->stun.uri);
        return -1;
    }
    if (getaddrinfo(uri.host().c_str(), uri.port().empty() ? "3478" : uri.port().c_str(), &hints, &info)) {
        spdlog::warn("resolve stun server domain name failed: {}:{}", uri.host(), uri.port());
        return -1;
    }

    this->stun.ip = Address::netToHost((uint32_t)((struct sockaddr_in *)info->ai_addr)->sin_addr.s_addr);
    this->stun.port = Address::netToHost((uint16_t)((struct sockaddr_in *)info->ai_addr)->sin_port);

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
    PeerHeartbeatMessage heartbeat;
    heartbeat.type = PeerMessageType::HEARTBEAT;
    heartbeat.tun = Address::hostToNet(this->tun.getIP());
    heartbeat.ip = Address::hostToNet(this->selfInfo.ip);
    heartbeat.port = Address::hostToNet(this->selfInfo.port);
    heartbeat.ack = peer.ack;

    UdpMessage message;
    message.ip = peer.ip;
    message.port = peer.port;
    message.buffer = encrypt(peer.getKey(), std::string((char *)&heartbeat, sizeof(heartbeat)));
    this->udpHolder.write(message);
    return 0;
}

int Client::sendPeerForwardMessage(const std::string &buffer) {
    std::shared_lock ipPeerLock(this->ipPeerMutex);
    std::shared_lock rtTableLock(this->rtTableMutex);

    IPv4Header *header = (IPv4Header *)buffer.data();
    uint32_t dst = Address::netToHost(header->daddr);

    // 优先尝试直连
    if (!sendPeerForwardMessage(buffer, dst)) {
        return 0;
    }

    // 没有开路由功能
    if (!routeCost) {
        return 1;
    }

    auto route = this->rtTable.find(dst);
    // 没有找到路由
    if (route == this->rtTable.end()) {
        return 1;
    }

    // 尝试通过路由转发
    return sendPeerForwardMessage(buffer, route->second.next);
}

int Client::sendPeerForwardMessage(const std::string &buffer, uint32_t nextHop) {
    auto it = this->ipPeerMap.find(nextHop);
    if (it == this->ipPeerMap.end()) {
        return 1;
    }

    const auto &peer = it->second;
    if (peer.getState() != PeerState::CONNECTED) {
        return 1;
    }

    UdpMessage message;
    message.ip = peer.ip;
    message.port = peer.port;
    message.buffer.push_back(PeerMessageType::Forward);
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
    return message.buffer.front() == PeerMessageType::Forward;
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

    this->selfInfo.ip = ip;
    this->selfInfo.port = port;

    // 收到 STUN 响应后,向所有 PREPARING 状态的对端发送自己的公网信息,如果当前持有对端公网信息,就将状态调整为 CONNECTING,
    // 否则调整为 SYNCHRONIZING
    std::unique_lock lock(this->ipPeerMutex);
    for (auto &[tun, peer] : this->ipPeerMap) {
        if (peer.getState() == PeerState::PREPARING) {
            sendPeerConnMessage(this->tun.getIP(), peer.getTun(), ip, port);
            if (peer.ip && peer.port) {
                peer.updateState(PeerState::CONNECTING);
            } else {
                peer.updateState(PeerState::SYNCHRONIZING);
            }
        }
    }

    return 0;
}

int Client::handleHeartbeatMessage(const UdpMessage &message) {
    if (message.buffer.length() < sizeof(PeerHeartbeatMessage)) {
        spdlog::debug("invalid heartbeat length: {}", message.buffer.length());
        return -1;
    }

    // 收到对端的心跳,检查地址,更新端口,并将状态调整为 CONNECTED
    PeerHeartbeatMessage *heartbeat = (PeerHeartbeatMessage *)message.buffer.c_str();
    std::unique_lock lock(this->ipPeerMutex);
    uint32_t tun = Address::netToHost(heartbeat->tun);
    PeerInfo &peer = this->ipPeerMap[tun];
    if (peer.getState() != PeerState::CONNECTING && peer.getState() != PeerState::CONNECTED) {
        spdlog::debug("heartbeat peer state invalid: {} {}", Address::ipToStr(tun), peer.getStateStr());
        return -1;
    }
    if (peer.ip != message.ip) {
        spdlog::warn("heartbeat ip mismatch: {} auth {} real {}", Address::ipToStr(tun), Address::ipToStr(peer.ip),
                     Address::ipToStr(message.ip));
        peer.ip = message.ip;
    }
    if (peer.port != message.port) {
        spdlog::warn("heartbeat port mismatch: {} auth {} real {}", Address::ipToStr(tun), peer.port, message.port);
        peer.port = message.port;
    }
    if (!peer.ack) {
        peer.ack = 1;
    }
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
        this->tun.write(std::string(src, len));

        // 可能是转发来的,尝试跟源地址建立直连
        tryDirectConnection(Address::netToHost(ipv4Message->iph.saddr));
        return 0;
    }

    std::shared_lock ipPeerLock(this->ipPeerMutex);
    std::shared_lock rtTableLock(this->rtTableMutex);
    auto route = this->rtTable.find(Address::netToHost(ipv4Message->iph.daddr));
    if (route == this->rtTable.end()) {
        return 0;
    }

    auto peer = this->ipPeerMap.find(route->second.next);
    if (peer == this->ipPeerMap.end() || peer->second.getState() != PeerState::CONNECTED) {
        return 0;
    }

    UdpMessage forward;
    forward.ip = peer->second.ip;
    forward.port = peer->second.port;
    forward.buffer = encrypt(peer->second.getKey(), message.buffer);
    this->udpHolder.write(forward);
    return 0;
}

// Route
void Client::showRouteChange(const RouteEntry &entry) {
    std::string dstStr = Address::ipToStr(entry.dst);
    std::string nextStr = Address::ipToStr(entry.next);
    std::string delayStr = (entry.delay == DELAY_LIMIT) ? "[deleted]" : std::to_string(entry.delay);
    spdlog::debug("route: dst={} next={} delay={}", dstStr, nextStr, delayStr);
}

int Client::updateRouteTable(RouteEntry entry) {
    bool isDirect = (entry.dst == entry.next);
    bool isDelete = (entry.delay < 1 || entry.delay > 1000);

    std::unique_lock lock(this->rtTableMutex);

    // 拿到的到达此目的地址的历史路由
    auto oldEntry = this->rtTable.find(entry.dst);

    // 直连的操作,修改完需要广播
    if (isDirect) {
        // 与直连设备断开了连接,删除所有以该设备作为下一跳的路由
        if (isDelete) {
            // 路由表里曾经没有以它作为直连的记录,就不可能以它作为下一跳的记录
            if (oldEntry == this->rtTable.end() || oldEntry->second.dst != oldEntry->second.next) {
                return 0;
            }
            // 删除所有以该设备作为下一跳的路由
            for (auto it = this->rtTable.begin(); it != this->rtTable.end();) {
                if (it->second.next == entry.next) {
                    sendRouteMessage(it->second.dst, DELAY_LIMIT);
                    it->second.delay = DELAY_LIMIT;
                    showRouteChange(it->second);
                    it = this->rtTable.erase(it);
                    continue;
                }
                ++it;
            }

            return 0;
        }

        // 1. 此前不存在这条路由
        // 2. 存在这条路由,但是并非直连且直连更快
        if ((oldEntry == this->rtTable.end()) ||
            ((oldEntry->second.dst != oldEntry->second.next) && (oldEntry->second.delay > entry.delay))) {
            this->rtTable[entry.dst] = entry;
            sendRouteMessage(entry.dst, entry.delay);
            showRouteChange(entry);
            return 0;
        }

        // 获取时延变化量,并更新以该设备作为下一跳的路由
        int32_t diff = entry.delay - oldEntry->second.delay;
        for (auto it = this->rtTable.begin(); it != this->rtTable.end(); ++it) {
            if (it->second.next == entry.next) {
                it->second.delay += diff;
                sendRouteMessage(it->second.dst, it->second.delay);
                showRouteChange(it->second);
                continue;
            }
        }
        return 0;
    }

    // 非直连的操作,更新完路由表后不需要广播
    if (isDelete) {
        // 不存在到该目的地址的路由,无需删除
        if (oldEntry == this->rtTable.end()) {
            return 0;
        }
        // 存在到该目的地址的路由,但是下一跳不同,无需删除
        if (oldEntry->second.next != entry.next) {
            return 0;
        }

        sendRouteMessage(oldEntry->second.dst, DELAY_LIMIT);
        oldEntry->second.delay = DELAY_LIMIT;
        showRouteChange(oldEntry->second);
        this->rtTable.erase(oldEntry);
        return 0;
    }

    // 只要存在直连,无论延迟多高都不跳转
    if (oldEntry != this->rtTable.end() && oldEntry->second.dst == oldEntry->second.next) {
        return 0;
    }

    // 拿到与下一跳直连的时延,加上传来的时延计算总时延
    auto directEntry = this->rtTable.find(entry.next);
    // 没有与下一跳建立直连,异常情况,直接返回
    if (directEntry == this->rtTable.end()) {
        spdlog::warn("route broadcast received from non-directly connected device");
        return 1;
    }

    // 1. 以前不存在到该目的地址的路由
    // 2. 存在路由且下一跳相同
    // 3. 存在路由且下一跳不同,但延迟更低
    int32_t nowDelay = directEntry->second.delay + entry.delay;
    if (oldEntry == this->rtTable.end() || oldEntry->second.next == entry.next || oldEntry->second.delay > nowDelay) {
        entry.delay = nowDelay;
        this->rtTable[entry.dst] = entry;
        sendRouteMessage(entry.dst, entry.delay);
        showRouteChange(entry);
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
    return sendDelayMessageHelper(peer, delayMessage);
}

int Client::sendDelayMessageHelper(const PeerInfo &peer, const PeerDelayMessage &delay) {
    UdpMessage message;
    message.ip = peer.ip;
    message.port = peer.port;
    message.buffer = encrypt(peer.getKey(), std::string((char *)&delay, sizeof(delay)));
    this->udpHolder.write(message);
    return 0;
}

int Client::sendRouteMessage(uint32_t dst, int32_t delay) {
    PeerRouteMessage routeMessage;
    routeMessage.type = PeerMessageType::ROUTE;
    routeMessage.dst = Address::hostToNet(dst);
    routeMessage.next = Address::hostToNet(this->tun.getIP());
    routeMessage.delay = Time::hostToNet(delay == DELAY_LIMIT ? DELAY_LIMIT : delay + routeCost);

    for (auto &[_, peer] : this->ipPeerMap) {
        if (peer.getState() == PeerState::CONNECTED) {
            UdpMessage message;
            message.ip = peer.ip;
            message.port = peer.port;
            message.buffer = encrypt(peer.getKey(), std::string((char *)&routeMessage, sizeof(routeMessage)));
            this->udpHolder.write(message);
        }
    }

    return 0;
}

bool Client::isDelayMessage(const UdpMessage &message) {
    return message.buffer.front() == PeerMessageType::DELAY;
}

bool Client::isRouteMessage(const UdpMessage &message) {
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
            updateRouteTable(RouteEntry(dst, dst, delay));
        }
        return 0;
    }

    if (dst == this->tun.getIP()) {
        auto it = this->ipPeerMap.find(src);
        if (it != this->ipPeerMap.end()) {
            sendDelayMessageHelper(it->second, *delayMessage);
        }
        return 0;
    }

    return 0;
}

int Client::handleRouteMessage(const UdpMessage &message) {
    if (message.buffer.length() < sizeof(PeerRouteMessage)) {
        spdlog::debug("invalid route message length: {}", message.buffer.length());
        return -1;
    }

    PeerRouteMessage *routeMessage = (PeerRouteMessage *)message.buffer.c_str();
    uint32_t dst = Address::netToHost(routeMessage->dst);
    uint32_t next = Address::netToHost(routeMessage->next);
    int32_t delay = Time::netToHost(routeMessage->delay);

    if (dst != this->tun.getIP()) {
        updateRouteTable(RouteEntry(dst, next, delay));
    }

    return 0;
}

} // namespace Candy

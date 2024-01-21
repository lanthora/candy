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
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

namespace {

static constexpr size_t AES_256_GCM_IV_LEN = 12;
static constexpr size_t AES_256_GCM_TAG_LEN = 16;
static constexpr size_t AES_256_GCM_KEY_LEN = 32;

} // namespace

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

int Client::setVirtualMac(const std::string &vmac) {
    this->virtualMac = vmac;
    return 0;
}

int Client::setStun(const std::string &stun) {
    this->stun.uri = stun;
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

int Client::startUdpThread() {
    if (this->stun.uri.empty()) {
        return 0;
    }
    this->selfInfo.tun = this->tun.getIP();
    if (this->selfInfo.updateKey(this->password)) {
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
            spdlog::warn("unknown message: {:n}", spdlog::to_hex(message.buffer));
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

        {
            // 发包时检查对端是否为 CONNECTED,是的话直接发送,否则走服务端转发
            std::unique_lock lock(this->ipPeerMutex);
            PeerInfo &peer = this->ipPeerMap[Address::netToHost(header->daddr)];
            if (peer.getState() == PeerState::CONNECTED) {
                UdpMessage message;
                message.ip = peer.ip;
                message.port = peer.port;
                message.buffer.push_back(PeerMessageType::IPv4);
                message.buffer.append(buffer);
                message.buffer = encrypt(peer.getKey(), message.buffer);
                this->udpHolder.write(message);
                continue;
            }
        }

        // 通过 WebSocket 转发
        WebSocketMessage message;
        message.buffer.push_back(MessageType::FORWARD);
        message.buffer.append(buffer);
        ws.write(message);
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
            spdlog::warn("invalid peer message: ip {}", Address::ipToStr(message.ip));
            continue;
        }
        if (isHeartbeatMessage(message)) {
            handleHeartbeatMessage(message);
            continue;
        }
        if (isIPv4Message(message)) {
            handleIPv4Message(message);
            continue;
        }
        spdlog::warn("unknown peer message type");
    }
}

void Client::tick() {
    std::unique_lock lock(this->ipPeerMutex);
    bool needSendStunRequest = false;
    for (auto &[ip, peer] : this->ipPeerMap) {
        switch (peer.getState()) {
        case PeerState::INIT:
            // 收到对方通过服务器转发的数据的时候,会切换为 PERPARING,这里不做处理
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
                    std::string ip = Address::ipToStr(peer.tun);
                    std::string saddr = Address::ipToStr(this->selfInfo.ip);
                    std::string daddr = Address::ipToStr(peer.ip);
                    uint16_t sport = this->selfInfo.port;
                    uint16_t dport = peer.port;
                    spdlog::debug("connecting: {} {}:{} => {}:{}", ip, saddr, sport, daddr, dport);
                }
                sendHeartbeat(peer);
            }
            break;

        case PeerState::CONNECTED:
            // 进行超时检测,超时后清空对端信息,否则发送心跳
            if (peer.count > 3) {
                peer.reset();
            } else {
                sendHeartbeat(peer);
            }
            break;

        case PeerState::WAITTING:
            // 指数退避算法
            if (peer.count > peer.retry) {
                uint32_t next = std::min(peer.retry * 2, 3600U);
                peer.reset();
                peer.retry = next;
            }
            break;

        case PeerState::FAILED:
            // 两端任意一方不支持或者未启用对等连接功能,进入失败状态,不再主动重连
            break;
        }
        ++peer.count;
    }
    if (needSendStunRequest) {
        sendStunRequest();
    }
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

void Client::handleForwardMessage(WebSocketMessage &message) {
    if (message.buffer.size() < sizeof(ForwardHeader)) {
        spdlog::warn("invalid forward message: {:n}", spdlog::to_hex(message.buffer));
    }

    const char *src = message.buffer.c_str() + sizeof(ForwardHeader::type);
    const size_t len = message.buffer.length() - sizeof(ForwardHeader::type);
    this->tun.write(std::string(src, len));

    const IPv4Header *header = (const IPv4Header *)src;

    // 收到转发包,判断源地址的状态是否为 INIT,是则进入 PREPARING 状态,其他状态忽略
    std::unique_lock lock(this->ipPeerMutex);
    PeerInfo &peer = this->ipPeerMap[Address::netToHost(header->saddr)];
    if (peer.getState() == PeerState::INIT) {
        peer.tun = Address::netToHost(header->saddr);
        if (this->stun.uri.empty()) {
            peer.updateState(PeerState::FAILED);
            return;
        }
        peer.updateState(PeerState::PREPARING);
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
    }

    std::unique_lock lock(this->ipPeerMutex);
    PeerInfo &peer = this->ipPeerMap[src];
    peer.tun = src;
    peer.ip = ip;
    peer.port = port;
    peer.count = 0;
    peer.updateKey(this->password);
    if (this->stun.uri.empty()) {
        peer.updateState(PeerState::FAILED);
    } else if (peer.getState() == PeerState::SYNCHRONIZING) {
        peer.updateState(PeerState::CONNECTING);
    } else if (peer.getState() != PeerState::CONNECTING) {
        peer.updateState(PeerState::PREPARING);
    }
    return;
}

std::string Client::encrypt(const std::string &key, const std::string &plaintext) {
    if (key.size() != AES_256_GCM_KEY_LEN) {
        spdlog::error("invalid key size: {}", key.size());
        return "";
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        spdlog::error("failed to create cipher context");
        return "";
    }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to initialize cipher context");
        return "";
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_LEN, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to set IV length");
        return "";
    }
    unsigned char iv[AES_256_GCM_IV_LEN];
    if (!RAND_bytes(iv, AES_256_GCM_IV_LEN)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to generate random IV");
        return "";
    }
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char *)key.data(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to set key and IV");
        return "";
    }
    int len;
    unsigned char ciphertext[plaintext.size()];
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext.data(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to encrypt plaintext");
        return "";
    }
    int ciphertextLen = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to finalize encryption");
        return "";
    }
    ciphertextLen += len;
    unsigned char tag[AES_256_GCM_TAG_LEN];
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_LEN, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to get tag");
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
        spdlog::error("invalid key length: {}", key.size());
        return "";
    }
    if (ciphertext.size() < AES_256_GCM_IV_LEN + AES_256_GCM_TAG_LEN) {
        spdlog::error("invalid ciphertext length");
        return "";
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        spdlog::error("failed to create cipher context");
        return "";
    }
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to initialize cipher context");
        return "";
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_LEN, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to set IV length");
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
        spdlog::error("failed to set key and IV");
        return "";
    }

    int len;
    unsigned char plaintext[ciphertext.size() - AES_256_GCM_IV_LEN - AES_256_GCM_TAG_LEN];
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, enc, ciphertext.size() - AES_256_GCM_IV_LEN - AES_256_GCM_TAG_LEN)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to decrypt ciphertext");
        return "";
    }

    int plaintextLen = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_256_GCM_TAG_LEN, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to set tag");
        return "";
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        spdlog::error("failed to finalize decryption");
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

bool Client::isStunResponse(const UdpMessage &message) {
    return message.ip == this->stun.ip && message.port == this->stun.port;
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
            sendPeerConnMessage(this->tun.getIP(), peer.tun, ip, port);
            if (peer.ip && peer.port) {
                peer.updateState(PeerState::CONNECTING);
            } else {
                peer.updateState(PeerState::SYNCHRONIZING);
            }
        }
    }

    return 0;
}

bool Client::isHeartbeatMessage(const UdpMessage &message) {
    return message.buffer.front() == PeerMessageType::HEARTBEAT;
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
        peer.count = 0;
        peer.updateState(PeerState::CONNECTED);
    }
    return 0;
}

int Client::sendHeartbeat(const PeerInfo &peer) {
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

bool Client::isIPv4Message(const UdpMessage &message) {
    return message.buffer.front() == PeerMessageType::IPv4;
}

int Client::handleIPv4Message(const UdpMessage &message) {
    if (message.buffer.length() < sizeof(PeerRawIPv4Message)) {
        spdlog::debug("invalid raw ipv4 length: {}", message.buffer.length());
        return -1;
    }

    const char *src = message.buffer.c_str() + sizeof(ForwardHeader::type);
    const size_t len = message.buffer.length() - sizeof(ForwardHeader::type);
    this->tun.write(std::string(src, len));
    return 0;
}

} // namespace Candy

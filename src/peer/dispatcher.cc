// SPDX-License-Identifier: MIT
#include "peer/dispatcher.h"
#include "peer/peer.h"
#include "utility/address.h"
#include <array>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>
#include <string.h>
#include <utility/uri.h>

#if defined(__linux__) || defined(__linux)

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#endif

namespace PeerMessageType {

constexpr uint8_t HEARTBEAT = 0;
constexpr uint8_t FORWARD = 1;

}; // namespace PeerMessageType

namespace {

struct stun_request {
    uint8_t type[2] = {0x00, 0x01};
    uint8_t length[2] = {0x00, 0x08};
    uint8_t cookie[4] = {0x21, 0x12, 0xa4, 0x42};
    uint8_t id[12] = {0x00};
    struct {
        uint8_t type[2] = {0x00, 0x03};
        uint8_t length[2] = {0x00, 0x04};
        uint8_t notset[4] = {0x00};
    } attr;
};

struct stun_response {
    uint16_t type;
    uint16_t length;
    uint32_t cookie;
    uint8_t id[12];
    uint8_t attr[0];
};

}; // namespace

namespace Candy {

// 心跳,包含一些简单的身份信息
struct PeerMessageHeartbeat {
    uint8_t type;
    uint32_t tunIp;
    uint32_t pubIp;
    uint16_t pubPort;
} __attribute__((packed));

// 数据转发,与用 WebSocket 转发的格式相似
struct PeerMessageForward {
    uint8_t type;
    IPv4Header iph;
} __attribute__((packed));

#if defined(__linux__) || defined(__linux)
Dispatcher::Dispatcher() {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        spdlog::error("create udp socket failed: {}", strerror(errno));
        return;
    }
    this->socket = fd;
    return;
}
#endif

#if defined(__linux__) || defined(__linux)
Dispatcher::~Dispatcher() {
    int fd = std::any_cast<int>(this->socket);
    if (fd) {
        close(fd);
        this->socket = 0;
    }
    return;
}
#endif

int Dispatcher::setStun(const std::string &stun) {
    this->stun = stun;
    return 0;
}

int Dispatcher::setTunIP(uint32_t ip) {
    this->tunIp = ip;

    return 0;
}

int Dispatcher::setPassword(const std::string &password) {
    this->password = password;
    return 0;
}

int Dispatcher::run() {
    std::string data;
    data.append(this->password);
    data.append((char *)&this->tunIp, sizeof(this->tunIp));
    this->key.resize(SHA256_DIGEST_LENGTH);
    SHA256((unsigned char *)data.data(), data.size(), (unsigned char *)this->key.data());

    this->running = true;
    this->tickThread = std::move(std::thread([&] { this->tick(); }));
    this->udpMessageThread = std::move(std::thread([&] { this->handleUdpMessage(); }));
    return 0;
}

int Dispatcher::shutdown() {
    this->running = false;
    if (this->tickThread.joinable()) {
        this->tickThread.join();
    }
    if (this->udpMessageThread.joinable()) {
        this->udpMessageThread.join();
    }
    return 0;
}

#if defined(__linux__) || defined(__linux)
int Dispatcher::fetchPublicInfo(uint32_t &pubIp, uint16_t &pubPort) {
    struct addrinfo hints = {}, *info = NULL;

    bzero(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    Uri uri(this->stun);
    if (!uri.isValid()) {
        spdlog::warn("invalid stun uri: {}", this->stun);
        return -1;
    }
    if (getaddrinfo(uri.host().c_str(), uri.port().empty() ? "3478" : uri.port().c_str(), &hints, &info)) {
        spdlog::debug("resolve stun server domain name failed");
        return -1;
    }

    this->stunIp = Address::netToHost(((struct sockaddr_in *)info->ai_addr)->sin_addr.s_addr);
    this->stunPort = Address::netToHost(((struct sockaddr_in *)info->ai_addr)->sin_port);

    int fd = std::any_cast<int>(this->socket);
    if (!fd) {
        spdlog::debug("invalid peer udp socket");
        return -1;
    }

    std::unique_lock<std::mutex> lock(this->pubMutex);

    this->stunResponded = false;

    stun_request request;
    int len = sendto(fd, &request, sizeof(request), 0, info->ai_addr, info->ai_addrlen);
    if (len == -1) {
        spdlog::debug("send stun request failed");
        return -1;
    }

    if (!this->pubCondition.wait_for(lock, std::chrono::seconds(1), [&] { return this->stunResponded; })) {
        spdlog::debug("recv stun response timeout");
        return -1;
    }
    if (!this->stunResponded || this->pubIp == 0 || this->pubPort == 0) {
        spdlog::debug("invalid public info: ip {:x} port {}", this->pubIp, this->pubPort);
        return -1;
    }

    pubIp = this->pubIp;
    pubPort = this->pubPort;
    return 0;
}
#endif

int Dispatcher::updatePeerPublicInfo(uint32_t tunIp, uint32_t pubIp, uint16_t pubPort, uint8_t forceSync) {
    if (this->running) {
        std::unique_lock<std::shared_mutex> lock(this->ipPeerMapMutex);
        Peer &peer = this->ipPeerMap[tunIp];

        if (forceSync) {
            peer.state = PeerConnState::SYNCHRONIZING;
            spdlog::debug("conn state: peer {:x} forceSync SYNCHRONIZING", tunIp);
        } else if (peer.state == PeerConnState::INIT) {
            peer.state = PeerConnState::SYNCHRONIZING;
            spdlog::debug("conn state: peer {:x} INIT -> SYNCHRONIZING", tunIp);
        } else if (peer.state == PeerConnState::FAILED) {
            peer.state = PeerConnState::SYNCHRONIZING;
            spdlog::debug("conn state: peer {:x} FAILED -> SYNCHRONIZING", tunIp);
        } else if (peer.state == PeerConnState::PERPARING) {
            peer.state = PeerConnState::CONNECTING;
            spdlog::debug("conn state: peer {:x} PERPARING -> CONNECTING", tunIp);
        } else {
            return 0;
        }

        peer.tunIp = tunIp;
        peer.pubIp = pubIp;
        peer.pubPort = pubPort;
        peer.tickCount = 0;
        peer.updateKey(this->password);
        spdlog::debug("update peer public info: tun {:x} ip {:x} port {}", tunIp, pubIp, pubPort);
    }
    return 0;
}

int Dispatcher::updatePeerState(uint32_t tunIp) {
    if (this->running) {
        std::unique_lock<std::shared_mutex> lock(this->ipPeerMapMutex);
        Peer &peer = this->ipPeerMap[tunIp];

        if (peer.state == PeerConnState::INIT) {
            peer.state = PeerConnState::PERPARING;
            spdlog::debug("conn state: peer {:x} INIT -> PERPARING", tunIp);
        } else if (peer.state == PeerConnState::SYNCHRONIZING) {
            peer.state = PeerConnState::CONNECTING;
            spdlog::debug("conn state: peer {:x} SYNCHRONIZING -> CONNECTING", tunIp);
        } else {
            return 0;
        }

        peer.tunIp = tunIp;
        peer.tickCount = 0;
        peer.updateKey(this->password);
    }
    return 0;
}

PeerConnState Dispatcher::getPeerState(uint32_t ip) {
    if (!this->running) {
        return PeerConnState::FAILED;
    }

    auto it = this->ipPeerMap.find(ip);
    if (it == this->ipPeerMap.end()) {
        return PeerConnState::INIT;
    }

    return it->second.state;
}

int Dispatcher::write(std::string &buffer) {
    const IPv4Header *header = (IPv4Header *)buffer.c_str();
    const uint32_t daddr = Address::netToHost(header->daddr);

    std::shared_lock<std::shared_mutex> lock(this->ipPeerMapMutex);
    const Peer &peer = this->ipPeerMap[daddr];

    std::string plaintext;
    plaintext.push_back(PeerMessageType::FORWARD);
    plaintext.append(buffer);

    std::string ciphertext = encrypt(peer.key, plaintext);

    sendRawUdp(peer.pubIp, peer.pubPort, ciphertext);
    return 0;
}

int Dispatcher::read(std::string &buffer) {
    std::unique_lock<std::mutex> lock(this->queueMutex);
    if (this->queueCondition.wait_for(lock, std::chrono::seconds(1), [&] { return !this->queue.empty(); })) {
        buffer = std::move(this->queue.front());
        this->queue.pop();
        return 1;
    }
    return 0;
}

std::string Dispatcher::encrypt(const std::string &key, const std::string &plaintext) {
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

std::string Dispatcher::decrypt(const std::string &key, const std::string &ciphertext) {
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

int Dispatcher::tick() {
    while (this->running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        std::unique_lock<std::shared_mutex> lock(this->ipPeerMapMutex);
        for (auto &[ip, peer] : this->ipPeerMap) {
            // 初始状态或者已经确定连接失败的不再做处理
            if (peer.state == PeerConnState::INIT || peer.state == PeerConnState::FAILED) {
                continue;
            }
            // 主动待连接状态
            if (peer.state == PeerConnState::PERPARING) {
                // 对方不在线或者对方版本不支持对等连接才会超时,标记为 FAILED 不再尝试连接.
                if (peer.tickCount > 30) {
                    peer.state = PeerConnState::FAILED;
                    spdlog::debug("conn state: peer {:x} PERPARING -> FAILED", ip);
                    continue;
                }
            }
            // 被动待连接状态
            if (peer.state == PeerConnState::SYNCHRONIZING) {
                if (peer.tickCount > 10) {
                    peer.state = PeerConnState::INIT;
                    spdlog::debug("conn state: peer {:x} SYNCHRONIZING -> INIT", ip);
                    continue;
                }
            }
            // 尝试连接状态
            if (peer.state == PeerConnState::CONNECTING) {
                if (peer.tickCount > 60) {
                    peer.state = PeerConnState::FAILED;
                    spdlog::debug("conn state: peer {:x} CONNECTING -> FAILED", ip);
                    continue;
                }
            }
            // 处于连接状态,当收到心跳后, tickCount 会重置,已经超过 2 秒没有重置,标记为初始状态,有新包会重新开始连接
            if (peer.state == PeerConnState::CONNECTED) {
                if (peer.tickCount > 2) {
                    peer.state = PeerConnState::INIT;
                    spdlog::debug("conn state: peer {:x} CONNECTED -> INIT", ip);
                    continue;
                }
            }
            // 发送心跳
            if (peer.state == PeerConnState::CONNECTING || peer.state == PeerConnState::CONNECTED) {
                PeerMessageHeartbeat heartbeat;
                heartbeat.type = PeerMessageType::HEARTBEAT;
                heartbeat.tunIp = Address::hostToNet(this->tunIp);
                heartbeat.pubIp = Address::hostToNet(this->pubIp);
                heartbeat.pubPort = Address::hostToNet(this->pubPort);

                std::string plaintext;
                plaintext.assign((char *)(&heartbeat), sizeof(heartbeat));
                std::string ciphertext = encrypt(peer.key, plaintext);
                sendRawUdp(peer.pubIp, peer.pubPort, ciphertext);
            }
            // 更新计数
            ++peer.tickCount;
        }
    }
    return 0;
}

int Dispatcher::handleUdpMessage() {
    uint32_t remotePubIp;
    uint16_t remotePubPort;
    std::string msg;
    int len;

    while (this->running) {
        len = recvRawUdp(remotePubIp, remotePubPort, msg);
        if (len <= 0) {
            continue;
        }
        if (remotePubIp == this->stunIp && remotePubPort == this->stunPort) {
            handleStunResponse(msg);
            continue;
        }
        std::string plaintext = decrypt(this->key, msg);
        if (plaintext.front() == PeerMessageType::HEARTBEAT) {
            handleHeartbeatMsg(plaintext, remotePubIp, remotePubPort);
            continue;
        }
        if (plaintext.front() == PeerMessageType::FORWARD) {
            handleForwardMsg(plaintext, remotePubIp, remotePubPort);
            continue;
        }
        spdlog::error("unknown peer message type: {}", (uint8_t)plaintext.front());
        return -1;
    }
    return 0;
}

int Dispatcher::handleHeartbeatMsg(const std::string &msg, uint32_t pubIp, uint16_t pubPort) {
    if (msg.size() < sizeof(PeerMessageHeartbeat)) {
        spdlog::debug("peer heartbeat message too short: len {}", msg.size());
        return -1;
    }

    std::unique_lock<std::shared_mutex> lock(this->ipPeerMapMutex);

    PeerMessageHeartbeat *heartbeat = (PeerMessageHeartbeat *)msg.c_str();
    if (!this->ipPeerMap.contains(Address::netToHost(heartbeat->tunIp))) {
        Address address;
        address.ipUpdate(Address::netToHost(heartbeat->tunIp));
        spdlog::debug("peer heartbeat unknown tun ip: {}", address.getIpStr());
        return -1;
    }

    Peer &peer = this->ipPeerMap[Address::netToHost(heartbeat->tunIp)];
    if (pubIp != peer.pubIp) {
        spdlog::debug("heartbeat address does not match: ip {:x} {:x}", pubIp, peer.pubIp);
        return -1;
    }
    if (peer.pubPort != pubPort) {
        spdlog::debug("heartbeat port does not match, update peer port: new {} old {}", pubPort, peer.pubPort);
        peer.pubPort = pubPort;
    }
    if (peer.state == PeerConnState::CONNECTED) {
        peer.tickCount = 0;
        return 0;
    }
    peer.tickCount = 0;
    peer.state = PeerConnState::CONNECTED;
    spdlog::debug("conn state: peer {:x} CONNECTED", peer.tunIp);
    return 0;
}

int Dispatcher::handleForwardMsg(const std::string &msg, uint32_t pubIp, uint16_t pubPort) {
    if (msg.size() < sizeof(PeerMessageForward)) {
        spdlog::debug("peer forward message too short: len {}", msg.size());
        return -1;
    }

    std::shared_lock<std::shared_mutex> lock(this->ipPeerMapMutex);

    PeerMessageForward *forward = (PeerMessageForward *)msg.c_str();
    if (!this->ipPeerMap.contains(Address::netToHost(forward->iph.saddr))) {
        Address address;
        address.ipUpdate(Address::netToHost(forward->iph.saddr));
        spdlog::debug("peer message unknown source address: {}", address.getIpStr());
        return -1;
    }
    const Peer &peer = this->ipPeerMap[Address::netToHost(forward->iph.saddr)];
    if (pubIp != peer.pubIp || pubPort != peer.pubPort) {
        spdlog::debug("the source address does not match the authentication address");
        return -1;
    }
    std::string buffer((char *)&forward->iph, msg.size() - sizeof(PeerMessageType::FORWARD));
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        this->queue.push(buffer);
    }
    queueCondition.notify_one();
    return 0;
}

#if defined(__linux__) || defined(__linux)
int Dispatcher::sendRawUdp(uint32_t ip, uint16_t port, const std::string &msg) {
    int fd = std::any_cast<int>(this->socket);
    if (!fd) {
        spdlog::error("socket not initialized successfully");
        return -1;
    }
    struct sockaddr_in to;
    bzero(&to, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = Address::hostToNet(ip);
    to.sin_port = Address::hostToNet(port);
    ssize_t len = sendto(fd, msg.c_str(), msg.length(), 0, (struct sockaddr *)&to, sizeof(to));
    if (len == -1) {
        spdlog::error("udp socket write failed: {}", strerror(errno));
        return -1;
    }
    return 0;
}
#endif

#if defined(__linux__) || defined(__linux)
int Dispatcher::recvRawUdp(uint32_t &ip, uint16_t &port, std::string &msg) {
    int fd = std::any_cast<int>(this->socket);
    if (!fd) {
        spdlog::error("udp socket not initialized successfully");
        return -1;
    }

    struct timeval timeout = {.tv_sec = 1};
    fd_set set;

    FD_ZERO(&set);
    FD_SET(fd, &set);

    int ret = select(fd + 1, &set, NULL, NULL, &timeout);
    if (ret < 0) {
        spdlog::error("udp socket select failed: error {}", ret);
        return -1;
    }
    if (ret == 0) {
        return 0;
    }

    char buffer[1500];
    struct sockaddr_in from;
    socklen_t addr_len = sizeof(from);
    bzero(&from, sizeof(from));

    ssize_t len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &addr_len);
    if (len == -1) {
        spdlog::error("udp socket read failed: {}", strerror(errno));
        return -1;
    }
    msg.assign(buffer, len);
    ip = Address::netToHost(from.sin_addr.s_addr);
    port = Address::netToHost(from.sin_port);
    return len;
}
#endif

#if defined(__linux__) || defined(__linux)
int Dispatcher::handleStunResponse(const std::string &msg) {
    uint32_t ip = 0;
    uint16_t port = 0;

    if (msg.length() < sizeof(stun_response)) {
        spdlog::debug("invalid stun response length: {}", msg.length());
        return -1;
    }
    stun_response *response = (stun_response *)msg.c_str();
    if (Address::netToHost(response->type) != 0x0101) {
        spdlog::debug("stun not success response");
        return -1;
    }
    uint8_t *attr = response->attr;
    int pos = 0;
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
    if (ip && port) {
        spdlog::debug("stun response: ip {:x} port {}", ip, port);
        this->pubIp = ip;
        this->pubPort = port;
    } else {
        spdlog::debug("stun response parse failed: {:n}", spdlog::to_hex(msg));
    }
    {
        std::lock_guard<std::mutex> lock(this->pubMutex);
        this->stunResponded = true;
    }
    pubCondition.notify_one();
    return 0;
}
#endif

}; // namespace Candy

// SPDX-License-Identifier: MIT
#include "peer/manager.h"
#include "core/client.h"
#include "core/message.h"
#include "core/net.h"
#include "peer/message.h"
#include "utils/time.h"
#include <Poco/Net/NetException.h>
#include <Poco/Net/NetworkInterface.h>
#include <Poco/Timespan.h>
#include <Poco/URI.h>
#include <openssl/sha.h>
#include <shared_mutex>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

namespace Candy {

int PeerManager::setPassword(const std::string &password) {
    this->password = password;
    return 0;
}

int PeerManager::setStun(const std::string &stun) {
    this->stun.uri = stun;
    return 0;
}

int PeerManager::setDiscoveryInterval(int interval) {
    this->discoveryInterval = interval;
    return 0;
}

int PeerManager::setRouteCost(int cost) {
    if (cost < 0) {
        this->routeCost = 0;
    } else if (cost > 1000) {
        this->routeCost = 1000;
    } else {
        this->routeCost = cost;
    }
    return 0;
}

int PeerManager::setPort(int port) {
    if (port > 0 && port <= UINT16_MAX) {
        this->listenPort = port;
    }
    return 0;
}

int PeerManager::setLocalhost(const std::string &ip) {
    this->localhost.fromString(ip);
    return 0;
}

int PeerManager::run(Client *client) {
    this->client = client;
    this->localP2PDisabled = false;

    if (this->localhost.empty()) {
        try {
            for (const auto &iface : Poco::Net::NetworkInterface::list()) {
                if (iface.supportsIPv4() && !iface.isLoopback() && !iface.isPointToPoint() &&
                    iface.type() != iface.NI_TYPE_OTHER) {
                    auto firstAddress = iface.firstAddress(Poco::Net::IPAddress::IPv4);
                    memcpy(&this->localhost, firstAddress.addr(), sizeof(this->localhost));
                    spdlog::debug("localhost: {}", this->localhost.toString());
                    break;
                }
            }
        } catch (std::exception &e) {
            spdlog::warn("local ip failed: {}", e.what());
        }
    }

    if (this->initSocket()) {
        Candy::shutdown(this->client);
        return -1;
    }

    this->msgThread = std::thread([&] {
        while (getClient().running) {
            handlePeerQueue();
        }
        spdlog::debug("peer msg thread exit");
    });
    this->tickThread = std::thread([&] {
        while (getClient().running) {
            auto wake_time = std::chrono::system_clock::now() + std::chrono::seconds(1);
            tick();
            std::this_thread::sleep_until(wake_time);
        }
        spdlog::debug("peer tick thread exit");
    });

    return 0;
}

int PeerManager::shutdown() {
    if (this->msgThread.joinable()) {
        this->msgThread.join();
    }
    if (this->tickThread.joinable()) {
        this->tickThread.join();
    }
    if (this->pollThread.joinable()) {
        this->pollThread.join();
    }

    this->socket.close();

    {
        std::unique_lock lock(this->rtTableMutex);
        this->rtTableMap.clear();
    }

    {
        std::unique_lock lock(this->ipPeerMutex);
        this->ipPeerMap.clear();
    }

    return 0;
}

std::string PeerManager::getPassword() {
    return this->password;
}

void PeerManager::handlePeerQueue() {
    Msg msg = getClient().getPeerMsgQueue().read();
    switch (msg.kind) {
    case MsgKind::TIMEOUT:
        break;
    case MsgKind::PACKET:
        handlePacket(std::move(msg));
        break;
    case MsgKind::TUNADDR:
        handleTunAddr(std::move(msg));
        break;
    case MsgKind::SYSRT:
        this->localP2PDisabled = true;
        break;
    case MsgKind::TRYP2P:
        handleTryP2P(std::move(msg));
        break;
    case MsgKind::PUBINFO:
        handlePubInfo(std::move(msg));
        break;
    default:
        spdlog::warn("unexcepted peer message type: {}", static_cast<int>(msg.kind));
        break;
    }
}

int PeerManager::sendPacket(IP4 dst, const Msg &msg) {
    if (!sendPacketDirect(dst, msg)) {
        return 0;
    }
    if (!sendPacketRelay(dst, msg)) {
        return 0;
    }
    return -1;
}

int PeerManager::sendPacketDirect(IP4 dst, const Msg &msg) {
    std::shared_lock ipPeerLock(this->ipPeerMutex);
    auto it = this->ipPeerMap.find(dst);
    if (it != this->ipPeerMap.end()) {
        auto &peer = it->second;
        if (peer.isConnected()) {
            return peer.sendEncrypted(PeerMsg::Forward::create(msg.data));
        }
    }
    return -1;
}

int PeerManager::sendPacketRelay(IP4 dst, const Msg &msg) {
    {
        std::shared_lock rtTableLock(this->rtTableMutex);
        auto it = this->rtTableMap.find(dst);
        if (it == this->rtTableMap.end()) {
            return -1;
        }
        dst = it->second.next;
    }
    return sendPacketDirect(dst, msg);
}

int PeerManager::sendPubInfo(CoreMsg::PubInfo info) {
    info.src = getClient().address();
    if (info.local) {
        info.ip = this->localhost;
        info.port = this->socket.address().port();
    } else {
        info.ip = this->stun.ip;
        info.port = this->stun.port;
    }
    getClient().getWsMsgQueue().write(Msg(MsgKind::PUBINFO, std::string((char *)(&info), sizeof(info))));
    return 0;
}

IP4 PeerManager::getTunIp() {
    return this->tunAddr.Host();
}

void PeerManager::handlePacket(Msg msg) {
    auto header = (IP4Header *)msg.data.data();
    if (!sendPacket(header->daddr, msg)) {
        return;
    }
    getClient().getWsMsgQueue().write(std::move(msg));
}

void PeerManager::handleTunAddr(Msg msg) {
    if (this->tunAddr.fromCidr(msg.data)) {
        spdlog::error("set tun addr failed: {}", msg.data);
        return;
    }

    std::string data;
    data.append(this->password);
    auto leaddr = hton(uint32_t(this->tunAddr.Host()));
    data.append((char *)&leaddr, sizeof(leaddr));

    this->key.resize(SHA256_DIGEST_LENGTH);
    SHA256((unsigned char *)data.data(), data.size(), (unsigned char *)this->key.data());
}

void PeerManager::handleTryP2P(Msg msg) {
    IP4 src(msg.data);

    {
        std::shared_lock lock(this->ipPeerMutex);
        auto it = this->ipPeerMap.find(src);
        if (it != this->ipPeerMap.end()) {
            it->second.tryConnecct();
            return;
        }
    }

    {
        std::unique_lock lock(this->ipPeerMutex);
        auto it = this->ipPeerMap.emplace(std::piecewise_construct, std::forward_as_tuple(src), std::forward_as_tuple(src, this));
        if (it.second) {
            it.first->second.tryConnecct();
            return;
        }
    }

    spdlog::warn("can not find peer: {}", src.toString());
}

void PeerManager::handlePubInfo(Msg msg) {
    auto info = (CoreMsg::PubInfo *)(msg.data.data());

    if (info->src == getClient().address() || info->dst != getClient().address()) {
        spdlog::warn("invalid public info: src=[{}] dst=[{}]", info->src.toString(), info->dst.toString());
        return;
    }

    std::shared_lock ipPeerLock(this->ipPeerMutex);
    auto it = this->ipPeerMap.find(info->src);
    if (it == this->ipPeerMap.end()) {
        this->ipPeerMutex.unlock_shared();
        {
            std::unique_lock lock(this->ipPeerMutex);
            this->ipPeerMap.emplace(std::piecewise_construct, std::forward_as_tuple(info->src),
                                    std::forward_as_tuple(info->src, this));
        }
        this->ipPeerMutex.lock_shared();
        it = this->ipPeerMap.find(info->src);
    }

    it->second.handlePubInfo(info->ip, info->port, info->local);
}

void PeerManager::tick() {
    if (this->discoveryInterval && !this->stun.uri.empty()) {
        if ((++tickTick % discoveryInterval == 0)) {
            getClient().getWsMsgQueue().write(Msg(MsgKind::DISCOVERY));
        }
    }
    {
        std::shared_lock ipPeerLock(this->ipPeerMutex);
        for (auto &[ip, peer] : this->ipPeerMap) {
            peer.tick();
        }
    }

    if (this->stun.needed) {
        sendStunRequest();
        this->stun.needed = false;
    }
}

int PeerManager::initSocket() {
    using Poco::Net::AddressFamily;
    using Poco::Net::PollSet;
    using Poco::Net::SocketAddress;

    try {
        this->socket.bind(SocketAddress(AddressFamily::IPv4, this->listenPort));
        spdlog::debug("listen port: {}", this->socket.address().port());
        this->pollSet.add(this->socket, PollSet::POLL_READ);
    } catch (Poco::Net::NetException &e) {
        spdlog::critical("peer socket init failed: {}: {}", e.what(), e.message());
        return -1;
    }

    this->decryptCtx = std::shared_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    this->pollThread = std::thread([&]() {
        while (getClient().running) {
            poll();
        }
        spdlog::debug("peer poll thread exit");
    });
    return 0;
}

void PeerManager::sendStunRequest() {
    try {
        Poco::URI uri(this->stun.uri);
        if (!uri.getPort()) {
            uri.setPort(3478);
        }
        {
            std::unique_lock lock(this->stun.addressMutex);
            this->stun.address = Poco::Net::SocketAddress(uri.getHost(), uri.getPort());
        }

        StunRequest request;
        std::shared_lock lock(this->stun.addressMutex);
        if (sendTo(&request, sizeof(request), this->stun.address) != sizeof(request)) {
            spdlog::warn("the stun request was not completely sent");
        }
    } catch (std::exception &e) {
        spdlog::debug("send stun request failed: {}", e.what());
    }
}

void PeerManager::handleStunResponse(std::string buffer) {
    if (buffer.length() < sizeof(StunResponse)) {
        spdlog::debug("invalid stun response length: {}", buffer.length());
        return;
    }
    auto response = (StunResponse *)buffer.c_str();
    if (ntoh(response->type) != 0x0101) {
        spdlog::debug("invalid stun reponse type: {}", ntoh(response->type));
        return;
    }

    int pos = 0;
    uint32_t ip = 0;
    uint16_t port = 0;
    uint8_t *attr = response->attr;
    while (pos < ntoh(response->length)) {
        // mapped address
        if (ntoh(*(uint16_t *)(attr + pos)) == 0x0001) {
            pos += 6; // 跳过 2 字节类型, 2 字节长度, 1 字节保留, 1 字节IP版本号,指向端口号
            port = ntoh(*(uint16_t *)(attr + pos));
            pos += 2; // 跳过2字节端口号,指向地址
            ip = *(uint32_t *)(attr + pos);
            break;
        }
        // xor mapped address
        if (ntoh(*(uint16_t *)(attr + pos)) == 0x0020) {
            pos += 6; // 跳过 2 字节类型, 2 字节长度, 1 字节保留, 1 字节IP版本号,指向端口号
            port = ntoh(*(uint16_t *)(attr + pos)) ^ 0x2112;
            pos += 2; // 跳过2字节端口号,指向地址
            ip = (*(uint32_t *)(attr + pos)) ^ hton(0x2112a442);
            break;
        }
        // 跳过 2 字节类型,指向属性长度
        pos += 2;
        // 跳过 2 字节长度和用该属性其他内容
        pos += 2 + ntoh(*(uint16_t *)(attr + pos));
    }
    if (!ip || !port) {
        spdlog::warn("stun response parse failed: {:n}", spdlog::to_hex(buffer));
        return;
    }

    memcpy(&this->stun.ip, &ip, sizeof(this->stun.ip));
    this->stun.port = port;

    std::shared_lock lock(this->ipPeerMutex);
    for (auto &[tun, peer] : this->ipPeerMap) {
        peer.handleStunResponse();
    }

    return;
}

void PeerManager::handleMessage(std::string buffer, const SocketAddress &address) {
    switch (buffer.front()) {
    case PeerMsgKind::HEARTBEAT:
        handleHeartbeatMessage(std::move(buffer), address);
        break;
    case PeerMsgKind::FORWARD:
        handleForwardMessage(std::move(buffer), address);
        break;
    case PeerMsgKind::DELAY:
        if (clientRelayEnabled()) {
            handleDelayMessage(std::move(buffer), address);
        }
        break;
    case PeerMsgKind::ROUTE:
        if (clientRelayEnabled()) {
            handleRouteMessage(std::move(buffer), address);
        }
        break;
    default:
        spdlog::info("udp4 unknown message: {}", address.toString());
        break;
    }
}

void PeerManager::handleHeartbeatMessage(std::string buffer, const SocketAddress &address) {
    if (buffer.size() < sizeof(PeerMsg::Heartbeat)) {
        spdlog::debug("udp4 heartbeat failed: len {} address {}", buffer.length(), address.toString());
        return;
    }

    auto heartbeat = (PeerMsg::Heartbeat *)buffer.c_str();
    std::shared_lock lock(this->ipPeerMutex);
    auto it = this->ipPeerMap.find(heartbeat->tunip);
    if (it == this->ipPeerMap.end()) {
        spdlog::debug("udp4 heartbeat find peer failed: tun ip {}", heartbeat->tunip.toString());
        return;
    }
    it->second.handleHeartbeatMessage(address, heartbeat->ack);
}

void PeerManager::handleForwardMessage(std::string buffer, const SocketAddress &address) {
    if (buffer.size() < sizeof(PeerMsg::Forward)) {
        spdlog::warn("invalid forward message: {:n}", spdlog::to_hex(buffer));
        return;
    }
    buffer.erase(0, 1);
    auto header = (IP4Header *)buffer.data();
    if (header->daddr == getTunIp()) {
        getClient().getTunMsgQueue().write(Msg(MsgKind::PACKET, std::move(buffer)));
    } else {
        getClient().getPeerMsgQueue().write(Msg(MsgKind::PACKET, std::move(buffer)));
    }
}

void PeerManager::handleDelayMessage(std::string buffer, const SocketAddress &address) {
    if (buffer.size() < sizeof(PeerMsg::Delay)) {
        spdlog::warn("invalid delay message: {:n}", spdlog::to_hex(buffer));
        return;
    }

    auto header = (PeerMsg::Delay *)buffer.data();

    if (header->dst == getTunIp()) {
        std::shared_lock ipPeerLock(this->ipPeerMutex);
        auto it = this->ipPeerMap.find(header->src);
        if (it != this->ipPeerMap.end()) {
            auto &peer = it->second;
            if (peer.isConnected()) {
                peer.sendEncrypted(buffer);
            }
        }
        return;
    }

    if (header->src == getTunIp()) {
        std::shared_lock ipPeerLock(this->ipPeerMutex);
        auto it = this->ipPeerMap.find(header->dst);
        if (it != this->ipPeerMap.end()) {
            auto &peer = it->second;
            peer.rtt = bootTime() - ntoh(header->timestamp);
            updateRtTable(PeerRouteEntry(header->dst, header->dst, peer.rtt));
        }
        return;
    }
}

void PeerManager::handleRouteMessage(std::string buffer, const SocketAddress &address) {
    if (!routeCost) {
        return;
    }

    if (buffer.size() < sizeof(PeerMsg::Route)) {
        spdlog::warn("invalid delay message: {:n}", spdlog::to_hex(buffer));
        return;
    }
    auto header = (PeerMsg::Route *)buffer.data();

    if (header->dst != getTunIp()) {
        updateRtTable(PeerRouteEntry(header->dst, header->next, ntoh(header->rtt)));
    }
}

void PeerManager::poll() {
    using Poco::Net::PollSet;
    using Poco::Net::Socket;
    using Poco::Net::SocketAddress;

    PollSet::SocketModeMap socketModeMap = this->pollSet.poll(Poco::Timespan(1, 0));
    for (auto &pair : socketModeMap) {
        if (pair.second & PollSet::POLL_READ) {
            if (pair.first == socket) {
                std::string buffer(1500, 0);
                SocketAddress address;
                auto size = socket.receiveFrom(buffer.data(), buffer.size(), address);
                if (size > 0) {
                    buffer.resize(size);

                    auto isStunResponse = [&]() {
                        std::shared_lock lock(this->stun.addressMutex);
                        return this->stun.address == address;
                    }();

                    if (isStunResponse) {
                        handleStunResponse(buffer);
                    } else if (auto plaintext = decrypt(buffer)) {
                        handleMessage(std::move(*plaintext), address);
                    }
                }
            }
        }
    }
}

std::optional<std::string> PeerManager::decrypt(const std::string &ciphertext) {
    int len = 0;
    int plaintextLen = 0;
    unsigned char *enc = NULL;
    unsigned char plaintext[1500] = {0};
    unsigned char iv[AES_256_GCM_IV_LEN] = {0};
    unsigned char tag[AES_256_GCM_TAG_LEN] = {0};

    if (this->key.size() != AES_256_GCM_KEY_LEN) {
        spdlog::debug("invalid key length: {}", this->key.size());
        return std::nullopt;
    }

    if (ciphertext.size() < AES_256_GCM_IV_LEN + AES_256_GCM_TAG_LEN) {
        spdlog::debug("invalid ciphertext length: {}", ciphertext.size());
        return std::nullopt;
    }

    std::lock_guard lock(this->decryptCtxMutex);
    auto ctx = this->decryptCtx.get();

    if (!EVP_CIPHER_CTX_reset(ctx)) {
        spdlog::debug("decrypt reset cipher context failed");
        return std::nullopt;
    }

    enc = (unsigned char *)ciphertext.data();
    memcpy(iv, enc, AES_256_GCM_IV_LEN);
    memcpy(tag, enc + AES_256_GCM_IV_LEN, AES_256_GCM_TAG_LEN);
    enc += AES_256_GCM_IV_LEN + AES_256_GCM_TAG_LEN;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char *)key.data(), iv)) {
        spdlog::debug("initialize cipher context failed");
        return std::nullopt;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_LEN, NULL)) {
        spdlog::debug("set iv length failed");
        return std::nullopt;
    }
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, enc, ciphertext.size() - AES_256_GCM_IV_LEN - AES_256_GCM_TAG_LEN)) {
        spdlog::debug("decrypt update failed");
        return std::nullopt;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_256_GCM_TAG_LEN, tag)) {
        spdlog::debug("set tag failed");
        return std::nullopt;
    }

    plaintextLen = len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        spdlog::debug("decrypt final failed");
        return std::nullopt;
    }

    plaintextLen += len;

    std::string result;
    result.append((char *)plaintext, plaintextLen);
    return result;
}

int PeerManager::sendTo(const void *buffer, int length, const SocketAddress &address) {
    std::lock_guard lock(this->socketMutex);
    return this->socket.sendTo(buffer, length, address);
}

int PeerManager::getDiscoveryInterval() const {
    return this->discoveryInterval;
}

bool PeerManager::clientRelayEnabled() const {
    return this->routeCost > 0;
}

Client &PeerManager::getClient() {
    return *this->client;
}

void PeerManager::showRtChange(const PeerRouteEntry &entry) {
    std::string rtt = (entry.rtt == RTT_LIMIT) ? "[deleted]" : std::to_string(entry.rtt);
    spdlog::debug("route: dst={} next={} delay={}", entry.dst.toString(), entry.next.toString(), rtt);
}

int PeerManager::sendRtMessage(IP4 dst, int32_t rtt) {
    PeerMsg::Route message;
    message.type = PeerMsgKind::ROUTE;
    message.dst = dst;
    message.next = getTunIp();

    if (rtt != RTT_LIMIT) {
        rtt += routeCost;
    }

    message.rtt = ntoh(rtt);

    for (auto &[_, peer] : this->ipPeerMap) {
        if (peer.isConnected()) {
            peer.sendEncrypted(std::string((char *)&message, sizeof(message)));
        }
    }

    return 0;
}

int PeerManager::updateRtTable(PeerRouteEntry entry) {
    bool isDirect = (entry.dst == entry.next);
    bool isDelete = (entry.rtt < 0 || entry.rtt > 1000);

    std::unique_lock lock(this->rtTableMutex);

    auto oldEntry = this->rtTableMap.find(entry.dst);

    if (isDirect && isDelete) {
        for (auto it = this->rtTableMap.begin(); it != this->rtTableMap.end();) {
            if (it->second.next == entry.next) {
                it->second.rtt = RTT_LIMIT;
                sendRtMessage(it->second.dst, it->second.rtt);
                showRtChange(it->second);
                it = this->rtTableMap.erase(it);
                continue;
            }
            ++it;
        }
        return 0;
    }

    if (isDirect && !isDelete) {
        if (oldEntry == this->rtTableMap.end() || oldEntry->second.next == entry.next || oldEntry->second.rtt > entry.rtt) {
            this->rtTableMap[entry.dst] = entry;
            sendRtMessage(entry.dst, entry.rtt);
            showRtChange(entry);
        }
        return 0;
    }

    if (!isDirect && isDelete) {
        if (oldEntry != this->rtTableMap.end() && oldEntry->second.next == entry.next) {
            oldEntry->second.rtt = RTT_LIMIT;
            sendRtMessage(oldEntry->second.dst, oldEntry->second.rtt);
            showRtChange(oldEntry->second);
            this->rtTableMap.erase(oldEntry);
        }
        return 0;
    }

    if (!isDirect && !isDelete) {
        auto directEntry = this->rtTableMap.find(entry.next);
        if (directEntry == this->rtTableMap.end()) {
            return 0;
        }
        int32_t rttNow = directEntry->second.rtt + entry.rtt;
        if (oldEntry == this->rtTableMap.end() || oldEntry->second.next == entry.next || oldEntry->second.rtt > rttNow) {
            entry.rtt = rttNow;
            this->rtTableMap[entry.dst] = entry;
            sendRtMessage(entry.dst, entry.rtt);
            showRtChange(entry);
            return 0;
        }
        return 0;
    }
    return 0;
}

} // namespace Candy

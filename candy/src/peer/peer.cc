// SPDX-License-Identifier: MIT
#include "peer/peer.h"
#include "core/client.h"
#include "core/message.h"
#include "peer/manager.h"
#include "peer/peer.h"
#include "utils/time.h"
#include <Poco/Net/IPAddress.h>
#include <Poco/Net/SocketAddress.h>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>

namespace {

using namespace Poco::Net;

bool isLocalNetwork(const SocketAddress &addr) {
    IPAddress ip = addr.host();

    if (ip.isV4()) {
        return ip.isSiteLocal() || ip.isLinkLocal() || ip.isSiteLocalMC();
    } else if (ip.isV6()) {
        spdlog::error("unexpected ipv6 local address");
    }

    return false;
}

} // namespace

namespace candy {

Peer::Peer(const IP4 &addr, PeerManager *peerManager) : peerManager(peerManager), addr(addr) {
    std::string data;
    data.append(this->peerManager->getPassword());
    auto leaddr = hton(uint32_t(this->addr));
    data.append((char *)&leaddr, sizeof(leaddr));

    this->key.resize(SHA256_DIGEST_LENGTH);
    SHA256((unsigned char *)data.data(), data.size(), (unsigned char *)this->key.data());

    this->encryptCtx = std::shared_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
}

Peer::~Peer() {}

void Peer::tryConnecct() {
    if (this->state == PeerState::INIT) {
        updateState(PeerState::PREPARING);
    }
}

PeerManager &Peer::getManager() {
    return *this->peerManager;
}

std::optional<std::string> Peer::encrypt(const std::string &plaintext) {
    int len = 0;
    int ciphertextLen = 0;
    unsigned char ciphertext[1500] = {0};
    unsigned char iv[AES_256_GCM_IV_LEN] = {0};
    unsigned char tag[AES_256_GCM_TAG_LEN] = {0};

    if (!RAND_bytes(iv, AES_256_GCM_IV_LEN)) {
        spdlog::debug("generate random iv failed");
        return std::nullopt;
    }

    std::lock_guard lock(this->encryptCtxMutex);
    auto ctx = this->encryptCtx.get();

    if (!EVP_CIPHER_CTX_reset(ctx)) {
        spdlog::debug("encrypt reset cipher context failed");
        return std::nullopt;
    }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char *)key.data(), iv)) {
        spdlog::debug("encrypt initialize cipher context failed");
        return std::nullopt;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_LEN, NULL)) {
        spdlog::debug("set iv length failed");
        return std::nullopt;
    }
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext.data(), plaintext.size())) {
        spdlog::debug("encrypt update failed");
        return std::nullopt;
    }
    ciphertextLen = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        spdlog::debug("encrypt final failed");
        return std::nullopt;
    }
    ciphertextLen += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_LEN, tag)) {
        spdlog::debug("get tag failed");
        return std::nullopt;
    }

    std::string result;
    result.append((char *)iv, AES_256_GCM_IV_LEN);
    result.append((char *)tag, AES_256_GCM_TAG_LEN);
    result.append((char *)ciphertext, ciphertextLen);
    return result;
}

int Peer::sendEncrypted(const std::string &data) {
    if (auto buffer = encrypt(data)) {
        return send(*buffer);
    }
    return -1;
}

bool Peer::checkActivityWithin(std::chrono::system_clock::duration duration) {
    return std::chrono::system_clock::now() - lastActiveTime < duration;
}

std::optional<int32_t> Peer::isConnected() const {
    if (this->state == PeerState::CONNECTED) {
        return this->rtt;
    }
    return std::nullopt;
}

bool Peer::updateState(PeerState state) {
    this->lastActiveTime = std::chrono::system_clock::now();

    if (this->state == state) {
        return false;
    }

    spdlog::debug("state: {} {} => {}", this->addr.toString(), stateString(), stateString(state));

    if (state == PeerState::INIT || state == PeerState::WAITING || state == PeerState::FAILED) {
        resetState();
    }

    if (this->state == PeerState::WAITING && state == PeerState::INIT) {
        this->retry = std::min(this->retry * 2, RETRY_MAX);
    } else if (state == PeerState::INIT || state == PeerState::FAILED) {
        this->retry = RETRY_MIN;
    }

    this->state = state;
    return true;
}

std::string Peer::stateString() const {
    return this->stateString(this->state);
}

std::string Peer::stateString(PeerState state) const {
    switch (state) {
    case PeerState::INIT:
        return "INIT";
    case PeerState::PREPARING:
        return "PREPARING";
    case PeerState::SYNCHRONIZING:
        return "SYNCHRONIZING";
    case PeerState::CONNECTING:
        return "CONNECTING";
    case PeerState::CONNECTED:
        return "CONNECTED";
    case PeerState::WAITING:
        return "WAITING";
    case PeerState::FAILED:
        return "FAILED";
    default:
        return "UNKNOWN";
    }
}

void Peer::handlePubInfo(IP4 ip, uint16_t port, bool local) {
    try {
        std::unique_lock lock(this->socketAddressMutex);
        if (local) {
            this->local = SocketAddress(ip.toString(), port);
            return;
        }

        this->wide = SocketAddress(ip.toString(), port);
    } catch (const Poco::Exception &e) {
        spdlog::warn("peer handle pubinfo failed: ip={}, port={}, error={}", ip.toString(), port, e.message());
        return;
    }

    if (this->state == PeerState::CONNECTED) {
        return;
    }

    if (this->state == PeerState::SYNCHRONIZING) {
        updateState(PeerState::CONNECTING);
        return;
    }

    if (this->state != PeerState::CONNECTING) {
        updateState(PeerState::PREPARING);
        CoreMsg::PubInfo info = {.dst = this->addr, .local = true};
        getManager().sendPubInfo(info);
        return;
    }
}

void Peer::handleStunResponse() {
    if (this->state != PeerState::PREPARING) {
        return;
    }
    if (this->wide == std::nullopt) {
        updateState(PeerState::SYNCHRONIZING);
    } else {
        updateState(PeerState::CONNECTING);
    }
    CoreMsg::PubInfo info = {.dst = this->addr};
    getManager().sendPubInfo(info);
}

void Peer::tick() {
    switch (this->state) {
    case PeerState::INIT:
        break;
    case PeerState::PREPARING:
        if (getManager().stun.enabled() && checkActivityWithin(std::chrono::seconds(10))) {
            getManager().stun.needed = true;
        } else {
            updateState(PeerState::FAILED);
        }
        break;
    case PeerState::SYNCHRONIZING:
        if (checkActivityWithin(std::chrono::seconds(10))) {
            sendHeartbeatMessage();
        } else {
            updateState(PeerState::FAILED);
        }
        break;
    case PeerState::CONNECTING:
        if (checkActivityWithin(std::chrono::seconds(10))) {
            sendHeartbeatMessage();
        } else {
            updateState(PeerState::WAITING);
        }
        break;
    case PeerState::CONNECTED:
        if (checkActivityWithin(std::chrono::seconds(3))) {
            sendHeartbeatMessage();
            if (getManager().clientRelayEnabled() && tickCount % 60 == 0) {
                sendDelayMessage();
            }
        } else {
            updateState(PeerState::INIT);
            if (getManager().clientRelayEnabled()) {
                getManager().updateRtTable(PeerRouteEntry(addr, addr, RTT_LIMIT));
            }
        }
        break;
    case PeerState::WAITING:
        if (!checkActivityWithin(std::chrono::seconds(this->retry))) {
            updateState(PeerState::INIT);
        }
        break;
    case PeerState::FAILED:
        break;
    default:
        break;
    }
    ++tickCount;
}

void Peer::handleHeartbeatMessage(const SocketAddress &address, uint8_t heartbeatAck) {
    if (this->state == PeerState::INIT || this->state == PeerState::WAITING || this->state == PeerState::FAILED) {
        spdlog::debug("heartbeat peer state invalid: {} {}", this->addr.toString(), stateString());
        return;
    }

    if (!isLocalNetwork(address)) {
        this->wide = address;
    } else if (!getManager().localP2PDisabled) {
        this->local = address;
    } else {
        return;
    }

    {
        std::unique_lock lock(this->socketAddressMutex);
        if (!this->real || isLocalNetwork(address) || !isLocalNetwork(*this->real)) {
            this->real = address;
        }
    }

    if (!this->ack) {
        this->ack = 1;
    }

    if (heartbeatAck && updateState(PeerState::CONNECTED)) {
        sendDelayMessage();
    }
}

int Peer::send(const std::string &buffer) {
    try {
        std::shared_lock lock(this->socketAddressMutex);
        if (this->real) {
            if (buffer.size() == getManager().sendTo(buffer.data(), buffer.size(), *this->real)) {
                return 0;
            }
        }
    } catch (std::exception &e) {
        spdlog::debug("peer send failed: {}", e.what());
    }
    return -1;
}

void Peer::sendHeartbeatMessage() {
    PeerMsg::Heartbeat heartbeat;
    heartbeat.kind = PeerMsgKind::HEARTBEAT;
    heartbeat.tunip = getManager().getTunIp();
    heartbeat.ack = this->ack;

    if (auto buffer = encrypt(std::string((char *)&heartbeat, sizeof(heartbeat)))) {
        using Poco::Net::SocketAddress;
        std::shared_lock lock(this->socketAddressMutex);
        if (this->real && (this->state == PeerState::CONNECTED)) {
            heartbeat.ip = this->real->host().toString();
            heartbeat.port = this->real->port();
            getManager().sendTo(buffer->data(), buffer->size(), *this->real);
        }

        if (this->wide && (this->state == PeerState::CONNECTING)) {
            heartbeat.ip = this->wide->host().toString();
            heartbeat.port = this->wide->port();
            getManager().sendTo(buffer->data(), buffer->size(), *this->wide);
        }

        if (this->local && (this->state == PeerState::PREPARING || this->state == PeerState::SYNCHRONIZING ||
                            this->state == PeerState::CONNECTING)) {
            heartbeat.ip = this->local->host().toString();
            heartbeat.port = this->local->port();
            getManager().sendTo(buffer->data(), buffer->size(), *this->local);
        }
    }
}

void Peer::sendDelayMessage() {
    PeerMsg::Delay delay;
    delay.type = PeerMsgKind::DELAY;
    delay.src = getManager().getTunIp();
    delay.dst = this->addr;
    delay.timestamp = hton(bootTime());
    sendEncrypted(std::string((char *)&delay, sizeof(delay)));
}

void Peer::resetState() {
    std::unique_lock lock(this->socketAddressMutex);
    this->wide = std::nullopt;
    this->local = std::nullopt;
    this->real = std::nullopt;
    this->ack = 0;
    this->rtt = RTT_LIMIT;
}

} // namespace candy

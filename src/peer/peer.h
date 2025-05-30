// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_PEER_H
#define CANDY_PEER_PEER_H

#include "core/net.h"
#include "utils/random.h"
#include <Poco/Net/SocketAddress.h>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <shared_mutex>
#include <string>

namespace Candy {

class PeerManager;

constexpr int32_t RTT_LIMIT = INT32_MAX;
constexpr int32_t RETRY_MIN = 30;
constexpr int32_t RETRY_MAX = 3600;

using Poco::Net::SocketAddress;

enum class PeerState {
    INIT,
    PREPARING,
    SYNCHRONIZING,
    CONNECTING,
    CONNECTED,
    WAITING,
    FAILED,
};

class Peer {
public:
    Peer(const IP4 &addr, PeerManager *peerManager);
    ~Peer();

    void tick();
    void tryConnecct();
    void handleStunResponse();
    void handlePubInfo(IP4 ip, uint16_t port, bool local = false);

    void handleHeartbeatMessage(const SocketAddress &address, uint8_t heartbeatAck);
    int sendEncrypted(const std::string &buffer);
    std::optional<int32_t> isConnected() const;

    int32_t rtt = RTT_LIMIT;
    uint32_t tickCount = randomUint32();

private:
    PeerManager &getManager();
    PeerManager *peerManager;

    std::optional<std::string> encrypt(const std::string &plaintext);
    std::shared_ptr<EVP_CIPHER_CTX> encryptCtx;
    std::mutex encryptCtxMutex;
    std::string key;

    std::string stateString() const;
    std::string stateString(PeerState state) const;
    bool updateState(PeerState state);
    void resetState();
    bool checkActivityWithin(std::chrono::system_clock::duration duration);
    PeerState state = PeerState::INIT;
    uint8_t ack = 0;
    int32_t retry = RETRY_MIN;
    std::chrono::system_clock::time_point lastActiveTime;

    int send(const std::string &buffer);
    void sendHeartbeatMessage();
    void sendDelayMessage();

    std::optional<SocketAddress> wide, local, real;
    std::shared_mutex socketAddressMutex;

    IP4 addr;
};

} // namespace Candy

#endif

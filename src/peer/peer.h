// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_PEER_H
#define CANDY_PEER_PEER_H

#include <any>
#include <cstdint>
#include <string>

namespace Candy {

enum class PeerState {
    INIT,
    PREPARING,
    SYNCHRONIZING,
    CONNECTING,
    CONNECTED,
    WAITTING,
    FAILED,
};

constexpr int32_t DELAY_LIMIT = INT32_MAX;
constexpr uint32_t RETRY_MIN = 30;

class PeerInfo {
public:
    uint32_t ip = 0;
    uint16_t port = 0;
    uint8_t ack = 0;
    uint32_t count = 0;
    uint32_t tick = std::rand();
    uint32_t retry = RETRY_MIN;
    int32_t delay = DELAY_LIMIT;

public:
    int setTun(uint32_t tun, const std::string &password);
    std::string getKey() const;
    uint32_t getTun() const;
    void updateState(PeerState state);
    PeerState getState() const;
    std::string getStateStr() const;

private:
    static std::string getStateStr(PeerState state);
    PeerState state = PeerState::INIT;
    uint32_t tun = 0;
    std::string key;
};

class UdpMessage {
public:
    uint32_t ip;
    uint16_t port;
    std::string buffer;
};

class UdpHolder {
public:
    UdpHolder();
    ~UdpHolder();
    size_t read(UdpMessage &message);
    size_t write(const UdpMessage &message);

private:
    std::any socket;
};

} // namespace Candy

#endif

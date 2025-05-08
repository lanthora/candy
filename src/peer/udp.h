// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_UDP_H
#define CANDY_PEER_UDP_H

#include "core/net.h"
#include "peer/connector.h"
#include <Poco/Net/SocketAddress.h>
#include <shared_mutex>

namespace Candy {

constexpr int32_t RTT_LIMIT = INT32_MAX;
constexpr uint32_t RETRY_MIN = 30;
constexpr uint32_t RETRY_MAX = 3600;

using Poco::Net::SocketAddress;

enum class UdpPeerState {
    INIT,          // 默认状态
    PREPARING,     // 开始尝试建立对等连接
    SYNCHRONIZING, // 本机已经将建立对等连接所需的信息发送给了对端,但还没有收到对方的信息
    CONNECTING,    // 已经收到了对端的对等连接信息,且将自己的信息发送给了对方
    CONNECTED,     // 连接成功,持续发送心跳
    WAITING,       // 连接失败,一段时间后重新进入 INIT
    FAILED,        // 连接失败,且不会再主动进入其他状态,除非收到对端的对等连接信息
};

class UDP : public Connector {
public:
    UDP(Peer *peer) : Connector(peer) {}

    std::optional<int32_t> isConnected() const;
    bool tryToConnect();

protected:
    UdpPeerState state = UdpPeerState::INIT;
    std::string stateString() const;
    std::string stateString(UdpPeerState state) const;
    bool updateState(UdpPeerState state);
    virtual void resetState() = 0;

    uint8_t ack = 0;
    uint32_t retry = RETRY_MIN;
    int32_t rtt = RTT_LIMIT;
};

class UDP4 : public UDP {
public:
    UDP4(Peer *peer) : UDP(peer) {}

    std::string getName();
    void updateInfo(IP4 ip, uint16_t port, bool local = false);
    void handleStunResponse();
    void tick();
    void handleHeartbeatMessage(const SocketAddress &address, uint8_t heartbeatAck);

protected:
    void resetState();

private:
    int send(const std::string &buffer);
    void sendHeartbeat();
    std::optional<SocketAddress> wide, local, real;
    std::shared_mutex socket_address_mutex;
};

class UDP6 : public UDP {
public:
    UDP6(Peer *peer) : UDP(peer) {}
    std::string getName();
    void tick();

protected:
    void resetState() {}

private:
    int send(const std::string &buffer);
};

} // namespace Candy

#endif

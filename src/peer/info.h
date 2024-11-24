// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_INFO_H
#define CANDY_PEER_INFO_H

#include <cstdint>
namespace Candy {

enum class PeerState {
    INIT,          // 默认状态
    PREPARING,     // 开始尝试建立对等连接
    SYNCHRONIZING, // 本机已经将建立对等连接所需的信息发送给了对端,但还没有收到对方的信息
    CONNECTING,    // 已经收到了对端的对等连接信息,且将自己的信息发送给了对方
    CONNECTED,     // 连接成功,持续发送心跳
    WAITING,       // 连接失败,一段时间后重新进入 INIT
    FAILED,        // 连接失败,且不会再主动进入其他状态,除非收到对端的对等连接信息
};

constexpr int32_t DELAY_LIMIT = INT32_MAX;
constexpr int32_t RETRY_MIN = 30;
constexpr int32_t RETRY_MAX = 3600;

class PeerInfo {
public:
    bool isConnected() const;
    PeerState getState() const;

private:
    PeerState state;
};

} // namespace Candy

#endif

// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_PEER_H
#define CANDY_PEER_PEER_H

#include <cstdint>
#include <string>

namespace Candy {

enum class PeerConnState {
    INIT,
    PERPARING,
    SYNCHRONIZING,
    CONNECTING,
    CONNECTED,
    FAILED,
};

struct Peer {
    uint32_t tunIp;
    // 对端公网地址和端口
    uint32_t pubIp;
    uint16_t pubPort;

    // 每个对端维护一个状态,并在 tick 时更新状态机
    PeerConnState state;

    // 相同状态 tick 的次数.做出超时检查的效果.
    int tickCount;

    // 密钥
    std::string key;

    int updateKey(const std::string &password);
};

}; // namespace Candy

#endif

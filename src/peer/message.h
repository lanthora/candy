// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_MESSAGE_H
#define CANDY_PEER_MESSAGE_H

#include <cstdint>

namespace Candy {
namespace PeerMsgKind {
constexpr uint8_t HEARTBEAT = 0;
constexpr uint8_t FORWARD = 1;
constexpr uint8_t DELAY = 2;
// TODO: 遗漏了 3, 新功能时使用
constexpr uint8_t ROUTE = 4;
} // namespace PeerMsgKind
} // namespace Candy

#endif

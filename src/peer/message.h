// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_MESSAGE_H
#define CANDY_PEER_MESSAGE_H

#include "core/net.h"
#include <cstdint>

namespace Candy {

namespace PeerMsgKind {

constexpr uint8_t HEARTBEAT = 0;
constexpr uint8_t FORWARD = 1;
constexpr uint8_t DELAY = 2;
constexpr uint8_t ROUTE = 4;

} // namespace PeerMsgKind

struct __attribute__((packed)) StunRequest {
    uint8_t type[2] = {0x00, 0x01};
    uint8_t length[2] = {0x00, 0x08};
    uint8_t cookie[4] = {0x21, 0x12, 0xa4, 0x42};
    uint8_t id[12] = {0x00};
    struct __attribute__((packed)) {
        uint8_t type[2] = {0x00, 0x03};
        uint8_t length[2] = {0x00, 0x04};
        uint8_t notset[4] = {0x00};
    } attr;
};

struct __attribute__((packed)) StunResponse {
    uint16_t type;
    uint16_t length;
    uint32_t cookie;
    uint8_t id[12];
    uint8_t attr[0];
};

namespace PeerMsg {

struct __attribute__((packed)) Heartbeat {
    uint8_t kind;
    IP4 tunip;
    IP4 ip;
    uint16_t port;
    uint8_t ack;
};

struct __attribute__((packed)) Forward {
    uint8_t type;
    IP4Header iph;

    static std::string create(const std::string &packet);
};

struct __attribute__((packed)) Delay {
    uint8_t type;
    IP4 src;
    IP4 dst;
    int64_t timestamp;
};

struct __attribute__((packed)) Route {
    uint8_t type;
    IP4 dst;
    IP4 next;
    int32_t rtt;
};

} // namespace PeerMsg

} // namespace Candy

#endif

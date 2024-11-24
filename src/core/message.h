// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_MESSAGE_H
#define CANDY_CORE_MESSAGE_H

#include "core/net.h"
#include <cstring>
#include <string>

namespace Candy {

enum class MsgKind {
    TIMEOUT,
    PACKET,
    TUNADDR,
    SYSRT,
    TRYP2P,
    PUBINFO,
    DISCOVERY,
};

struct Msg {
    MsgKind kind;
    std::string data;

    Msg(const Msg &) = delete;
    Msg &operator=(const Msg &) = delete;

    Msg(MsgKind kind = MsgKind::TIMEOUT, std::string = "");
    Msg(Msg &&packet);
    Msg &operator=(Msg &&packet);
};

namespace CoreMsg {

struct PubInfo {
    IP4 src;
    IP4 dst;
    IP4 ip;
    uint16_t port;
    bool local = false;
};

} // namespace CoreMsg

} // namespace Candy

#endif

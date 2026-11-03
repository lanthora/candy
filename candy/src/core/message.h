// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_MESSAGE_H
#define CANDY_CORE_MESSAGE_H

#include "core/net.h"
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <queue>
#include <string>

namespace candy {

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

class MsgQueue {
public:
    Msg read();
    void write(Msg msg, size_t limit = 0);
    void clear();

private:
    std::queue<Msg> msgQueue;
    std::mutex msgMutex;
    std::condition_variable msgCondition;
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

} // namespace candy

#endif

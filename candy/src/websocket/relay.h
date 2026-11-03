// SPDX-License-Identifier: MIT
#ifndef CANDY_WEBSOCKET_RELAY_H
#define CANDY_WEBSOCKET_RELAY_H

#include "core/message.h"
#include "utils/atomic.h"
#include <Poco/Net/WebSocket.h>
#include <atomic>
#include <functional>

namespace candy {

struct WsRelay {
    MsgQueue queue;
    Utils::Atomic<bool> running{true};
    std::atomic<int> connections{0};
    std::string key;
    int limit = 0;

    void run(Poco::Net::WebSocket &ws, std::function<void(std::string)> receive, std::function<bool()> active);
};

} // namespace candy

#endif

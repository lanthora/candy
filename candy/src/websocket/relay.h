// SPDX-License-Identifier: MIT
#ifndef CANDY_WEBSOCKET_RELAY_H
#define CANDY_WEBSOCKET_RELAY_H

#include "core/message.h"
#include "utils/atomic.h"
#include <Poco/Net/WebSocket.h>
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>

namespace candy {

// A data connection that has not delivered any frame for this long can be
// replaced while the relay loop still considers it alive (the relay loop
// itself times out after 30 seconds).
constexpr int64_t RELAY_STALE_CONNECTION_MS = 25000;

struct WsRelay {
    MsgQueue queue;
    Utils::Atomic<bool> running{true};
    std::atomic<int> connections{0};
    std::string key;
    // Server side: number of negotiated data connections, filled from MULTI.
    int target = 0;

    // Server side: live data connections and the time of their last frame.
    struct Slot {
        Poco::Net::WebSocket *ws;
        int64_t lastActive;
    };
    std::mutex slotsMutex;
    std::unordered_map<uint64_t, Slot> slots;
    uint64_t nextSlotId = 0;

    void run(Poco::Net::WebSocket &ws, std::function<void(std::string)> receive, std::function<bool()> active,
             uint64_t slotId = 0);

    // Returns 0 when the connection has to be rejected, otherwise a slot id.
    uint64_t admit(Poco::Net::WebSocket *ws, int64_t now);
    void touch(uint64_t slotId, int64_t now);
    void leave(uint64_t slotId);
};

} // namespace candy

#endif

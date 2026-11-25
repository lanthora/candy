// SPDX-License-Identifier: MIT
#include "websocket/relay.h"
#include "utils/log.h"
#include "utils/time.h"
#include "websocket/message.h"
#include <Poco/Timespan.h>
#include <thread>

namespace candy {

void WsRelay::run(Poco::Net::WebSocket &ws, std::function<void(std::string)> receive, std::function<bool()> active,
                  uint64_t slotId) {
    ws.setSendTimeout(Poco::Timespan(3, 0));
    ws.setReceiveTimeout(Poco::Timespan(3, 0));
    std::mutex sendMutex;
    Utils::Atomic<bool> connected{true};
    ++connections;
    std::thread sender([&] {
        try {
            while (running.load() && connected.load() && active()) {
                Msg msg = queue.read();
                if (msg.kind == MsgKind::PACKET) {
                    // The connection may have died while read() was waiting.
                    // Put the packet back so another data connection can
                    // deliver it instead of dropping it.
                    if (!connected.load() || !running.load() || !active()) {
                        queue.write(std::move(msg));
                        break;
                    }
                    std::unique_lock lock(sendMutex);
                    ws.sendFrame(msg.data.data(), msg.data.size(), Poco::Net::WebSocket::FRAME_BINARY);
                }
            }
        } catch (const std::exception &e) {
            candy::logger().debug(std::string("data websocket send failed: ") + e.what());
            connected.store(false);
        }
    });
    try {
        int64_t timestamp = bootTime();
        int64_t ping = timestamp;
        while (running.load() && connected.load() && active()) {
            if (bootTime() - timestamp > 30000) {
                break;
            }
            if (bootTime() - ping > 15000) {
                std::unique_lock lock(sendMutex);
                ws.sendFrame("", 0, Poco::Net::WebSocket::FRAME_FLAG_FIN | Poco::Net::WebSocket::FRAME_OP_PING);
                ping = bootTime();
            }
            if (!ws.poll(Poco::Timespan(1, 0), Poco::Net::Socket::SELECT_READ)) {
                continue;
            }
            std::string buffer(1500, '\0');
            int flags = 0;
            int length = ws.receiveFrame(buffer.data(), buffer.size(), flags);
            int op = flags & Poco::Net::WebSocket::FRAME_OP_BITMASK;
            if ((length == 0 && flags == 0) || op == Poco::Net::WebSocket::FRAME_OP_CLOSE) {
                break;
            }
            timestamp = bootTime();
            touch(slotId, timestamp);
            if (op == Poco::Net::WebSocket::FRAME_OP_PING) {
                std::unique_lock lock(sendMutex);
                ws.sendFrame(buffer.data(), length, Poco::Net::WebSocket::FRAME_FLAG_FIN | Poco::Net::WebSocket::FRAME_OP_PONG);
            } else if (op == Poco::Net::WebSocket::FRAME_OP_BINARY) {
                if (length < sizeof(WsMsg::Forward) || uint8_t(buffer.front()) != WsMsgKind::FORWARD) {
                    break;
                }
                buffer.resize(length);
                receive(std::move(buffer));
            } else if (op != Poco::Net::WebSocket::FRAME_OP_PONG) {
                break;
            }
        }
    } catch (const std::exception &e) {
        candy::logger().debug(std::string("data websocket receive failed: ") + e.what());
    }
    connected.store(false);
    leave(slotId);
    sender.join();
    if (--connections == 0) {
        queue.clear();
    }
}

uint64_t WsRelay::admit(Poco::Net::WebSocket *ws, int64_t now) {
    Poco::Net::WebSocket *evicted = nullptr;
    uint64_t slotId = 0;
    {
        std::unique_lock lock(slotsMutex);
        if (!running.load()) {
            return 0;
        }
        if (slots.size() >= static_cast<size_t>(target)) {
            uint64_t staleId = 0;
            int64_t oldest = 0;
            for (const auto &entry : slots) {
                if (now - entry.second.lastActive > RELAY_STALE_CONNECTION_MS && (!staleId || entry.second.lastActive < oldest)) {
                    staleId = entry.first;
                    oldest = entry.second.lastActive;
                }
            }
            if (staleId) {
                evicted = slots[staleId].ws;
                slots.erase(staleId);
            } else if (slots.size() >= static_cast<size_t>(target + 1)) {
                // Allow one temporary extra connection while the peer replaces
                // a connection the server has not timed out yet.
                return 0;
            }
        }
        slotId = ++nextSlotId;
        slots.emplace(slotId, Slot{ws, now});
    }
    if (evicted) {
        try {
            evicted->shutdown();
        } catch (const std::exception &) {
        }
        try {
            evicted->close();
        } catch (const std::exception &) {
        }
    }
    return slotId;
}

void WsRelay::touch(uint64_t slotId, int64_t now) {
    if (!slotId) {
        return;
    }
    std::unique_lock lock(slotsMutex);
    auto it = slots.find(slotId);
    if (it != slots.end()) {
        it->second.lastActive = now;
    }
}

void WsRelay::leave(uint64_t slotId) {
    if (!slotId) {
        return;
    }
    std::unique_lock lock(slotsMutex);
    slots.erase(slotId);
}

} // namespace candy

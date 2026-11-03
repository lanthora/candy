// SPDX-License-Identifier: MIT
#include "websocket/relay.h"
#include "utils/log.h"
#include "utils/time.h"
#include "websocket/message.h"
#include <Poco/Timespan.h>
#include <thread>

namespace candy {

void WsRelay::run(Poco::Net::WebSocket &ws, std::function<void(std::string)> receive, std::function<bool()> active) {
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
    sender.join();
    if (--connections == 0) {
        queue.clear();
    }
}

} // namespace candy

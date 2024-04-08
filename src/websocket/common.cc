// SPDX-License-Identifier: MIT
#include "websocket/common.h"
#include <Poco/Net/WebSocket.h>
#include <memory>

namespace Candy {

bool WebSocketConn::operator<(const WebSocketConn &other) const {
    return std::owner_less<std::weak_ptr<Poco::Net::WebSocket>>()(this->ws, other.ws);
}

bool WebSocketConn::operator==(const WebSocketConn &other) const {
    return this->ws.lock() == other.ws.lock();
}

} // namespace Candy

// SPDX-License-Identifier: MIT
#include "websocket/common.h"
#include <any>
#include <ixwebsocket/IXWebSocket.h>
#include <memory>

namespace Candy {

bool WebSocketConn::operator<(const WebSocketConn &other) const {
    using IXWebSocketPtr = std::weak_ptr<ix::WebSocket>;

    IXWebSocketPtr thisConn = std::any_cast<IXWebSocketPtr>(this->conn);
    IXWebSocketPtr otherConn = std::any_cast<IXWebSocketPtr>(other.conn);

    return std::owner_less<IXWebSocketPtr>()(thisConn, otherConn);
}

bool WebSocketConn::operator==(const WebSocketConn &other) const {
    using IXWebSocketPtr = std::weak_ptr<ix::WebSocket>;
    IXWebSocketPtr thisConn = std::any_cast<IXWebSocketPtr>(this->conn);
    IXWebSocketPtr otherConn = std::any_cast<IXWebSocketPtr>(other.conn);
    return thisConn.lock() == otherConn.lock();
}

} // namespace Candy

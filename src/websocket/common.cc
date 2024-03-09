// SPDX-License-Identifier: MIT
#include "websocket/common.h"
#include <Poco/Net/WebSocket.h>
#include <memory>

namespace Candy {

bool WebSocketConn::operator<(const WebSocketConn &other) const {
    return std::owner_less<std::weak_ptr<Poco::Net::WebSocket>>()(this->conn, other.conn);
}

bool WebSocketConn::operator==(const WebSocketConn &other) const {
    return this->conn.lock() == other.conn.lock();
}

} // namespace Candy

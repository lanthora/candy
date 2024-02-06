// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_SERVER_H
#define CANDY_CORE_SERVER_H

#include "utility/address.h"
#include "websocket/server.h"
#include <map>
#include <string>
#include <thread>

namespace Candy {

class Server {
public:
    int setWebSocketServer(const std::string &uri);
    int setPassword(const std::string &password);
    int setDynamicAddressRange(const std::string &cidr);

    int run();
    int shutdown();

private:
    int startWsThread();
    void handleWebSocketMessage();

    void handleAuthMessage(WebSocketMessage &message);
    void handleForwardMessage(WebSocketMessage &message);
    void handleDynamicAddressMessage(WebSocketMessage &message);
    void handlePeerConnMessage(WebSocketMessage &message);
    void handleVirtualMacMessage(WebSocketMessage &message);
    void handleCloseMessage(WebSocketMessage &message);

    bool running = false;
    uint16_t port;
    std::string host;
    std::string password;
    std::thread wsThread;
    WebSocketServer ws;

    Address dynamic;
    bool dynamicAddrEnabled = false;

    std::map<uint32_t, WebSocketConn> ipWsMap;
    std::map<WebSocketConn, uint32_t> wsIpMap;
    std::map<WebSocketConn, std::string> wsMacMap;
};

} // namespace Candy

#endif

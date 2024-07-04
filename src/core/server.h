// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_SERVER_H
#define CANDY_CORE_SERVER_H

#include "utility/address.h"
#include "websocket/server.h"
#include <list>
#include <map>
#include <string>
#include <thread>
#include <unordered_map>

namespace Candy {

struct SysRoute {
    Address dev;
    Address dst;
    Address next;
};

class Server {
public:
    int setWebSocketServer(const std::string &uri);
    int setPassword(const std::string &password);
    int setDynamicAddressRange(const std::string &cidr);
    int setSdwan(const std::string &sdwan);

    int run();
    int shutdown();

private:
    int startWsThread();
    void handleWebSocketMessage();

    void handleAuthMessage(WebSocketMessage &message);
    void handleForwardMessage(WebSocketMessage &message);
    void handleExpectedAddressMessage(WebSocketMessage &message);
    void handlePeerConnMessage(WebSocketMessage &message);
    void handleVirtualMacMessage(WebSocketMessage &message);
    void handleDiscoveryMessage(WebSocketMessage &message);
    void handleGeneralMessage(WebSocketMessage &message);
    void handleCloseMessage(WebSocketMessage &message);

    void updateClientRoute(WebSocketMessage &message, uint32_t client);

    bool running = false;
    uint16_t port;
    std::string host;
    std::string password;
    std::thread wsThread;
    WebSocketServer ws;

    Address dynamic;
    bool dynamicAddrEnabled = false;

    std::unordered_map<uint32_t, WebSocketConn> ipWsMap;
    std::map<WebSocketConn, uint32_t> wsIpMap;
    std::map<WebSocketConn, std::string> wsMacMap;
    std::list<SysRoute> routes;
};

} // namespace Candy

#endif

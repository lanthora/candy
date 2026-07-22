// SPDX-License-Identifier: MIT
#ifndef CANDY_WEBSOCKET_SERVER_H
#define CANDY_WEBSOCKET_SERVER_H

#include "core/net.h"
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/WebSocket.h>
#include <list>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace candy {

struct WsCtx {
    Poco::Net::WebSocket *ws;

    std::string buffer;
    int status;

    IP4 ip;
    std::string vmac;

    void sendFrame(const std::string &frame, int flags = Poco::Net::WebSocket::FRAME_BINARY);
};

struct SysRoute {
    // Determines which clients to send the policy to based on address and mask
    Address dev;
    // Address, mask, and next-hop in the system route policy
    Address dst;
    IP4 next;
};

class WebSocketServer {
public:
    int setWebSocket(const std::string &uri);
    int setPassword(const std::string &password);
    int setDHCP(const std::string &cidr);
    int setSdwan(const std::string &sdwan);
    int run();
    int shutdown();

private:
    std::string host;
    uint16_t port;
    std::string password;
    Address dhcp;
    std::list<SysRoute> routes;

private:
    void handleMsg(WsCtx &ctx);
    void handleAuthMsg(WsCtx &ctx);
    void handleForwardMsg(WsCtx &ctx);
    void handleExptTunMsg(WsCtx &ctx);
    void handleUdp4ConnMsg(WsCtx &ctx);
    void handleVMacMsg(WsCtx &ctx);
    void handleDiscoveryMsg(WsCtx &ctx);
    void HandleGeneralMsg(WsCtx &ctx);

    // Update client system route
    void updateSysRoute(WsCtx &ctx);

    // Map of IP to corresponding connection pointer
    std::unordered_map<IP4, WsCtx *> ipCtxMap;
    // Lock when accessing the map to keep pointers valid
    std::shared_mutex ipCtxMutex;

    bool running;

private:
    // Start listening; new requests will invoke handleWebsocket
    int listen();
    // Synchronously handle each client request; connection is released on return
    void handleWebsocket(Poco::Net::WebSocket &ws);

    std::shared_ptr<Poco::Net::HTTPServer> httpServer;
};

} // namespace candy

#endif

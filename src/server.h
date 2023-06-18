// SPDX-License-Identifier: MIT
#ifndef CANDY_SERVER_H
#define CANDY_SERVER_H

#include <ixwebsocket/IXWebSocketServer.h>
#include <map>
#include <memory>
#include <string>

namespace candy {

class Server {
public:
    int setWebsocketServer(const std::string &ws);
    int setPassword(std::string password);
    int setDHCP(std::string dhcp);
    int start();
    void stop();

private:
    using WebSocketServer = std::shared_ptr<ix::WebSocketServer>;
    using WebSocket = std::weak_ptr<ix::WebSocket>;
    using ConnectionState = std::shared_ptr<ix::ConnectionState>;
    using WebSocketMessagePtr = ix::WebSocketMessagePtr;

    void handleConnection(WebSocket webSocket, ConnectionState connectionState);
    void handleMessage(WebSocket webSocket, ConnectionState connectionState, const WebSocketMessagePtr &msg);
    void handleClientMessage(WebSocket webSocket, const WebSocketMessagePtr &msg);
    void handleCloseMessage(WebSocket webSocket, const WebSocketMessagePtr &msg);
    void handleErrorMessage(WebSocket webSocket, const WebSocketMessagePtr &msg);

    uint16_t _wsPort;
    std::string _wsHost;
    WebSocketServer _wsServer;
    std::string _password;
    std::map<uint32_t, WebSocket> _ipWsClientMap;
    std::map<WebSocket, uint32_t, std::owner_less<>> _wsIpClientMap;

private:
    uint32_t _lastClientTunIp;
    uint32_t _network;
    uint32_t _subnet;
    uint32_t newClientTunIP();
};

}; // namespace candy

#endif

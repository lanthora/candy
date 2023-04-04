#ifndef CANDY_SERVER_H
#define CANDY_SERVER_H

#include <ixwebsocket/IXWebSocketServer.h>
#include <memory>
#include <string>
#include <map>

namespace candy {

class Server {
public:
    int setWebsocketServer(const std::string &ws);
    int setPassword(std::string password);
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
    void handleErrorMessage(WebSocket webSocket, const WebSocketMessagePtr &msg);

    uint16_t _wsPort;
    std::string _wsHost;
    WebSocketServer _wsServer;
    std::string _password;
    std::map<uint32_t, WebSocket> _ipWsClientMap;
};

}; // namespace candy

#endif

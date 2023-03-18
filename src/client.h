#ifndef CANDY_CLIENT_H
#define CANDY_CLIENT_H

#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXUserAgent.h>
#include <spdlog/spdlog.h>
#include <memory>
#include <string>

namespace candy {
class Client {
public:
    int setWebsocketServer(std::string ws);
    int setTun(std::string tun);
    int start();
    void stop();

private:
    using WebSocketMessagePtr = ix::WebSocketMessagePtr;

    void handleMessage(const WebSocketMessagePtr &msg);
    void sendHandshakeMsg();
    void handleServerMessage(const WebSocketMessagePtr &msg);
    void handleErrorMessage(const WebSocketMessagePtr &msg);

    int _tunFd;
    std::string _tunIp;
    std::string _tunMask;
    std::shared_ptr<ix::WebSocket> _wsClient;
    std::string _password;
};
}; // namespace candy

#endif

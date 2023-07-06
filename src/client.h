// SPDX-License-Identifier: MIT
#ifndef CANDY_CLIENT_H
#define CANDY_CLIENT_H

#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXUserAgent.h>
#include <ixwebsocket/IXWebSocket.h>
#include <memory>
#include <spdlog/spdlog.h>
#include <string>

namespace candy {
class Client {
public:
    int setWebsocketServer(std::string ws);
    int setPassword(std::string password);
    int setTun(std::string tun, std::string name);
    int start();
    void stop();

private:
    using WebSocketMessagePtr = ix::WebSocketMessagePtr;

    void handleMessage(const WebSocketMessagePtr &msg);
    void sendAuthMessage();
    void sendDHCPMessage();
    void handleServerMessage(const WebSocketMessagePtr &msg);
    void handleCloseMessage(const WebSocketMessagePtr &msg);
    void handleErrorMessage(const WebSocketMessagePtr &msg);

    int _tunFd;
    std::string _tunIp;
    std::string _tunMask;
    std::shared_ptr<ix::WebSocket> _wsClient;
    std::string _password;
    bool _useDHCP;
    std::string _DHCPInterfaceName;

    static const int MTU = 65535;

private:
    std::string getInterfaceName(std::string name);
    int initTun(std::string tun, std::string name);
    void disableIPv6(std::string interface);
    std::string getDHCPConfigFile();
    int saveDHCPAddress(std::string cidr);
    std::string getLastDHCPAddress();
};
}; // namespace candy

#endif

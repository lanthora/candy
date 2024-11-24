// SPDX-License-Identifier: MIT
#ifndef CANDY_WEBSOCKET_CLIENT_H
#define CANDY_WEBSOCKET_CLIENT_H

#include "core/message.h"
#include "core/net.h"
#include <Poco/Net/WebSocket.h>
#include <functional>
#include <memory>
#include <string>
#include <thread>

namespace Candy {

class Client;

class WebSocketClient {
public:
    int setPassword(const std::string &password);
    int setWsServerUri(const std::string &uri);
    int setExptTunAddress(const std::string &cidr);
    int setAddress(const std::string &cidr);
    int setVirtualMac(const std::string &vmac);
    int setTunUpdateCallback(std::function<int(const std::string &)> callback);

    int run(Client *client);
    int shutdown();

private:
    void handleWsQueue();
    void handlePacket(Msg msg);

    std::thread msgThread;

    void handleWsConn();
    void handleWsMsg(std::string buffer);
    void handleForwardMsg(std::string buffer);
    void handleExptTunMsg(std::string buffer);
    void handleDiscoveryMsg(std::string buffer);
    void handleRouteMsg(std::string buffer);
    std::thread wsThread;

    void sendFrame(const std::string &buffer, int flags = Poco::Net::WebSocket::FRAME_BINARY);
    void sendFrame(const void *buffer, int length, int flags = Poco::Net::WebSocket::FRAME_BINARY);

    void sendVirtualMacMsg();
    void sendExptTunMsg();
    void sendAuthMsg();
    void sendDiscoveryMsg(IP4 dst);

    std::function<int(const std::string &)> addressUpdateCallback;

private:
    std::string hostName();
    void sendPingMessage();

private:
    int connect();
    int disconnect();

    std::shared_ptr<Poco::Net::WebSocket> ws;
    std::string pingMessage;
    int64_t timestamp;

private:
    std::string wsServerUri;
    std::string exptTunCidr;
    std::string tunCidr;
    std::string vmac;
    std::string password;
    Client *client;
};

} // namespace Candy

#endif

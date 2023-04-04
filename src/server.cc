#include "server.h"
#include "util.h"
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>
#include <string>
#include <cstdlib>

namespace candy {

int Server::setWebsocketServer(const std::string &ws) {
    candy::WsUriParser parser(ws);
    if (!parser.isValid()) {
        spdlog::critical("websocket uri is invalid. ws: {0}", ws);
        exit(1);
    }

    _wsPort = std::stoi(parser.getPort());
    _wsHost = parser.getHost();

    if (!INet::isIpv4Address(parser.getHost())) {
        spdlog::critical("{0} is not a valid websocket server ip address", parser.getHost());
        exit(1);
    }

    if (parser.getScheme() != "ws") {
        spdlog::critical("websocket server only support ws. please use a proxy such as nginx to handle encryption");
        exit(1);
    }

    return 0;
}

int Server::setPassword(std::string password) {
    _password = password;
    return 0;
}

void Server::handleClientMessage(WebSocket webSocket, const WebSocketMessagePtr &msg) {

    if (msg->str.size() < 1) {
        return;
    }

    if (msg->str.front() == TYPE_AUTH) {
        if (msg->str.size() < sizeof(AuthHeader)) {
            return;
        }

        AuthHeader *auth = (AuthHeader *)msg->str.data();
        if (std::abs(time(NULL) - (time_t)ntohll(auth->timestamp)) > 30) {
            return;
        }

        if (!auth->checkHash(_password)) {
            return;
        }

        _ipWsClientMap[auth->tunIp] = webSocket;
        return;
    }

    if (msg->str.front() == TYPE_FORWARD) {
        if (msg->str.size() < sizeof(ForwardHeader)) {
            return;
        }

        ForwardHeader *forward = (ForwardHeader *)msg->str.data();

        if (!_ipWsClientMap.contains(forward->iph.saddr)) {
            return;
        }

        if (_ipWsClientMap[forward->iph.saddr].lock() != webSocket.lock()) {
            return;
        }

        if (!_ipWsClientMap.contains(forward->iph.daddr)) {
            return;
        }

        auto ws = _ipWsClientMap[forward->iph.daddr].lock();
        if (!ws) {
            return;
        }
        ws->sendBinary(msg->str);
    }
}

void Server::handleErrorMessage(WebSocket webSocket, const WebSocketMessagePtr &msg) {
    spdlog::critical("{0}", msg->errorInfo.reason);
    exit(1);
}

void Server::handleMessage(WebSocket webSocket, ConnectionState connectionState, const WebSocketMessagePtr &msg) {
    switch (msg->type) {
    case ix::WebSocketMessageType::Message:
        handleClientMessage(webSocket, msg);
        break;
    case ix::WebSocketMessageType::Error:
        handleErrorMessage(webSocket, msg);
        break;
    default:
        break;
    }
}

void Server::handleConnection(WebSocket webSocket, ConnectionState connectionState) {
    using namespace std::placeholders;

    auto ws = webSocket.lock();
    if (!ws)
        return;

    ws->setOnMessageCallback(std::bind(&Server::handleMessage, this, webSocket, connectionState, _1));
}

int Server::start() {
    using namespace std::placeholders;

    _wsServer = std::make_shared<ix::WebSocketServer>(_wsPort, _wsHost);
    _wsServer->setOnConnectionCallback(std::bind(&Server::handleConnection, this, _1, _2));

    if (!_wsServer->listen().first) {
        spdlog::critical("websocket server listen failed");
        exit(1);
    }

    _wsServer->disablePerMessageDeflate();
    _wsServer->start();

    return 0;
}

void Server::stop() {
    _wsServer->stop();
}

} // namespace candy

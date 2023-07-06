// SPDX-License-Identifier: MIT
#include "server.h"
#include "util.h"
#include <cstdlib>
#include <spdlog/spdlog.h>
#include <string>

namespace candy {

int Server::setWebsocketServer(const std::string &ws) {
    candy::Uri uri(ws);

    if (!uri.isValid()) {
        spdlog::critical("websocket uri is invalid. ws: {0}", ws);
        exit(1);
    }

    if (uri.scheme() != "ws") {
        spdlog::critical("websocket server only support ws. please use a proxy such as nginx to handle encryption");
        exit(1);
    }

    if (uri.port().empty()) {
        spdlog::critical("websocket server must specify the listening port");
        exit(1);
    }

    _wsPort = std::stoi(uri.port());
    _wsHost = uri.host();

    if (!INet::isIpv4Address(uri.host())) {
        spdlog::critical("{0} is not a valid websocket server ipv4 address", uri.host());
        exit(1);
    }

    return 0;
}

int Server::setPassword(std::string password) {
    _password = password;
    return 0;
}

int Server::setDHCP(std::string dhcp) {
    if (dhcp.empty()) {
        return 0;
    }

    std::size_t pos = dhcp.find("/");
    std::string addr = dhcp.substr(0, pos);

    try {
        _subnet = std::stoi(dhcp.substr(pos + 1));
    } catch (...) {
        spdlog::critical("dhcp format error: {0}", dhcp);
        exit(1);
    }

    if (_subnet <= 0 || _subnet >= 31 || !INet::isIpv4Address(addr)) {
        spdlog::critical("dhcp: {0} invalid", dhcp);
        exit(1);
    }

    _network = ntohl(INet::ipStringToU32(addr));
    _network &= ~((1 << (32 - _subnet)) - 1);
    _lastClientTunIp = _network;
    return 0;
}

void Server::handleClientMessage(WebSocket webSocket, const WebSocketMessagePtr &msg) {

    if (msg->str.size() < 1) {
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
        if (ws) {
            ws->sendBinary(msg->str);
        }
        return;
    }

    if (msg->str.front() == TYPE_AUTH) {
        if (msg->str.size() < sizeof(AuthHeader)) {
            return;
        }

        AuthHeader *auth = (AuthHeader *)msg->str.data();
        if (std::abs(unixTimeStamp() - (int64_t)ntohll(auth->timestamp)) > 30) {
            return;
        }

        if (!auth->checkHash(_password)) {
            return;
        }

        if (_ipWsClientMap.contains(auth->ip)) {
            auto ws = _ipWsClientMap[auth->ip].lock();
            if (ws) {
                ws->close();
            }
            spdlog::info("{} conflict, old connection kicked out", INet::ipU32ToString(auth->ip));
        }

        spdlog::info("{} connected", INet::ipU32ToString(auth->ip));
        _ipWsClientMap[auth->ip] = webSocket;
        _wsIpClientMap[webSocket] = auth->ip;
        return;
    }

    if (msg->str.front() == TYPE_DHCP) {
        if (!_subnet) {
            return;
        }

        if (msg->str.size() < sizeof(DHCPHeader)) {
            return;
        }

        DHCPHeader *dhcp = (DHCPHeader *)msg->str.data();
        if (std::abs(unixTimeStamp() - (int64_t)ntohll(dhcp->timestamp)) > 30) {
            return;
        }

        if (!dhcp->checkHash(_password)) {
            return;
        }

        if (!canUseThisAddress(dhcp->cidr)) {
            strcpy(dhcp->cidr, nextClientAddress().data());
        }

        auto ws = webSocket.lock();
        if (ws) {
            ws->sendBinary(msg->str);
        }
    }
}

void Server::handleCloseMessage(WebSocket webSocket, const WebSocketMessagePtr &msg) {
    auto it = _wsIpClientMap.find(webSocket);
    if (it == _wsIpClientMap.end()) {
        return;
    }
    if (webSocket.lock() != _ipWsClientMap[it->second].lock()) {
        return;
    }
    spdlog::info("{} disconnected", INet::ipU32ToString(it->second));
    _ipWsClientMap.erase(it->second);
    _wsIpClientMap.erase(webSocket);
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
    case ix::WebSocketMessageType::Close:
        handleCloseMessage(webSocket, msg);
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

bool Server::canUseThisAddress(std::string cidr) {
    std::size_t pos;
    uint32_t ip, subnet;

    try {
        pos = cidr.find("/");
        ip = ntohl(INet::ipStringToU32(cidr.substr(0, pos)));
        subnet = std::stoi(cidr.substr(pos + 1));
    } catch (...) {
        return false;
    }

    if (subnet != _subnet) {
        return false;
    }

    if ((ip & (~((1 << (32 - _subnet)) - 1))) != _network) {
        return false;
    }

    if (_ipWsClientMap.contains(htonl(ip))) {
        return false;
    }

    return true;
}

std::string Server::nextClientAddress() {
    uint32_t nextClientTunIp = _lastClientTunIp;
    uint32_t mask = (1 << (32 - _subnet)) - 1;

    bool no_address_available = false;
    while (true) {
        nextClientTunIp += 1;
        nextClientTunIp &= mask;

        if (nextClientTunIp == 0) {
            continue;
        }

        if (nextClientTunIp == mask) {
            if (no_address_available) {
                spdlog::critical("no address available");
                exit(1);
            }
            no_address_available = true;
            continue;
        }

        if (_ipWsClientMap.contains(htonl(_network | nextClientTunIp))) {
            continue;
        }

        _lastClientTunIp = _network | nextClientTunIp;
        break;
    }

    std::string cidr = INet::ipU32ToString(htonl(_lastClientTunIp));
    cidr += "/";
    cidr += std::to_string(_subnet);
    return cidr;
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

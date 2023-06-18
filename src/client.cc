// SPDX-License-Identifier: MIT
#include "client.h"
#include "util.h"
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <ixwebsocket/IXWebSocketSendData.h>
#include <linux/if_tun.h>
#include <map>
#include <net/if.h>
#include <net/route.h>
#include <spdlog/spdlog.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace candy {

void Client::sendHandshakeMsg() {
    AuthHeader buffer;

    buffer.type = TYPE_AUTH;
    buffer.tunIp = inet_addr(_tunIp.data());

    buffer.timestamp = htonll(unixTimeStamp());
    buffer.calculateHash(_password);

    auto data = ix::IXWebSocketSendData((const char *)&buffer, sizeof(buffer));
    _wsClient->sendBinary(data);
}

void Client::handleServerMessage(const WebSocketMessagePtr &msg) {
    if (msg->str.size() < sizeof(ForwardHeader)) {
        return;
    }
    ForwardHeader *forward = (ForwardHeader *)msg->str.data();
    if (forward->type != TYPE_FORWARD) {
        return;
    }

    write(_tunFd, &forward->iph, msg->str.size() - 1);
}

void Client::handleCloseMessage(const WebSocketMessagePtr &msg) {
    spdlog::info("{0}", msg->closeInfo.reason);
    exit(1);
}

void Client::handleErrorMessage(const WebSocketMessagePtr &msg) {
    spdlog::critical("{0}", msg->errorInfo.reason);
    exit(1);
}

void Client::handleMessage(const WebSocketMessagePtr &msg) {
    switch (msg->type) {
    case ix::WebSocketMessageType::Message:
        handleServerMessage(msg);
        break;
    case ix::WebSocketMessageType::Open:
        sendHandshakeMsg();
        break;
    case ix::WebSocketMessageType::Close:
        handleCloseMessage(msg);
        break;
    case ix::WebSocketMessageType::Error:
        handleErrorMessage(msg);
        break;
    default:
        break;
    }
}

int Client::setWebsocketServer(std::string ws) {
    using namespace std::placeholders;

    candy::Uri uri(ws);
    if (!uri.isValid()) {
        spdlog::critical("websocket uri is invalid. ws: {0}", ws);
        exit(1);
    }

    _wsClient = std::make_shared<ix::WebSocket>();
    _wsClient->setUrl(ws);
    _wsClient->setPingInterval(30);
    _wsClient->disablePerMessageDeflate();
    _wsClient->setOnMessageCallback(std::bind(&Client::handleMessage, this, _1));

    return 0;
}

int Client::setPassword(std::string password) {
    _password = password;
    return 0;
}

int Client::setTun(std::string tun, std::string name) {
    std::string interfaceName = "candy";
    if (!name.empty()) {
        interfaceName += "-";
        interfaceName += name;
    }

    std::size_t pos = tun.find("/");
    _tunIp = tun.substr(0, pos);
    _tunMask = CIDR::networkPrefixToSubnetMask(tun.substr(pos + 1));

    if (_tunIp.empty() || _tunMask.empty()) {
        spdlog::critical("please set client tun ip");
        exit(1);
    }

    _tunFd = open("/dev/net/tun", O_RDWR);
    if (_tunFd < 0) {
        spdlog::critical("open /dev/net/tun failed");
        exit(1);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, interfaceName.data(), IFNAMSIZ);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(_tunFd, TUNSETIFF, &ifr) == -1) {
        spdlog::critical("create tun failed", _tunFd);
        exit(1);
    }

    struct sockaddr_in *addr;
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;

    int sock = socket(addr->sin_family, SOCK_DGRAM, 0);
    if (sock == -1) {
        spdlog::critical("create socket failed");
        exit(1);
    }

    addr->sin_addr.s_addr = inet_addr(_tunIp.data());
    if (ioctl(sock, SIOCSIFADDR, (caddr_t)&ifr) == -1) {
        spdlog::critical("set ip address failed", sock);
        exit(1);
    }

    addr->sin_addr.s_addr = inet_addr(_tunMask.data());
    if (ioctl(sock, SIOCSIFNETMASK, (caddr_t)&ifr) == -1) {
        spdlog::critical("set subnet mask failed. mask: {0}", _tunMask);
        exit(1);
    }

    ifr.ifr_mtu = Client::MTU;
    if (ioctl(sock, SIOCSIFMTU, (caddr_t)&ifr) == -1) {
        spdlog::critical("set mtu failed");
        exit(1);
    }

    ifr.ifr_ifru.ifru_flags |= IFF_UP;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
        spdlog::critical("up interface failed");
        exit(1);
    }

    struct rtentry route;
    memset(&route, 0, sizeof(route));

    addr = (struct sockaddr_in *)&route.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(_tunIp.data());

    addr = (struct sockaddr_in *)&route.rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(_tunMask.data());

    route.rt_dev = interfaceName.data();
    route.rt_flags = RTF_UP | RTF_HOST;
    if (ioctl(sock, SIOCADDRT, &route) == -1) {
        spdlog::critical("set route failed");
        exit(1);
    }

    close(sock);

    disableIPv6(interfaceName);

    return 0;
}

int Client::start() {
    _wsClient->start();

    ssize_t len;
    constexpr int fix_header_len = sizeof(ForwardHeader::type);
    std::array<char, Client::MTU + fix_header_len> buffer;
    ForwardHeader *forward = (ForwardHeader *)&buffer;
    forward->type = TYPE_FORWARD;
    while ((len = read(_tunFd, buffer.begin() + fix_header_len, buffer.size() - fix_header_len)) > 0) {
        if ((unsigned long)len < sizeof(ForwardHeader)) {
            continue;
        }
        if (forward->iph.version != 4) {
            continue;
        }
        auto data = ix::IXWebSocketSendData(buffer.data(), len + fix_header_len);
        _wsClient->sendBinary(data);
    }

    return 0;
}

void Client::stop() {
    close(_tunFd);
    _wsClient->stop();
}

void Client::disableIPv6(std::string interface) {
    std::string config = "/proc/sys/net/ipv6/conf/" + interface + "/disable_ipv6";
    int fd = open(config.data(), O_WRONLY);
    if (fd < 0) {
        spdlog::debug("Opening interface IPv6 configuration file failed");
        return;
    }

    if (write(fd, "1", 1) < 0) {
        spdlog::debug("Disable current interface IPv6 failed");
    }

    close(fd);
}

}; // namespace candy

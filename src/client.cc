// SPDX-License-Identifier: MIT
#include "client.h"
#include "util.h"
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
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

void Client::sendAuthMessage() {
    AuthHeader buffer;
    buffer.type = TYPE_AUTH;
    buffer.ip = inet_addr(_tunIp.data());
    buffer.timestamp = htonll(unixTimeStamp());
    buffer.calculateHash(_password);
    auto data = ix::IXWebSocketSendData((const char *)&buffer, sizeof(buffer));
    _wsClient->sendBinary(data);
}

void Client::sendDHCPMessage() {
    DHCPHeader buffer;
    buffer.type = TYPE_DHCP;
    buffer.timestamp = htonll(unixTimeStamp());
    buffer.calculateHash(_password);
    strcpy(buffer.cidr, getLastDHCPAddress().data());
    auto data = ix::IXWebSocketSendData((const char *)&buffer, sizeof(buffer));
    _wsClient->sendBinary(data);
}

void Client::handleServerMessage(const WebSocketMessagePtr &msg) {
    if (msg->str.size() < sizeof(ForwardHeader)) {
        return;
    }

    if (msg->str.front() == TYPE_FORWARD) {
        ForwardHeader *forward = (ForwardHeader *)msg->str.data();
        size_t size = msg->str.size() - sizeof(ForwardHeader::type);
        if (write(_tunFd, &forward->iph, size) != (ssize_t)size) {
            spdlog::warn("data not fully written to TUN device");
            return;
        }
    }

    if (msg->str.front() == TYPE_DHCP) {
        DHCPHeader *dhcp = (DHCPHeader *)msg->str.data();
        saveDHCPAddress(dhcp->cidr);
        initTun(dhcp->cidr, _DHCPInterfaceName);
        sendAuthMessage();
    }
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
        if (_useDHCP) {
            sendDHCPMessage();
        } else {
            sendAuthMessage();
        }
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
    if (tun.empty()) {
        _DHCPInterfaceName = name;
        _useDHCP = true;
        return 0;
    }
    return initTun(tun, name);
}

std::string Client::getInterfaceName(std::string name) {
    std::string interfaceName = "candy";
    if (!name.empty()) {
        interfaceName += "-";
        interfaceName += name;
    }
    return interfaceName;
}

int Client::initTun(std::string tun, std::string name) {
    std::string interfaceName = getInterfaceName(name);
    std::size_t pos = tun.find("/");
    _tunIp = tun.substr(0, pos);
    _tunMask = CIDR::networkPrefixToSubnetMaskString(tun.substr(pos + 1));

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
    ssize_t len;
    constexpr int fix_header_len = sizeof(ForwardHeader::type);
    std::array<char, Client::MTU + fix_header_len> buffer;
    ForwardHeader *forward = (ForwardHeader *)&buffer;
    forward->type = TYPE_FORWARD;

    _wsClient->start();
    while (_tunFd == 0) {
        sleep(1);
    }

    while (true) {
        len = read(_tunFd, buffer.begin() + fix_header_len, buffer.size() - fix_header_len);
        if (len <= 0) {
            break;
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
        spdlog::warn("Opening interface IPv6 configuration file failed");
        return;
    }

    if (write(fd, "1", 1) < 0) {
        spdlog::warn("Disable current interface IPv6 failed");
    }

    close(fd);
}
std::string Client::getDHCPConfigFile() {
    std::string dhcpConfigFile = "/var/lib/candy/dhcp/" + getInterfaceName(_DHCPInterfaceName);
    return dhcpConfigFile;
}

int Client::saveDHCPAddress(std::string cidr) {
    std::string dhcpConfigFile = getDHCPConfigFile();
    std::filesystem::create_directories(std::filesystem::path(dhcpConfigFile).parent_path());
    std::ofstream ofs(dhcpConfigFile);
    if (ofs.is_open()) {
        ofs << cidr;
        ofs.close();
    }
    return 0;
}

std::string Client::getLastDHCPAddress() {
    std::string dhcpConfigFile = getDHCPConfigFile();
    std::ifstream ifs(dhcpConfigFile);
    if (!ifs.is_open()) {
        return "";
    }
    std::stringstream ss;
    ss << ifs.rdbuf();
    ifs.close();
    return ss.str();
}

}; // namespace candy

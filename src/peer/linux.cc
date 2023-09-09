// SPDX-License-Identifier: MIT
#if defined(__linux__) || defined(__linux)

#include "peer/peer.h"
#include "utility/address.h"
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <spdlog/spdlog.h>
#include <sys/socket.h>

namespace Candy {

UdpHolder::UdpHolder() {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        spdlog::error("create udp socket failed: {}", strerror(errno));
        return;
    }
    this->socket = fd;
    return;
}

UdpHolder::~UdpHolder() {
    int fd = std::any_cast<int>(this->socket);
    if (fd) {
        close(fd);
        this->socket = 0;
    }
    return;
}

size_t UdpHolder::read(UdpMessage &message) {
    int fd = std::any_cast<int>(this->socket);
    if (!fd) {
        spdlog::error("udp socket not initialized successfully");
        return -1;
    }

    struct timeval timeout = {.tv_sec = 1};

    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);

    int ret = select(fd + 1, &set, NULL, NULL, &timeout);
    if (ret == 0) {
        return 0;
    }
    if (ret < 0) {
        spdlog::error("udp socket select failed: error {}", ret);
        return -1;
    }

    char buffer[1500];
    struct sockaddr_in from;
    socklen_t addr_len = sizeof(from);
    bzero(&from, sizeof(from));

    ssize_t len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &addr_len);
    if (len == -1) {
        spdlog::error("udp socket read failed: {}", strerror(errno));
        return -1;
    }
    message.buffer.assign(buffer, len);
    message.ip = Address::netToHost(from.sin_addr.s_addr);
    message.port = Address::netToHost(from.sin_port);
    return len;
}

size_t UdpHolder::write(const UdpMessage &message) {
    int fd = std::any_cast<int>(this->socket);
    if (!fd) {
        spdlog::error("socket not initialized successfully");
        return -1;
    }
    struct sockaddr_in to;
    bzero(&to, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = Address::hostToNet(message.ip);
    to.sin_port = Address::hostToNet(message.port);
    size_t len = sendto(fd, message.buffer.c_str(), message.buffer.length(), 0, (struct sockaddr *)&to, sizeof(to));
    if (len != message.buffer.length()) {
        spdlog::warn("udp socket write failed: {}", strerror(errno));
        return -1;
    }
    return len;
}

}; // namespace Candy

#endif

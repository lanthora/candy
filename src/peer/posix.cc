// SPDX-License-Identifier: MIT
#if defined(__linux__) || defined(__linux) || defined(__APPLE__) || defined(__MACH__)

#include "peer/peer.h"
#include "utility/address.h"
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <spdlog/spdlog.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

namespace Candy {

UdpHolder::UdpHolder() {
    this->socket = 0;
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

int UdpHolder::init() {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        spdlog::error("create udp socket failed: {}", strerror(errno));
        return -1;
    }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(this->port);

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        spdlog::error("udp socket bind failed: {}", strerror(errno));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        spdlog::error("get udp socket flags failed: {}", strerror(errno));
        return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0) {
        spdlog::error("set non-blocking udp socket failed: {}", strerror(errno));
        return -1;
    }
    this->socket = fd;
    return 0;
}

uint16_t UdpHolder::getBindPort() {
    if (this->port) {
        return this->port;
    }

    int fd = std::any_cast<int>(this->socket);
    if (fd) {
        struct sockaddr_in local;
        socklen_t len = sizeof(local);
        memset(&local, 0, sizeof(local));
        if (!getsockname(fd, (struct sockaddr *)&local, &len)) {
            this->port = ntohs(local.sin_port);
            return this->port;
        }
    }
    return 0;
}

uint32_t UdpHolder::getDefaultIP() {
    if (this->ip) {
        return this->ip;
    }
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 0;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = 0x12345678;
    addr.sin_family = AF_INET;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(fd);
        return 0;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len)) {
        close(fd);
        return 0;
    }
    this->ip = ntohl(addr.sin_addr.s_addr);
    close(fd);
    return this->ip;
}

size_t UdpHolder::read(UdpMessage &message) {
    int fd = std::any_cast<int>(this->socket);
    if (!fd) {
        spdlog::error("udp socket not initialized successfully");
        return -1;
    }

    char buffer[1500];
    struct sockaddr_in from;
    socklen_t addr_len = sizeof(from);
    memset(&from, 0, sizeof(from));

    ssize_t len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &addr_len);
    if (len >= 0) {
        message.buffer.assign(buffer, len);
        message.ip = Address::netToHost(from.sin_addr.s_addr);
        message.port = Address::netToHost(from.sin_port);
        return len;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        struct timeval timeout = {.tv_sec = 1};

        fd_set set;
        FD_ZERO(&set);
        FD_SET(fd, &set);

        select(fd + 1, &set, NULL, NULL, &timeout);
        return 0;
    }
    spdlog::error("udp socket read failed: {}", strerror(errno));
    return -1;
}

size_t UdpHolder::write(const UdpMessage &message) {
    if (message.buffer.empty()) {
        spdlog::debug("udp send empty message");
        return -1;
    }

    int fd = std::any_cast<int>(this->socket);
    if (!fd) {
        spdlog::error("socket not initialized successfully");
        return -1;
    }
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = Address::hostToNet(message.ip);
    to.sin_port = Address::hostToNet(message.port);
    size_t len = sendto(fd, message.buffer.c_str(), message.buffer.length(), 0, (struct sockaddr *)&to, sizeof(to));
    if (len != message.buffer.length()) {
        spdlog::debug("udp socket write failed: {}", strerror(errno));
        return -1;
    }
    return len;
}

} // namespace Candy

#endif

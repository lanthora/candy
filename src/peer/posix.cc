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
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        spdlog::error("create udp socket failed: {}", strerror(errno));
        return;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        spdlog::error("get udp socket flags failed: {}", strerror(errno));
        return;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0) {
        spdlog::error("set non-blocking udp socket failed: {}", strerror(errno));
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

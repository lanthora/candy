// SPDX-License-Identifier: MIT
#if defined(_WIN32) || defined(_WIN64)

#include "peer/peer.h"
#include "utility/address.h"
#include <spdlog/spdlog.h>
#include <string.h>
#include <winsock2.h>

namespace Candy {

UdpHolder::UdpHolder() {
    this->socket = INVALID_SOCKET;
    SOCKET winsock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (winsock == INVALID_SOCKET) {
        spdlog::error("create udp socket failed: {}", WSAGetLastError());
        return;
    }
    // set non-blocking
    u_long mode = 1;
    if (ioctlsocket(winsock, FIONBIO, &mode) != NO_ERROR) {
        closesocket(winsock);
        spdlog::error("set non-blocking failed: {}", WSAGetLastError());
        return;
    }
    struct sockaddr_in local_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = 0;
    if (bind(winsock, (struct sockaddr *)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        closesocket(winsock);
        spdlog::error("socket binding failed: %d\n", WSAGetLastError());
        return;
    }
    this->socket = winsock;
}

UdpHolder::~UdpHolder() {
    SOCKET winsock = std::any_cast<SOCKET>(this->socket);
    if (winsock != INVALID_SOCKET) {
        closesocket(winsock);
        this->socket = INVALID_SOCKET;
    }
    return;
}

size_t UdpHolder::read(UdpMessage &message) {
    SOCKET winsock = std::any_cast<SOCKET>(this->socket);
    if (winsock == INVALID_SOCKET) {
        spdlog::error("udp socket not initialized successfully");
        return -1;
    }
    char buffer[1500];
    struct sockaddr_in from;
    int addr_len = sizeof(from);
    memset(&from, 0, sizeof(from));

    int len = recvfrom(winsock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &addr_len);
    if (len != SOCKET_ERROR) {
        message.buffer.assign(buffer, len);
        message.ip = Address::netToHost((uint32_t)from.sin_addr.s_addr);
        message.port = Address::netToHost((uint16_t)from.sin_port);
        return len;
    }
    int error = WSAGetLastError();
    if (error == WSAEWOULDBLOCK) {
        struct timeval timeout = {.tv_sec = 1};
        fd_set set;
        FD_ZERO(&set);
        FD_SET(winsock, &set);
        select(0, &set, NULL, NULL, &timeout);
        return 0;
    }
    spdlog::error("udp socket read failed: {}", error);
    return -1;
}

size_t UdpHolder::write(const UdpMessage &message) {
    SOCKET winsock = std::any_cast<SOCKET>(this->socket);
    if (winsock == INVALID_SOCKET) {
        spdlog::error("udp socket not initialized successfully");
        return -1;
    }

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = Address::hostToNet(message.ip);
    to.sin_port = Address::hostToNet(message.port);
    int len = sendto(winsock, message.buffer.c_str(), message.buffer.length(), 0, (struct sockaddr *)&to, sizeof(to));
    if (len == SOCKET_ERROR) {
        spdlog::warn("udp socket write failed: {}", WSAGetLastError());
        return -1;
    }
    return len;
}

} // namespace Candy

#endif

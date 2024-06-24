// SPDX-License-Identifier: MIT
#include "utility/time.h"
#include "utility/address.h"
#include "utility/byteswap.h"
#include <bit>
#include <chrono>
#include <limits>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>
#include <string>

namespace {

struct ntp_packet {
    uint8_t li_vn_mode = 0x23;

    uint8_t stratum;
    uint8_t poll;
    uint8_t precision;

    uint32_t rootDelay;
    uint32_t rootDispersion;
    uint32_t refId;

    uint32_t refTm_s;
    uint32_t refTm_f;

    uint32_t origTm_s;
    uint32_t origTm_f;

    uint32_t rxTm_s;
    uint32_t rxTm_f;

    uint32_t txTm_s;
    uint32_t txTm_f;
};

} // namespace

#if defined(__linux__) || defined(__linux) || defined(__APPLE__) || defined(__MACH__)
#include <netdb.h>
#include <sys/select.h>
#include <unistd.h>

static int64_t ntpTime() {
    struct addrinfo hints = {}, *info = NULL;
    int sockfd = 0, len = 0;
    struct ntp_packet packet = {};
    int64_t retval = 0;
    struct timeval timeout = {.tv_sec = 1};
    fd_set set;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo("pool.ntp.org", "123", &hints, &info)) {
        spdlog::warn("resolve ntp server domain name failed");
        goto out;
    }

    sockfd = socket(info->ai_family, info->ai_socktype, IPPROTO_UDP);
    if (sockfd == -1) {
        spdlog::warn("create udp socket failed");
        goto out;
    }

    if (connect(sockfd, info->ai_addr, info->ai_addrlen)) {
        spdlog::warn("connect ntp server failed");
        goto out;
    }

    FD_ZERO(&set);
    FD_SET(sockfd, &set);

    len = send(sockfd, &packet, sizeof(packet), 0);
    if (len == -1) {
        spdlog::warn("send ntp request failed");
        goto out;
    }

    len = select(sockfd + 1, &set, NULL, NULL, &timeout);
    if (len == 0) {
        goto out;
    }
    if (len < 0) {
        spdlog::warn("ntp client select failed");
        goto out;
    }

    len = recv(sockfd, &packet, sizeof(packet), 0);
    if (len == -1) {
        spdlog::warn("recv ntp response failed");
        goto out;
    }

    if (len != sizeof(packet) || (packet.li_vn_mode & 0x07) != 4) {
        spdlog::warn("invalid ntp response");
        goto out;
    }

    retval = (int64_t)(Candy::Address::netToHost(packet.rxTm_s));
    if (retval == 0) {
        spdlog::warn("invalid ntp response buffer: {:n}", spdlog::to_hex(std::string((char *)(&packet), sizeof(packet))));
        goto out;
    }

    // Fix ntp 2036 problem
    if (!(retval & 0x80000000)) {
        retval += UINT32_MAX;
    }

    retval -= 2208988800U;

out:
    if (info) {
        freeaddrinfo(info);
    }
    if (sockfd) {
        close(sockfd);
    }
    return retval;
}
#else

#include <ws2tcpip.h>

static int64_t ntpTime() {
    struct addrinfo hints = {}, *info = NULL;
    SOCKET winsock = INVALID_SOCKET;
    int len = 0;
    struct ntp_packet packet = {};
    int64_t retval = 0;
    struct timeval timeout = {.tv_sec = 1};
    fd_set set;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo("pool.ntp.org", "123", &hints, &info)) {
        spdlog::warn("resolve ntp server domain name failed");
        goto out;
    }

    winsock = socket(info->ai_family, info->ai_socktype, IPPROTO_UDP);
    if (winsock == INVALID_SOCKET) {
        spdlog::warn("create udp socket failed");
        goto out;
    }

    if (connect(winsock, info->ai_addr, info->ai_addrlen) == SOCKET_ERROR) {
        spdlog::warn("connect ntp server failed");
        goto out;
    }

    FD_ZERO(&set);
    FD_SET(winsock, &set);

    len = send(winsock, (const char *)&packet, sizeof(packet), 0);
    if (len == SOCKET_ERROR) {
        spdlog::warn("send ntp request failed");
        goto out;
    }

    len = select(0, &set, NULL, NULL, &timeout);
    if (len == 0) {
        goto out;
    }
    if (len < 0) {
        spdlog::warn("ntp client select failed");
        goto out;
    }

    len = recv(winsock, (char *)&packet, sizeof(packet), 0);
    if (len == -1) {
        spdlog::warn("recv ntp response failed");
        goto out;
    }

    if (len != sizeof(packet) || (packet.li_vn_mode & 0x07) != 4) {
        spdlog::warn("invalid ntp response");
        goto out;
    }

    retval = (int64_t)(Candy::Address::netToHost(packet.rxTm_s));
    if (retval == 0) {
        spdlog::warn("invalid ntp response buffer: {:n}", spdlog::to_hex(std::string((char *)(&packet), sizeof(packet))));
        goto out;
    }

    // Fix ntp 2036 problem
    if (!(retval & 0x80000000)) {
        retval += UINT32_MAX;
    }

    retval -= 2208988800U;

out:
    if (info) {
        freeaddrinfo(info);
    }
    if (winsock != INVALID_SOCKET) {
        closesocket(winsock);
    }
    return retval;
}
#endif

namespace Candy {

bool Time::useSystemTime = false;

int64_t Time::unixTime() {
    using namespace std::chrono;

    int64_t sysTime;
    int64_t netTime;

    if (useSystemTime) {
        sysTime = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
        return sysTime;
    }

    netTime = 0;
    for (int i = 0; i < 3 && netTime == 0; ++i) {
        if (i > 0) {
            spdlog::debug("get time from ntp server failed: retry {}", i);
        }
        netTime = ntpTime();
    }

    sysTime = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    if (std::abs(netTime - sysTime) < 3) {
        useSystemTime = true;
        spdlog::debug("system time is accurate");
    }
    if (netTime) {
        return netTime;
    }

    spdlog::warn("request network time failed");
    return sysTime;
}

int64_t Time::bootTime() {
    using namespace std::chrono;
    auto now = steady_clock::now();
    return duration_cast<milliseconds>(now.time_since_epoch()).count();
}

int64_t Time::hostToNet(int64_t host) {
    if (std::endian::native == std::endian::little) {
        return byteswap(host);
    }
    return host;
}

int64_t Time::netToHost(int64_t net) {
    return Time::hostToNet(net);
}

int32_t Time::hostToNet(int32_t host) {
    if (std::endian::native == std::endian::little) {
        return byteswap(host);
    }
    return host;
}

int32_t Time::netToHost(int32_t net) {
    return Time::hostToNet(net);
}

} // namespace Candy

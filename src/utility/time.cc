// SPDX-License-Identifier: MIT
#include "utility/time.h"
#include "utility/address.h"
#include <bit>
#include <chrono>
#include <spdlog/spdlog.h>

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
#include <limits>
#include <netdb.h>

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

    FD_ZERO(&set);
    FD_SET(sockfd, &set);

    len = sendto(sockfd, &packet, sizeof(packet), 0, info->ai_addr, info->ai_addrlen);
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
// TODO(windows): 从网络上获取当前时间戳
static int64_t ntpTime() {
    return 0;
}

#endif

namespace Candy {

int64_t Time::unixTime() {
    int64_t timestamp = 0;
    for (int i = 0; i < 3 && timestamp == 0; ++i) {
        if (i > 0) {
            spdlog::debug("get time from ntp server failed: retry {}", i);
        }
        timestamp = ntpTime();
    }

    if (timestamp) {
        return timestamp;
    }

    using namespace std::chrono;
    spdlog::warn("unable to get the time from the network, please make sure the local time is accurate");
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

int64_t Time::hostToNet(int64_t host) {
    if (std::endian::native == std::endian::little) {
        return std::byteswap(host);
    }
    return host;
}

int64_t Time::netToHost(int64_t net) {
    return Time::hostToNet(net);
}

} // namespace Candy

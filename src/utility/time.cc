// SPDX-License-Identifier: MIT
#include "utility/time.h"
#include "utility/address.h"
#include "utility/byteswap.h"
#include <Poco/Net/DatagramSocket.h>
#include <Poco/Platform.h>
#include <bit>
#include <chrono>
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

#include <unistd.h>

static int64_t ntpTime() {
    Poco::Net::DatagramSocket socket;
    socket.connect(Poco::Net::SocketAddress("pool.ntp.org", 123));

    struct ntp_packet packet = {};
    socket.sendBytes(&packet, sizeof(packet));

    socket.setReceiveTimeout(Poco::Timespan(1, 0));
    int len = socket.receiveBytes(&packet, sizeof(packet));

    if (len != sizeof(packet) || (packet.li_vn_mode & 0x07) != 4) {
        spdlog::warn("invalid ntp response");
        return 0;
    }

    int64_t retval = (int64_t)(Candy::Address::netToHost(packet.rxTm_s));
    if (retval == 0) {
        spdlog::warn("invalid ntp response buffer: {:n}", spdlog::to_hex(std::string((char *)(&packet), sizeof(packet))));
        return 0;
    }

    // Fix ntp 2036 problem
    if (!(retval & 0x80000000)) {
        retval += UINT32_MAX;
    }

    retval -= 2208988800U;
    return retval;
}

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

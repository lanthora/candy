// SPDX-License-Identifier: MIT
#include "utility/time.h"
#include "core/net.h"
#include <Poco/Net/DatagramSocket.h>
#include <chrono>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>
#include <string>
#include <unistd.h>

namespace Candy {

bool useSystemTime = false;
std::string ntpServer;

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

int64_t ntpTime() {
    try {
        Poco::Net::DatagramSocket socket;
        socket.connect(Poco::Net::SocketAddress(ntpServer, 123));

        struct ntp_packet packet = {};
        socket.sendBytes(&packet, sizeof(packet));

        socket.setReceiveTimeout(Poco::Timespan(1, 0));
        int len = socket.receiveBytes(&packet, sizeof(packet));

        if (len != sizeof(packet) || (packet.li_vn_mode & 0x07) != 4) {
            spdlog::warn("invalid ntp response");
            return 0;
        }

        int64_t retval = (int64_t)(ntoh(packet.rxTm_s));
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
    } catch (std::exception &e) {
        spdlog::debug("ntp time failed: {}", e.what());
        return 0;
    }
}

int64_t unixTime() {
    using namespace std::chrono;

    int64_t sysTime;
    int64_t netTime;

    if (useSystemTime || ntpServer.empty()) {
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

int64_t bootTime() {
    using namespace std::chrono;
    auto now = steady_clock::now();
    return duration_cast<milliseconds>(now.time_since_epoch()).count();
}

} // namespace Candy

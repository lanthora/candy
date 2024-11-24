// SPDX-License-Identifier: MIT
#include "utils/time.h"
#include "core/net.h"
#include <Poco/Net/DatagramSocket.h>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>
#include <sstream>
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
        spdlog::debug("use system time");
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

std::string getCurrentTimeWithMillis() {
    // 获取当前时间点（精确到纳秒）
    auto now = std::chrono::system_clock::now();

    // 将时间点转换为time_point<system_clock, milliseconds>
    auto ms_tp = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
    auto epoch = ms_tp.time_since_epoch();
    auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();

    // 分离秒和毫秒部分
    std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm *ptm = std::localtime(&now_time_t);

    // 格式化输出时间和毫秒
    std::ostringstream oss;
    oss << std::put_time(ptm, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << (value % 1000);

    return oss.str();
}

} // namespace Candy

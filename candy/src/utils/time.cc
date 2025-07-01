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

namespace candy {

int64_t unixTime() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

int64_t bootTime() {
    using namespace std::chrono;
    auto now = steady_clock::now();
    return duration_cast<milliseconds>(now.time_since_epoch()).count();
}

std::string getCurrentTimeWithMillis() {
    auto now = std::chrono::system_clock::now();

    auto ms_tp = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
    auto epoch = ms_tp.time_since_epoch();
    auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();

    std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm *ptm = std::localtime(&now_time_t);

    std::ostringstream oss;
    oss << std::put_time(ptm, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << (value % 1000);

    return oss.str();
}

} // namespace candy

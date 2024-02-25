// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILITY_TIME_H
#define CANDY_UTILITY_TIME_H

#include <cstdint>

namespace Candy {

class Time {
public:
    static void reset();
    // 秒级的 Unix 时间戳,优先使用从互联网获取的时间
    static int64_t unixTime();
    // 毫秒级别的系统启动时间戳,不受时间回滚影响,用于计算网络延迟
    static int64_t bootTime();
    static int64_t hostToNet(int64_t host);
    static int64_t netToHost(int64_t net);
    static int32_t hostToNet(int32_t host);
    static int32_t netToHost(int32_t net);

private:
    static bool useSystemTime;
};

} // namespace Candy

#endif

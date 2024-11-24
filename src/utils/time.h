// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILS_TIME_H
#define CANDY_UTILS_TIME_H

#include <cstdint>
#include <string>

namespace Candy {

extern bool useSystemTime;
extern std::string ntpServer;

int64_t unixTime();
int64_t bootTime();

std::string getCurrentTimeWithMillis();

} // namespace Candy

#endif

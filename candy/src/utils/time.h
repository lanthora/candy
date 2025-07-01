// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILS_TIME_H
#define CANDY_UTILS_TIME_H

#include <cstdint>
#include <string>

namespace candy {

int64_t unixTime();
int64_t bootTime();

std::string getCurrentTimeWithMillis();

} // namespace candy

#endif

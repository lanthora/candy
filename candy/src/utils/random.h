// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILS_RANDOM_H
#define CANDY_UTILS_RANDOM_H

#include <cstdint>
#include <string>

namespace candy {

uint32_t randomUint32();
std::string randomHexString(int length);

} // namespace candy

#endif

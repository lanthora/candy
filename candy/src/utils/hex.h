// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILS_HEX_H
#define CANDY_UTILS_HEX_H

#include <iomanip>
#include <sstream>
#include <string>

namespace candy {

inline std::string to_hex(const std::string &buffer) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buffer) {
        oss << std::setw(2) << static_cast<int>(c);
    }
    return oss.str();
}

} // namespace candy

#endif

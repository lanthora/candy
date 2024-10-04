// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILITY_BYTESWAP_H
#define CANDY_UTILITY_BYTESWAP_H

#include <cstddef>
#include <cstdint>

namespace Candy {
template <typename T> static inline T byteswap(const T &input) {
    T output(0);
    const std::size_t size = sizeof(input);
    const uint8_t *in = reinterpret_cast<const uint8_t *>(&input);
    uint8_t *out = reinterpret_cast<uint8_t *>(&output);

    for (std::size_t i = 0; i < size; i++) {
        out[i] = in[size - i - 1];
    }

    return output;
}
} // namespace Candy

#endif

// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILITY_BYTESWAP_H
#define CANDY_UTILITY_BYTESWAP_H

namespace Candy {
template <typename T> static inline T byteswap(const T &input) {
    T output(0);
    const std::size_t size = sizeof(input);
    uint8_t *data = reinterpret_cast<uint8_t *>(&output);

    for (std::size_t i = 0; i < size; i++) {
        data[i] = input >> ((size - i - 1) * 8);
    }

    return output;
}
} // namespace Candy

#endif

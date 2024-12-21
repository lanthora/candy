// SPDX-License-Identifier: MIT
#include "utility/random.h"
#include <iostream>
#include <random>
#include <sstream>

namespace {

uint32_t randomUint32() {
    std::random_device device;
    std::mt19937 engine(device());
    std::uniform_int_distribution<uint32_t> distrib;
    return distrib(engine);
}

int randomHex() {
    std::random_device device;
    std::mt19937 engine(device());
    std::uniform_int_distribution<int> distrib(0, 15);
    return distrib(engine);
}
} // namespace

namespace Candy {
std::string randomHexString(int length) {
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        ss << std::hex << randomHex();
    }
    return ss.str();
}

} // namespace Candy

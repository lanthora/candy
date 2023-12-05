#include "utility/random.h"
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>

namespace Candy {

int randomHex() {
    std::random_device device;
    std::mt19937 engine(device());
    std::uniform_int_distribution<int> distrib(0, 15);
    return distrib(engine);
}

std::string randomHexString(int length) {
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        ss << std::hex << randomHex();
    }
    return ss.str();
}

} // namespace Candy

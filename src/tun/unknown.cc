// SPDX-License-Identifier: MIT
#include <Poco/Platform.h>

#if POCO_OS != POCO_OS_LINUX && POCO_OS != POCO_OS_MAC_OS_X && POCO_OS != POCO_OS_WINDOWS_NT

#include "tun/tun.h"

namespace Candy {

Tun::Tun() {}

Tun::~Tun() {}

int Tun::setName(const std::string &name) {
    return -1;
}

int Tun::setAddress(const std::string &cidr) {
    return -1;
}

int Tun::setMTU(int mtu) {
    return -1;
}

int Tun::up() {
    return -1;
}

int Tun::down() {
    return -1;
}

int Tun::read(std::string &buffer) {
    return -1;
}

int Tun::write(const std::string &buffer) {
    return -1;
}

int Tun::setSysRtTable(IP4 dst, IP4 mask, IP4 nexthop) {
    return -1;
}

} // namespace Candy

#endif

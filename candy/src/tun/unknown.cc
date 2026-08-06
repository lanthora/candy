// SPDX-License-Identifier: MIT
#include <Poco/Platform.h>

#if POCO_OS != POCO_OS_LINUX && POCO_OS != POCO_OS_MAC_OS_X && POCO_OS != POCO_OS_WINDOWS_NT

#include "tun/tun.h"

namespace candy {

struct Tun::Impl {
    int setName(const std::string &name) {
        return -1;
    }

    int setMTU(int mtu) {
        return -1;
    }

    int up(IP4 ip, IP4 mask) {
        return -1;
    }

    int down() {
        return -1;
    }

    int read(std::string &buffer) {
        return -1;
    }

    int write(const std::string &buffer) {
        return -1;
    }

    int setSysRtTable(IP4 dst, IP4 mask, IP4 nexthop) {
        return -1;
    }
};

Tun::Tun() {
    this->impl = std::make_unique<Impl>();
}

Tun::~Tun() {}

int Tun::setName(const std::string &name) {
    return this->impl->setName(name);
}

int Tun::setMTU(int mtu) {
    return this->impl->setMTU(mtu);
}

int Tun::up() {
    return this->impl->up(this->ip, this->mask);
}

int Tun::down() {
    return this->impl->down();
}

int Tun::read(std::string &buffer) {
    return this->impl->read(buffer);
}

int Tun::write(const std::string &buffer) {
    return this->impl->write(buffer);
}

int Tun::setSysRtTable(IP4 dst, IP4 mask, IP4 nexthop) {
    return this->impl->setSysRtTable(dst, mask, nexthop);
}

} // namespace candy

#endif

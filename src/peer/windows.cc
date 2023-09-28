// SPDX-License-Identifier: MIT
#if defined(_WIN32) || defined(_WIN64)

#include "peer/peer.h"
#include "utility/address.h"
#include <spdlog/spdlog.h>

namespace Candy {

// TODO: 实现对等连接 UDP 收发,这部分与操作系统相关,封装 UDP 操作
UdpHolder::UdpHolder() {
    return;
}

UdpHolder::~UdpHolder() {
    return;
}

size_t UdpHolder::read(UdpMessage &message) {
    return 0;
}

size_t UdpHolder::write(const UdpMessage &message) {
    return 0;
}

} // namespace Candy

#endif

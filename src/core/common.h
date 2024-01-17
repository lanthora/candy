// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_COMMON_H
#define CANDY_CORE_COMMON_H

#if defined(__linux__) || defined(__linux) || defined(__APPLE__) || defined(__MACH__)
#include <netdb.h>
#endif
#if defined(_WIN32) || defined(_WIN64)
#include <ws2tcpip.h>
#endif

namespace Candy {

// 出现内部异常时调用,调整进程退出码为 1, 并模拟产生 SIGTERM, 进程将回收资源并退出
void shutdown();

} // namespace Candy

#endif

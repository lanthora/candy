// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_COMMON_H
#define CANDY_CORE_COMMON_H

#if defined(__linux__) || defined(__linux)
#include <netdb.h>
#define CANDY_SYSTEM "linux"
#endif

#if defined(__APPLE__) || defined(__MACH__)
#include <netdb.h>
#define CANDY_SYSTEM "macos"
#endif

#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
#include <ws2tcpip.h>
#define CANDY_SYSTEM "windows"
#endif

#ifndef CANDY_VERSION
#define CANDY_VERSION "unknown"
#endif

#include "core/client.h"
#include "core/server.h"

namespace Candy {

// 出现内部异常时调用
void shutdown(Client *client);
void shutdown(Server *client);

} // namespace Candy

#endif

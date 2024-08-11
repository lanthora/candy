// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_COMMON_H
#define CANDY_CORE_COMMON_H

#include <Poco/Platform.h>

#if POCO_OS == POCO_OS_LINUX
#include <netdb.h>
#define CANDY_SYSTEM "linux"
#elif POCO_OS == POCO_OS_MAC_OS_X
#include <netdb.h>
#define CANDY_SYSTEM "macos"
#elif POCO_OS == POCO_OS_ANDROID
#include <netdb.h>
#define CANDY_SYSTEM "android"
#elif POCO_OS == POCO_OS_WINDOWS_NT
#include <winsock2.h>
#include <ws2tcpip.h>
#define CANDY_SYSTEM "windows"
#else
#define CANDY_SYSTEM "unknown"
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

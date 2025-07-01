// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_VERSION_H
#define CANDY_CORE_VERSION_H

#include <Poco/Platform.h>

#if POCO_OS == POCO_OS_LINUX
#define CANDY_SYSTEM "linux"
#elif POCO_OS == POCO_OS_MAC_OS_X
#define CANDY_SYSTEM "macos"
#elif POCO_OS == POCO_OS_ANDROID
#define CANDY_SYSTEM "android"
#elif POCO_OS == POCO_OS_WINDOWS_NT
#define CANDY_SYSTEM "windows"
#else
#define CANDY_SYSTEM "unknown"
#endif

#ifndef CANDY_VERSION
#define CANDY_VERSION "unknown"
#endif

#endif

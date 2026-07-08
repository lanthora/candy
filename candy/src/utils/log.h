// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILS_LOG_H
#define CANDY_UTILS_LOG_H

#include <Poco/Logger.h>

namespace candy {

inline Poco::Logger &logger() {
    return Poco::Logger::root();
}

} // namespace candy

#endif

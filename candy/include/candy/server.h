// SPDX-License-Identifier: MIT
#ifndef CANDY_SERVER_H
#define CANDY_SERVER_H

#include <Poco/JSON/Object.h>
#include <string>

namespace candy {
namespace server {

bool run(const Poco::JSON::Object &config);
bool shutdown();

} // namespace server
} // namespace candy

#endif

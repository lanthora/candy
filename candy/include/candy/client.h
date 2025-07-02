// SPDX-License-Identifier: MIT
#ifndef CANDY_CLIENT_H
#define CANDY_CLIENT_H

#include <Poco/JSON/Object.h>
#include <optional>
#include <string>

namespace candy {
namespace client {

bool run(const std::string &id, const Poco::JSON::Object &config);
bool shutdown(const std::string &id);
std::optional<Poco::JSON::Object> status(const std::string &id);

} // namespace client
} // namespace candy

#endif

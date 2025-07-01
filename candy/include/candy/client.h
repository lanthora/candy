// SPDX-License-Identifier: MIT
#ifndef CANDY_CLIENT_H
#define CANDY_CLIENT_H

#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace candy {
namespace client {

bool run(const std::string &id, const nlohmann::json &config);
bool shutdown(const std::string &id);
std::optional<nlohmann::json> status(const std::string &id);

} // namespace client
} // namespace candy

#endif

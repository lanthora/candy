// SPDX-License-Identifier: MIT
#ifndef CANDY_SERVER_H
#define CANDY_SERVER_H

#include <nlohmann/json.hpp>
#include <string>

namespace candy {
namespace server {

bool run(const nlohmann::json &config);
bool shutdown();

} // namespace server
} // namespace candy

#endif

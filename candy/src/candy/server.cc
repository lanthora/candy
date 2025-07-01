// SPDX-License-Identifier: MIT
#include "candy/server.h"
#include "core/server.h"
#include "utils/atomic.h"

namespace candy {
namespace server {

namespace {
Utils::Atomic<bool> running(true);
std::shared_ptr<Server> server;
} // namespace

bool run(const nlohmann::json &config) {
    while (running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        server = std::make_shared<Server>();
        server->setWebSocket(config["websocket"]);
        server->setPassword(config["password"]);
        server->setDHCP(config["dhcp"]);
        server->setSdwan(config["sdwan"]);
        server->run();
    }
    return true;
}

bool shutdown() {
    running.store(false);
    server->shutdown();
    return true;
}

} // namespace server
} // namespace candy

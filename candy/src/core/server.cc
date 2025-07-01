// SPDX-License-Identifier: MIT
#include "core/server.h"

namespace candy {

void Server::setWebSocket(const std::string &uri) {
    ws.setWebSocket(uri);
}

void Server::setPassword(const std::string &password) {
    ws.setPassword(password);
}

void Server::setDHCP(const std::string &cidr) {
    ws.setDHCP(cidr);
}

void Server::setSdwan(const std::string &sdwan) {
    ws.setSdwan(sdwan);
}

void Server::run() {
    running.store(true);
    ws.run();
    running.wait(true);
    ws.shutdown();
}

void Server::shutdown() {
    running.store(false);
}

} // namespace candy

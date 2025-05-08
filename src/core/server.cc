// SPDX-License-Identifier: MIT
#include "core/server.h"

namespace Candy {

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
    ws.run();
}

void Server::shutdown() {
    ws.shutdown();
}

} // namespace Candy

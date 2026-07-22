// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_SERVER_H
#define CANDY_CORE_SERVER_H

#include "utils/atomic.h"
#include "websocket/server.h"
#include <string>

namespace candy {

class Server {
public:
    // Parameters set from config file or command line
    void setWebSocket(const std::string &uri);
    void setPassword(const std::string &password);
    void setDHCP(const std::string &cidr);
    void setSdwan(const std::string &sdwan);

    // Start the server (non-blocking)
    void run();
    // Shut down the server (blocking, until all submodules exit)
    void shutdown();

private:
    // Currently only the WebSocket server submodule
    WebSocketServer ws;
    Utils::Atomic<bool> running;
};

} // namespace candy

#endif

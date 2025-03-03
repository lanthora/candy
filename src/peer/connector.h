// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_CONNECTOR_H
#define CANDY_PEER_CONNECTOR_H

#include "core/net.h"
#include <chrono>
#include <string>

namespace Candy {

class Peer;
class PeerManager;

class Connector {
public:
    Connector(Peer *peer) : peer(peer) {}

    virtual std::optional<int32_t> isConnected() const = 0;
    virtual bool tryToConnect() = 0;
    virtual void tick() = 0;
    virtual int send(const std::string &buffer) = 0;
    virtual std::string getName() = 0;
    IP4 getPeerAddress();
    PeerManager &getPeerManager();
    Peer &getPeer();

protected:
    void refreshActiveTime();
    bool isActiveIn(std::chrono::system_clock::duration duration);
    Peer *peer;

private:
    std::chrono::system_clock::time_point lastActiveTime;
};

} // namespace Candy

#endif

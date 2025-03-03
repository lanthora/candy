#include "peer/connector.h"
#include "peer/peer.h"

namespace Candy {

IP4 Connector::getPeerAddress() {
    return getPeer().getAddr();
}

PeerManager &Connector::getPeerManager() {
    return getPeer().getManager();
}

Peer &Connector::getPeer() {
    return *this->peer;
}

void Connector::refreshActiveTime() {
    this->lastActiveTime = std::chrono::system_clock::now();
}

bool Connector::isActiveIn(std::chrono::system_clock::duration duration) {
    return std::chrono::system_clock::now() - lastActiveTime < duration;
}

} // namespace Candy

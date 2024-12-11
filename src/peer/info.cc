#include "peer/info.h"

namespace Candy {

bool PeerInfo::isConnected() const {
    return this->state == PeerState::CONNECTED;
}

PeerState PeerInfo::getState() const {
    return this->state;
}

} // namespace Candy

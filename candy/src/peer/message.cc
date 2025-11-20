// SPDX-License-Identifier: MIT
#include "peer/message.h"
#include <string>

namespace candy {

namespace PeerMsg {
std::string Forward::create(const std::string &packet) {
    std::string data;
    data.push_back(PeerMsgKind::FORWARD);
    data += packet;
    return data;
}
} // namespace PeerMsg

} // namespace candy

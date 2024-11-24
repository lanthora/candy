// SPDX-License-Identifier: MIT
#include "core/message.h"

namespace Candy {

Msg::Msg(MsgKind kind, std::string data) {
    this->kind = kind;
    this->data = std::move(data);
}

Msg::Msg(Msg &&packet) {
    kind = packet.kind;
    data = std::move(packet.data);
}

Msg &Msg::operator=(Msg &&packet) {
    kind = packet.kind;
    data = std::move(packet.data);
    return *this;
}

} // namespace Candy

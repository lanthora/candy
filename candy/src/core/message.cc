// SPDX-License-Identifier: MIT
#include "core/message.h"
#include <chrono>

namespace candy {

Msg MsgQueue::read() {
    std::unique_lock lock(msgMutex);
    if (!msgCondition.wait_for(lock, std::chrono::seconds(1), [this] { return !msgQueue.empty(); })) {
        return Msg(MsgKind::TIMEOUT);
    }

    Msg msg = std::move(msgQueue.front());
    msgQueue.pop();
    return msg;
}

void MsgQueue::write(Msg msg, size_t limit) {
    {
        std::unique_lock lock(this->msgMutex);
        if (limit && msgQueue.size() >= limit) {
            return;
        }
        msgQueue.push(std::move(msg));
    }
    msgCondition.notify_one();
}

void MsgQueue::clear() {
    std::unique_lock lock(this->msgMutex);
    while (!msgQueue.empty()) {
        msgQueue.pop();
    }
}

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

} // namespace candy

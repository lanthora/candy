#include "peer/tcp.h"
#include "peer/peer.h"
#include "spdlog/spdlog.h"

namespace Candy {

std::optional<int32_t> TCP::isConnected() const {
    // TODO: 判断 TCP 是否是连接状态
    return std::nullopt;
}

bool TCP::tryToConnect() {
    // TODO: 尝试 TCP P2P
    return false;
}

std::string TCP4::getName() {
    return "TCP4";
}

void TCP4::tick() {
    // TODO: TCP4 tick
}

int TCP4::send(const std::string &buffer) {
    // TODO: TCP4 tick
    return -1;
}

std::string TCP6::getName() {
    return "TCP6";
}

void TCP6::tick() {
    // TODO: TCP6 tick
}

int TCP6::send(const std::string &buffer) {
    // TODO: TCP6 send
    return -1;
}

} // namespace Candy

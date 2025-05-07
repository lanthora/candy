#include "peer/tcp.h"
#include "peer/peer.h"
#include "spdlog/spdlog.h"

namespace Candy {

std::optional<int32_t> TCP::isConnected() const {
    return std::nullopt;
}

bool TCP::tryToConnect() {
    return false;
}

std::string TCP4::getName() {
    return "TCP4";
}

void TCP4::tick() {}

int TCP4::send(const std::string &buffer) {
    return -1;
}

std::string TCP6::getName() {
    return "TCP6";
}

void TCP6::tick() {}

int TCP6::send(const std::string &buffer) {
    return -1;
}

} // namespace Candy

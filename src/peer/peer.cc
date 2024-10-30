// SPDX-License-Identifier: MIT
#include "peer/peer.h"
#include "utility/address.h"
#include "utility/byteswap.h"
#include <Poco/Net/NetworkInterface.h>
#include <cstdlib>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>

namespace Candy {

int PeerInfo::setTun(uint32_t tun, const std::string &password) {
    this->tun = tun;

    if (std::endian::native == std::endian::big) {
        tun = byteswap(tun);
    }

    std::string data;
    data.append(password);
    data.append((char *)&tun, sizeof(tun));

    this->key.resize(SHA256_DIGEST_LENGTH);
    SHA256((unsigned char *)data.data(), data.size(), (unsigned char *)this->key.data());
    return 0;
}

std::string PeerInfo::getKey() const {
    return this->key;
}

uint32_t PeerInfo::getTun() const {
    return this->tun;
}

void PeerInfo::updateState(PeerState state) {
    this->count = 0;
    if (this->state == state) {
        return;
    }

    spdlog::debug("conn state: {} {} => {}", Address::ipToStr(this->tun), getStateStr(this->state), getStateStr(state));
    if (state == PeerState::INIT || state == PeerState::WAITING || state == PeerState::FAILED) {
        this->wide.ip = 0;
        this->wide.port = 0;
        this->local.ip = 0;
        this->local.port = 0;
        this->real.ip = 0;
        this->real.port = 0;
        this->ack = 0;
        this->delay = DELAY_LIMIT;
    }
    if (this->state == PeerState::WAITING && state == PeerState::INIT) {
        this->retry = std::min(this->retry * 2, RETRY_MAX);
    } else if (state == PeerState::INIT || state == PeerState::FAILED) {
        this->retry = RETRY_MIN;
    }
    this->state = state;
}

PeerState PeerInfo::getState() const {
    return this->state;
}

std::string PeerInfo::getStateStr() const {
    return getStateStr(this->state);
}

std::string PeerInfo::getStateStr(PeerState state) {
    switch (state) {
    case PeerState::INIT:
        return "INIT";
    case PeerState::PREPARING:
        return "PREPARING";
    case PeerState::SYNCHRONIZING:
        return "SYNCHRONIZING";
    case PeerState::CONNECTING:
        return "CONNECTING";
    case PeerState::CONNECTED:
        return "CONNECTED";
    case PeerState::WAITING:
        return "WAITING";
    case PeerState::FAILED:
        return "FAILED";
    default:
        return "UNKNOWN";
    }
}

} // namespace Candy

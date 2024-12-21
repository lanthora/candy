// SPDX-License-Identifier: MIT
#include "websocket/message.h"
#include "utility/time.h"

namespace Candy {
namespace WsMsg {

Auth::Auth(IP4 ip) {
    this->type = WsMsgKind::AUTH;
    this->ip = ip;
    this->timestamp = hton(unixTime());
}

void Auth::updateHash(const std::string &password) {
    std::string data;
    data.append(password);
    data.append((char *)&ip, sizeof(ip));
    data.append((char *)&timestamp, sizeof(timestamp));
    SHA256((unsigned char *)data.data(), data.size(), this->hash);
}

bool Auth::check(const std::string &password) {
    // 检查时间
    int64_t localTime = unixTime();
    int64_t remoteTime = ntoh(this->timestamp);
    if (std::abs(localTime - remoteTime) > 30) {
        spdlog::warn("auth header timestamp check failed: server {} client {}", localTime, remoteTime);
    }

    // 备份上报的数据
    uint8_t reported[SHA256_DIGEST_LENGTH];
    std::memcpy(reported, this->hash, SHA256_DIGEST_LENGTH);

    // 用口令计算正确的哈希并填充
    updateHash(password);

    // 检查上报的哈希和填充的哈希是否相等
    if (std::memcmp(reported, this->hash, SHA256_DIGEST_LENGTH)) {
        spdlog::warn("auth header hash check failed");
        return false;
    }
    return true;
}

Forward::Forward() {
    this->type = WsMsgKind::FORWARD;
}

ExptTun::ExptTun(const std::string &cidr) {
    this->type = WsMsgKind::EXPTTUN;
    this->timestamp = hton(unixTime());
    std::strcpy(this->cidr, cidr.c_str());
}

void ExptTun::updateHash(const std::string &password) {
    std::string data;
    data.append(password);
    data.append((char *)&this->timestamp, sizeof(this->timestamp));
    SHA256((unsigned char *)data.data(), data.size(), this->hash);
}

bool ExptTun::check(const std::string &password) {
    int64_t localTime = unixTime();
    int64_t remoteTime = ntoh(this->timestamp);
    if (std::abs(localTime - remoteTime) > 30) {
        spdlog::warn("expected address header timestamp check failed: server {} client {}", localTime, remoteTime);
        return false;
    }

    uint8_t reported[SHA256_DIGEST_LENGTH];
    std::memcpy(reported, this->hash, SHA256_DIGEST_LENGTH);

    updateHash(password);

    if (std::memcmp(reported, this->hash, SHA256_DIGEST_LENGTH)) {
        spdlog::warn("expected address header hash check failed");
        return false;
    }
    return true;
}

Udp4Conn::Udp4Conn() {
    this->type = WsMsgKind::UDP4CONN;
}

VMac::VMac(const std::string &vmac) {
    this->type = WsMsgKind::VMAC;
    this->timestamp = hton(unixTime());
    if (vmac.length() >= sizeof(this->vmac)) {
        memcpy(this->vmac, vmac.c_str(), sizeof(this->vmac));
    } else {
        memset(this->vmac, 0, sizeof(this->vmac));
    }
}

void VMac::updateHash(const std::string &password) {
    std::string data;
    data.append(password);
    data.append((char *)&this->vmac, sizeof(this->vmac));
    data.append((char *)&this->timestamp, sizeof(this->timestamp));
    SHA256((unsigned char *)data.data(), data.size(), this->hash);
}

bool VMac::check(const std::string &password) {
    int64_t localTime = unixTime();
    int64_t remoteTime = ntoh(this->timestamp);
    if (std::abs(localTime - remoteTime) > 30) {
        spdlog::warn("vmac message timestamp check failed: server {} client {}", localTime, remoteTime);
        return false;
    }

    uint8_t reported[SHA256_DIGEST_LENGTH];
    std::memcpy(reported, this->hash, SHA256_DIGEST_LENGTH);

    updateHash(password);

    if (std::memcmp(reported, this->hash, SHA256_DIGEST_LENGTH)) {
        spdlog::warn("vmac message hash check failed");
        return false;
    }
    return true;
}

Discovery::Discovery() {
    this->type = WsMsgKind::DISCOVERY;
}

General::General() {
    this->type = WsMsgKind::GENERAL;
}

} // namespace WsMsg
} // namespace Candy

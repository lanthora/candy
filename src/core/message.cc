// SPDX-License-Identifier: MIT
#include "core/message.h"
#include "utility/address.h"
#include "utility/time.h"
#include <spdlog/spdlog.h>

namespace Candy {

AuthHeader::AuthHeader(uint32_t ip) {
    this->type = MessageType::AUTH;
    this->ip = Address::hostToNet(ip);
    this->timestamp = Time::hostToNet(Time::unixTime());
}

void AuthHeader::updateHash(const std::string &password) {
    std::string data;
    data.append(password);
    data.append((char *)&ip, sizeof(ip));
    data.append((char *)&timestamp, sizeof(timestamp));
    SHA256((unsigned char *)data.data(), data.size(), this->hash);
}

bool AuthHeader::check(const std::string &password) {
    // 检查时间
    int64_t localTime = Time::unixTime();
    int64_t remoteTime = Time::netToHost(this->timestamp);
    if (std::abs(localTime - remoteTime) > 30) {
        spdlog::warn("auth header timestamp check failed: server {} client {}", localTime, remoteTime);
        return false;
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

ForwardHeader::ForwardHeader() {
    this->type = MessageType::FORWARD;
}

ExpectedAddressMessage::ExpectedAddressMessage(const std::string &cidr) {
    this->type = MessageType::EXPECTED;
    this->timestamp = Time::hostToNet(Time::unixTime());
    std::strcpy(this->cidr, cidr.c_str());
}

void ExpectedAddressMessage::updateHash(const std::string &password) {
    std::string data;
    data.append(password);
    data.append((char *)&this->timestamp, sizeof(this->timestamp));
    SHA256((unsigned char *)data.data(), data.size(), this->hash);
}

bool ExpectedAddressMessage::check(const std::string &password) {
    int64_t localTime = Time::unixTime();
    int64_t remoteTime = Time::netToHost(this->timestamp);
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

VMacMessage::VMacMessage(const std::string &vmac) {
    this->type = MessageType::VMAC;
    this->timestamp = Time::hostToNet(Time::unixTime());
    if (vmac.length() >= sizeof(this->vmac)) {
        memcpy(this->vmac, vmac.c_str(), sizeof(this->vmac));
    } else {
        memset(this->vmac, 0, sizeof(this->vmac));
    }
}

DiscoveryMessage::DiscoveryMessage() {
    this->type = MessageType::DISCOVERY;
}

GeneralHeader::GeneralHeader() {
    this->type = MessageType::GENERAL;
}

void VMacMessage::updateHash(const std::string &password) {
    std::string data;
    data.append(password);
    data.append((char *)&this->vmac, sizeof(this->vmac));
    data.append((char *)&this->timestamp, sizeof(this->timestamp));
    SHA256((unsigned char *)data.data(), data.size(), this->hash);
}

bool VMacMessage::check(const std::string &password) {
    int64_t localTime = Time::unixTime();
    int64_t remoteTime = Time::netToHost(this->timestamp);
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

PeerConnMessage::PeerConnMessage() {
    this->type = MessageType::PEER;
}

} // namespace Candy

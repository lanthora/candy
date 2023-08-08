#include "core/message.h"
#include "utility/address.h"
#include <spdlog/spdlog.h>

namespace Candy {

AuthHeader::AuthHeader(uint32_t ip) {
    this->type = MessageType::TYPE_AUTH;
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
    // 检查时间戳
    if (std::abs(Time::unixTime() - Time::netToHost(this->timestamp)) > 30) {
        spdlog::warn("Auth header timestamp check failed. timestamp={0}", Time::netToHost(this->timestamp));
        return false;
    }

    // 备份上报的数据
    uint8_t reported[SHA256_DIGEST_LENGTH];
    std::memcpy(reported, this->hash, SHA256_DIGEST_LENGTH);

    // 用口令计算正确的哈希并填充
    updateHash(password);

    // 检查上报的哈希和填充的哈希是否相等
    if (std::memcmp(reported, this->hash, SHA256_DIGEST_LENGTH)) {
        spdlog::warn("Auth header hash check failed");
        return false;
    }
    return true;
}

ForwardHeader::ForwardHeader() {
    this->type = MessageType::TYPE_FORWARD;
}

DynamicAddressHeader::DynamicAddressHeader(const std::string &cidr) {
    this->type = MessageType::TYPE_DYNAMIC_ADDRESS;
    this->timestamp = Time::hostToNet(Time::unixTime());
    std::strcpy(this->cidr, cidr.c_str());
}

void DynamicAddressHeader::updateHash(const std::string &password) {
    std::string data;
    data.append(password);
    data.append((char *)&timestamp, sizeof(timestamp));
    SHA256((unsigned char *)data.data(), data.size(), this->hash);
}

bool DynamicAddressHeader::check(const std::string &password) {
    // 检查时间戳
    if (std::abs(Time::unixTime() - Time::netToHost(this->timestamp)) > 30) {
        spdlog::warn("Dynamic address header timestamp check failed. timestamp={0}", Time::netToHost(this->timestamp));
        return false;
    }

    // 备份上报的数据
    uint8_t reported[SHA256_DIGEST_LENGTH];
    std::memcpy(reported, this->hash, SHA256_DIGEST_LENGTH);

    // 用口令计算正确的哈希并填充
    updateHash(password);

    // 检查上报的哈希和填充的哈希是否相等
    if (std::memcmp(reported, this->hash, SHA256_DIGEST_LENGTH)) {
        spdlog::warn("Dynamic address header hash check failed");
        return false;
    }
    return true;
}

}; // namespace Candy

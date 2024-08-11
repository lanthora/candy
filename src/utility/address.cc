// SPDX-License-Identifier: MIT
#include "utility/address.h"
#include "utility/byteswap.h"
#include <Poco/Platform.h>
#include <spdlog/spdlog.h>

#if defined(POCO_OS_FAMILY_UNIX)
#include <arpa/inet.h>
#include <sys/socket.h>
#elif defined(POCO_OS_FAMILY_WINDOWS)
#include <ws2tcpip.h>
#endif

namespace Candy {

int Address::cidrUpdate(const std::string &cidr) {
    if (cidr.empty()) {
        spdlog::error("cidr is empty");
        return -1;
    }
    std::size_t pos = cidr.find('/');
    if (pos == std::string::npos) {
        spdlog::error("invalid cidr format: {}", cidr);
        return -1;
    }

    std::string ipStr = cidr.substr(0UL, pos);
    std::string maskStr;
    prefixStrToMaskStr(cidr.substr(pos + 1), maskStr);
    return ipMaskStrUpdate(ipStr, maskStr);
}

int Address::ipMaskStrUpdate(const std::string &ipStr, const std::string &maskStr) {
    uint32_t ip, mask;
    if (inet_pton(AF_INET, ipStr.c_str(), &ip) != 1) {
        spdlog::error("invalid ip format: ip {}", ipStr);
        return -1;
    }
    if (inet_pton(AF_INET, maskStr.c_str(), &mask) != 1) {
        spdlog::error("invalid mask format: mask {}", maskStr);
        return -1;
    }
    ip = netToHost(ip);
    mask = netToHost(mask);
    return this->ipMaskUpdate(ip, mask);
}

int Address::ipMaskUpdate(uint32_t ip, uint32_t mask) {
    this->ip = ip;
    this->mask = mask;
    ip = hostToNet(ip);
    mask = hostToNet(mask);
    char buffer[16];
    if (!inet_ntop(AF_INET, &ip, buffer, sizeof(buffer))) {
        spdlog::error("invalid ip format: ip {:08x}", ip);
        return -1;
    }
    this->ipStr = buffer;
    if (!inet_ntop(AF_INET, &mask, buffer, sizeof(buffer))) {
        spdlog::error("invalid mask format: mask {:08x}", mask);
        return -1;
    }
    this->maskStr = buffer;

    if (maskToPrefix(this->mask, this->prefix)) {
        spdlog::error("mask to prefix failed: mask {:08x}", mask);
        return -1;
    }
    this->prefixStr = std::to_string(this->prefix);
    this->net = this->ip & this->mask;
    this->host = this->ip & (~this->mask);
    this->cidr = this->ipStr + "/" + this->prefixStr;
    return 0;
}

int Address::ipStrUpdate(const std::string &ipStr) {
    return ipMaskStrUpdate(ipStr, "255.255.255.255");
}

int Address::ipUpdate(uint32_t ip) {
    return ipMaskUpdate(ip, UINT32_MAX);
}

bool Address::inSameNetwork(const Address &address) {
    if (getMask() != address.getMask()) {
        return false;
    }
    if (getNet() != address.getNet()) {
        return false;
    }
    if (address.getHost() == 0) {
        return false;
    }
    if (address.getHost() == (~address.getMask())) {
        return false;
    }
    return true;
}

int Address::next() {
    if (this->prefix >= 31) {
        spdlog::error("unable to generate next available address: prefix {}", this->prefix);
        return -1;
    }

    do {
        this->host = (this->host + 1) & (~this->mask);
    } while (this->host == (~this->mask) || this->host == 0);

    uint32_t ip = this->net | this->host;
    uint32_t mask = this->mask;

    return ipMaskUpdate(ip, mask);
}

int Address::dump() const {
    spdlog::debug("cidr={}", this->cidr);
    spdlog::debug("ipStr={} ip=0x{:0>8x}", this->ipStr, this->ip);
    spdlog::debug("maskStr={} mask=0x{:0>8x}", this->maskStr, this->mask);
    spdlog::debug("prefixStr={} prefix={}", this->prefixStr, this->prefix);
    spdlog::debug("net=0x{:0>8x} host=0x{:0>8x}", this->net, this->host);
    return 0;
}

uint32_t Address::getIp() const {
    return this->ip;
}

std::string Address::getIpStr() const {
    return this->ipStr;
}

uint32_t Address::getMask() const {
    return this->mask;
}

uint32_t Address::getPrefix() const {
    return this->prefix;
}

uint32_t Address::getNet() const {
    return this->net;
}

uint32_t Address::getHost() const {
    return this->host;
}

std::string Address::getMaskStr() const {
    return this->maskStr;
}

std::string Address::getCidr() const {
    return this->cidr;
}

uint32_t Address::netToHost(uint32_t address) {
    if (std::endian::native == std::endian::little) {
        return byteswap(address);
    }
    return address;
}

uint32_t Address::hostToNet(uint32_t address) {
    return netToHost(address);
}

uint16_t Address::netToHost(uint16_t port) {
    if (std::endian::native == std::endian::little) {
        return byteswap(port);
    }
    return port;
}

uint16_t Address::hostToNet(uint16_t port) {
    return netToHost(port);
}

std::string Address::ipToStr(uint32_t ip) {
    Address address;
    address.ipUpdate(ip);
    return address.getIpStr();
}

int Address::prefixStrToMaskStr(const std::string &prefixStr, std::string &maskStr) {
    uint32_t prefix = std::stoi(prefixStr);
    uint32_t mask = 0;

    if (prefixToMask(prefix, mask) != 0) {
        return -1;
    }

    char buffer[16];
    mask = hostToNet(mask);
    if (!inet_ntop(AF_INET, &mask, buffer, sizeof(buffer))) {
        spdlog::error("invalid mask format: mask {:08x}", mask);
        return -1;
    }
    maskStr = buffer;
    return 0;
}

int Address::prefixToMask(uint32_t prefix, uint32_t &mask) {
    if (prefix > 32 || prefix < 0) {
        spdlog::critical("cidr prefix exception: prefix {}", prefix);
        return -1;
    }

    mask = 0;
    for (uint32_t idx = 0; idx < prefix; ++idx) {
        mask |= 0x80000000 >> idx;
    }

    return 0;
}

int Address::maskToPrefix(uint32_t mask, uint32_t &prefix) {
    prefix = 0;
    for (uint32_t idx = 0; idx < 32; ++idx) {
        if ((0x80000000 >> idx) & (mask)) {
            ++prefix;
            continue;
        }
        break;
    }
    for (uint32_t idx = prefix; idx < 32; ++idx) {
        if ((0x80000000 >> idx) & (mask)) {
            spdlog::error("invalid mask: mask {}", mask);
            return -1;
        }
    }
    return 0;
}

} // namespace Candy

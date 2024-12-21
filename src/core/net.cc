// SPDX-License-Identifier: MIT
#include "core/net.h"
#include <Poco/Net/IPAddress.h>
#include <cstring>
#include <exception>

namespace Candy {

IP4::IP4(const std::string &ip) {
    fromString(ip);
}

IP4 IP4::operator=(const std::string &ip) {
    fromString(ip);
    return *this;
}

IP4::operator std::string() const {
    return toString();
}

IP4::operator uint32_t() const {
    uint32_t val = 0;
    std::memcpy(&val, raw.data(), sizeof(val));
    return val;
}

IP4 IP4::operator|(IP4 another) const {
    for (int i = 0; i < raw.size(); ++i) {
        another.raw[i] |= raw[i];
    }
    return another;
}

IP4 IP4::operator^(IP4 another) const {
    for (int i = 0; i < raw.size(); ++i) {
        another.raw[i] ^= raw[i];
    }
    return another;
}

IP4 IP4::operator~() const {
    IP4 retval;
    for (int i = 0; i < raw.size(); ++i) {
        retval.raw[i] |= ~raw[i];
    }
    return retval;
}

bool IP4::operator==(IP4 another) const {
    return raw == another.raw;
}

IP4 IP4::operator&(IP4 another) const {
    for (int i = 0; i < raw.size(); ++i) {
        another.raw[i] &= raw[i];
    }
    return another;
}

IP4 IP4::next() const {
    IP4 ip;
    uint32_t t = hton(ntoh(uint32_t(*this)) + 1);
    std::memcpy(&ip, &t, sizeof(ip));
    return ip;
}

int IP4::fromString(const std::string &ip) {
    memcpy(raw.data(), Poco::Net::IPAddress(ip).addr(), 4);
    return 0;
}

std::string IP4::toString() const {
    return Poco::Net::IPAddress(raw.data(), sizeof(raw)).toString();
}

int IP4::fromPrefix(int prefix) {
    std::memset(raw.data(), 0, sizeof(raw));
    for (int i = 0; i < prefix; ++i) {
        raw[i / 8] |= (0x80 >> (i % 8));
    }
    return 0;
}

int IP4::toPrefix() {
    int i;
    for (i = 0; i < 32; ++i) {
        if (!(raw[i / 8] & (0x80 >> (i % 8)))) {
            break;
        }
    }
    return i;
}

bool IP4::empty() const {
    return raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0;
}

bool IP4Header::isIPv4() {
    return true;
}

bool IP4Header::isIPIP() {
    return false;
}

Address::Address() {}

Address::Address(const std::string &cidr) {
    fromCidr(cidr);
}

IP4 &Address::Host() {
    return this->host;
}

IP4 &Address::Mask() {
    return this->mask;
}

IP4 Address::Net() {
    return Host() & Mask();
}

Address Address::Next() {
    Address next;
    next.mask = this->mask;
    next.host = (Net() | (~Mask() & this->host.next()));
    return next;
}

bool Address::isValid() {
    // 主机号全为 0
    if ((~mask & host) == 0) {
        return false;
    }
    // 主机号全为 1
    if (~(mask | host) == 0) {
        return false;
    }
    return true;
}

int Address::fromCidr(const std::string &cidr) {
    try {
        std::size_t pos = cidr.find('/');
        host.fromString(cidr.substr(0UL, pos));
        mask.fromPrefix(std::stoi(cidr.substr(pos + 1)));
    } catch (std::exception &e) {
        spdlog::warn("address parse cidr failed: {}: {}", e.what(), cidr);
        return -1;
    }
    return 0;
}

std::string Address::toCidr() {
    return host.toString() + "/" + std::to_string(mask.toPrefix());
}

} // namespace Candy

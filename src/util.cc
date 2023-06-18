// SPDX-License-Identifier: MIT
#include "util.h"
#include <arpa/inet.h>
#include <chrono>
#include <spdlog/spdlog.h>

namespace candy {

uint32_t CIDR::networkPrefixToSubnetMask(int num) {
    if (num > 32 || num < 0) {
        spdlog::critical("cidr prefix exception. value: {0}", num);
        exit(1);
    }

    uint32_t addr = 0;
    for (int idx = 0; idx < num; ++idx) {
        addr |= 0x80000000 >> idx;
    }
    return htonl(addr);
}

uint32_t CIDR::networkPrefixToSubnetMask(std::string prefix) {
    int num = std::stoi(prefix);
    return networkPrefixToSubnetMask(num);
}

std::string CIDR::networkPrefixToSubnetMaskString(std::string prefix) {
    struct in_addr addr;
    memset(&addr, 0, sizeof(addr));
    addr.s_addr = networkPrefixToSubnetMask(prefix);
    return inet_ntoa(addr);
}

Uri::Uri(std::string uri) : uri_(uri) {
    UriParserStateA state_;
    state_.uri = &uriParse_;
    isValid_ = uriParseUriA(&state_, uri_.c_str()) == URI_SUCCESS;
}

Uri::~Uri() {
    uriFreeUriMembersA(&uriParse_);
}

bool Uri::isValid() const {
    return isValid_;
}

std::string Uri::scheme() const {
    return fromRange(uriParse_.scheme);
}

std::string Uri::host() const {
    return fromRange(uriParse_.hostText);
}

std::string Uri::port() const {
    return fromRange(uriParse_.portText);
}

std::string Uri::path() const {
    return fromList(uriParse_.pathHead, "/");
}

std::string Uri::query() const {
    return fromRange(uriParse_.query);
}

std::string Uri::fragment() const {
    return fromRange(uriParse_.fragment);
}

std::string Uri::fromRange(const UriTextRangeA &rng) const {
    return std::string(rng.first, rng.afterLast);
}

std::string Uri::fromList(UriPathSegmentA *xs, const std::string &delim) const {
    UriPathSegmentStructA *head(xs);
    std::string accum;

    while (head) {
        accum += delim + fromRange(head->text);
        head = head->next;
    }

    return accum;
}

bool INet::isIpv4Address(std::string address) {
    struct in_addr sin_addr;
    return inet_pton(AF_INET, address.data(), &sin_addr) == 1;
}

std::string INet::ipU32ToString(uint32_t ip) {
    struct in_addr sin_addr;
    sin_addr.s_addr = ip;
    return inet_ntoa(sin_addr);
}

uint32_t INet::ipStringToU32(std::string address) {
    uint32_t ip;
    if (inet_pton(AF_INET, address.data(), &ip) != 1) {
        return 0;
    }
    return ip;
}

void AuthHeader::calculateHash(const std::string &password) {
    std::string data = password;
    data.append((char *)&ip, sizeof(ip));
    data.append((char *)&timestamp, sizeof(timestamp));
    SHA256((unsigned char *)data.data(), data.size(), hash);
}

bool AuthHeader::checkHash(const std::string &password) {
    uint8_t calculated[SHA256_DIGEST_LENGTH];
    std::string data = password;
    data.append((char *)&ip, sizeof(ip));
    data.append((char *)&timestamp, sizeof(timestamp));
    SHA256((unsigned char *)data.data(), data.size(), calculated);

    return memcmp(calculated, hash, SHA256_DIGEST_LENGTH) == 0;
}

void DHCPHeader::calculateHash(const std::string &password) {
    std::string data = password;
    data.append((char *)&timestamp, sizeof(timestamp));
    SHA256((unsigned char *)data.data(), data.size(), hash);
}

bool DHCPHeader::checkHash(const std::string &password) {
    uint8_t calculated[SHA256_DIGEST_LENGTH];
    std::string data = password;
    data.append((char *)&timestamp, sizeof(timestamp));
    SHA256((unsigned char *)data.data(), data.size(), calculated);

    return memcmp(calculated, hash, SHA256_DIGEST_LENGTH) == 0;
}

int64_t unixTimeStamp() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

}; // namespace candy

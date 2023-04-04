#include "util.h"
#include <spdlog/spdlog.h>
#include <arpa/inet.h>

namespace candy {

std::string CIDR::networkPrefixToSubnetMask(std::string prefix) {
    int num = std::stoi(prefix);
    if (num > 32 || num < 0) {
        spdlog::critical("cidr prefix exception. value: {0}", num);
        exit(1);
    }

    struct in_addr addr;
    memset(&addr, 0, sizeof(addr));
    for (int idx = 0; idx < num; ++idx) {
        addr.s_addr |= 0x80000000 >> idx;
    }

    addr.s_addr = htonl(addr.s_addr);
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

std::string INet::ipToString(uint32_t ip) {
    struct in_addr sin_addr;
    sin_addr.s_addr = ip;
    return inet_ntoa(sin_addr);
}

void AuthHeader::calculateHash(const std::string &password) {
    std::string data = password;
    data.append((char *)&tunIp, sizeof(tunIp));
    data.append((char *)&timestamp, sizeof(timestamp));
    SHA256((unsigned char *)data.data(), data.size(), _hash);
}

bool AuthHeader::checkHash(const std::string &password) {
    uint8_t calculated[SHA256_DIGEST_LENGTH];
    std::string data = password;
    data.append((char *)&tunIp, sizeof(tunIp));
    data.append((char *)&timestamp, sizeof(timestamp));
    SHA256((unsigned char *)data.data(), data.size(), calculated);

    return memcmp(calculated, _hash, SHA256_DIGEST_LENGTH) == 0;
}

}; // namespace candy

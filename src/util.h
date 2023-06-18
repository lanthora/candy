// SPDX-License-Identifier: MIT
#ifndef CANDY_UTIL_H
#define CANDY_UTIL_H

#include <netinet/ip.h>
#include <openssl/sha.h>
#include <string>
#include <uriparser/Uri.h>

namespace candy {

#define htonll(x) ((1 == htonl(1)) ? (x) : ((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1 == ntohl(1)) ? (x) : ((uint64_t)ntohl((x)&0xFFFFFFFF) << 32) | ntohl((x) >> 32))

class CIDR {
public:
    static uint32_t networkPrefixToSubnetMask(int num);
    static uint32_t networkPrefixToSubnetMask(std::string prefix);
    static std::string networkPrefixToSubnetMaskString(std::string prefix);
};

class Uri {
public:
    Uri(std::string uri);
    ~Uri();
    bool isValid() const;

    std::string scheme() const;
    std::string host() const;
    std::string port() const;
    std::string path() const;
    std::string query() const;
    std::string fragment() const;

private:
    std::string uri_;
    UriUriA uriParse_;
    bool isValid_;

    std::string fromRange(const UriTextRangeA &rng) const;
    std::string fromList(UriPathSegmentA *xs, const std::string &delim) const;
};

class INet {
public:
    static bool isIpv4Address(std::string address);
    static std::string ipU32ToString(uint32_t ip);
    static uint32_t ipStringToU32(std::string address);
};

enum {
    TYPE_AUTH,
    TYPE_FORWARD,
    TYPE_DHCP,
};

struct AuthHeader {
    uint8_t type;
    uint32_t ip;
    int64_t timestamp;
    uint8_t hash[SHA256_DIGEST_LENGTH];

    void calculateHash(const std::string &password);
    bool checkHash(const std::string &password);
} __attribute__((packed));

struct ForwardHeader {
    uint8_t type;
    struct iphdr iph;
} __attribute__((packed));

struct DHCPHeader {
    uint8_t type;
    int64_t timestamp;
    char cidr[32];
    uint8_t hash[SHA256_DIGEST_LENGTH];

    void calculateHash(const std::string &password);
    bool checkHash(const std::string &password);
} __attribute__((packed));

int64_t unixTimeStamp();

}; // namespace candy

#endif

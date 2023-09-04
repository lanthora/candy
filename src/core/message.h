// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_MESSAGE_H
#define CANDY_CORE_MESSAGE_H

#include "utility/address.h"
#include "utility/time.h"
#include <cstdint>
#include <cstring>
#include <openssl/sha.h>
#include <string>

namespace Candy {

namespace MessageType {

constexpr uint8_t AUTH = 0;
constexpr uint8_t FORWARD = 1;
constexpr uint8_t DHCP = 2;
constexpr uint8_t PEER = 3;

}; // namespace MessageType

struct AuthHeader {
    uint8_t type;
    uint32_t ip;
    int64_t timestamp;
    uint8_t hash[SHA256_DIGEST_LENGTH];

    AuthHeader(uint32_t ip);
    void updateHash(const std::string &password);
    bool check(const std::string &password);
} __attribute__((packed));

struct ForwardHeader {
    uint8_t type;
    IPv4Header iph;

    ForwardHeader();
} __attribute__((packed));

struct DynamicAddressMessage {
    uint8_t type;
    int64_t timestamp;
    char cidr[32];
    uint8_t hash[SHA256_DIGEST_LENGTH];

    DynamicAddressMessage(const std::string &cidr);
    void updateHash(const std::string &password);
    bool check(const std::string &password);
} __attribute__((packed));

struct PeerConnMessage {
    uint8_t type;
    uint32_t tunSrcIp;
    uint32_t tunDestIp;
    uint32_t pubIp;
    uint16_t pubPort;
    uint8_t forceSync;

    PeerConnMessage();
} __attribute__((packed));

}; // namespace Candy

#endif

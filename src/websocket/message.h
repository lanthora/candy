// SPDX-License-Identifier: MIT
#ifndef CANDY_WEBSOCKET_MESSAGE_H
#define CANDY_WEBSOCKET_MESSAGE_H

#include "core/net.h"
#include <openssl/sha.h>

namespace Candy {

namespace WsMsgKind {
constexpr uint8_t AUTH = 0;
constexpr uint8_t FORWARD = 1;
constexpr uint8_t EXPTTUN = 2;
constexpr uint8_t UDP4CONN = 3;
constexpr uint8_t VMAC = 4;
constexpr uint8_t DISCOVERY = 5;
constexpr uint8_t ROUTE = 6;
constexpr uint8_t GENERAL = 255;
} // namespace WsMsgKind

namespace GeSubType {
constexpr uint8_t LOCALUDP4CONN = 0;
}

namespace WsMsg {

struct __attribute__((packed)) Auth {
    uint8_t type;
    IP4 ip;
    int64_t timestamp;
    uint8_t hash[SHA256_DIGEST_LENGTH];

    Auth(IP4 ip);
    void updateHash(const std::string &password);
    bool check(const std::string &password);
};

struct __attribute__((packed)) Forward {
    uint8_t type;
    IP4Header iph;

    Forward();
};

struct __attribute__((packed)) ExptTun {
    uint8_t type;
    int64_t timestamp;
    char cidr[32];
    uint8_t hash[SHA256_DIGEST_LENGTH];

    ExptTun(const std::string &cidr);
    void updateHash(const std::string &password);
    bool check(const std::string &password);
};

struct __attribute__((packed)) Udp4Conn {
    uint8_t type;
    IP4 src;
    IP4 dst;
    IP4 ip;
    uint16_t port;

    Udp4Conn();
};

struct __attribute__((packed)) VMac {
    uint8_t type;
    uint8_t vmac[16];
    int64_t timestamp;
    uint8_t hash[SHA256_DIGEST_LENGTH];

    VMac(const std::string &vmac);
    void updateHash(const std::string &password);
    bool check(const std::string &password);
};

struct __attribute__((packed)) Discovery {
    uint8_t type;
    IP4 src;
    IP4 dst;

    Discovery();
};

struct __attribute__((packed)) SysRoute {
    uint8_t type;
    uint8_t size;
    uint16_t reserved;
    SysRouteEntry rtTable[0];
};

struct __attribute__((packed)) General {
    uint8_t type;
    uint8_t subtype;
    uint16_t extra;
    IP4 src;
    IP4 dst;

    General();
};

struct __attribute__((packed)) LocalUDP4 {
    General ge;
    IP4 ip;
    uint16_t port;
};

} // namespace WsMsg
} // namespace Candy

#endif

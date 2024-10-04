// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_MESSAGE_H
#define CANDY_CORE_MESSAGE_H

#include "utility/address.h"
#include <cstdint>
#include <cstring>
#include <openssl/sha.h>
#include <string>

namespace Candy {

namespace MessageType {

constexpr uint8_t AUTH = 0;
constexpr uint8_t FORWARD = 1;
constexpr uint8_t EXPECTED = 2;
constexpr uint8_t PEER = 3;
constexpr uint8_t VMAC = 4;
constexpr uint8_t DISCOVERY = 5;
constexpr uint8_t ROUTE = 6;
constexpr uint8_t GENERAL = 255;

} // namespace MessageType

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

struct ExpectedAddressMessage {
    uint8_t type;
    int64_t timestamp;
    char cidr[32];
    uint8_t hash[SHA256_DIGEST_LENGTH];

    ExpectedAddressMessage(const std::string &cidr);
    void updateHash(const std::string &password);
    bool check(const std::string &password);
} __attribute__((packed));

struct PeerConnMessage {
    uint8_t type;
    uint32_t src;
    uint32_t dst;
    uint32_t ip;
    uint16_t port;

    PeerConnMessage();
} __attribute__((packed));

struct VMacMessage {
    uint8_t type;
    uint8_t vmac[16];
    int64_t timestamp;
    uint8_t hash[SHA256_DIGEST_LENGTH];

    VMacMessage(const std::string &vmac);
    void updateHash(const std::string &password);
    bool check(const std::string &password);
} __attribute__((packed));

struct DiscoveryMessage {
    uint8_t type;
    uint32_t src;
    uint32_t dst;

    DiscoveryMessage();
} __attribute__((packed));

struct SysRouteItem {
    uint32_t dest;
    uint32_t mask;
    uint32_t nexthop;
} __attribute__((packed));

struct SysRouteMessage {
    uint8_t type;
    uint8_t size;
    uint16_t reserved;
    SysRouteItem rtTable[0];
} __attribute__((packed));

struct GeneralHeader {
    uint8_t type;
    uint8_t subtype;
    uint16_t extra;
    uint32_t src;
    uint32_t dst;

    GeneralHeader();
} __attribute__((packed));

namespace GeSubType {

constexpr uint8_t LOCAL_PEER_CONN = 0;

} // namespace GeSubType

struct LocalPeerConnMessage {
    GeneralHeader ge;
    uint32_t ip;
    uint16_t port;
} __attribute__((packed));

struct StunRequest {
    uint8_t type[2] = {0x00, 0x01};
    uint8_t length[2] = {0x00, 0x08};
    uint8_t cookie[4] = {0x21, 0x12, 0xa4, 0x42};
    uint8_t id[12] = {0x00};
    struct {
        uint8_t type[2] = {0x00, 0x03};
        uint8_t length[2] = {0x00, 0x04};
        uint8_t notset[4] = {0x00};
    } attr;
};

struct StunResponse {
    uint16_t type;
    uint16_t length;
    uint32_t cookie;
    uint8_t id[12];
    uint8_t attr[0];
};

namespace PeerMessageType {

constexpr uint8_t HEARTBEAT = 0;
constexpr uint8_t FORWARD = 1;
constexpr uint8_t DELAY = 2;
// TODO: 遗漏了 3, 新功能时使用
constexpr uint8_t ROUTE = 4;

} // namespace PeerMessageType

struct PeerHeartbeatMessage {
    uint8_t type;
    uint32_t tun;
    uint32_t ip;
    uint16_t port;
    uint8_t ack;
} __attribute__((packed));

struct PeerForwardMessage {
    uint8_t type;
    IPv4Header iph;
} __attribute__((packed));

struct PeerDelayMessage {
    uint8_t type;
    uint32_t src;
    uint32_t dst;
    int64_t timestamp;
} __attribute__((packed));

struct PeerRouteMessage {
    uint8_t type;
    uint32_t dst;
    uint32_t next;
    int32_t delay;
} __attribute__((packed));

constexpr uint32_t BROADCAST_IP = UINT32_MAX;

} // namespace Candy

#endif

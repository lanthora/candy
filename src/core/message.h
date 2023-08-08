// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_MESSAGE_H
#define CANDY_CORE_MESSAGE_H

#include "utility/time.h"
#include <cstdint>
#include <cstring>
#include <openssl/sha.h>
#include <string>

namespace Candy {

struct IPv4Header {
    unsigned char version_ihl; // 版本号和首部长度
    unsigned char tos;         // 服务类型
    unsigned short tot_len;    // 总长度
    unsigned short id;         // 标识
    unsigned short frag_off;   // 分片偏移
    unsigned char ttl;         // 生存时间
    unsigned char protocol;    // 协议类型
    unsigned short check;      // 校验和
    unsigned int saddr;        // 源地址
    unsigned int daddr;        // 目的地址
};

namespace MessageType {
enum {
    TYPE_AUTH = 0,
    TYPE_FORWARD = 1,
    TYPE_DYNAMIC_ADDRESS = 2,
};
};

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

struct DynamicAddressHeader {
    uint8_t type;
    int64_t timestamp;
    char cidr[32];
    uint8_t hash[SHA256_DIGEST_LENGTH];

    DynamicAddressHeader(const std::string &cidr);
    void updateHash(const std::string &password);
    bool check(const std::string &password);
} __attribute__((packed));

}; // namespace Candy

#endif

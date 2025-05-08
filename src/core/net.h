// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_NET_H
#define CANDY_CORE_NET_H

#include <array>
#include <bit>
#include <cstdint>
#include <spdlog/spdlog.h>
#include <string>

namespace Candy {

// 统一函数处理网络序与主机序之间的转换
template <typename T> T ntoh(T v) {
    if (std::endian::native == std::endian::little) {
        return std::byteswap(v);
    }
    return v;
}

template <typename T> T hton(T v) {
    return ntoh(v);
}

/* 用于表示 IPv4 地址,数据在内部以网络序的形式存储,并提供与之对应的字符串操作 */
class __attribute__((packed)) IP4 {
public:
    IP4(const std::string &ip = "0.0.0.0");
    IP4 operator=(const std::string &ip);
    IP4 operator&(IP4 another) const;
    IP4 operator|(IP4 another) const;
    IP4 operator^(IP4 another) const;
    IP4 operator~() const;
    bool operator==(IP4 another) const;
    operator std::string() const;
    operator uint32_t() const;
    IP4 next() const;
    int fromString(const std::string &ip);
    std::string toString() const;
    int fromPrefix(int prefix);
    int toPrefix();
    bool empty() const;
    void reset();

private:
    std::array<uint8_t, 4> raw;
};

/* IPv4 头,分装于 IPv4 相关的操作 */
struct __attribute__((packed)) IP4Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    IP4 saddr;
    IP4 daddr;

    // 判断是否为 IPv4, 对于 TUN 设备需要丢弃所有非 IPv4 的报文
    bool isIPv4();
    // 判断是否为模拟的 IPIP 协议
    bool isIPIP();
};

struct __attribute__((packed)) SysRouteEntry {
    IP4 dst;
    IP4 mask;
    IP4 nexthop;
};

/* 用于表示地址和掩码的组合,用于判断主机是否属于某个网络 */
class Address {
public:
    Address();
    Address(const std::string &cidr);

    IP4 &Host();
    IP4 &Mask();
    IP4 Net();

    // 当前网络内的下一个地址
    Address Next();

    // 判断是否是有效的主机地址
    bool isValid();

    int fromCidr(const std::string &cidr);
    std::string toCidr();

    bool empty() const {
        return host.empty() && mask.empty();
    }

private:
    IP4 host;
    IP4 mask;
};

} // namespace Candy

namespace std {
template <> struct hash<Candy::IP4> {
    size_t operator()(const Candy::IP4 &ip) const noexcept {
        return hash<uint32_t>{}(ip);
    }
};
} // namespace std

namespace {

constexpr std::size_t AES_256_GCM_IV_LEN = 12;
constexpr std::size_t AES_256_GCM_TAG_LEN = 16;
constexpr std::size_t AES_256_GCM_KEY_LEN = 32;

} // namespace

#endif

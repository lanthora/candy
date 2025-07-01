// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_NET_H
#define CANDY_CORE_NET_H

#include <array>
#include <cstdint>
#include <spdlog/spdlog.h>
#include <string>
#include <type_traits>

namespace candy {

template <typename T> typename std::enable_if<std::is_integral<T>::value, T>::type byteswap(T value) {
    static_assert(std::is_integral<T>::value, "byteswap requires integral type");

    union {
        T value;
        uint8_t bytes[sizeof(T)];
    } src, dst;

    src.value = value;
    for (size_t i = 0; i < sizeof(T); i++) {
        dst.bytes[i] = src.bytes[sizeof(T) - i - 1];
    }
    return dst.value;
}

template <typename T> T ntoh(T v) {
    static_assert(std::is_integral<T>::value, "ntoh requires integral type");

    uint8_t *bytes = reinterpret_cast<uint8_t *>(&v);
    bool isLittleEndian = true;
    {
        uint16_t test = 0x0001;
        isLittleEndian = (*reinterpret_cast<uint8_t *>(&test) == 0x01);
    }

    if (isLittleEndian) {
        return byteswap(v);
    }
    return v;
}

template <typename T> T hton(T v) {
    return ntoh(v);
}

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

    bool isIPv4();
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

} // namespace candy

namespace std {
using candy::IP4;
template <> struct hash<IP4> {
    size_t operator()(const IP4 &ip) const noexcept {
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

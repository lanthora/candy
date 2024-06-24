// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILITY_ADDRESS_H
#define CANDY_UTILITY_ADDRESS_H

#include <cstdint>
#include <string>

namespace Candy {

struct IPv4Header {
    uint8_t version_ihl; // 版本号和首部长度
    uint8_t tos;         // 服务类型
    uint16_t tot_len;    // 总长度
    uint16_t id;         // 标识
    uint16_t frag_off;   // 分片偏移
    uint8_t ttl;         // 生存时间
    uint8_t protocol;    // 协议类型
    uint16_t check;      // 校验和
    uint32_t saddr;      // 源地址
    uint32_t daddr;      // 目的地址
};

class Address {
public:
    // 以不同的形式更新地址
    int cidrUpdate(const std::string &cidr);
    int ipMaskStrUpdate(const std::string &ip, const std::string &mask);
    int ipMaskUpdate(uint32_t ip, uint32_t mask);
    // 以单个地址更新,掩码为 255.255.255.255
    int ipStrUpdate(const std::string &ip);
    int ipUpdate(uint32_t ip);

    // 获取地址里的参数
    uint32_t getIp() const;
    uint32_t getMask() const;
    uint32_t getPrefix() const;
    uint32_t getNet() const;
    uint32_t getHost() const;
    std::string getIpStr() const;
    std::string getMaskStr() const;
    std::string getCidr() const;

    // 地址在这个网络且主机地址有效
    bool inSameNetwork(const Address &address);

    // 地址更新为同网络的下一个地址,动态分配 IP 地址时使用
    int next();

    // 显示地址信息,用于调试
    int dump() const;

    static uint32_t netToHost(uint32_t address);
    static uint32_t hostToNet(uint32_t address);
    static uint16_t netToHost(uint16_t port);
    static uint16_t hostToNet(uint16_t port);

    static std::string ipToStr(uint32_t ip);

private:
    int prefixStrToMaskStr(const std::string &netPrefixStr, std::string &maskStr);
    int prefixToMask(uint32_t prefix, uint32_t &mask);
    int maskToPrefix(uint32_t mask, uint32_t &prefix);

    // 原始数据首先转换成地址和掩码
    uint32_t ip;
    uint32_t mask;

    // 根据地址和掩码计算网络号和主机号
    uint32_t net;
    uint32_t host;
    // 根据掩码计算网络前缀
    uint32_t prefix;
    // 把上面的数据转换为字符串格式
    std::string ipStr;
    std::string maskStr;
    std::string prefixStr;
    // 根据地址和网络前缀获取 CIDR
    std::string cidr;
};

} // namespace Candy

#endif

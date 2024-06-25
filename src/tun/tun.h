// SPDX-License-Identifier: MIT
#ifndef CANDY_TUN_TUN_H
#define CANDY_TUN_TUN_H

#include <any>
#include <cstdint>
#include <string>

namespace Candy {

class Tun {
public:
    Tun();
    ~Tun();

    // 为了支持一台设备接入多个 VPN 网络.用名称区分 TUN 设备.
    int setName(const std::string &name);

    // 设置 TUN 设备的地址和网络,以及由网络引入的路由.设置相同网络的流量路由到本设备.
    int setAddress(const std::string &cidr);

    // 获取 IP 地址,用于发包前校验源 IP 是否相同
    uint32_t getIP();

    // 设置 MTU, 这个数值应该略小于网络实际 MTU, 这样即使添加了 VPN 的包头也能一次发包.
    int setMTU(int mtu);

    // 设置读超时时间.
    int setTimeout(int timeout);

    // 网卡 up/down
    int up();
    int down();

    // 阻塞的从 TUN 设备读写数据.读操作返回 0 表示超时.
    int read(std::string &buffer);
    int write(const std::string &buffer);

    // 设置系统路由表
    int setSysRtTable(uint32_t dst, uint32_t mask, uint32_t nexthop);

private:
    std::any impl;
};

} // namespace Candy

#endif

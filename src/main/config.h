// SPDX-License-Identifier: MIT
#ifndef CANDY_MAIN_CONFIG_H
#define CANDY_MAIN_CONFIG_H

#include <map>
#include <spdlog/spdlog.h>
#include <string>

struct arguments {
    // 通用配置
    std::string mode;
    std::string websocket;
    std::string password;
    std::string ntp;
    int restart = 0;
    bool noTimestamp = false;
    bool debug = false;

    // 服务端配置
    std::string dhcp;
    std::string sdwan;

    // 客户端配置
    std::string name;
    std::string tun;
    std::string stun;
    std::string localhost;
    int workers = 0;
    int udpPort = 0;
    int discovery = 0;
    int routeCost = 0;
    int mtu = 1400;

    int parse(int argc, char *argv[]);

private:
    void dump(const std::string &key, const std::string &value);
    void dump(const std::string &key, int value);
    void dump();
    void parseFile(std::string cfgFile);
    std::map<std::string, std::string> fileToKvMap(const std::string &filename);
};

// 保存虚拟地址
int saveTunAddress(const std::string &name, const std::string &cidr);

// 获取虚拟地址
std::string loadTunAddress(const std::string &name);

// 获取或生成虚拟硬件地址
std::string virtualMac(const std::string &name);

// 检查是否能成功保存虚拟硬件地址,虚拟硬件地址不能持久化会导致
// 1. 址申请动态 IP 时会重复获取地址资源
// 2. 使用静态地址时可能会冲突
bool hasContainerVolume(const arguments &args);

// 获取数据存储目录,默认参数非空是追加为子目录或目录下的文件
std::string storageDirectory(std::string subdir = "");

#endif

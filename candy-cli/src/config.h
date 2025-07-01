// SPDX-License-Identifier: MIT
#ifndef CANDY_CLI_CONFIG_H
#define CANDY_CLI_CONFIG_H

#include <map>
#include <nlohmann/json.hpp>
#include <string>

struct arguments {
    int parse(int argc, char *argv[]);
    nlohmann::json json();

private:
    void parseFile(std::string cfgFile);
    std::map<std::string, std::string> fileToKvMap(const std::string &filename);

    std::string mode;
    std::string websocket;
    std::string password;
    bool noTimestamp = false;
    bool debug = false;

    std::string dhcp;
    std::string sdwan;

    std::string name;
    std::string tun;
    std::string stun;
    std::string localhost;
    int port = 0;
    int discovery = 0;
    int routeCost = 0;
    int mtu = 1400;
};

int saveTunAddress(const std::string &name, const std::string &cidr);
std::string loadTunAddress(const std::string &name);
std::string virtualMac(const std::string &name);
std::string storageDirectory(std::string subdir = "");

#endif

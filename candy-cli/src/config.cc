// SPDX-License-Identifier: MIT
#include "config.h"
#include "argparse.h"
#include "candy/candy.h"
#include <Poco/Platform.h>
#include <Poco/String.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <sstream>
#include <string>

nlohmann::json arguments::json() {
    nlohmann::json config = {
        {"mode", this->mode},
        {"websocket", this->websocket},
        {"password", this->password},
        {"dhcp", this->dhcp},
        {"sdwan", this->sdwan},
        {"name", this->name},
        {"tun", this->tun},
        {"stun", this->stun},
        {"localhost", this->localhost},
        {"discovery", this->discovery},
        {"route", this->routeCost},
        {"mtu", this->mtu},
        {"port", this->port},
        {"vmac", virtualMac(this->name)},
        {"expt", loadTunAddress(this->name)},
    };
    return config;
}

int arguments::parse(int argc, char *argv[]) {
    argparse::ArgumentParser program("candy", candy::version());

    program.add_argument("-c", "--config").help("config file path");
    program.add_argument("-m", "--mode").help("working mode");
    program.add_argument("-w", "--websocket").help("websocket address");
    program.add_argument("-p", "--password").help("authorization password");
    program.add_argument("-d", "--dhcp").help("dhcp address range");
    program.add_argument("--sdwan").help("software-defined wide area network");
    program.add_argument("-n", "--name").help("network interface name");
    program.add_argument("-t", "--tun").help("static address");
    program.add_argument("-s", "--stun").help("stun address");
    program.add_argument("--port").help("p2p listen port").scan<'i', int>();
    program.add_argument("--mtu").help("maximum transmission unit").scan<'i', int>();
    program.add_argument("-r", "--route").help("routing cost").scan<'i', int>();
    program.add_argument("--discovery").help("discovery interval").scan<'i', int>();
    program.add_argument("--localhost").help("local ip");

    program.add_argument("--no-timestamp").implicit_value(true);
    program.add_argument("--debug").implicit_value(true);

    try {
        program.parse_args(argc, argv);
        if (program.is_used("--config")) {
            parseFile(program.get<std::string>("--config"));
        }

        if (program.is_used("--mode")) {
            this->mode = program.get<std::string>("--mode");
        }

        program.set_if_used("--mode", this->mode);
        program.set_if_used("--websocket", this->websocket);
        program.set_if_used("--password", this->password);
        program.set_if_used("--no-timestamp", this->noTimestamp);
        program.set_if_used("--debug", this->debug);
        program.set_if_used("--dhcp", this->dhcp);
        program.set_if_used("--sdwan", this->sdwan);
        program.set_if_used("--name", this->name);
        program.set_if_used("--tun", this->tun);
        program.set_if_used("--stun", this->stun);
        program.set_if_used("--localhost", this->localhost);
        program.set_if_used("--port", this->port);
        program.set_if_used("--mtu", this->mtu);
        program.set_if_used("--discovery", this->discovery);
        program.set_if_used("--route", this->routeCost);

        bool needShowUsage = [&]() {
            if (this->mode != "client" && this->mode != "server")
                return true;
            if (this->websocket.empty())
                return true;

            return false;
        }();

        if (needShowUsage) {
            std::cout << program.usage() << std::endl;
            exit(1);
        }

        if (this->noTimestamp) {
            spdlog::set_pattern("[%^%l%$] %v");
        }
        if (this->debug) {
            spdlog::set_level(spdlog::level::debug);
        }
        return 0;
    } catch (const std::exception &e) {
        std::cout << program.usage() << std::endl;
        exit(1);
    }
}

void arguments::parseFile(std::string cfgFile) {
    try {
        std::map<std::string, std::function<void(const std::string &)>> cfgHandlers = {
            {"mode", [&](const std::string &value) { this->mode = value; }},
            {"websocket", [&](const std::string &value) { this->websocket = value; }},
            {"password", [&](const std::string &value) { this->password = value; }},
            {"debug", [&](const std::string &value) { this->debug = (value == "true"); }},
            {"dhcp", [&](const std::string &value) { this->dhcp = value; }},
            {"sdwan", [&](const std::string &value) { this->sdwan = value; }},
            {"tun", [&](const std::string &value) { this->tun = value; }},
            {"stun", [&](const std::string &value) { this->stun = value; }},
            {"name", [&](const std::string &value) { this->name = value; }},
            {"discovery", [&](const std::string &value) { this->discovery = std::stoi(value); }},
            {"route", [&](const std::string &value) { this->routeCost = std::stoi(value); }},
            {"port", [&](const std::string &value) { this->port = std::stoi(value); }},
            {"mtu", [&](const std::string &value) { this->mtu = std::stoi(value); }},
            {"localhost", [&](const std::string &value) { this->localhost = value; }},
        };
        auto trim = [](std::string str) {
            if (str.length() >= 2 && str.front() == '\"' && str.back() == '\"') {
                return str.substr(1, str.length() - 2);
            }
            return str;
        };
        auto configs = fileToKvMap(cfgFile);
        for (auto cfg : configs) {
            auto handler = cfgHandlers.find(cfg.first);
            if (handler != cfgHandlers.end()) {
                handler->second(trim(cfg.second));
            } else {
                spdlog::warn("unknown config: {}={}", cfg.first, cfg.second);
            }
        }
    } catch (std::exception &e) {
        spdlog::error("parse config file failed: {}", e.what());
        exit(1);
    }
}

std::map<std::string, std::string> arguments::fileToKvMap(const std::string &filename) {
    std::map<std::string, std::string> config;
    std::ifstream file(filename);
    std::string line;

    while (std::getline(file, line)) {
        line = Poco::trimLeft(line);
        if (line.empty() || line.front() == '#')
            continue;
        line.erase(line.find_last_not_of(" \t;") + 1);
        std::size_t delimiterPos = line.find('=');
        if (delimiterPos != std::string::npos) {
            std::string key = Poco::trim(line.substr(0, delimiterPos));
            std::string value = Poco::trim(line.substr(delimiterPos + 1));
            config[key] = value;
        }
    }
    return config;
}

int saveTunAddress(const std::string &name, const std::string &cidr) {
    try {
        std::string cache = storageDirectory("address/");
        cache += name.empty() ? "__noname__" : name;
        std::filesystem::create_directories(std::filesystem::path(cache).parent_path());
        std::ofstream ofs(cache);
        if (ofs.is_open()) {
            ofs << cidr;
            ofs.close();
        }
        return 0;
    } catch (std::exception &e) {
        spdlog::critical("save latest address failed: {}", e.what());
        return -1;
    }
}

std::string loadTunAddress(const std::string &name) {
    std::string cache = storageDirectory("address/");
    cache += name.empty() ? "__noname__" : name;
    std::ifstream ifs(cache);
    if (ifs.is_open()) {
        std::stringstream ss;
        ss << ifs.rdbuf();
        ifs.close();
        return ss.str();
    }
    return "0.0.0.0/0";
}

std::string virtualMacHelper(std::string name = "") {
    try {
        std::string path = storageDirectory("vmac/");
        path += name.empty() ? "__noname__" : name;
        char buffer[candy::VMAC_SIZE];
        std::stringstream ss;
        std::ifstream ifs(path);
        if (ifs.is_open()) {
            ifs.read(buffer, sizeof(buffer));
            if (ifs) {
                for (int i = 0; i < (int)sizeof(buffer); i++) {
                    ss << std::hex << buffer[i];
                }
            }
            ifs.close();
            return ss.str();
        }
        return "";
    } catch (std::exception &e) {
        return "";
    }
}

std::string initVirtualMac() {
    try {
        std::string path = storageDirectory("vmac/__noname__");
        std::filesystem::create_directories(std::filesystem::path(path).parent_path());
        std::string vmac = candy::create_vmac();
        std::ofstream ofs(path);
        if (ofs.is_open()) {
            ofs << vmac;
            ofs.close();
        }
        return vmac;
    } catch (std::exception &e) {
        spdlog::critical("init vmac failed: {}", e.what());
        return "";
    }
}

std::string virtualMac(const std::string &name) {
    std::string path;
    // 兼容老版本,优先获取与配置网卡名对应的 vmac
    path = virtualMacHelper(name);
    if (!path.empty()) {
        return path;
    }
    // 获取网卡名无关的全局 vmac
    path = virtualMacHelper();
    if (!path.empty()) {
        return path;
    }
    // 初次启动,生成全局 vmac
    return initVirtualMac();
}

bool starts_with(const std::string &str, const std::string &prefix) {
    return str.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), str.begin());
}

#if POCO_OS == POCO_OS_WINDOWS_NT
std::string storageDirectory(std::string subdir) {
    return "C:/ProgramData/Candy/" + subdir;
}
#else
std::string storageDirectory(std::string subdir) {
    return "/var/lib/candy/" + subdir;
}
#endif

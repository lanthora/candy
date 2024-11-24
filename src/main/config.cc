// SPDX-License-Identifier: MIT
#include "main/config.h"
#include "core/version.h"
#include "main/config.h"
#include "utility/argparse.h"
#include "utility/random.h"
#include <Poco/Platform.h>
#include <Poco/String.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <spdlog/spdlog.h>
#include <sstream>
#include <string>

void arguments::dump(const std::string &key, const std::string &value) {
    if (!value.empty()) {
        spdlog::debug("--{}={}", key, value);
    }
}

void arguments::dump(const std::string &key, int value) {
    if (value) {
        spdlog::debug("--{}={}", key, value);
    }
}

void arguments::dump() {
    spdlog::debug("================================");
    dump("mode", this->mode);
    dump("websocket", this->websocket);
    dump("password", this->password);
    dump("ntp", this->ntp);
    dump("restart", this->restart);
    dump("dhcp", this->dhcp);
    dump("sdwan", this->sdwan);
    dump("name", this->name);
    dump("tun", this->tun);
    dump("stun", this->stun);
    dump("localhost", this->localhost);
    dump("discovery", this->discovery);
    dump("route", this->routeCost);
    dump("mtu", this->mtu);
    dump("workers", this->workers);
    dump("port", this->udpPort);
    spdlog::debug("================================");
}

int arguments::parse(int argc, char *argv[]) {
    argparse::ArgumentParser program("candy", CANDY_VERSION);

    program.add_argument("-m", "--mode").help("working mode").metavar("TEXT");
    program.add_argument("-w", "--websocket").help("websocket address").metavar("URI");
    program.add_argument("-p", "--password").help("authorization password").metavar("TEXT");
    program.add_argument("--ntp").help("ntp server").metavar("HOST");
    program.add_argument("--restart").help("restart interval").scan<'i', int>().metavar("SECONDS");
    program.add_argument("-d", "--dhcp").help("dhcp address range").metavar("CIDR");
    program.add_argument("--sdwan").help("software-defined wide area network").metavar("ROUTES");
    program.add_argument("-n", "--name").help("network interface name").metavar("TEXT");
    program.add_argument("--workers").help("workers number").scan<'i', int>().metavar("NUM");
    program.add_argument("-t", "--tun").help("static address").metavar("CIDR");
    program.add_argument("-s", "--stun").help("stun address").metavar("URI");
    program.add_argument("--port").help("udp port").scan<'i', int>().metavar("NUMBER");
    program.add_argument("--mtu").help("maximum transmission unit").scan<'i', int>().metavar("NUMBER");
    program.add_argument("-r", "--route").help("routing cost").scan<'i', int>().metavar("COST");
    program.add_argument("--discovery").help("discovery interval").scan<'i', int>().metavar("SECONDS");
    program.add_argument("--localhost").help("local ip").metavar("IP");
    program.add_argument("-c", "--config").help("config file path").metavar("PATH");
    program.add_argument("--no-timestamp").implicit_value(true).help("disable log time");
    program.add_argument("--debug").implicit_value(true).help("show debug log");

    try {
        program.parse_args(argc, argv);
        if (program.is_used("--config")) {
            parseFile(program.get<std::string>("--config"));
        }

        this->mode = program.is_used("--mode") ? program.get<std::string>("--mode") : this->mode;
        this->websocket = program.is_used("--websocket") ? program.get<std::string>("--websocket") : this->websocket;
        this->password = program.is_used("--password") ? program.get<std::string>("--password") : this->password;
        this->ntp = program.is_used("--ntp") ? program.get<std::string>("--ntp") : this->ntp;
        this->restart = program.is_used("--restart") ? program.get<int>("--restart") : this->restart;
        this->noTimestamp = program.is_used("--no-timestamp") ? program.get<bool>("--no-timestamp") : this->noTimestamp;
        this->debug = program.is_used("--debug") ? program.get<bool>("--debug") : this->debug;
        this->dhcp = program.is_used("--dhcp") ? program.get<std::string>("--dhcp") : this->dhcp;
        this->sdwan = program.is_used("--sdwan") ? program.get<std::string>("--sdwan") : this->sdwan;
        this->name = program.is_used("--name") ? program.get<std::string>("--name") : this->name;
        this->workers = program.is_used("--workers") ? program.get<int>("--workers") : this->workers;
        this->tun = program.is_used("--tun") ? program.get<std::string>("--tun") : this->tun;
        this->stun = program.is_used("--stun") ? program.get<std::string>("--stun") : this->stun;
        this->localhost = program.is_used("--localhost") ? program.get<std::string>("--localhost") : this->localhost;
        this->udpPort = program.is_used("--port") ? program.get<int>("--port") : this->udpPort;
        this->mtu = program.is_used("--mtu") ? program.get<int>("--mtu") : this->mtu;
        this->discovery = program.is_used("--discovery") ? program.get<int>("--discovery") : this->discovery;
        this->routeCost = program.is_used("--route") ? program.get<int>("--route") : this->routeCost;

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
            this->dump();
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
            {"ntp", [&](const std::string &value) { this->ntp = value; }},
            {"debug", [&](const std::string &value) { this->debug = (value == "true"); }},
            {"restart", [&](const std::string &value) { this->restart = std::stoi(value); }},
            {"dhcp", [&](const std::string &value) { this->dhcp = value; }},
            {"sdwan", [&](const std::string &value) { this->sdwan = value; }},
            {"tun", [&](const std::string &value) { this->tun = value; }},
            {"stun", [&](const std::string &value) { this->stun = value; }},
            {"name", [&](const std::string &value) { this->name = value; }},
            {"workers", [&](const std::string &value) { this->workers = std::stoi(value); }},
            {"discovery", [&](const std::string &value) { this->discovery = std::stoi(value); }},
            {"route", [&](const std::string &value) { this->routeCost = std::stoi(value); }},
            {"port", [&](const std::string &value) { this->udpPort = std::stoi(value); }},
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

std::string virtualMac(const std::string &name) {
    try {
        std::string cache = storageDirectory("vmac/");
        cache += name.empty() ? "__noname__" : name;
        std::filesystem::create_directories(std::filesystem::path(cache).parent_path());

        char buffer[16];
        std::stringstream ss;

        std::ifstream ifs(cache);
        if (ifs.is_open()) {
            ifs.read(buffer, sizeof(buffer));
            if (ifs) {
                for (int i = 0; i < (int)sizeof(buffer); i++) {
                    ss << std::hex << buffer[i];
                }
            }
            ifs.close();
        } else {
            ss << Candy::randomHexString(sizeof(buffer));
            std::ofstream ofs(cache);
            if (ofs.is_open()) {
                ofs << ss.str();
                ofs.close();
            }
        }
        return ss.str();
    } catch (std::exception &e) {
        spdlog::critical("vmac failed: {}", e.what());
        return "";
    }
}

bool hasContainerVolume(const arguments &args) {
    if (args.mode != "client") {
        return true;
    }
    if (!std::filesystem::exists(storageDirectory("lost"))) {
        return true;
    }
    if (args.websocket.starts_with("wss://canets.org")) {
        return false;
    }
    if (!args.tun.empty()) {
        return true;
    }
    return false;
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

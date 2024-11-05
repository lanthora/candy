// SPDX-License-Identifier: MIT
#include "core/client.h"
#include "core/common.h"
#include "core/server.h"
#include "utility/argparse.h"
#include "utility/random.h"
#include "utility/time.h"
#include <Poco/Platform.h>
#include <Poco/String.h>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <signal.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <string>

namespace {

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

    void dump(const std::string &key, const std::string &value) {
        if (!value.empty()) {
            spdlog::debug("--{}={}", key, value);
        }
    }
    void dump(const std::string &key, int value) {
        if (value) {
            spdlog::debug("--{}={}", key, value);
        }
    }
    void dump() {
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
};

int disableLogTimestamp() {
    spdlog::set_pattern("[%^%l%$] %v");
    return 0;
}

int setLogLevelDebug() {
    spdlog::set_level(spdlog::level::debug);
    return 0;
}

std::map<std::string, std::string> parseConfig(const std::string &filename) {
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

void parseConfig(std::string cfgFile, arguments &args) {
    try {
        std::map<std::string, std::function<void(const std::string &)>> cfgHandlers = {
            {"mode", [&](const std::string &value) { args.mode = value; }},
            {"websocket", [&](const std::string &value) { args.websocket = value; }},
            {"password", [&](const std::string &value) { args.password = value; }},
            {"ntp", [&](const std::string &value) { args.ntp = value; }},
            {"debug", [&](const std::string &value) { args.debug = (value == "true"); }},
            {"restart", [&](const std::string &value) { args.restart = std::stoi(value); }},
            {"dhcp", [&](const std::string &value) { args.dhcp = value; }},
            {"sdwan", [&](const std::string &value) { args.sdwan = value; }},
            {"tun", [&](const std::string &value) { args.tun = value; }},
            {"stun", [&](const std::string &value) { args.stun = value; }},
            {"name", [&](const std::string &value) { args.name = value; }},
            {"workers", [&](const std::string &value) { args.workers = std::stoi(value); }},
            {"discovery", [&](const std::string &value) { args.discovery = std::stoi(value); }},
            {"route", [&](const std::string &value) { args.routeCost = std::stoi(value); }},
            {"port", [&](const std::string &value) { args.udpPort = std::stoi(value); }},
            {"mtu", [&](const std::string &value) { args.mtu = std::stoi(value); }},
            {"localhost", [&](const std::string &value) { args.localhost = value; }},
        };
        auto trim = [](std::string str) {
            if (str.length() >= 2 && str.front() == '\"' && str.back() == '\"') {
                return str.substr(1, str.length() - 2);
            }
            return str;
        };
        auto configs = parseConfig(cfgFile);
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

#if POCO_OS == POCO_OS_WINDOWS_NT

std::string storageDirectory = "C:/ProgramData/Candy/";

#else

std::string storageDirectory = "/var/lib/candy/";

#endif

int saveLatestAddress(const std::string &name, const std::string &cidr) {
    try {
        std::string cache = storageDirectory + "address/";
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

std::string getLastestAddress(const std::string &name) {
    std::string cache = storageDirectory + "address/";
    cache += name.empty() ? "__noname__" : name;
    std::ifstream ifs(cache);
    if (ifs.is_open()) {
        std::stringstream ss;
        ss << ifs.rdbuf();
        ifs.close();
        return ss.str();
    }
    return "";
}

std::string virtualMac(const std::string &name) {
    try {
        std::string cache = storageDirectory + "vmac/";
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

bool checkStorageDirectory(const arguments &args) {
    if (args.mode != "client") {
        return true;
    }
    if (!std::filesystem::exists(storageDirectory + "lost")) {
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

std::atomic<bool> running = true;

} // namespace

namespace Candy {

void shutdown(Client *client) {
    running = false;
    running.notify_one();
}

void shutdown(Server *server) {
    running = false;
    running.notify_one();
}

} // namespace Candy

namespace {

std::atomic<int> exitCode = 1;

void signalHandler(int signal) {
    exitCode = 0;
    running = false;
    running.notify_one();
}

int serve(const arguments &args) {

    Poco::Net::initializeNetwork();

    Candy::Server server;
    Candy::Client client;

    if (args.mode == "server") {
        server.setPassword(args.password);
        server.setWebSocketServer(args.websocket);
        server.setDynamicAddressRange(args.dhcp);
        server.setSdwan(args.sdwan);
        server.run();
    }

    if (args.mode == "client") {
        client.setAddressUpdateCallback([&](const std::string &cidr) { return saveLatestAddress(args.name, cidr); });
        client.setDiscoveryInterval(args.discovery);
        client.setRouteCost(args.routeCost);
        client.setUdpBindPort(args.udpPort);
        client.setLocalhost(args.localhost);
        client.setPassword(args.password);
        client.setWebSocketServer(args.websocket);
        client.setStun(args.stun);
        client.setTunAddress(args.tun);
        client.setExpectedAddress(getLastestAddress(args.name));
        client.setVirtualMac(virtualMac(args.name));
        client.setMtu(args.mtu);
        client.setWorkers(args.workers);
        client.setName(args.name);
        client.run();
    }

    running.wait(true);

    server.shutdown();
    client.shutdown();

    if (exitCode == 0) {
        spdlog::info("service exit: normal");
    } else {
        spdlog::info("service exit: internal exception");
    }

    Poco::Net::uninitializeNetwork();
    return exitCode;
}
} // namespace

int parseConfig(int argc, char *argv[], arguments &args) {
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
            parseConfig(program.get<std::string>("--config"), args);
        }

        args.mode = program.is_used("--mode") ? program.get<std::string>("--mode") : args.mode;
        args.websocket = program.is_used("--websocket") ? program.get<std::string>("--websocket") : args.websocket;
        args.password = program.is_used("--password") ? program.get<std::string>("--password") : args.password;
        args.ntp = program.is_used("--ntp") ? program.get<std::string>("--ntp") : args.ntp;
        args.restart = program.is_used("--restart") ? program.get<int>("--restart") : args.restart;
        args.noTimestamp = program.is_used("--no-timestamp") ? program.get<bool>("--no-timestamp") : args.noTimestamp;
        args.debug = program.is_used("--debug") ? program.get<bool>("--debug") : args.debug;
        args.dhcp = program.is_used("--dhcp") ? program.get<std::string>("--dhcp") : args.dhcp;
        args.sdwan = program.is_used("--sdwan") ? program.get<std::string>("--sdwan") : args.sdwan;
        args.name = program.is_used("--name") ? program.get<std::string>("--name") : args.name;
        args.workers = program.is_used("--workers") ? program.get<int>("--workers") : args.workers;
        args.tun = program.is_used("--tun") ? program.get<std::string>("--tun") : args.tun;
        args.stun = program.is_used("--stun") ? program.get<std::string>("--stun") : args.stun;
        args.localhost = program.is_used("--localhost") ? program.get<std::string>("--localhost") : args.localhost;
        args.udpPort = program.is_used("--port") ? program.get<int>("--port") : args.udpPort;
        args.mtu = program.is_used("--mtu") ? program.get<int>("--mtu") : args.mtu;
        args.discovery = program.is_used("--discovery") ? program.get<int>("--discovery") : args.discovery;
        args.routeCost = program.is_used("--route") ? program.get<int>("--route") : args.routeCost;

        bool needShowUsage = [&]() {
            if (args.mode != "client" && args.mode != "server")
                return true;
            if (args.websocket.empty())
                return true;

            return false;
        }();

        if (needShowUsage) {
            std::cout << program.usage() << std::endl;
            exit(1);
        }

        if (args.noTimestamp) {
            disableLogTimestamp();
        }
        if (args.debug) {
            setLogLevelDebug();
            args.dump();
        }
        return 0;
    } catch (const std::exception &e) {
        std::cout << program.usage() << std::endl;
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    arguments args;
    parseConfig(argc, argv, args);

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    if (!checkStorageDirectory(args)) {
        spdlog::critical("the container needs to add a storage volume: {}", storageDirectory);
        running = false;
    }

    Candy::Time::ntpServer = args.ntp;

    while (running && serve(args) && args.restart) {
        running = true;
        Candy::Time::useSystemTime = false;
        spdlog::info("service will restart in {} seconds", args.restart);
        std::this_thread::sleep_for(std::chrono::seconds(args.restart));
    }

    return exitCode;
}

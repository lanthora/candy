// SPDX-License-Identifier: MIT
#include "core/client.h"
#include "core/common.h"
#include "core/server.h"
#include "utility/random.h"
#include "utility/time.h"
#include <argp.h>
#include <bit>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <libconfig.h++>
#include <mutex>
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
    bool autoRestart = false;
    bool exitOnEOF = false;

    // 服务端配置
    std::string dhcp;

    // 客户端配置
    std::string name;
    std::string tun;
    std::string stun;
    std::string localhost;
    int udpPort = 0;
    int discoveryInterval = 0;
    int routeCost = 0;
};

const int OPT_NO_TIMESTAMP = 1;
const int OPT_LOG_LEVEL_DEBUG = 2;
const int OPT_AUTO_RESTART = 3;
const int OPT_EXIT_ON_EOF = 4;
const int OPT_DISCOVERY_INTERVAL = 5;
const int OPT_UDP_BIND_PORT = 6;
const int OPT_UDP_P2P_IP = 7;

const int GROUP_CLIENT_AND_SERVER = 1;
const int GROUP_SERVER_ONLY = 2;
const int GROUP_CLIENT_ONLY = 3;
const int GROUP_OTHERS = 4;

struct argp_option options[] = {
    {0, 0, 0, 0, "Client and Server:", GROUP_CLIENT_AND_SERVER},
    {"mode", 'm', "TEXT", 0, "Working mode", GROUP_CLIENT_AND_SERVER},
    {"websocket", 'w', "URI", 0, "Websocket address", GROUP_CLIENT_AND_SERVER},
    {"password", 'p', "TEXT", 0, "Authorization password", GROUP_CLIENT_AND_SERVER},

    {0, 0, 0, 0, "Server:", GROUP_SERVER_ONLY},
    {"dhcp", 'd', "CIDR", 0, "Automatically assigned address range", GROUP_SERVER_ONLY},

    {0, 0, 0, 0, "Client:", GROUP_CLIENT_ONLY},
    {"name", 'n', "TEXT", 0, "Network interface name", GROUP_CLIENT_ONLY},
    {"tun", 't', "CIDR", 0, "Static configured IP address", GROUP_CLIENT_ONLY},
    {"stun", 's', "URI", 0, "STUN service address", GROUP_CLIENT_ONLY},
    {"port", OPT_UDP_BIND_PORT, "PORT", 0, "Bind udp port", GROUP_CLIENT_ONLY},
    {"route", 'r', "COST", 0, "Cost of routing", GROUP_CLIENT_ONLY},
    {"discovery", OPT_DISCOVERY_INTERVAL, "SECONDS", 0, "Active discovery broadcast interval", GROUP_CLIENT_ONLY},
    {"localhost", OPT_UDP_P2P_IP, "IP", 0, "Local P2P IP", GROUP_CLIENT_ONLY},

    {0, 0, 0, 0, "Others:", GROUP_OTHERS},
    {"config", 'c', "PATH", 0, "Configuration file path", GROUP_OTHERS},
    {"no-timestamp", OPT_NO_TIMESTAMP, 0, 0, "Log does not show time", GROUP_OTHERS},
    {"debug", OPT_LOG_LEVEL_DEBUG, 0, 0, "Show debug level logs", GROUP_OTHERS},
    {"auto-restart", OPT_AUTO_RESTART, 0, 0, "Automatic restart", GROUP_OTHERS},
    {"eof-exit", OPT_EXIT_ON_EOF, 0, 0, "Exit the process after receiving EOF", GROUP_OTHERS},
    {"version", 'v', 0, 0, "Show version", GROUP_OTHERS},
    {},
};

int disableLogTimestamp() {
    spdlog::set_pattern("[%^%l%$] %v");
    return 0;
}

int setLogLevelDebug() {
    spdlog::set_level(spdlog::level::debug);
    spdlog::debug("set log level: debug");
    return 0;
}

void showVersion() {
    std::cout << CANDY_VERSION << std::endl;
    exit(0);
}

bool needShowUsage(struct arguments *arguments, struct argp_state *state) {
    if (state->arg_num > 0)
        return true;

    if (arguments->mode != "client" && arguments->mode != "server")
        return true;

    if (arguments->websocket.empty())
        return true;

    return false;
}

void parseConfigFile(struct arguments *arguments, std::string config) {
    try {
        libconfig::Config cfg;
        cfg.readFile(config.c_str());
        cfg.lookupValue("mode", arguments->mode);
        cfg.lookupValue("websocket", arguments->websocket);
        cfg.lookupValue("tun", arguments->tun);
        cfg.lookupValue("dhcp", arguments->dhcp);
        cfg.lookupValue("stun", arguments->stun);
        cfg.lookupValue("password", arguments->password);
        cfg.lookupValue("name", arguments->name);
        cfg.lookupValue("discovery", arguments->discoveryInterval);
        cfg.lookupValue("route", arguments->routeCost);
        cfg.lookupValue("port", arguments->udpPort);
        cfg.lookupValue("localhost", arguments->localhost);
    } catch (const libconfig::FileIOException &fioex) {
        spdlog::critical("i/o error while reading configuration file");
        exit(1);
    } catch (const libconfig::ParseException &pex) {
        spdlog::critical("parse error at {} : {} - {}", pex.getFile(), pex.getLine(), pex.getError());
        exit(1);
    }
}

int parseOption(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = (struct arguments *)state->input;

    switch (key) {
    case 'm':
        arguments->mode = arg;
        break;
    case 'w':
        arguments->websocket = arg;
        break;
    case 't':
        arguments->tun = arg;
        break;
    case 'd':
        arguments->dhcp = arg;
        break;
    case 'p':
        arguments->password = arg;
        break;
    case 'n':
        arguments->name = arg;
        break;
    case 's':
        arguments->stun = arg;
        break;
    case OPT_UDP_BIND_PORT:
        arguments->udpPort = atoi(arg);
        break;
    case OPT_DISCOVERY_INTERVAL:
        arguments->discoveryInterval = atoi(arg);
        break;
    case 'r':
        arguments->routeCost = atoi(arg);
        break;
    case OPT_UDP_P2P_IP:
        arguments->localhost = arg;
        break;
    case 'c':
        parseConfigFile(arguments, arg);
        break;
    case 'v':
        showVersion();
        break;
    case OPT_NO_TIMESTAMP:
        disableLogTimestamp();
        break;
    case OPT_LOG_LEVEL_DEBUG:
        setLogLevelDebug();
        break;
    case OPT_AUTO_RESTART:
        arguments->autoRestart = true;
        break;
    case OPT_EXIT_ON_EOF:
        arguments->exitOnEOF = true;
        break;
    case ARGP_KEY_END:
        if (needShowUsage(arguments, state))
            argp_usage(state);
        break;
    }
    return 0;
}

struct argp config = {
    .options = options,
    .parser = parseOption,
};

#if defined(_WIN32) || defined(_WIN64)

bool netStartup() {
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}

bool netCleanup() {
    return WSACleanup() == 0;
}

std::string storageDirectory = "C:/ProgramData/Candy/";

#else

bool netStartup() {
    return true;
}

bool netCleanup() {
    return true;
}

std::string storageDirectory = "/var/lib/candy/";

#endif

int saveLatestAddress(const std::string &name, const std::string &cidr) {
    std::string cache = storageDirectory + "address/";
    cache += name.empty() ? "__noname__" : name;
    std::filesystem::create_directories(std::filesystem::path(cache).parent_path());
    std::ofstream ofs(cache);
    if (ofs.is_open()) {
        ofs << cidr;
        ofs.close();
    }
    return 0;
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

std::string getVirtualMac(const std::string &name) {
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
}

bool checkStorageDirectory(const struct arguments &arguments) {
    if (arguments.mode != "client") {
        return true;
    }
    if (!arguments.tun.empty()) {
        return true;
    }
    if (!std::filesystem::exists(storageDirectory + "lost")) {
        return true;
    }
    return false;
}

volatile bool running = true;
std::mutex mutex;
std::condition_variable condition;

} // namespace

namespace Candy {
void shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex);
        running = false;
    }
    condition.notify_one();
}
} // namespace Candy

namespace {

volatile int exitCode = 1;

void signalHandler(int signal) {
    exitCode = 0;
    Candy::shutdown();
}

int serve(const struct arguments &arguments) {

    netStartup();

    Candy::Server server;
    Candy::Client client;

    if (arguments.mode == "server") {
        server.setPassword(arguments.password);
        server.setWebSocketServer(arguments.websocket);
        server.setDynamicAddressRange(arguments.dhcp);
        server.run();
    }

    if (arguments.mode == "client") {
        client.setAddressUpdateCallback([&](const std::string &cidr) { saveLatestAddress(arguments.name, cidr); });
        client.setDiscoveryInterval(arguments.discoveryInterval);
        client.setRouteCost(arguments.routeCost);
        client.setUdpBindPort(arguments.udpPort);
        client.setLocalhost(arguments.localhost);
        client.setPassword(arguments.password);
        client.setWebSocketServer(arguments.websocket);
        client.setStun(arguments.stun);
        client.setTunAddress(arguments.tun);
        client.setExpectedAddress(getLastestAddress(arguments.name));
        client.setVirtualMac(getVirtualMac(arguments.name));
        client.setName(arguments.name);
        client.run();
    }

    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&] { return !running; });
    }

    server.shutdown();
    client.shutdown();

    if (exitCode == 0) {
        spdlog::info("service exit: normal");
    } else {
        spdlog::info("service exit: internal exception");
    }

    netCleanup();
    return exitCode;
}
} // namespace

int main(int argc, char *argv[]) {
    struct arguments arguments;
    argp_parse(&config, argc, argv, 0, 0, &arguments);

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    if (!checkStorageDirectory(arguments)) {
        spdlog::critical("tun not config, must set volume: {}", storageDirectory);
        running = false;
    }

    if (arguments.exitOnEOF) {
        std::thread([] {
            std::ios::sync_with_stdio(false);
            std::cin.tie(nullptr);
            std::cout.tie(nullptr);

            while (std::cin.ignore()) {
                if (std::cin.eof()) {
                    signalHandler(SIGTERM);
                    return;
                }
            }
        }).detach();
    }

    while (running && serve(arguments) && arguments.autoRestart) {
        running = true;
        Candy::Time::reset();
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    return exitCode;
}

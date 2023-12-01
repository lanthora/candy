// SPDX-License-Identifier: MIT
#if defined(_WIN32) || defined(_WIN64)

#include "core/client.h"
#include "core/server.h"
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <libconfig.h++>
#include <mutex>
#include <signal.h>
#include <spdlog/spdlog.h>
#include <winsock.h>

namespace {

struct arguments {
    std::string mode;
    std::string websocket;
    std::string tun;
    std::string dhcp;
    std::string password;
    std::string name;
    std::string stun;
};

volatile int exitCode = 0;
bool running = true;
std::mutex mutex;
std::condition_variable condition;

void signalHandler(int signal) {
    {
        std::lock_guard<std::mutex> lock(mutex);
        running = false;
    }
    condition.notify_one();
}

bool windowsNetworkStartup() {
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}

bool windowsNetworkCleanup() {
    return WSACleanup() == 0;
}

int saveLatestAddress(const std::string &name, const std::string &cidr) {
    std::string cfgFile = "address/";
    cfgFile += name.empty() ? "__noname__" : name;
    std::filesystem::create_directories(std::filesystem::path(cfgFile).parent_path());
    std::ofstream ofs(cfgFile);
    if (ofs.is_open()) {
        ofs << cidr;
        ofs.close();
    }
    return 0;
}

std::string getLastestAddress(const std::string &name) {
    std::string cfgFile = "address/";
    cfgFile += name.empty() ? "__noname__" : name;
    std::ifstream ifs(cfgFile);
    if (!ifs.is_open()) {
        return "";
    }
    std::stringstream ss;
    ss << ifs.rdbuf();
    ifs.close();
    return ss.str();
}

} // namespace

namespace Candy {
void shutdown() {
    exitCode = 1;
    signalHandler(SIGTERM);
}
} // namespace Candy

int main() {
    windowsNetworkStartup();

    Candy::Server server;
    Candy::Client client;
    struct arguments arguments;

    try {
        libconfig::Config cfg;
        cfg.readFile("candy.conf");
        cfg.lookupValue("mode", arguments.mode);
        cfg.lookupValue("websocket", arguments.websocket);
        cfg.lookupValue("tun", arguments.tun);
        cfg.lookupValue("dhcp", arguments.dhcp);
        cfg.lookupValue("stun", arguments.stun);
        cfg.lookupValue("password", arguments.password);
        cfg.lookupValue("name", arguments.name);
    } catch (const libconfig::FileIOException &fioex) {
        spdlog::critical("i/o error while reading configuration file");
        return 0;
    } catch (const libconfig::ParseException &pex) {
        spdlog::critical("parse error at {} : {} - {}", pex.getFile(), pex.getLine(), pex.getError());
        return 0;
    }

    if (arguments.mode == "server") {
        server.setPassword(arguments.password);
        server.setWebSocketServer(arguments.websocket);
        server.setDynamicAddressRange(arguments.dhcp);
        server.run();
    }

    if (arguments.mode == "client") {
        client.setPassword(arguments.password);
        client.setWebSocketServer(arguments.websocket);
        client.setStun(arguments.stun);
        client.setLocalAddress(arguments.tun);
        client.setDynamicAddress(getLastestAddress(arguments.name));
        client.setName(arguments.name);
        client.run();
    }

    spdlog::info("service started successfully");

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&] { return !running; });
    }

    server.shutdown();
    client.shutdown();

    if (!client.getAddress().empty()) {
        saveLatestAddress(arguments.name, client.getAddress());
    }

    windowsNetworkCleanup();

    spdlog::info("service stopped successfully");
    return exitCode;
}

#endif

// SPDX-License-Identifier: MIT
#if defined(__linux__) || defined(__linux)

#include "core/client.h"
#include "core/server.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <argp.h>
#include <condition_variable>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <libconfig.h++>
#include <mutex>
#include <spdlog/spdlog.h>
#include <string>

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

const int OPT_NO_TIMESTAMP = 1;
const int OPT_LOG_LEVEL_DEBUG = 2;

struct argp_option options[] = {
    {"mode", 'm', "MODE", 0,
     "Select work mode. MODE must choose one of the following values: server, client. When MODE is server, the websocket service "
     "will be started. When MODE is client, a connection will be initiated to the websocket service. At the same time, IP layer "
     "data forwarding will be performed through tun."},
    {"websocket", 'w', "URI", 0,
     "Set websocket address and port. when running as a server, You can choose to encrypt traffic with nginx. This service only "
     "handles unencrypted data. You can configure ws://127.0.0.1:80 only to monitor local requests. Except for testing needs, it "
     "is recommended that the client configure TLS Encryption. e.g. wss://domain:443"},
    {"tun", 't', "CIDR", 0,
     "Set the virtual IP address and subnet. Use CIDR format, e.g. 172.16.1.1/16. Not setting this configuration means using the "
     "address dynamically allocated by the server"},
    {"dhcp", 'd', "CIDR", 0,
     "The server automatically assigns the client IP address. The assigned address conforms to the current subnet. If this "
     "option is not configured, this function is not enabled. e.g. 172.16.0.0/16"},
    {"password", 'p', "TEXT", 0,
     "The password used for authentication. Client and server require the same value, this value will not be passed across the "
     "network"},
    {"name", 'n', "TEXT", 0,
     "Interface name suffix. Used to avoid name collisions when using multiple clients in the same network namespace"},
    {"stun", 's', "URI", 0,
     "stun server address, used to obtain the public network address of the peer communication. For example: stun://stun.qq.com"},
    {"config", 'c', "PATH", 0,
     "Configuration file path. All other configuration items can be configured through the configuration file"},
    {"no-timestamp", OPT_NO_TIMESTAMP, 0, 0,
     "Do not record the log time, in order to avoid redundant display of time with other tools such as systemd"},
    {"debug", OPT_LOG_LEVEL_DEBUG, 0, 0, "Output debug level log"},
    {},
};

int disableLogTimestamp() {
    auto logger = spdlog::stdout_color_mt("candy");
    logger->set_pattern("[%^%l%$] %v");
    spdlog::set_default_logger(logger);
    return 0;
}

int setLogLevelDebug() {
    spdlog::set_level(spdlog::level::debug);
    spdlog::debug("set log level: debug");
    return 0;
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
        cfg.readFile(config);
        cfg.lookupValue("mode", arguments->mode);
        cfg.lookupValue("websocket", arguments->websocket);
        cfg.lookupValue("tun", arguments->tun);
        cfg.lookupValue("dhcp", arguments->dhcp);
        cfg.lookupValue("stun", arguments->stun);
        cfg.lookupValue("password", arguments->password);
        cfg.lookupValue("name", arguments->name);
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
    case 'c':
        parseConfigFile(arguments, arg);
        break;
    case OPT_NO_TIMESTAMP:
        disableLogTimestamp();
        break;
    case OPT_LOG_LEVEL_DEBUG:
        setLogLevelDebug();
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

bool running = true;
std::mutex mutex;
std::condition_variable condition;

void shutdown(int signal) {
    {
        std::lock_guard<std::mutex> lock(mutex);
        running = false;
    }
    condition.notify_one();
}

int saveLatestAddress(const std::string &name, const std::string &cidr) {
    std::string cfgFile = "/var/lib/candy/address/";
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
    std::string cfgFile = "/var/lib/candy/address/";
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

}; // namespace

namespace Candy {
void shutdown() {
    ::shutdown(SIGQUIT);
}
} // namespace Candy

int main(int argc, char *argv[]) {
    Candy::Server server;
    Candy::Client client;

    struct arguments arguments;
    argp_parse(&config, argc, argv, 0, 0, &arguments);

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

    std::signal(SIGINT, shutdown);
    std::signal(SIGTERM, shutdown);

    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&] { return !running; });
    }

    server.shutdown();
    client.shutdown();

    if (!client.getAddress().empty()) {
        saveLatestAddress(arguments.name, client.getAddress());
    }

    spdlog::info("service stopped successfully");

    return 0;
}

#endif

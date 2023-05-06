// SPDX-License-Identifier: MIT
#include "client.h"
#include "server.h"
#include "util.h"
#include <argp.h>
#include <csignal>
#include <filesystem>
#include <libconfig.h++>
#include <spdlog/spdlog.h>

static volatile bool running = true;
static void handleSignal(int signum) {
    running = false;
}

static void waitExit() {
    int64_t current = 0;
    int64_t last = candy::unixTimeStamp();

    signal(SIGINT, handleSignal);
    signal(SIGTERM, handleSignal);

    while (running) {
        sleep(1);
        current = candy::unixTimeStamp();
        if (std::abs(current - last) > 2)
            break;
        last = current;
    }
}

struct arguments {
    std::string mode;
    std::string websocket;
    std::string tun;
    std::string password;
    std::string name;
};

static const struct argp_option options[] = {
    {"mode", 'm', "MODE", 0,
     "Select work mode. MODE must choose one of the following values: server, client, mixed. When MODE is server, the "
     "websocket service will be started. When MODE is client, a connection will be initiated to the websocket service. "
     "At the same time, IP layer data forwarding will be performed through tun. When MODE is mixed, it works as server "
     "and client at the same time."},
    {"websocket", 'w', "URI", 0,
     "Set websocket address and port. when running as a server, You can choose to encrypt traffic with nginx. This "
     "service only handles unencrypted data. You can configure ws://127.0.0.1:80 only to monitor local requests. "
     "Except for testing needs, it is recommended that the client configure TLS Encryption. e.g. wss://domain:443"},
    {"tun", 't', "IP", 0,
     "Set local virtual IP and subnet mask. IP is address and subnet in CIDR notation. e.g. 10.0.0.1/24"},
    {"password", 'p', "TEXT", 0, "Password for simple authentication"},
    {"name", 'n', "TEXT", 0, "Interface name suffix"},
    {"config", 'c', "PATH", 0, "Configuration file path"},
    {},
};

static bool needShowUsage(struct arguments *arguments, struct argp_state *state) {
    if (state->arg_num > 0)
        return true;

    if (arguments->mode.empty())
        return true;

    if (arguments->websocket.empty())
        return true;

    if (arguments->tun.empty() && arguments->mode != "server")
        return true;

    return false;
}

static void parseConfigFile(struct arguments *arguments, std::string config) {
    try {
        libconfig::Config cfg;
        cfg.readFile(config);
        cfg.lookupValue("mode", arguments->mode);
        cfg.lookupValue("websocket", arguments->websocket);
        cfg.lookupValue("tun", arguments->tun);
        cfg.lookupValue("password", arguments->password);
        cfg.lookupValue("name", arguments->name);

        if (config != "/etc/candy.conf" && arguments->name.empty()) {
            std::filesystem::path path = config;
            arguments->name = path.stem();
        }

    } catch (const libconfig::FileIOException &fioex) {
        spdlog::critical("I/O error while reading configuration file");
        exit(1);
    } catch (const libconfig::ParseException &pex) {
        spdlog::critical("Parse error at {0} : {1} - {2}", pex.getFile(), pex.getLine(), pex.getError());
        exit(1);
    }
}

static int parseOption(int key, char *arg, struct argp_state *state) {
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
    case 'p':
        arguments->password = arg;
        break;
    case 'n':
        arguments->name = arg;
        break;
    case 'c':
        parseConfigFile(arguments, arg);
        break;
    case ARGP_KEY_END:
        if (needShowUsage(arguments, state))
            argp_usage(state);
        break;
    }
    return 0;
}

static const struct argp argp = {
    .options = options,
    .parser = parseOption,
};

int main(int argc, char *argv[]) {
    struct arguments arguments;
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    std::shared_ptr<candy::Server> server;
    std::shared_ptr<candy::Client> client;

    if (arguments.mode == "mixed" || arguments.mode == "server") {
        server = std::make_shared<candy::Server>();
        server->setPassword(arguments.password);
        server->setWebsocketServer(arguments.websocket);
        std::thread([&]() { server->start(); }).detach();
    }

    if (arguments.mode == "mixed" || arguments.mode == "client") {
        client = std::make_shared<candy::Client>();
        client->setPassword(arguments.password);
        client->setWebsocketServer(arguments.websocket);
        client->setTun(arguments.tun, arguments.name);
        std::thread([&]() { client->start(); }).detach();
    }

    waitExit();

    if (client) {
        client->stop();
    }

    if (server) {
        server->stop();
    }

    return 0;
}

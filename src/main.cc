#include "client.h"
#include "server.h"
#include <spdlog/spdlog.h>
#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <set>

static volatile bool running = true;
static void handleSignal(int signum) {
    running = false;
}

struct arguments {
    std::string mode;
    std::string websocket;
    std::string tun;
    std::string password;
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
        client->setTun(arguments.tun);
        std::thread([&]() { client->start(); }).detach();
    }

    signal(SIGINT, handleSignal);
    signal(SIGTERM, handleSignal);

    while (running) {
        sleep(1);
    }

    if (client) {
        client->stop();
    }

    if (server) {
        server->stop();
    }

    return 0;
}

// SPDX-License-Identifier: MIT
#include "core/client.h"
#include "core/server.h"
#include "main/config.h"
#include "utility/time.h"
#include <atomic>
#include <signal.h>
#include <spdlog/spdlog.h>
#include <string>

std::atomic<bool> running = true;

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

int exitCode = 1;

int serve(const arguments &args) {

    Poco::Net::initializeNetwork();

    if (args.mode == "server") {
        Candy::Server server;
        server.setPassword(args.password);
        server.setWebSocket(args.websocket);
        server.setDHCP(args.dhcp);
        server.setSdwan(args.sdwan);
        server.run();
        running.wait(true);
        server.shutdown();
    }

    if (args.mode == "client") {
        Candy::Client client;
        client.setDiscoveryInterval(args.discovery);
        client.setRouteCost(args.routeCost);
        client.setPort(args.udpPort);
        client.setLocalhost(args.localhost);
        client.setPassword(args.password);
        client.setWebSocket(args.websocket);
        client.setStun(args.stun);
        client.setTunAddress(args.tun);
        client.setExptTunAddress(loadTunAddress(args.name));
        client.setVirtualMac(virtualMac(args.name));
        client.setMtu(args.mtu);
        client.setName(args.name);
        client.setTunUpdateCallback([&](auto tunCidr) { return saveTunAddress(args.name, tunCidr); });
        client.run();
        running.wait(true);
        client.shutdown();
    }

    if (exitCode == 0) {
        spdlog::info("service exit: normal");
    } else {
        spdlog::info("service exit: internal exception");
    }

    Poco::Net::uninitializeNetwork();
    return exitCode;
}

void signalHandler(int signal) {
    exitCode = 0;
    running = false;
    running.notify_one();
}

int main(int argc, char *argv[]) {
    arguments args;
    args.parse(argc, argv);

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    if (!hasContainerVolume(args)) {
        spdlog::critical("the container needs to add a storage volume: {}", storageDirectory());
        running = false;
    }

    Candy::ntpServer = args.ntp;

    while (running && serve(args) && args.restart) {
        running = true;
        Candy::useSystemTime = false;
        spdlog::info("service will restart in {} seconds", args.restart);
        std::this_thread::sleep_for(std::chrono::seconds(args.restart));
    }

    spdlog::drop_all();
    spdlog::shutdown();
    return exitCode;
}

// SPDX-License-Identifier: MIT
#include "core/client.h"
#include "core/server.h"
#include "main/config.h"
#include "utils/time.h"
#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <signal.h>
#include <spdlog/spdlog.h>
#include <string>

template <typename T> class Atomic {
public:
    explicit Atomic(T initial = T()) : value_(initial) {}

    T load() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return value_;
    }

    void store(T new_value) {
        std::lock_guard<std::mutex> lock(mutex_);
        value_ = new_value;
        cv_.notify_all();
    }

    void wait(const T &expected) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this, &expected] { return value_ != expected; });
    }

    template <typename Predicate> void wait_until(Predicate pred) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, pred);
    }

    void notify_one() {
        std::lock_guard<std::mutex> lock(mutex_);
        cv_.notify_one();
    }

    void notify_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        cv_.notify_all();
    }

private:
    T value_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
};

Atomic<bool> running(true);

namespace Candy {

void shutdown(Client *client) {
    running.store(false);
}

void shutdown(Server *server) {
    running.store(false);
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
        client.setPort(args.port);
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
    running.store(false);
}

int main(int argc, char *argv[]) {
    arguments args;
    args.parse(argc, argv);

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    if (!hasContainerVolume(args)) {
        spdlog::critical("the container needs to add a storage volume: {}", storageDirectory());
        running.store(false);
    }

    Candy::ntpServer = args.ntp;

    while (running.load() && serve(args) && args.restart) {
        running.store(true);
        Candy::useSystemTime = false;
        spdlog::info("service will restart in {} seconds", args.restart);
        std::this_thread::sleep_for(std::chrono::seconds(args.restart));
    }

    spdlog::drop_all();
    spdlog::shutdown();
    return exitCode;
}

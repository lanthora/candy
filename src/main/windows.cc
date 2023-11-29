// SPDX-License-Identifier: MIT
#if defined(_WIN32) || defined(_WIN64)

#include "core/client.h"
#include <condition_variable>
#include <mutex>
#include <signal.h>
#include <spdlog/spdlog.h>
#include <winsock.h>

namespace {

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
    WORD version;
    WSADATA data;

    version = MAKEWORD(2, 2);
    return WSAStartup(version, &data) == 0;
}

bool windowsNetworkCleanup() {
    return WSACleanup() == 0;
}

} // namespace

namespace Candy {
void shutdown() {
    signalHandler(SIGTERM);
}
} // namespace Candy

// TODO(windows): 实现 Windows 的主函数
int main() {
    windowsNetworkStartup();

    Candy::Client client;
    client.setWebSocketServer("wss://zone.icandy.one/demo");
    client.setName("demo");
    client.run();

    spdlog::info("service started successfully");

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&] { return !running; });
    }

    client.shutdown();
    windowsNetworkCleanup();

    spdlog::info("service stopped successfully");
    return 0;
}

#endif

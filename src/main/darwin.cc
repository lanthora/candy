// SPDX-License-Identifier: MIT
#if defined(__APPLE__) || defined(__MACH__)

#include "core/client.h"
#include <condition_variable>
#include <csignal>
#include <mutex>
#include <spdlog/spdlog.h>

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

namespace Candy {
void shutdown() {
    ::shutdown(SIGQUIT);
}
} // namespace Candy

int main() {
    spdlog::set_level(spdlog::level::debug);
    Candy::Client client;

    // TODO(macos): 用某种方式动态配置参数.现在的配置仅能用来连接 demo 环境.
    client.setWebSocketServer("wss://zone.icandy.one/demo");
    client.setName("candy-demo");
    client.setStun("stun://stun.qq.com");
    client.run();

    spdlog::info("service started successfully");

    std::signal(SIGINT, shutdown);
    std::signal(SIGTERM, shutdown);

    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&] { return !running; });
    }

    client.shutdown();

    spdlog::info("service stopped successfully");

    return 0;
}

#endif

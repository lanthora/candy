#include "candy/candy.h"
#include "config.h"
#include <signal.h>
#include <spdlog/spdlog.h>

int main(int argc, char *argv[]) {
    arguments args;
    args.parse(argc, argv);
    auto config = args.json();

    if (config.getValue<std::string>("mode") == "client") {
        static const std::string id = "cli";

        auto handler = [](int) -> void { candy::client::shutdown(id); };

        signal(SIGINT, handler);
        signal(SIGTERM, handler);

        std::thread([&]() {
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                auto status = candy::client::status(id);
                if (status && (*status).has("address")) {
                    std::string address = (*status).getValue<std::string>("address");
                    if (!address.empty()) {
                        saveTunAddress(config.getValue<std::string>("name"), address);
                        break;
                    }
                }
            }
        }).detach();

        candy::client::run(id, config);
        return 0;
    }

    if (config.getValue<std::string>("mode") == "server") {
        auto handler = [](int) -> void { candy::server::shutdown(); };

        signal(SIGINT, handler);
        signal(SIGTERM, handler);

        candy::server::run(config);
        return 0;
    }

    return -1;
}

// SPDX-License-Identifier: MIT
#include "candy/client.h"
#include "core/client.h"
#include "utils/atomic.h"
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <shared_mutex>
#include <spdlog/spdlog.h>

namespace candy {
namespace client {

namespace {
using Utils::Atomic;

class Instance {
public:
    bool is_running() {
        return this->running.load();
    }

    void exit() {
        this->running.store(false);
        if (auto client = this->client.lock()) {
            client->shutdown();
        }
    }

    nlohmann::json status() {
        nlohmann::json data;
        if (auto client = this->client.lock()) {
            data["address"] = client->getTunCidr();
        }
        return data;
    }

    std::shared_ptr<Client> create_client() {
        auto client = std::make_shared<Client>();
        this->client = client;
        return client;
    }

private:
    Atomic<bool> running = Atomic(true);
    std::weak_ptr<Client> client;
};

std::map<std::string, std::shared_ptr<Instance>> instance_map;
std::shared_mutex instance_mutex;

std::optional<std::shared_ptr<Instance>> try_create_instance(const std::string &id) {
    std::unique_lock lock(instance_mutex);
    auto it = instance_map.find(id);
    if (it != instance_map.end()) {
        spdlog::warn("instance already exists: id={}", id);
        return std::nullopt;
    }
    auto manager = std::make_shared<Instance>();
    instance_map.emplace(id, manager);
    return manager;
}

bool try_erase_instance(const std::string &id) {
    std::unique_lock lock(instance_mutex);
    return instance_map.erase(id) > 0;
}

} // namespace

bool run(const std::string &id, const nlohmann::json &config) {
    auto instance = try_create_instance(id);
    if (!instance) {
        return false;
    }

    spdlog::info("run enter: id={} config={}", id, config.dump(4));
    while ((*instance)->is_running()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto client = (*instance)->create_client();
        client->setName(config["name"]);
        client->setPassword(config["password"]);
        client->setWebSocket(config["websocket"]);
        client->setTunAddress(config["tun"]);
        client->setVirtualMac(config["vmac"]);
        client->setExptTunAddress(config["expt"]);
        client->setStun(config["stun"]);
        client->setDiscoveryInterval(config["discovery"]);
        client->setRouteCost(config["route"]), client->setMtu(config["mtu"]);
        client->setPort(config["port"]);
        client->setLocalhost(config["localhost"]);
        client->run();
    }
    spdlog::info("run exit: id={} ", id);

    return try_erase_instance(id);
}

bool shutdown(const std::string &id) {
    std::shared_lock lock(instance_mutex);
    auto it = instance_map.find(id);
    if (it == instance_map.end()) {
        spdlog::warn("instance not found: id={}", id);
        return false;
    }
    if (auto instance = it->second) {
        instance->exit();
    }
    return true;
}

std::optional<nlohmann::json> status(const std::string &id) {
    std::shared_lock lock(instance_mutex);
    auto it = instance_map.find(id);
    if (it != instance_map.end()) {
        if (auto instance = it->second) {
            return instance->status();
        }
    }
    return std::nullopt;
}

} // namespace client
} // namespace candy

// SPDX-License-Identifier: MIT
#include "candy/client.h"
#include "core/client.h"
#include "utils/atomic.h"
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Stringifier.h>
#include <map>
#include <memory>
#include <mutex>
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

    Poco::JSON::Object status() {
        Poco::JSON::Object data;
        if (auto client = this->client.lock()) {
            data.set("address", client->getTunCidr());
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

bool run(const std::string &id, const Poco::JSON::Object &config) {
    auto instance = try_create_instance(id);
    if (!instance) {
        return false;
    }

    auto toString = [](const Poco::JSON::Object &obj) -> std::string {
        std::ostringstream oss;
        Poco::JSON::Stringifier::stringify(obj, oss);
        return oss.str();
    };

    spdlog::info("run enter: id={} config={}", id, toString(config));
    while ((*instance)->is_running()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto client = (*instance)->create_client();
        client->setName(config.getValue<std::string>("name"));
        client->setPassword(config.getValue<std::string>("password"));
        client->setWebSocket(config.getValue<std::string>("websocket"));
        client->setTunAddress(config.getValue<std::string>("tun"));
        client->setVirtualMac(config.getValue<std::string>("vmac"));
        client->setExptTunAddress(config.getValue<std::string>("expt"));
        client->setStun(config.getValue<std::string>("stun"));
        client->setDiscoveryInterval(config.getValue<int>("discovery"));
        client->setRouteCost(config.getValue<int>("route")), client->setMtu(config.getValue<int>("mtu"));
        client->setPort(config.getValue<int>("port"));
        client->setLocalhost(config.getValue<std::string>("localhost"));
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

std::optional<Poco::JSON::Object> status(const std::string &id) {
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

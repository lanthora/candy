// SPDX-License-Identifier: MIT
#include "cffi/candy.h"
#include "core/client.h"
#include "utility/time.h"
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/spdlog.h>
#include <stdlib.h>

void candy_init() {}

void *candy_client_create() {
    Candy::Client *c = new Candy::Client();
    return c;
}

void candy_client_release(void *candy) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    delete c;
}

void candy_client_set_name(void *candy, const char *name) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setName(name);
}

void candy_client_set_password(void *candy, const char *password) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setPassword(password);
}

void candy_client_set_websocket(void *candy, const char *server) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setWebSocket(server);
}

void candy_client_set_tun_address(void *candy, const char *cidr) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setTunAddress(cidr);
}

void candy_client_set_expt_tun_address(void *candy, const char *cidr) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setExptTunAddress(cidr);
}

void candy_client_set_virtual_mac(void *candy, const char *vmac) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setVirtualMac(vmac);
}

void candy_client_set_stun(void *candy, const char *stun) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setStun(stun);
}

void candy_client_set_discovery_interval(void *candy, int interval) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setDiscoveryInterval(interval);
}

void candy_client_set_route_cost(void *candy, int cost) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setRouteCost(cost);
}

void candy_client_set_mtu(void *candy, int mtu) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setMtu(mtu);
}

void candy_client_set_tun_update_callback(void *candy, void (*callback)(const char *, const char *)) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setTunUpdateCallback([=](const std::string &address) {
        callback(c->getName().c_str(), address.c_str());
        return 0;
    });
}

void candy_client_set_port(void *candy, int port) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setPort(port);
}

void candy_client_set_localhost(void *candy, const char *ip) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->setLocalhost(ip);
}

void candy_client_run(void *candy) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->run();
}

void candy_client_shutdown(void *candy) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    c->shutdown();
}

namespace {
void (*client_error_cb)(void *) = NULL;
}

namespace Candy {
void shutdown(Client *c) {
    if (client_error_cb) {
        client_error_cb(c);
    } else {
        exit(1);
    }
}
} // namespace Candy

void candy_client_set_error_cb(void (*callback)(void *)) {
    client_error_cb = callback;
}

void candy_use_system_time() {
    Candy::useSystemTime = true;
}

void candy_set_log_path(const char *path) {
    auto max_size = 1048576 * 5;
    auto max_files = 3;
    auto logger = spdlog::rotating_logger_mt("candy", path, max_size, max_files, true);
    spdlog::set_default_logger(logger);
    spdlog::flush_every(std::chrono::seconds(1));
}

void candy_enable_debug() {
    spdlog::set_level(spdlog::level::debug);
}

void candy_release() {
    spdlog::drop_all();
    spdlog::shutdown();
}

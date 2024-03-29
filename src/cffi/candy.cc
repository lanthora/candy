// SPDX-License-Identifier: MIT
#include "cffi/candy.h"
#include "core/client.h"
#include <stdlib.h>

void *candy_client_create() {
    Candy::Client *c = new Candy::Client();
    return c;
}

void candy_client_release(void *candy) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    delete c;
}

int candy_client_set_name(void *candy, const char *name) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setName(name);
}

int candy_client_set_password(void *candy, const char *password) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setPassword(password);
}

int candy_client_set_websocket_server(void *candy, const char *server) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setWebSocketServer(server);
}

int candy_client_set_tun_address(void *candy, const char *cidr) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setTunAddress(cidr);
}

int candy_client_set_expected_address(void *candy, const char *cidr) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setExpectedAddress(cidr);
}

int candy_client_set_virtual_mac(void *candy, const char *vmac) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setVirtualMac(vmac);
}

int candy_client_set_stun(void *candy, const char *stun) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setStun(stun);
}

int candy_client_set_discovery_interval(void *candy, int interval) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setDiscoveryInterval(interval);
}

int candy_client_set_route_cost(void *candy, int cost) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setRouteCost(cost);
}

int candy_client_set_address_update_callback(void *candy, void (*callback)(const char *)) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setAddressUpdateCallback([&](const std::string address) { callback(address.c_str()); });
}

int candy_client_set_udp_bind_port(void *candy, int port) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setUdpBindPort(port);
}

int candy_client_set_localhost(void *candy, char *ip) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->setLocalhost(ip);
}

int candy_client_run(void *candy) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->run();
}

int candy_client_shutdown(void *candy) {
    Candy::Client *c = static_cast<Candy::Client *>(candy);
    return c->shutdown();
}

namespace {
void (*internal_error_cb)(void *) = NULL;
}

namespace Candy {
void shutdown(Client *c) {
    if (internal_error_cb) {
        internal_error_cb(c);
    } else {
        exit(1);
    }
}
} // namespace Candy

int candy_client_set_error_cb(void (*callback)(void *)) {
    internal_error_cb = callback;
    return 0;
}

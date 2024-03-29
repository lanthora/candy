// SPDX-License-Identifier: MIT
#ifndef CANDY_CFFI_CANDY_H
#define CANDY_CFFI_CANDY_H

extern "C" {
void *candy_client_create();
void candy_client_release(void *candy);
int candy_client_set_name(void *candy, const char *&name);
int candy_client_set_password(void *candy, const char *&password);
int candy_client_set_websocket_server(void *candy, const char *&server);
int candy_client_set_tun_address(void *candy, const char *&cidr);
int candy_client_set_expected_address(void *candy, const char *&cidr);
int candy_client_set_virtual_mac(void *candy, const char *&vmac);
int candy_client_set_stun(void *candy, const char *&stun);
int candy_client_set_discovery_interval(void *candy, int interval);
int candy_client_set_route_cost(void *candy, int cost);
int candy_client_set_address_update_callback(void *candy, void (*callback)(const char *));
int candy_client_set_udp_bind_port(void *candy, int port);
int candy_client_set_localhost(void *candy, char *ip);
int candy_client_run(void *candy);
int candy_client_shutdown(void *candy);
int candy_client_set_internal_error_cb(void (*callback)());
}

#endif

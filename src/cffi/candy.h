// SPDX-License-Identifier: MIT
#ifndef CANDY_CFFI_CANDY_H
#define CANDY_CFFI_CANDY_H

#ifdef __cplusplus
extern "C" {
#endif

void candy_init();
void *candy_client_create();
int candy_client_set_name(void *candy, const char *name);
int candy_client_set_password(void *candy, const char *password);
int candy_client_set_websocket_server(void *candy, const char *server);
int candy_client_set_tun_address(void *candy, const char *cidr);
int candy_client_set_expected_address(void *candy, const char *cidr);
int candy_client_set_virtual_mac(void *candy, const char *vmac);
int candy_client_set_stun(void *candy, const char *stun);
int candy_client_set_discovery_interval(void *candy, int interval);
int candy_client_set_route_cost(void *candy, int cost);
int candy_client_set_mtu(void *candy, int mtu);
int candy_client_set_udp_bind_port(void *candy, int port);
int candy_client_set_localhost(void *candy, const char *ip);
int candy_client_set_address_update_callback(void *candy, void (*callback)(const char *, const char *));
int candy_client_set_error_cb(void (*callback)(void *));
int candy_client_run(void *candy);
int candy_client_shutdown(void *candy);
void candy_client_release(void *candy);
void candy_use_system_time();
void candy_set_log_path(const char *path);
void candy_enable_debug();
void candy_release();

#ifdef __cplusplus
}
#endif

#endif

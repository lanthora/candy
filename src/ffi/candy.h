// SPDX-License-Identifier: MIT
#ifndef CANDY_FFI_CANDY_H
#define CANDY_FFI_CANDY_H

#ifdef __cplusplus
extern "C" {
#endif

void candy_init();
void *candy_client_create();
void candy_client_set_name(void *candy, const char *name);
void candy_client_set_password(void *candy, const char *password);
void candy_client_set_websocket(void *candy, const char *server);
void candy_client_set_tun_address(void *candy, const char *cidr);
void candy_client_set_expt_tun_address(void *candy, const char *cidr);
void candy_client_set_virtual_mac(void *candy, const char *vmac);
void candy_client_set_stun(void *candy, const char *stun);
void candy_client_set_discovery_interval(void *candy, int interval);
void candy_client_set_route_cost(void *candy, int cost);
void candy_client_set_mtu(void *candy, int mtu);
void candy_client_set_port(void *candy, int port);
void candy_client_set_localhost(void *candy, const char *ip);
void candy_client_set_address_update_callback(void *candy, void (*callback)(const char *, const char *));
void candy_client_set_error_cb(void (*callback)(void *));
void candy_client_run(void *candy);
void candy_client_shutdown(void *candy);
void candy_client_release(void *candy);
void candy_use_system_time();
void candy_set_log_path(const char *path);
void candy_enable_debug();
void candy_release();

#ifdef __cplusplus
}
#endif

#endif

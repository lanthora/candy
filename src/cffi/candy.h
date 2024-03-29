// SPDX-License-Identifier: MIT
#ifndef CANDY_CFFI_CANDY_H
#define CANDY_CFFI_CANDY_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT int candy_client_set_error_cb(void (*callback)(void *));
EXPORT void *candy_client_create();
EXPORT int candy_client_set_name(void *candy, const char *name);
EXPORT int candy_client_set_password(void *candy, const char *password);
EXPORT int candy_client_set_websocket_server(void *candy, const char *server);
EXPORT int candy_client_set_tun_address(void *candy, const char *cidr);
EXPORT int candy_client_set_expected_address(void *candy, const char *cidr);
EXPORT int candy_client_set_virtual_mac(void *candy, const char *vmac);
EXPORT int candy_client_set_stun(void *candy, const char *stun);
EXPORT int candy_client_set_discovery_interval(void *candy, int interval);
EXPORT int candy_client_set_route_cost(void *candy, int cost);
EXPORT int candy_client_set_udp_bind_port(void *candy, int port);
EXPORT int candy_client_set_localhost(void *candy, char *ip);
EXPORT int candy_client_set_address_update_callback(void *candy, void (*callback)(const char *));
EXPORT int candy_client_run(void *candy);
EXPORT int candy_client_shutdown(void *candy);
EXPORT void candy_client_release(void *candy);

#ifdef __cplusplus
}
#endif

#endif

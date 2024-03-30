// SPDX-License-Identifier: MIT
#ifndef CANDY_CFFI_CANDY_H
#define CANDY_CFFI_CANDY_H

#ifdef _WIN32
#define IMPORT __declspec(dllimport)
#else
#define IMPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

IMPORT void *candy_client_create();
IMPORT int candy_client_set_name(void *candy, const char *name);
IMPORT int candy_client_set_password(void *candy, const char *password);
IMPORT int candy_client_set_websocket_server(void *candy, const char *server);
IMPORT int candy_client_set_tun_address(void *candy, const char *cidr);
IMPORT int candy_client_set_expected_address(void *candy, const char *cidr);
IMPORT int candy_client_set_virtual_mac(void *candy, const char *vmac);
IMPORT int candy_client_set_stun(void *candy, const char *stun);
IMPORT int candy_client_set_discovery_interval(void *candy, int interval);
IMPORT int candy_client_set_route_cost(void *candy, int cost);
IMPORT int candy_client_set_udp_bind_port(void *candy, int port);
IMPORT int candy_client_set_localhost(void *candy, char *ip);
IMPORT int candy_client_set_address_update_callback(void *candy, void (*callback)(const char *));
IMPORT int candy_client_set_error_cb(void (*callback)(void *));
IMPORT int candy_client_run(void *candy);
IMPORT int candy_client_shutdown(void *candy);
IMPORT void candy_client_release(void *candy);

#ifdef __cplusplus
}
#endif

#endif

// SPDX-License-Identifier: MIT
#ifndef CANDY_CFFI_CANDY_H
#define CANDY_CFFI_CANDY_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#ifdef LIBRARY_EXPORTS
#define LIBRARY_API __declspec(dllexport)
#else
#define LIBRARY_API __declspec(dllimport)
#endif
#else
#define LIBRARY_API
#endif

LIBRARY_API int candy_client_set_error_cb(void (*callback)(void *));
LIBRARY_API void *candy_client_create();
LIBRARY_API int candy_client_set_name(void *candy, const char *name);
LIBRARY_API int candy_client_set_password(void *candy, const char *password);
LIBRARY_API int candy_client_set_websocket_server(void *candy, const char *server);
LIBRARY_API int candy_client_set_tun_address(void *candy, const char *cidr);
LIBRARY_API int candy_client_set_expected_address(void *candy, const char *cidr);
LIBRARY_API int candy_client_set_virtual_mac(void *candy, const char *vmac);
LIBRARY_API int candy_client_set_stun(void *candy, const char *stun);
LIBRARY_API int candy_client_set_discovery_interval(void *candy, int interval);
LIBRARY_API int candy_client_set_route_cost(void *candy, int cost);
LIBRARY_API int candy_client_set_udp_bind_port(void *candy, int port);
LIBRARY_API int candy_client_set_localhost(void *candy, char *ip);
LIBRARY_API int candy_client_set_address_update_callback(void *candy, void (*callback)(const char *));
LIBRARY_API int candy_client_run(void *candy);
LIBRARY_API int candy_client_shutdown(void *candy);
LIBRARY_API void candy_client_release(void *candy);

#ifdef __cplusplus
}
#endif

#endif

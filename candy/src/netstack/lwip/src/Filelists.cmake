set(lwipcore_SRCS
    ${LWIP_DIR}/src/core/init.c
    ${LWIP_DIR}/src/core/def.c
    ${LWIP_DIR}/src/core/inet_chksum.c
    ${LWIP_DIR}/src/core/ip.c
    ${LWIP_DIR}/src/core/mem.c
    ${LWIP_DIR}/src/core/memp.c
    ${LWIP_DIR}/src/core/netif.c
    ${LWIP_DIR}/src/core/pbuf.c
    ${LWIP_DIR}/src/core/stats.c
    ${LWIP_DIR}/src/core/sys.c
    ${LWIP_DIR}/src/core/tcp.c
    ${LWIP_DIR}/src/core/tcp_in.c
    ${LWIP_DIR}/src/core/tcp_out.c
    ${LWIP_DIR}/src/core/timeouts.c
    ${LWIP_DIR}/src/core/udp.c
)

set(lwipcore4_SRCS
    ${LWIP_DIR}/src/core/ipv4/ip4.c
    ${LWIP_DIR}/src/core/ipv4/ip4_addr.c
    ${LWIP_DIR}/src/core/ipv4/ip4_frag.c
    ${LWIP_DIR}/src/core/ipv4/icmp.c
    ${LWIP_DIR}/src/core/ipv4/etharp.c
)

set(lwipapi_SRCS
    ${LWIP_DIR}/src/api/tcpip.c
)

set(lwipnetif_SRCS
    ${LWIP_DIR}/src/netif/ethernet.c
)

set(lwipnoapps_SRCS
    ${lwipcore_SRCS}
    ${lwipcore4_SRCS}
    ${lwipapi_SRCS}
    ${lwipnetif_SRCS}
)

add_library(lwipcore EXCLUDE_FROM_ALL ${lwipnoapps_SRCS})
target_compile_options(lwipcore PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwipcore PRIVATE ${LWIP_DEFINITIONS})
target_include_directories(lwipcore PRIVATE ${LWIP_INCLUDE_DIRS})

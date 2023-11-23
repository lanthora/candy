set(WINTUN_VERSION 0.14.1)
set(WINTUN_ZIP wintun-${WINTUN_VERSION}.zip)
set(WINTUN_URL https://www.wintun.net/builds/${WINTUN_ZIP})

file(DOWNLOAD ${WINTUN_URL} ${CMAKE_BINARY_DIR}/${WINTUN_ZIP})
file(ARCHIVE_EXTRACT INPUT ${CMAKE_BINARY_DIR}/${WINTUN_ZIP})

include_directories(${CMAKE_BINARY_DIR}/wintun/include)

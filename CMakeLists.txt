cmake_minimum_required (VERSION 3.18.4)

set(TARGET "candy")
project(${TARGET} CXX)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
aux_source_directory("./src" DIR_SRCS)
add_executable(${TARGET} ${DIR_SRCS})

set(CMAKE_C_FLAGS "-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++20 -Wall -Werror")

set(CMAKE_CXX_FLAGS_DEBUG_INIT "-g -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O2")

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
add_definitions(-DDEBUG)
endif()

find_package(PkgConfig REQUIRED)

pkg_check_modules(SPDLOG REQUIRED spdlog)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(LIBCONFIGXX REQUIRED libconfig++)
pkg_check_modules(IXWEBSOCKET REQUIRED ixwebsocket)
pkg_check_modules(URIPARSER REQUIRED liburiparser)

include_directories(${SPDLOG_INCLUDEDIR})
include_directories(${OPENSSL_INCLUDEDIR})
include_directories(${IXWEBSOCKET_INCLUDEDIR})
include_directories(${LIBCONFIGXX_INCLUDEDIR})
include_directories(${URIPARSER_INCLUDEDIR})

target_link_libraries(${TARGET} ${SPDLOG_LIBRARIES})
target_link_libraries(${TARGET} ${OPENSSL_LIBRARIES})
target_link_libraries(${TARGET} ${IXWEBSOCKET_LIBRARIES})
target_link_libraries(${TARGET} ${LIBCONFIGXX_LIBRARIES})
target_link_libraries(${TARGET} ${URIPARSER_LIBRARIES})

install(TARGETS ${TARGET})

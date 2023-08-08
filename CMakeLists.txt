cmake_minimum_required(VERSION 3.18.4)

project(candy CXX)

set(SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${SOURCE})
aux_source_directory(${SOURCE}/main DIR_SRCS)
add_executable(${CMAKE_PROJECT_NAME} ${DIR_SRCS})

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++23 -Wall -Werror -Wfatal-errors")
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-g -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O2")

find_package(PkgConfig REQUIRED)
pkg_check_modules(
    DEPENDENCIES
    REQUIRED
    openssl
    libconfig++
    liburiparser
)

find_library(ARGP_LIB argp)

include_directories(${DEPENDENCIES_INCLUDEDIR})
target_link_libraries(${CMAKE_PROJECT_NAME} ${DEPENDENCIES_LIBRARIES})

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ixwebsocket.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/spdlog.cmake)

include_directories(${ixwebsocket_SOURCE_DIR})
include_directories(${spdlog_SOURCE_DIR}/include)

add_subdirectory(${SOURCE}/core)
add_subdirectory(${SOURCE}/websocket)
add_subdirectory(${SOURCE}/tun)
add_subdirectory(${SOURCE}/utility)

target_link_libraries(${CMAKE_PROJECT_NAME} core)
target_link_libraries(${CMAKE_PROJECT_NAME} websocket)
target_link_libraries(${CMAKE_PROJECT_NAME} tun)
target_link_libraries(${CMAKE_PROJECT_NAME} utility)

target_link_libraries(${CMAKE_PROJECT_NAME} ixwebsocket)
target_link_libraries(${CMAKE_PROJECT_NAME} spdlog)

if(ARGP_LIB)
    target_link_libraries(${CMAKE_PROJECT_NAME} ${ARGP_LIB})
endif()

install(TARGETS ${CMAKE_PROJECT_NAME})

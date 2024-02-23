cmake_minimum_required(VERSION 3.18.4)

project(candy CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++2b -Wall -Werror -Wfatal-errors -Wno-unknown-pragmas")
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-g -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O2")

include_directories(${CMAKE_SOURCE_DIR}/src)

add_subdirectory(${CMAKE_SOURCE_DIR}/src/main)
add_subdirectory(${CMAKE_SOURCE_DIR}/src/core)
add_subdirectory(${CMAKE_SOURCE_DIR}/src/websocket)
add_subdirectory(${CMAKE_SOURCE_DIR}/src/tun)
add_subdirectory(${CMAKE_SOURCE_DIR}/src/peer)
add_subdirectory(${CMAKE_SOURCE_DIR}/src/utility)

install(TARGETS ${CMAKE_PROJECT_NAME})

cmake_minimum_required(VERSION 3.18.4)

project(candy LANGUAGES CXX VERSION 4.0)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2b -Wall -Werror -Wfatal-errors -Wno-unknown-pragmas")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")

add_compile_definitions(VERSION="${CMAKE_PROJECT_VERSION}")

include_directories(${CMAKE_SOURCE_DIR}/src)

add_subdirectory(${CMAKE_SOURCE_DIR}/src/main)
add_subdirectory(${CMAKE_SOURCE_DIR}/src/core)
add_subdirectory(${CMAKE_SOURCE_DIR}/src/websocket)
add_subdirectory(${CMAKE_SOURCE_DIR}/src/tun)
add_subdirectory(${CMAKE_SOURCE_DIR}/src/peer)
add_subdirectory(${CMAKE_SOURCE_DIR}/src/utility)

install(TARGETS ${CMAKE_PROJECT_NAME})

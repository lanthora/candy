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
    spdlog
    libconfig++
    liburiparser
)

find_library(ARGP_LIB argp)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ixwebsocket.cmake)

include_directories(${DEPENDENCIES_INCLUDEDIR})
include_directories(${ixwebsocket_SOURCE_DIR})

add_subdirectory(${SOURCE}/core)
add_subdirectory(${SOURCE}/websocket)
add_subdirectory(${SOURCE}/tun)
add_subdirectory(${SOURCE}/peer)
add_subdirectory(${SOURCE}/utility)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE core)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE websocket)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE tun)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE peer)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE utility)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ixwebsocket)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${DEPENDENCIES_LIBRARIES})
if(ARGP_LIB)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${ARGP_LIB})
endif()

install(TARGETS ${CMAKE_PROJECT_NAME})

cmake_minimum_required(VERSION 3.18.4)

project(candy CXX)

set(SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${SOURCE})
aux_source_directory(${SOURCE}/main DIR_SRCS)
add_executable(${CMAKE_PROJECT_NAME} ${DIR_SRCS})

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++2b -Wall -Werror -Wfatal-errors -Wno-unknown-pragmas")
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

pkg_check_modules(IXWEBSOCKET ixwebsocket)

find_library(ARGP_LIB argp)

if (NOT IXWEBSOCKET_FOUND)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ixwebsocket.cmake)
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/wintun.cmake)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/argp-standalone.cmake)
endif()

include_directories(${DEPENDENCIES_INCLUDEDIR})

if (IXWEBSOCKET_FOUND)
    include_directories(${IXWEBSOCKET_INCLUDEDIR})
else()
    include_directories(${ixwebsocket_SOURCE_DIR})
endif()

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

if (IXWEBSOCKET_FOUND)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${IXWEBSOCKET_LIBRARIES})
else()
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ixwebsocket)
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE iphlpapi)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE argp-standalone)    
endif()

if(ARGP_LIB)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${ARGP_LIB})
endif()

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${DEPENDENCIES_LIBRARIES})
install(TARGETS ${CMAKE_PROJECT_NAME})

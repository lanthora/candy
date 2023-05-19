cmake_minimum_required(VERSION 3.18.4)

set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

project(candy CXX)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
aux_source_directory("./src" DIR_SRCS)
add_executable(${CMAKE_PROJECT_NAME} ${DIR_SRCS})

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++20 -Wall -Werror")

set(CMAKE_CXX_FLAGS_DEBUG_INIT "-g -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O2")

find_package(PkgConfig REQUIRED)

pkg_check_modules(
  DEPENDENCIES
  REQUIRED
  spdlog
  openssl
  libconfig++
  liburiparser
)

include_directories(${DEPENDENCIES_INCLUDEDIR})
target_link_libraries(${CMAKE_PROJECT_NAME} ${DEPENDENCIES_LIBRARIES})

include(cmake/ixwebsocket.cmake)
target_link_libraries(${CMAKE_PROJECT_NAME} ixwebsocket)

install(TARGETS ${CMAKE_PROJECT_NAME})

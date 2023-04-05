cmake_minimum_required(VERSION 3.18.4)

set(TARGET "candy")
project(${TARGET} CXX)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
aux_source_directory("./src" DIR_SRCS)
add_executable(${TARGET} ${DIR_SRCS})

set(CMAKE_C_FLAGS "-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++20 -Wall -Werror")

set(CMAKE_CXX_FLAGS_DEBUG_INIT "-g -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O2")

if(NOT CMAKE_BUILD_TYPE MATCHES "Release")
  add_definitions(-DDEBUG)
endif()

find_package(PkgConfig REQUIRED)

pkg_check_modules(
  DEPENDENCIES
  REQUIRED
  spdlog
  openssl
  libconfig++
  ixwebsocket
  liburiparser)

include_directories(${DEPENDENCIES_INCLUDEDIR})
target_link_libraries(${TARGET} ${DEPENDENCIES_LIBRARIES})

install(TARGETS ${TARGET})

aux_source_directory(. DIR_LIB_SRCS)
add_library(websocket STATIC ${DIR_LIB_SRCS})

find_package(Libwebsockets REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE websockets)

include(${CMAKE_SOURCE_DIR}/cmake/ixwebsocket.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/spdlog.cmake)

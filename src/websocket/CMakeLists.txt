aux_source_directory(. DIR_LIB_SRCS)
add_library(websocket STATIC ${DIR_LIB_SRCS})

include(${CMAKE_SOURCE_DIR}/cmake/ixwebsocket.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/spdlog.cmake)

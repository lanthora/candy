aux_source_directory(. DIR_LIB_SRCS)
add_library(websocket STATIC ${DIR_LIB_SRCS})

set_target_properties(websocket PROPERTIES CXX_STANDARD 20)

include(${CMAKE_SOURCE_DIR}/cmake/poco.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/spdlog.cmake)

aux_source_directory(. DIR_LIB_SRCS)
add_library(utility STATIC ${DIR_LIB_SRCS})

include(${CMAKE_SOURCE_DIR}/cmake/liburiparser.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/spdlog.cmake)

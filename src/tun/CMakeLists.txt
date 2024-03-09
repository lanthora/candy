aux_source_directory(. DIR_LIB_SRCS)
add_library(tun STATIC ${DIR_LIB_SRCS})

set_target_properties(tun PROPERTIES CXX_STANDARD 20)

include(${CMAKE_SOURCE_DIR}/cmake/windows.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/wintun.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/spdlog.cmake)

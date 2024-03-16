aux_source_directory(. DIR_LIB_SRCS)
add_library(core STATIC ${DIR_LIB_SRCS})

set_target_properties(core PROPERTIES CXX_STANDARD 20)

include(${CMAKE_SOURCE_DIR}/cmake/fmt.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/spdlog.cmake)

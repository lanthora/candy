aux_source_directory(. DIR_LIB_SRCS)
add_library(utility STATIC ${DIR_LIB_SRCS})

set_target_properties(utility PROPERTIES CXX_STANDARD 20)

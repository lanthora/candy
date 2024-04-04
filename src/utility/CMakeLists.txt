aux_source_directory(. DIR_LIB_SRCS)
add_library(utility STATIC ${DIR_LIB_SRCS})

set_target_properties(utility PROPERTIES CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DEPS REQUIRED spdlog liburiparser)

add_definitions(${DEPS_CFLAGS})
include_directories(${DEPS_INCLUDEDIR})
target_link_libraries(utility PRIVATE ${DEPS_LIBRARIES})

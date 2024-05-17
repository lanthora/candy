aux_source_directory(. DIR_LIB_SRCS)
add_library(peer STATIC ${DIR_LIB_SRCS})

set_target_properties(peer PROPERTIES CXX_STANDARD 20)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    target_link_libraries(peer PRIVATE ws2_32)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(DEPS REQUIRED spdlog)

find_package(Poco REQUIRED Net)
target_link_libraries(peer PRIVATE Poco::Net)

add_definitions(${DEPS_CFLAGS})
include_directories(${DEPS_INCLUDEDIR})
target_link_libraries(peer PRIVATE ${DEPS_LIBRARIES})

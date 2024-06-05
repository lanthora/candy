aux_source_directory(. DIR_LIB_SRCS)
add_library(peer STATIC ${DIR_LIB_SRCS})

set_target_properties(peer PROPERTIES CXX_STANDARD 20)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    target_link_libraries(peer PRIVATE ws2_32)
endif()

if (${CANDY_STATIC})
    target_link_libraries(peer PRIVATE spdlog::spdlog)
    target_link_libraries(peer PRIVATE Poco::Net)
    target_link_libraries(peer PRIVATE ${OPENSSL_LIB_CRYPTO} ${OPENSSL_LIB_SSL})
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DEPS REQUIRED spdlog)
    add_definitions(${DEPS_CFLAGS})
    include_directories(${DEPS_INCLUDEDIR})
    target_link_libraries(peer PRIVATE ${DEPS_LIBRARIES})

    find_package(Poco REQUIRED Net)
    target_link_libraries(peer PRIVATE Poco::Net)
endif()

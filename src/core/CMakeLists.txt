aux_source_directory(. DIR_LIB_SRCS)
add_library(core STATIC ${DIR_LIB_SRCS})

set_target_properties(core PROPERTIES CXX_STANDARD 20)

if (${CANDY_STATIC_FMT})
    target_link_libraries(core PRIVATE fmt::fmt)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DEPS REQUIRED fmt)
    add_definitions(${DEPS_CFLAGS})
    include_directories(${DEPS_INCLUDEDIR})
    target_link_libraries(core PRIVATE ${DEPS_LIBRARIES})
endif()

if (${CANDY_STATIC_SPDLOG})
    target_link_libraries(core PRIVATE spdlog::spdlog)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DEPS REQUIRED spdlog)
    add_definitions(${DEPS_CFLAGS})
    include_directories(${DEPS_INCLUDEDIR})
    target_link_libraries(core PRIVATE ${DEPS_LIBRARIES})
endif()

if (${CANDY_STATIC_OPENSSL})
    target_link_libraries(core PRIVATE ${OPENSSL_LIB_CRYPTO} ${OPENSSL_LIB_SSL})
endif()

if (${CANDY_STATIC_POCO})
    target_link_libraries(core PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)
endif()


target_link_libraries(core PRIVATE websocket)
target_link_libraries(core PRIVATE tun)
target_link_libraries(core PRIVATE peer)

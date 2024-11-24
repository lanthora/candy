aux_source_directory(. DIR_LIB_SRCS)
add_library(peer STATIC ${DIR_LIB_SRCS})

set_target_properties(peer PROPERTIES CXX_STANDARD 20)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    target_link_libraries(peer PRIVATE ws2_32)
endif()

if (${CANDY_STATIC_SPDLOG})
    target_link_libraries(peer PRIVATE spdlog::spdlog)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SPDLOG REQUIRED spdlog)
    add_definitions(${SPDLOG_CFLAGS})
    include_directories(${SPDLOG_INCLUDEDIR})
    target_link_libraries(peer PRIVATE ${SPDLOG_LIBRARIES})
endif()

if (${CANDY_STATIC_OPENSSL})
    target_link_libraries(peer PRIVATE ${OPENSSL_LIB_CRYPTO} ${OPENSSL_LIB_SSL})
endif()

if (${CANDY_STATIC_POCO})
    target_link_libraries(peer PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)
else()
    find_package(Poco REQUIRED Net)
    target_link_libraries(peer PRIVATE Poco::Net)
endif()


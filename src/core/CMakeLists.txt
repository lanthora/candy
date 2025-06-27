aux_source_directory(. DIR_LIB_SRCS)
add_library(core STATIC ${DIR_LIB_SRCS})

set_target_properties(core PROPERTIES CXX_STANDARD 17)

if (${CANDY_STATIC_FMT})
    target_link_libraries(core PRIVATE fmt::fmt)
else()
    pkg_check_modules(FMT REQUIRED fmt)
    add_definitions(${FMT_CFLAGS})
    include_directories(${FMT_INCLUDEDIR})
    target_link_libraries(core PRIVATE ${FMT_LIBRARIES})
endif()

if (${CANDY_STATIC_SPDLOG})
    target_link_libraries(core PRIVATE spdlog::spdlog)
else()
    target_link_libraries(core PRIVATE ${SPDLOG_LIBRARIES})
endif()

if (${CANDY_STATIC_OPENSSL})
    target_link_libraries(core PRIVATE ${OPENSSL_LIB_CRYPTO} ${OPENSSL_LIB_SSL})
endif()

target_link_libraries(core PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)

target_link_libraries(core PRIVATE websocket)
target_link_libraries(core PRIVATE tun)
target_link_libraries(core PRIVATE peer)

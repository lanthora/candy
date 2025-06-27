aux_source_directory(. DIR_LIB_SRCS)
add_library(websocket STATIC ${DIR_LIB_SRCS})

set_target_properties(websocket PROPERTIES CXX_STANDARD 17)

if (${CANDY_STATIC_SPDLOG})
    target_link_libraries(websocket PRIVATE spdlog::spdlog)
else()
    target_link_libraries(websocket PRIVATE ${SPDLOG_LIBRARIES})
endif()

if (${CANDY_STATIC_OPENSSL})
    target_link_libraries(websocket PRIVATE ${OPENSSL_LIB_CRYPTO} ${OPENSSL_LIB_SSL})
endif()

target_link_libraries(websocket PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)

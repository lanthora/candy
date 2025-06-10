aux_source_directory(. DIR_LIB_SRCS)
add_library(peer STATIC ${DIR_LIB_SRCS})

set_target_properties(peer PROPERTIES CXX_STANDARD 23)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    target_link_libraries(peer PRIVATE ws2_32)
endif()

if (${CANDY_STATIC_SPDLOG})
    target_link_libraries(peer PRIVATE spdlog::spdlog)
else()
    target_link_libraries(peer PRIVATE ${SPDLOG_LIBRARIES})
endif()

if (${CANDY_STATIC_OPENSSL})
    target_link_libraries(peer PRIVATE ${OPENSSL_LIB_CRYPTO} ${OPENSSL_LIB_SSL})
else()
    target_link_libraries(peer PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

target_link_libraries(peer PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)


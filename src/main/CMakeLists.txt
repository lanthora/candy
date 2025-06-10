aux_source_directory(. DIR_SRCS)
add_executable(${CANDY_EXECUTE_NAME} ${DIR_SRCS})

set_target_properties(${CANDY_EXECUTE_NAME} PROPERTIES CXX_STANDARD 23)

find_library(STDCPPFS_LIB stdc++fs)
if(STDCPPFS_LIB)
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE ${STDCPPFS_LIB})
endif()

if (${CANDY_STATIC_SPDLOG})
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE spdlog::spdlog)
else()
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE ${SPDLOG_LIBRARIES})
endif()

if (${CANDY_STATIC_OPENSSL})
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE ${OPENSSL_LIB_CRYPTO} ${OPENSSL_LIB_SSL})
endif()

target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE Threads::Threads)

target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE core)
target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE utils)

if (NOT ${CANDY_NOEXE})
    install(TARGETS ${CANDY_EXECUTE_NAME})
endif()

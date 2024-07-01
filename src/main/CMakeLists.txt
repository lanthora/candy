aux_source_directory(. DIR_SRCS)
add_executable(${CANDY_EXECUTE_NAME} ${DIR_SRCS})

set_target_properties(${CANDY_EXECUTE_NAME} PROPERTIES CXX_STANDARD 20)

if (${CANDY_STATIC_SPDLOG})
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE spdlog::spdlog)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DEPS REQUIRED spdlog)
    add_definitions(${DEPS_CFLAGS})
    include_directories(${DEPS_INCLUDEDIR})
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE ${DEPS_LIBRARIES})
endif()

if (${CANDY_STATIC_OPENSSL})
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE ${OPENSSL_LIB_CRYPTO} ${OPENSSL_LIB_SSL})
endif()

if (${CANDY_STATIC_POCO})
    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)
endif()


set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE Threads::Threads)

target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE core)
target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE utility)

if (NOT ${CANDY_NOEXE})
    install(TARGETS ${CANDY_EXECUTE_NAME})
endif()

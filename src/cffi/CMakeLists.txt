aux_source_directory(. DIR_SRCS)
add_library(${CANDY_LIBRARY_NAME} STATIC ${DIR_SRCS})

set_target_properties(${CANDY_LIBRARY_NAME} PROPERTIES OUTPUT_NAME ${CANDY_EXECUTE_NAME})
set_target_properties(${CANDY_LIBRARY_NAME} PROPERTIES CXX_STANDARD 20)

target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE core)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE websocket)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE tun)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE peer)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE utility)

if (${CANDY_STATIC_SPDLOG})
    target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE spdlog::spdlog)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DEPS REQUIRED spdlog)
    add_definitions(${DEPS_CFLAGS})
    include_directories(${DEPS_INCLUDEDIR})
    target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE ${DEPS_LIBRARIES})
endif()

if (${CANDY_STATIC_OPENSSL})
    target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE ${OPENSSL_LIB_CRYPTO} ${OPENSSL_LIB_SSL})
endif()

if (${CANDY_STATIC_POCO})
    target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)
endif()

if (${CANDY_DEVEL})
    install(FILES candy.h DESTINATION include)
    install(TARGETS ${CANDY_LIBRARY_NAME} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

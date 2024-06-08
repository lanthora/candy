cmake_minimum_required(VERSION 3.18.4)
cmake_policy(SET CMP0135 NEW)
project(openssl)

include(ExternalProject)
ExternalProject_Add(
    openssl
    PREFIX                      ${CMAKE_BINARY_DIR}/openssl
    URL                         https://www.openssl.org/source/openssl-3.3.1.tar.gz
    LOG_BUILD                   ON
    BUILD_IN_SOURCE             YES
    BUILD_COMMAND               ""
    CONFIGURE_COMMAND           ./config --release no-unit-test no-shared ${TARGET_OPENSSL} CFLAGS=$ENV{CFLAGS} LDFLAGS=$ENV{LDFLAGS}
    INSTALL_COMMAND             ""
    TEST_COMMAND                ""
)

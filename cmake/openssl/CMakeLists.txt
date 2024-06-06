cmake_minimum_required(VERSION 3.18.4)

project(openssl)

include(ExternalProject)
ExternalProject_Add(
    openssl
    PREFIX                      ${CMAKE_BINARY_DIR}/openssl
    URL                         https://www.openssl.org/source/openssl-3.3.1.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP  TRUE
    LOG_BUILD                   ON
    BUILD_IN_SOURCE             YES
    BUILD_COMMAND               make
    CONFIGURE_COMMAND           ./config no-unit-test no-shared ${OPENSSL_TARGET} CFLAGS=$ENV{CFLAGS} LDFLAGS=$ENV{LDFLAGS}
    INSTALL_COMMAND             ""
    TEST_COMMAND                ""
)

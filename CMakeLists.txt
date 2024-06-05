cmake_minimum_required(VERSION 3.18.4)

project(candy LANGUAGES C CXX VERSION 5.8.6)

option(CANDY_NOEXE "not build exe")
option(CANDY_DEVEL "build static library")
option(CANDY_STATIC "static link deps")

if (${CANDY_STATIC})
    set(CMAKE_EXE_LINKER_FLAGS "-static")
    set(BUILD_SHARED_LIBS OFF)

    include(FetchContent)
    include(ExternalProject)

    # openssl
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    ExternalProject_Add(
        openssl
        PREFIX            openssl
        URL               https://www.openssl.org/source/openssl-3.3.1.tar.gz
        LOG_BUILD         ON
        BUILD_IN_SOURCE   YES
        BUILD_COMMAND     make
        CONFIGURE_COMMAND ./config no-unit-test no-shared --prefix=${CMAKE_BINARY_DIR}
        INSTALL_COMMAND   ""
        TEST_COMMAND      ""
    )
    set(OPENSSL_ROOT_DIR ${CMAKE_BINARY_DIR}/openssl/src/openssl)
    set(OPENSSL_INCLUDE ${OPENSSL_ROOT_DIR}/include)

    set(OPENSSL_LIB_CRYPTO ${OPENSSL_ROOT_DIR}/libcrypto.a)
    set(OPENSSL_LIB_SSL ${OPENSSL_ROOT_DIR}/libssl.a)
  
    include_directories(${OPENSSL_INCLUDE})

    # fmt
    FetchContent_Declare(
        fmt
        GIT_REPOSITORY  https://github.com/fmtlib/fmt.git
        GIT_TAG         10.2.1
    )
    FetchContent_GetProperties(fmt)
    if (NOT fmt_POPULATED)
        FetchContent_Populate(fmt)
        add_subdirectory(${fmt_SOURCE_DIR} ${fmt_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()

    # spdlog
    FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG        v1.14.1
    )
    FetchContent_GetProperties(spdlog)
    if (NOT spdlog_POPULATED)
        FetchContent_Populate(spdlog)
        add_subdirectory(${spdlog_SOURCE_DIR} ${spdlog_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()

    # libconfig
    FetchContent_Declare(
        libconfig
        GIT_REPOSITORY https://github.com/hyperrealm/libconfig.git
        GIT_TAG v1.7.3
    )
    FetchContent_GetProperties(libconfig)
    if (NOT libconfig_POPULATED)
        FetchContent_Populate(libconfig)
        add_subdirectory(${libconfig_SOURCE_DIR} ${libconfig_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()

    # poco
    FetchContent_Declare(
        poco
        GIT_REPOSITORY https://github.com/pocoproject/poco.git
        GIT_TAG        poco-1.13.3-release
    )
    FetchContent_GetProperties(poco)
    if (NOT poco_POPULATED)
        FetchContent_Populate(poco)
        add_subdirectory(${poco_SOURCE_DIR} ${poco_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()
endif()

set(CANDY_EXECUTE_NAME "candy")
set(CANDY_LIBRARY_NAME "libcandy")

add_compile_definitions(CANDY_VERSION="${PROJECT_VERSION}")

include_directories(${PROJECT_SOURCE_DIR}/src)

add_subdirectory(${PROJECT_SOURCE_DIR}/src/cffi)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/main)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/core)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/websocket)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/tun)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/peer)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/utility)

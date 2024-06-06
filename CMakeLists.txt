cmake_minimum_required(VERSION 3.18.4)

project(candy LANGUAGES C CXX VERSION 5.8.6)

option(CANDY_NOEXE  "Don't build executable")
option(CANDY_DEVEL  "Build development library")
option(CANDY_STATIC "Static linking dependent libraries")

if (${CANDY_STATIC})
    set(CMAKE_SKIP_BUILD_RPATH TRUE)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

    include(FetchContent)
    include(ExternalProject)

    # openssl
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/openssl
    )
    execute_process(
        COMMAND ${CMAKE_COMMAND} -DOPENSSL_TARGET=${OPENSSL_TARGET} ${CMAKE_SOURCE_DIR}/cmake/openssl
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/openssl
        RESULT_VARIABLE cfgresult
    )
    if(NOT cfgresult EQUAL "0")
        message(FATAL_ERROR "Config OpenSSL failed")
    endif()
    execute_process(
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/openssl
        RESULT_VARIABLE buildresult
    )
    if(NOT buildresult EQUAL "0")
        message(FATAL_ERROR "Build OpenSSL failed")
    endif()

    set(OPENSSL_ROOT_DIR ${CMAKE_BINARY_DIR}/openssl/openssl/src/openssl)
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
    if(NOT fmt_POPULATED)
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
    if(NOT spdlog_POPULATED)
        FetchContent_Populate(spdlog)
        add_subdirectory(${spdlog_SOURCE_DIR} ${spdlog_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()

    # libconfig
    set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        libconfig
        GIT_REPOSITORY https://github.com/hyperrealm/libconfig.git
        GIT_TAG v1.7.3
    )
    FetchContent_GetProperties(libconfig)
    if(NOT libconfig_POPULATED)
        FetchContent_Populate(libconfig)
        add_subdirectory(${libconfig_SOURCE_DIR} ${libconfig_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()

    # poco
    set(ENABLE_DATA OFF CACHE BOOL "" FORCE)
    set(ENABLE_DATA_MYSQL OFF CACHE BOOL "" FORCE)
    set(ENABLE_DATA_POSTGRESQL OFF CACHE BOOL "" FORCE)
    set(ENABLE_DATA_SQLITE OFF CACHE BOOL "" FORCE)
    set(ENABLE_DATA_ODBC OFF CACHE BOOL "" FORCE)
    set(ENABLE_MONGODB OFF CACHE BOOL "" FORCE)
    set(ENABLE_REDIS OFF CACHE BOOL "" FORCE)
    set(ENABLE_ENCODINGS OFF CACHE BOOL "" FORCE)
    set(ENABLE_PROMETHEUS OFF CACHE BOOL "" FORCE)
    set(ENABLE_PAGECOMPILER OFF CACHE BOOL "" FORCE)
    set(ENABLE_PAGECOMPILER_FILE2PAGE OFF CACHE BOOL "" FORCE)
    set(ENABLE_ACTIVERECORD OFF CACHE BOOL "" FORCE)
    set(ENABLE_ACTIVERECORD_COMPILER OFF CACHE BOOL "" FORCE)
    set(ENABLE_ZIP OFF CACHE BOOL "" FORCE)
    set(ENABLE_JWT OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        poco
        GIT_REPOSITORY https://github.com/pocoproject/poco.git
        GIT_TAG        poco-1.13.3-release
    )
    FetchContent_GetProperties(poco)
    if(NOT poco_POPULATED)
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

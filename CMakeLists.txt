cmake_minimum_required(VERSION 3.18.4)

project(candy LANGUAGES C CXX VERSION 5.8.6)

option(CANDY_NOEXE  "Don't build executable")
option(CANDY_DEVEL  "Build development library")
option(CANDY_STATIC "Static linking dependent libraries")

if (${CANDY_STATIC})
    set(CMAKE_SKIP_BUILD_RPATH TRUE)
    set(CMAKE_EXE_LINKER_FLAGS "-static")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

    include(FetchContent)
    include(ExternalProject)

    # openssl
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/openssl
    )
    execute_process(
        COMMAND ${CMAKE_COMMAND} ${CMAKE_SOURCE_DIR}/cmake/openssl
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/openssl
    )
    execute_process(
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/openssl
    )

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
    FetchContent_MakeAvailable(fmt)

    # spdlog
    FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG        v1.14.1
    )
    FetchContent_MakeAvailable(spdlog)

    # libconfig
    set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        libconfig
        GIT_REPOSITORY https://github.com/hyperrealm/libconfig.git
        GIT_TAG v1.7.3
    )
    FetchContent_MakeAvailable(libconfig)

    # poco
    FetchContent_Declare(
        poco
        GIT_REPOSITORY https://github.com/pocoproject/poco.git
        GIT_TAG        poco-1.13.3-release
    )
    FetchContent_MakeAvailable(poco)
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

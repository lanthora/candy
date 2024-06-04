cmake_minimum_required(VERSION 3.18.4)

project(candy LANGUAGES C CXX VERSION 5.8.6)

if (NOT DEFINED CANDY_NOEXE)
    set(CANDY_NOEXE OFF)
endif()

if (NOT DEFINED CANDY_DEVEL)
    set(CANDY_DEVEL OFF)
endif()

if (NOT DEFINED CANDY_STATIC)
    set(CANDY_STATIC OFF)
endif()

if (${CANDY_STATIC})
    set(BUILD_SHARED_LIBS OFF)

    include(FetchContent)

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

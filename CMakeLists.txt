cmake_minimum_required(VERSION 3.18.4)

project(candy LANGUAGES C CXX VERSION 5.10.4)

option(CANDY_NOEXE  "Don't build executable")
option(CANDY_DEVEL  "Build development library")
option(CANDY_STATIC "Static linking dependent libraries")

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

if (${CANDY_STATIC})
    set(CMAKE_SKIP_BUILD_RPATH TRUE)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    set(CANDY_STATIC_OPENSSL 1)
    set(CANDY_STATIC_FMT 1)
    set(CANDY_STATIC_SPDLOG 1)
    set(CANDY_STATIC_POCO 1)
endif()

if (${CANDY_STATIC_OPENSSL})
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/openssl
    )
    execute_process(
        COMMAND ${CMAKE_COMMAND} -DTARGET_OPENSSL=${TARGET_OPENSSL} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/openssl
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/openssl
        RESULT_VARIABLE result
    )
    if(NOT result EQUAL "0")
        message(FATAL_ERROR "OpenSSL CMake failed")
    endif()

    execute_process(
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_CURRENT_BINARY_DIR}/openssl
        RESULT_VARIABLE result
    )
    if(NOT result EQUAL "0")
        message(FATAL_ERROR "OpenSSL Download or Configure failed")
    endif()

    include(ProcessorCount)
    ProcessorCount(nproc)
    if(nproc EQUAL 0)
        set(nproc 1)
    endif()
    set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl/openssl/src/openssl)
    execute_process(
        COMMAND make -j${nproc}
        WORKING_DIRECTORY ${OPENSSL_ROOT_DIR}
        RESULT_VARIABLE result
    )
    if(NOT result EQUAL "0")
        message(FATAL_ERROR "OpenSSL Build failed")
    endif()

    set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl/openssl/src/openssl)
    set(OPENSSL_INCLUDE ${OPENSSL_ROOT_DIR}/include)
    set(OPENSSL_LIB_CRYPTO ${OPENSSL_ROOT_DIR}/libcrypto.a)
    set(OPENSSL_LIB_SSL ${OPENSSL_ROOT_DIR}/libssl.a)
    include_directories(${OPENSSL_INCLUDE})
endif()

if (${CANDY_STATIC_FMT})
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Fetch.cmake)
    Fetch(fmt "https://github.com/fmtlib/fmt.git" "10.2.1")
endif()

if (${CANDY_STATIC_SPDLOG})
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Fetch.cmake)
    Fetch(spdlog "https://github.com/gabime/spdlog.git" "v1.14.1")
endif()

if (${CANDY_STATIC_POCO})
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
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Fetch.cmake)
    Fetch(poco "https://github.com/pocoproject/poco.git" "poco-1.13.3-release")
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

cmake_minimum_required(VERSION 3.16)
project(Candy VERSION 6.1.7)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_definitions(CANDY_VERSION="${PROJECT_VERSION}")

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CMAKE_SKIP_BUILD_RPATH TRUE)

if (${CANDY_STATIC})
    set(CANDY_STATIC_OPENSSL 1)
    set(CANDY_STATIC_SPDLOG 1)
    set(CANDY_STATIC_NLOHMANN_JSON 1)
    set(CANDY_STATIC_POCO 1)
endif()

find_package(PkgConfig REQUIRED)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Fetch.cmake)

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
else()
    find_package(OpenSSL REQUIRED)
endif()

if (${CANDY_STATIC_SPDLOG})
    Fetch(spdlog "https://github.com/gabime/spdlog.git" "v1.15.3")
else()
    find_package(spdlog REQUIRED)
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
    Fetch(poco "https://github.com/pocoproject/poco.git" "poco-1.13.3-release")
else()
    find_package(Poco REQUIRED COMPONENTS Foundation XML JSON Net NetSSL Util)
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_subdirectory(candy)
add_subdirectory(candy-cli)
add_subdirectory(candy-service)

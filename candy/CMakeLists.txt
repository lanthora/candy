add_library(candy-library)

file(GLOB_RECURSE SOURCES "src/*.cc")
target_sources(candy-library PRIVATE ${SOURCES})

target_include_directories(candy-library PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>
)

if (${CANDY_STATIC_OPENSSL})
    target_link_libraries(candy-library PRIVATE ${OPENSSL_LIB_CRYPTO} ${OPENSSL_LIB_SSL})
else()
    target_link_libraries(candy-library PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

target_link_libraries(candy-library PRIVATE spdlog::spdlog)
target_link_libraries(candy-library PRIVATE Poco::Foundation Poco::JSON Poco::Net Poco::NetSSL)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(candy-library PRIVATE Threads::Threads)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    target_link_libraries(candy-library PRIVATE ws2_32)
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    target_link_libraries(candy-library PRIVATE iphlpapi)
    target_link_libraries(candy-library PRIVATE ws2_32)

    set(WINTUN_VERSION 0.14.1)
    set(WINTUN_ZIP wintun-${WINTUN_VERSION}.zip)
    set(WINTUN_URL https://www.wintun.net/builds/${WINTUN_ZIP})

    if (NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${WINTUN_ZIP})
        file(DOWNLOAD ${WINTUN_URL} ${CMAKE_CURRENT_BINARY_DIR}/${WINTUN_ZIP} STATUS DOWNLOAD_STATUS)
        list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
        list(GET DOWNLOAD_STATUS 1 ERROR_MESSAGE)

        if(${STATUS_CODE} EQUAL 0)
            message(STATUS "wintun download success")
        else()
            message(FATAL_ERROR "wintun download failed: ${ERROR_MESSAGE}")
        endif()
    else()
        message(STATUS "use wintun cache")
    endif()

    file(ARCHIVE_EXTRACT INPUT ${CMAKE_CURRENT_BINARY_DIR}/${WINTUN_ZIP})

    include_directories(${CMAKE_CURRENT_BINARY_DIR}/wintun/include)
endif()

set_target_properties(candy-library PROPERTIES OUTPUT_NAME "candy")

add_library(Candy::Library ALIAS candy-library)

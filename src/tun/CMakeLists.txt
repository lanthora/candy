aux_source_directory(. DIR_LIB_SRCS)
add_library(tun STATIC ${DIR_LIB_SRCS})

set_target_properties(tun PROPERTIES CXX_STANDARD 20)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    set(WINTUN_VERSION 0.14.1)
    set(WINTUN_ZIP wintun-${WINTUN_VERSION}.zip)
    set(WINTUN_URL https://www.wintun.net/builds/${WINTUN_ZIP})

    if (NOT EXISTS ${CMAKE_BINARY_DIR}/${WINTUN_ZIP})
        file(DOWNLOAD ${WINTUN_URL} ${CMAKE_BINARY_DIR}/${WINTUN_ZIP} STATUS DOWNLOAD_STATUS)
        list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
        list(GET DOWNLOAD_STATUS 1 ERROR_MESSAGE)

        if(${STATUS_CODE} EQUAL 0)
            message(STATUS "Download completed successfully!")
        else()
            message(FATAL_ERROR "Error occurred during download: ${ERROR_MESSAGE}")
        endif()
    endif()

    file(ARCHIVE_EXTRACT INPUT ${CMAKE_BINARY_DIR}/${WINTUN_ZIP})
    include_directories(${CMAKE_CURRENT_BINARY_DIR}/wintun/include)
endif()

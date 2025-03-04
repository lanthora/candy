aux_source_directory(. DIR_LIB_SRCS)
add_library(utility STATIC ${DIR_LIB_SRCS})

set_target_properties(utility PROPERTIES CXX_STANDARD 23)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    target_link_libraries(utility PRIVATE ws2_32)
endif()

if (${CANDY_STATIC_SPDLOG})
    target_link_libraries(utility PRIVATE spdlog::spdlog)
else()
    target_link_libraries(utility PRIVATE ${SPDLOG_LIBRARIES})
endif()

target_link_libraries(utility PRIVATE Poco::Foundation Poco::Net)

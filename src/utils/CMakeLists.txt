aux_source_directory(. DIR_LIB_SRCS)
add_library(utils STATIC ${DIR_LIB_SRCS})

set_target_properties(utils PROPERTIES CXX_STANDARD 17)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    target_link_libraries(utils PRIVATE ws2_32)
endif()

if (${CANDY_STATIC_SPDLOG})
    target_link_libraries(utils PRIVATE spdlog::spdlog)
else()
    target_link_libraries(utils PRIVATE ${SPDLOG_LIBRARIES})
endif()

target_link_libraries(utils PRIVATE Poco::Foundation Poco::Net)

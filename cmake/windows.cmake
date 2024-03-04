if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE iphlpapi)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ws2_32)
endif()

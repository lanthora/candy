find_package(PkgConfig REQUIRED)
pkg_check_modules(SPDLOG REQUIRED spdlog)

add_definitions(${SPDLOG_CFLAGS})

include_directories(${SPDLOG_INCLUDEDIR})
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${SPDLOG_LIBRARIES})
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE ${SPDLOG_LIBRARIES})

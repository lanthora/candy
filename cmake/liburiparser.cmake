find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBURIPARSER REQUIRED liburiparser)

include_directories(${LIBURIPARSER_INCLUDEDIR})
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${LIBURIPARSER_LIBRARIES})
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE ${LIBURIPARSER_LIBRARIES})

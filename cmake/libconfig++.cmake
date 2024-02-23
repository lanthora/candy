find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCONFIGXX REQUIRED libconfig++)

include_directories(${LIBCONFIGXX_INCLUDEDIR})
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${LIBCONFIGXX_LIBRARIES})

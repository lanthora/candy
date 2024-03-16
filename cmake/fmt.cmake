find_package(PkgConfig REQUIRED)
pkg_check_modules(FMT REQUIRED fmt)

include_directories(${FMT_INCLUDEDIR})
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${FMT_LIBRARIES})

find_package(PkgConfig REQUIRED)
pkg_check_modules(SPDLOG REQUIRED spdlog)

add_definitions(${SPDLOG_CFLAGS})

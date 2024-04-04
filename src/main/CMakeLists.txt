aux_source_directory(. DIR_SRCS)
add_executable(${CANDY_EXECUTE_NAME} ${DIR_SRCS})

set_target_properties(${CANDY_EXECUTE_NAME} PROPERTIES CXX_STANDARD 20)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    include(FetchContent)

    FetchContent_Declare(
        argp-standalone
        GIT_REPOSITORY https://github.com/tom42/argp-standalone.git
        GIT_TAG        1684ac2e8d75918e5e244057ae4dd01369bed660
    )

    FetchContent_GetProperties(argp-standalone)
    if(NOT argp-standalone_POPULATED)
        FetchContent_Populate(argp-standalone)
        add_subdirectory(${argp-standalone_SOURCE_DIR} ${argp-standalone_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()

    target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE argp-standalone)  
else()
    find_library(ARGP_LIB argp)
    if(ARGP_LIB)
        target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE ${ARGP_LIB})
    endif()
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(DEPS REQUIRED spdlog libconfig++)

add_definitions(${DEPS_CFLAGS})
include_directories(${DEPS_INCLUDEDIR})
target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE ${DEPS_LIBRARIES})

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE Threads::Threads)

target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE core)
target_link_libraries(${CANDY_EXECUTE_NAME} PRIVATE utility)

if (NOT DEFINED CANDY_NOEXE OR NOT ${CANDY_NOEXE})
    install(TARGETS ${CANDY_EXECUTE_NAME})
endif()

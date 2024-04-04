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
else()
    find_library(ARGP_LIB argp)
endif()

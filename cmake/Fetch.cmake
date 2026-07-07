# Fetch a Git repository and add it to the build.
# Usage:
#   Fetch(<name> <git_url> <git_tag>)
#   Fetch(<name> <git_url> <git_tag> <add_subdir>)
#
# The 4th parameter controls whether add_subdirectory is performed.
# Defaults to TRUE when omitted.  Pass FALSE to only download the source.
macro(Fetch NAME GIT_REPOSITORY GIT_TAG)
    include(FetchContent)
    if(POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
    endif()

    set(_ADD_SUBDIR TRUE)
    if(${ARGC} GREATER 3)
        set(_ADD_SUBDIR ${ARGV3})
    endif()

    FetchContent_Declare(
        ${NAME}
        GIT_REPOSITORY ${GIT_REPOSITORY}
        GIT_TAG        ${GIT_TAG}
    )
    FetchContent_GetProperties(${NAME})

    if(NOT ${NAME}_POPULATED)
        FetchContent_Populate(${NAME})
    endif()

    if(_ADD_SUBDIR)
        add_subdirectory(${${NAME}_SOURCE_DIR} ${${NAME}_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()
endmacro()

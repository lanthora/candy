macro(Fetch NAME GIT_REPOSITORY GIT_TAG)
    include(FetchContent)
    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.28")
        FetchContent_Declare(
            ${NAME}
            GIT_REPOSITORY ${GIT_REPOSITORY}
            GIT_TAG        ${GIT_TAG}
            EXCLUDE_FROM_ALL
        )
        FetchContent_MakeAvailable(${NAME})
    else()
        FetchContent_Declare(
            ${NAME}
            GIT_REPOSITORY ${GIT_REPOSITORY}
            GIT_TAG        ${GIT_TAG}
        )
        FetchContent_GetProperties(${NAME})
        if(NOT ${NAME}_POPULATED)
            FetchContent_Populate(${NAME})
            add_subdirectory(${${NAME}_SOURCE_DIR} ${${NAME}_BINARY_DIR} EXCLUDE_FROM_ALL)
        endif()
    endif()
endmacro()

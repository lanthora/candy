find_package(PkgConfig REQUIRED)
pkg_check_modules(IXWEBSOCKET ixwebsocket)

if (IXWEBSOCKET_FOUND)
    include_directories(${IXWEBSOCKET_INCLUDEDIR})
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${IXWEBSOCKET_LIBRARIES})
else()
    include(FetchContent)

    FetchContent_Declare(
        ixwebsocket
        GIT_REPOSITORY https://github.com/machinezone/IXWebSocket.git
        GIT_TAG        c5a02f1066fb0fde48f80f51178429a27f689a39
    )

    set(USE_TLS 1 CACHE BOOL "" FORCE)
    set(USE_OPEN_SSL 1 CACHE BOOL "" FORCE)

    FetchContent_GetProperties(ixwebsocket)
    if(NOT ixwebsocket_POPULATED)
        FetchContent_Populate(ixwebsocket)
        add_subdirectory(${ixwebsocket_SOURCE_DIR} ${ixwebsocket_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()

    include_directories(${ixwebsocket_SOURCE_DIR})
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ixwebsocket)  
endif()

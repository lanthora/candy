aux_source_directory(. DIR_LIB_SRCS)
add_library(websocket STATIC ${DIR_LIB_SRCS})

set_target_properties(websocket PROPERTIES CXX_STANDARD 20)

if (${CANDY_STATIC})
    target_link_libraries(websocket PRIVATE spdlog::spdlog)
    target_link_libraries(websocket PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)
else()
    find_package(Poco REQUIRED COMPONENTS Foundation XML JSON Net NetSSL)
    target_link_libraries(websocket PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DEPS REQUIRED spdlog)
    add_definitions(${DEPS_CFLAGS})
    include_directories(${DEPS_INCLUDEDIR})
    target_link_libraries(websocket PRIVATE ${DEPS_LIBRARIES})
endif()

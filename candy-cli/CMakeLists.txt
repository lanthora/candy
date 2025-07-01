file(GLOB_RECURSE SOURCES "src/*.cc")
add_executable(candy_cli ${SOURCES})

target_include_directories(candy_library PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

set_target_properties(candy_cli PROPERTIES
    OUTPUT_NAME "candy"
)

target_link_libraries(candy_cli PRIVATE spdlog::spdlog)
target_link_libraries(candy_cli PRIVATE Poco::Foundation)
target_link_libraries(candy_cli PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(candy_cli PRIVATE Candy::Library)

install(TARGETS candy_cli)

add_executable(Candy::CLI ALIAS candy_cli)

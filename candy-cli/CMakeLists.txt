file(GLOB_RECURSE SOURCES "src/*.cc")
add_executable(candy-cli ${SOURCES})

target_include_directories(candy-cli PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

set_target_properties(candy-cli PROPERTIES OUTPUT_NAME "candy")

target_link_libraries(candy-cli PRIVATE spdlog::spdlog)
target_link_libraries(candy-cli PRIVATE Poco::Foundation)
target_link_libraries(candy-cli PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(candy-cli PRIVATE Candy::Library)

install(TARGETS candy-cli)

add_executable(Candy::CLI ALIAS candy-cli)

file(GLOB_RECURSE SOURCES "src/*.cc")
add_executable(candy-service ${SOURCES})

target_include_directories(candy-service PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

set_target_properties(candy-service PROPERTIES OUTPUT_NAME "candy-service")

target_link_libraries(candy-service PRIVATE Poco::Foundation Poco::Net Poco::JSON Poco::Util)
target_link_libraries(candy-service PRIVATE Threads::Threads)
target_link_libraries(candy-service PRIVATE Candy::Library)

install(TARGETS candy-service)

add_executable(Candy::Service ALIAS candy-service)

aux_source_directory(. DIR_SRCS)
add_executable(${CMAKE_PROJECT_NAME} ${DIR_SRCS})

include(${CMAKE_SOURCE_DIR}/cmake/argp.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/libconfig++.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/spdlog.cmake)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE core)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE websocket)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE tun)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE peer)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE utility)

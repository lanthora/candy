aux_source_directory(. DIR_SRCS)
add_library(${CANDY_LIBRARY_NAME} SHARED ${DIR_SRCS})

set_target_properties(${CANDY_LIBRARY_NAME} PROPERTIES OUTPUT_NAME ${CMAKE_PROJECT_NAME})
set_target_properties(${CANDY_LIBRARY_NAME} PROPERTIES CXX_STANDARD 20)

target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE core)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE websocket)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE tun)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE peer)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE utility)

install(FILES candy.h DESTINATION include)
install(TARGETS ${CANDY_LIBRARY_NAME} DESTINATION lib)

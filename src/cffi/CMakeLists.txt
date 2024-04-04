aux_source_directory(. DIR_SRCS)
add_library(${CANDY_LIBRARY_NAME} STATIC ${DIR_SRCS})

set_target_properties(${CANDY_LIBRARY_NAME} PROPERTIES OUTPUT_NAME ${CANDY_EXECUTE_NAME})
set_target_properties(${CANDY_LIBRARY_NAME} PROPERTIES CXX_STANDARD 20)

target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE core)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE websocket)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE tun)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE peer)
target_link_libraries(${CANDY_LIBRARY_NAME} PRIVATE utility)

if (${CANDY_DEVEL})
    install(FILES candy.h DESTINATION include)
    install(TARGETS ${CANDY_LIBRARY_NAME} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

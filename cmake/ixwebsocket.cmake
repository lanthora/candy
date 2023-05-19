include(FetchContent)

FetchContent_Declare(
  ixwebsocket
  GIT_REPOSITORY https://github.com/lanthora/IXWebSocket.git
  GIT_TAG        8c6ffce54d12b57a943e530e60e3b56b4d98722d
)

set(USE_TLS 1 CACHE BOOL "" FORCE)

FetchContent_GetProperties(ixwebsocket)
if(NOT ixwebsocket_POPULATED)
  FetchContent_Populate(ixwebsocket)
  add_subdirectory(${ixwebsocket_SOURCE_DIR} ${ixwebsocket_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()


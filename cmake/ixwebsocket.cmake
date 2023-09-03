include(FetchContent)

FetchContent_Declare(
  ixwebsocket
  GIT_REPOSITORY https://github.com/machinezone/IXWebSocket.git
  GIT_TAG        ef57e3a2b14c17b1a05aed0079f55fac2ece4996
)

set(USE_TLS 1 CACHE BOOL "" FORCE)
set(USE_OPEN_SSL 1 CACHE BOOL "" FORCE)

FetchContent_GetProperties(ixwebsocket)
if(NOT ixwebsocket_POPULATED)
  FetchContent_Populate(ixwebsocket)
  add_subdirectory(${ixwebsocket_SOURCE_DIR} ${ixwebsocket_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

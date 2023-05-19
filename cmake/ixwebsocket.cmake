include(FetchContent)

FetchContent_Declare(
  ixwebsocket
  GIT_REPOSITORY https://github.com/lanthora/IXWebSocket.git
  GIT_TAG        8c6ffce54d12b57a943e530e60e3b56b4d98722d
)

FetchContent_MakeAvailable(ixwebsocket)

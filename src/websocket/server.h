// SPDX-License-Identifier: MIT
#ifndef CANDY_WEBSOCKET_SERVER_H
#define CANDY_WEBSOCKET_SERVER_H

#include "websocket/common.h"
#include <cstdint>
#include <string>

namespace Candy {

class WebSocketServer {
public:
    WebSocketServer();
    ~WebSocketServer();

    // 开始监听和停止监听
    int listen(const std::string &ipStr, uint16_t port);
    int stop();

    // 设置读操作超时时间
    int setTimeout(int timeout);

    // 阻塞的读写操作
    int read(WebSocketMessage &message);
    int write(const WebSocketMessage &message);

    // 关闭单个客户端连接
    int close(WebSocketConn conn);

private:
    std::any impl;
};

}; // namespace Candy

#endif

// SPDX-License-Identifier: MIT
#ifndef CANDY_WEBSOCKET_SERVER_H
#define CANDY_WEBSOCKET_SERVER_H

#include "websocket/common.h"
#include <Poco/Net/HTTPServer.h>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <queue>
#include <string>

namespace Candy {

class WebSocketServer {
public:
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

    void push(const WebSocketMessage &msg);

    bool running;
    int timeout;

private:
    std::mutex mutex;
    std::condition_variable condition;
    std::queue<WebSocketMessage> queue;
    std::shared_ptr<Poco::Net::HTTPServer> server;
};

} // namespace Candy

#endif

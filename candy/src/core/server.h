// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_SERVER_H
#define CANDY_CORE_SERVER_H

#include "utils/atomic.h"
#include "websocket/server.h"
#include <string>

namespace candy {

class Server {
public:
    // 通过配置文件或命令行设置的参数
    void setWebSocket(const std::string &uri);
    void setPassword(const std::string &password);
    void setDHCP(const std::string &cidr);
    void setSdwan(const std::string &sdwan);

    // 启动服务端,非阻塞
    void run();
    // 关闭客户端,阻塞,直到所有子模块退出
    void shutdown();

private:
    // 目前只有一个 WebSocket 服务端的子模块
    WebSocketServer ws;
    Utils::Atomic<bool> running;
};

} // namespace candy

#endif

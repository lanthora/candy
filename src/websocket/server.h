// SPDX-License-Identifier: MIT
#ifndef CANDY_WEBSOCKET_SERVER_H
#define CANDY_WEBSOCKET_SERVER_H

#include "core/net.h"
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/WebSocket.h>
#include <list>
#include <memory>
#include <shared_mutex>
#include <string>

namespace Candy {

struct WsCtx {
    Poco::Net::WebSocket *ws;

    std::string buffer;
    int status;

    IP4 ip;
    std::string vmac;

    void sendFrame(const std::string &frame, int flags = Poco::Net::WebSocket::FRAME_BINARY);
};

struct SysRoute {
    // 通过地址和掩码确定策略下发给哪些客户端
    Address dev;
    // 系统路由策略中的地址掩码和下一跳
    Address dst;
    IP4 next;
};

class WebSocketServer {
public:
    int setWebSocket(const std::string &uri);
    int setPassword(const std::string &password);
    int setDHCP(const std::string &cidr);
    int setSdwan(const std::string &sdwan);
    int run();
    int shutdown();

private:
    std::string host;
    uint16_t port;
    std::string password;
    Address dhcp;
    std::list<SysRoute> routes;

private:
    void handleMsg(WsCtx &ctx);
    void handleAuthMsg(WsCtx &ctx);
    void handleForwardMsg(WsCtx &ctx);
    void handleExptTunMsg(WsCtx &ctx);
    void handleUdp4ConnMsg(WsCtx &ctx);
    void handleVMacMsg(WsCtx &ctx);
    void handleDiscoveryMsg(WsCtx &ctx);
    void HandleGeneralMsg(WsCtx &ctx);

    // 更新客户端系统路由
    void updateSysRoute(WsCtx &ctx);

    // 保存 IP 到对应连接指针的映射
    std::unordered_map<IP4, WsCtx *> ipCtxMap;
    // 操作 map 时需要加锁,以确保操作时指针有效
    std::shared_mutex ipCtxMutex;

    bool running;

private:
    // 开始监听,新的请求将调用 handleWebsocket
    int listen();
    // 同步的处理每个客户独的请求,函数返回后连接将断开
    void handleWebsocket(Poco::Net::WebSocket &ws);

    std::shared_ptr<Poco::Net::HTTPServer> httpServer;
};

} // namespace Candy

#endif

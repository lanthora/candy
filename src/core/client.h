// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_CLIENT_H
#define CANDY_CORE_CLIENT_H

#include "peer/dispatcher.h"
#include "tun/tun.h"
#include "websocket/client.h"
#include <string>
#include <thread>

namespace Candy {

class Client {
public:
    // 设置客户端名称,用于设置 TUN 设备的名称,格式为 candy-name, 如果 name 为空将被命名为 candy.
    int setName(const std::string &name);

    // 连接 websocket 服务端时身份认证的密码
    int setPassword(const std::string &password);

    // 用于数据转发的服务端地址
    int setWebSocketServer(const std::string &server);

    // 设置静态 IP 地址,向服务端要求强制使用这个地址,使用相同地址的前一个设备会被踢出网络
    int setLocalAddress(const std::string &cidr);

    // 设置默认动态 IP 地址,向服务端建议使用这个地址,这个地址不可用时服务端将返回一个可用的新地址
    int setDynamicAddress(const std::string &cidr);

    // 设置 STUN 服务端,用于开启对等连接
    int setStun(const std::string &stun);

    // 获取当前地址,设置的静态地址或者由服务端分发的动态地址
    std::string getAddress();

    // 启停客户端用于处理任务的线程
    int run();
    int shutdown();

private:
    int startWsThread();
    int startTunThread();
    int startDispatcherThread();

    // 处理来自 WebSocket 服务端的消息
    void handleWebSocketMessage();
    // 处理来自 TUN 设备的消息
    void handleTunMessage();
    // 处理来自 Dispatcher 的消息
    void handleDispatcherMessage();

    void sendDynamicAddressMessage();
    void sendAuthMessage();
    void sendPeerConnMessage(uint32_t src, uint32_t dst, uint32_t pubIp, uint16_t pubPort, uint8_t forceSync);

    void handleForwardMessage(WebSocketMessage &message);
    void handleDynamicAddressMessage(WebSocketMessage &message);
    void handlePeerConnMessage(WebSocketMessage &message);

    std::string tunName;
    std::string password;
    std::string wsUri;
    // tunThread 和 dispatcherThread 运行依赖正确的 localAddress, 赋值后才能启动这两个线程
    std::string localAddress;
    std::string dynamicAddress;

    std::string stun;

    std::thread wsThread;
    std::thread tunThread;
    std::thread dispatcherThread;

    bool running = false;

    Tun tun;
    WebSocketClient ws;
    Dispatcher dispatcher;
};

}; // namespace Candy

#endif

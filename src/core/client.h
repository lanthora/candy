// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_CLIENT_H
#define CANDY_CORE_CLIENT_H

#include "peer/peer.h"
#include "tun/tun.h"
#include "websocket/client.h"
#include <functional>
#include <map>
#include <shared_mutex>
#include <string>
#include <thread>

namespace Candy {

struct StunCache {
    uint32_t ip;
    uint16_t port;
    std::string uri;
};

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

    // 设置虚拟 Mac 地址
    int setVirtualMac(const std::string &vmac);

    // 设置 STUN 服务端,用于开启对等连接
    int setStun(const std::string &stun);

    // 设置主动发现时间间隔
    int setDiscoveryInterval(int interval);

    // 设置本地地址更新时执行的回调函数
    int setupAddressUpdateCallback(std::function<void(const std::string &)> callback);

    // 启停客户端用于处理任务的线程
    int run();
    int shutdown();

private:
    // Common
    std::string password;
    bool running = false;
    std::function<void(const std::string &)> addressUpdateCallback;

    // WebSocket
    int startWsThread();
    void handleWebSocketMessage();
    void sendVirtualMacMessage();
    void sendDynamicAddressMessage();
    void sendAuthMessage();
    void sendPeerConnMessage(uint32_t src, uint32_t dst, uint32_t ip, uint16_t port);
    void handleForwardMessage(WebSocketMessage &message);
    void handleDynamicAddressMessage(WebSocketMessage &message);
    void handlePeerConnMessage(WebSocketMessage &message);

    WebSocketClient ws;
    std::string wsUri;
    std::thread wsThread;

    // TUN
    int startTunThread();
    void handleTunMessage();

    Tun tun;
    std::string tunName;
    std::string localAddress;
    std::string dynamicAddress;
    std::string virtualMac;
    std::thread tunThread;

    // P2P
    int startUdpThread();
    int startTickThread();
    void handleUdpMessage();
    void tick();
    std::string encrypt(const std::string &key, const std::string &plaintext);
    std::string decrypt(const std::string &key, const std::string &ciphertext);
    int sendStunRequest();
    bool isStunResponse(const UdpMessage &message);
    int handleStunResponse(const std::string &buffer);
    bool isHeartbeatMessage(const UdpMessage &message);
    int handleHeartbeatMessage(const UdpMessage &message);
    int sendHeartbeat(const PeerInfo &peer);
    bool isIPv4Message(const UdpMessage &message);
    int handleIPv4Message(const UdpMessage &message);

    UdpHolder udpHolder;
    StunCache stun;
    PeerInfo selfInfo;
    std::shared_mutex ipPeerMutex;
    std::map<uint32_t, PeerInfo> ipPeerMap;
    std::thread udpThread;
    std::thread tickThread;
    uint64_t tickCount;
    uint32_t discoveryInterval;
};

} // namespace Candy

#endif

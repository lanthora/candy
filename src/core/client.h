// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_CLIENT_H
#define CANDY_CORE_CLIENT_H

#include "core/message.h"
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

struct RouteEntry {
    uint32_t dst;
    uint32_t next;
    int32_t delay;

    RouteEntry(uint32_t dst = 0, uint32_t next = 0, int32_t delay = DELAY_LIMIT) : dst(dst), next(next), delay(delay) {}
};

class Client {
public:
    // 设置客户端名称,用于设置 TUN 设备的名称,格式为 candy-name, 如果 name 为空将被命名为 candy.
    int setName(const std::string &name);
    std::string getName() const;

    // 连接 websocket 服务端时身份认证的密码
    int setPassword(const std::string &password);

    // 用于数据转发的服务端地址
    int setWebSocketServer(const std::string &server);

    // TUN 地址,向服务端要求强制使用这个地址,使用相同地址的前一个设备会被踢出网络
    int setTunAddress(const std::string &cidr);

    // 向服务端请求时期望获得的地址,地址不可用时服务端返回新地址
    int setExpectedAddress(const std::string &cidr);

    // 虚拟 Mac 地址
    int setVirtualMac(const std::string &vmac);

    // STUN 服务端,用于开启对等连接
    int setStun(const std::string &stun);

    // 主动发现时间间隔
    int setDiscoveryInterval(int interval);

    // 通过本节点路由的代价
    int setRouteCost(int cost);

    // 本地地址更新时执行的回调函数
    int setAddressUpdateCallback(std::function<void(const std::string &)> callback);

    // 绑定用于 P2P 连接的 UDP 端口, 0 表示由操作系统分配
    int setUdpBindPort(int port);

    // 用于局域网连接的地址
    int setLocalhost(std::string ip);

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
    void sendForwardMessage(const std::string &buffer);
    void sendVirtualMacMessage();
    void sendDynamicAddressMessage();
    void sendAuthMessage();
    void sendPeerConnMessage(const PeerInfo &peer, uint32_t ip, uint16_t port);
    void sendDiscoveryMessage(uint32_t dst);
    void sendLocalPeerConnMessage(const PeerInfo &peer, uint32_t ip, uint16_t port);
    void handleForwardMessage(WebSocketMessage &message);
    void handleExpectedAddressMessage(WebSocketMessage &message);
    void handlePeerConnMessage(WebSocketMessage &message);
    void handleDiscoveryMessage(WebSocketMessage &message);
    void handleGeneralMessage(WebSocketMessage &message);
    void handleLocalPeerConnMessage(WebSocketMessage &message);
    void tryDirectConnection(uint32_t ip);

    WebSocketClient ws;
    std::string wsUri;
    std::thread wsThread;

    // TUN
    int startTunThread();
    void handleTunMessage();

    Tun tun;
    std::string tunName;
    std::string tunAddress;
    std::string expectedAddress;
    std::string realAddress;
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
    int sendHeartbeatMessage(const PeerInfo &peer);
    int sendHeartbeatMessage(const PeerInfo &peer, uint32_t ip, uint32_t port);
    int sendPeerForwardMessage(const std::string &buffer);
    int sendPeerForwardMessage(const std::string &buffer, uint32_t nextHop);
    bool isStunResponse(const UdpMessage &message);
    bool isHeartbeatMessage(const UdpMessage &message);
    bool isPeerForwardMessage(const UdpMessage &message);
    int handleStunResponse(const std::string &buffer);
    int handleHeartbeatMessage(const UdpMessage &message);
    int handlePeerForwardMessage(const UdpMessage &message);

    UdpHolder udpHolder;
    StunCache stun;
    PeerInfo selfInfo;
    std::shared_mutex ipPeerMutex;
    std::map<uint32_t, PeerInfo> ipPeerMap;
    std::thread udpThread;
    std::thread tickThread;
    uint64_t tickTick = std::rand();
    uint32_t discoveryInterval;

    // Route
    void showRouteChange(const RouteEntry &entry);
    int updateRouteTable(RouteEntry entry);
    int sendDelayMessage(const PeerInfo &peer);
    int sendDelayMessage(const PeerInfo &peer, const PeerDelayMessage &delay);
    int sendRouteMessage(uint32_t dst, int32_t delay);
    bool isDelayMessage(const UdpMessage &message);
    bool isRouteMessage(const UdpMessage &message);
    int handleDelayMessage(const UdpMessage &message);
    int handleRouteMessage(const UdpMessage &message);

    std::shared_mutex rtTableMutex;
    std::map<uint32_t, RouteEntry> rtTable;
    int32_t routeCost;
};

} // namespace Candy

#endif

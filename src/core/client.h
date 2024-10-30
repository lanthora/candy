// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_CLIENT_H
#define CANDY_CORE_CLIENT_H

#include "core/message.h"
#include "peer/udp.h"
#include "tun/tun.h"
#include "utility/random.h"
#include "websocket/client.h"
#include <atomic>
#include <condition_variable>
#include <functional>
#include <list>
#include <queue>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace Candy {

struct StunCache {
    uint32_t ip;
    uint16_t port;
    std::string uri;
};

struct CandyRouteEntry {
    uint32_t dst;
    uint32_t next;
    int32_t delay;

    CandyRouteEntry(uint32_t dst = 0, uint32_t next = 0, int32_t delay = DELAY_LIMIT) : dst(dst), next(next), delay(delay) {}
};

struct SysRouteEntry {
    uint32_t dst;
    uint32_t mask;
    uint32_t next;

    SysRouteEntry(uint32_t dst = 0, uint32_t mask = 0, uint32_t next = 0) : dst(dst), mask(mask), next(next) {}
};

class Client {
public:
    // 设置客户端名称,用于设置 TUN 设备的名称,格式为 candy-name, 如果 name 为空将被命名为 candy.
    int setName(const std::string &name);
    std::string getName() const;

    // 客户端工作线程数量
    int setWorkers(int number);

    // 连接 websocket 服务端时身份认证的口令
    int setPassword(const std::string &password);

    // 用于数据转发和对等连接控制的服务端地址
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
    int setAddressUpdateCallback(std::function<int(const std::string &)> callback);

    // 绑定用于 P2P 连接的 UDP 端口, 0 表示由操作系统分配
    int setUdpBindPort(int port);

    // 用于局域网连接的地址
    int setLocalhost(std::string ip);

    // 设置最大传输单元
    int setMtu(int mtu);

    // 启停客户端用于处理任务的线程
    int run();
    int shutdown();

private:
    // Common
    int workers = 0;
    int mtu = 1400;
    bool running = false;
    std::string password;
    std::mutex runningMutex;
    std::function<int(const std::string &)> addressUpdateCallback;
    int startWorkerThreads();
    int stopWorkerThreads();

    // WebSocket
    int startWsThread();
    void handleWebSocketMessage();
    void sendForwardMessage(const std::string &buffer);
    void sendVirtualMacMessage();
    void sendDynamicAddressMessage();
    void sendAuthMessage();
    void sendPeerConnMessage(const PeerInfo &peer);
    void sendDiscoveryMessage(uint32_t dst);
    void sendLocalPeerConnMessage(const PeerInfo &peer);
    void handleForwardMessage(WebSocketMessage &message);
    void handleExpectedAddressMessage(WebSocketMessage &message);
    void handlePeerConnMessage(WebSocketMessage &message);
    void handleDiscoveryMessage(WebSocketMessage &message);
    void handleSysRtMessage(WebSocketMessage &message);
    void handleGeneralMessage(WebSocketMessage &message);
    void handleLocalPeerConnMessage(WebSocketMessage &message);
    void tryDirectConnection(uint32_t ip);
    std::string hostName();

    WebSocketClient ws;
    std::string wsUri;
    std::thread wsThread;

    // TUN
    int startTunThread();
    void recvTunMessage();
    void handleTunMessage(std::string message);

    Tun tun;
    std::string tunName;
    std::string tunAddress;
    std::string expectedAddress;
    std::string realAddress;
    std::string virtualMac;
    std::thread tunThread;
    std::vector<std::thread> tunMsgWorkerThreads;
    std::mutex tunMsgQueueMutex;
    std::queue<std::string> tunMsgQueue;
    std::condition_variable tunMsgQueueCondition;

    // P2P
    int startUdpThread();
    int startTickThread();
    void recvUdpMessage();
    void handleUdpMessage(UdpMessage message);
    void tick();
    std::string encrypt(const std::string &key, const std::string &plaintext);
    std::string decrypt(const std::string &key, const std::string &ciphertext);
    std::string encryptHelper(const std::string &key, const std::string &plaintext);
    std::string decryptHelper(const std::string &key, const std::string &ciphertext);
    int sendStunRequest();
    int sendHeartbeatMessage(const PeerInfo &peer);
    int sendPeerForwardMessage(const std::string &buffer);
    int sendPeerForwardMessage(const std::string &buffer, uint32_t nextHop);
    bool isStunResponse(const UdpMessage &message);
    bool isHeartbeatMessage(const UdpMessage &message);
    bool isPeerForwardMessage(const UdpMessage &message);
    int handleStunResponse(const std::string &buffer);
    int handleHeartbeatMessage(const UdpMessage &message);
    int handlePeerForwardMessage(const UdpMessage &message);
    static bool isLocalIp(uint32_t ip);

    UdpHolder udpHolder;
    StunCache stun;
    PeerInfo selfInfo;
    std::shared_mutex ipPeerMutex;
    std::unordered_map<uint32_t, PeerInfo> ipPeerMap;
    std::thread udpThread;
    std::thread tickThread;
    uint64_t tickTick = randomUint32();
    uint32_t discoveryInterval;
    std::mutex cryptMutex;
    std::atomic<bool> localP2PDisabled;
    std::vector<std::thread> udpMsgWorkerThreads;
    std::mutex udpMsgQueueMutex;
    std::queue<UdpMessage> udpMsgQueue;
    std::condition_variable udpMsgQueueCondition;

    // Route
    void showCandyRtChange(const CandyRouteEntry &entry);
    int updateCandyRtTable(CandyRouteEntry entry);
    int sendDelayMessage(const PeerInfo &peer);
    int sendDelayMessage(const PeerInfo &peer, const PeerDelayMessage &delay);
    int sendCandyRtMessage(uint32_t dst, int32_t delay);
    bool isDelayMessage(const UdpMessage &message);
    bool isCandyRtMessage(const UdpMessage &message);
    int handleDelayMessage(const UdpMessage &message);
    int handleCandyRtMessage(const UdpMessage &message);

    std::shared_mutex sysRtTableMutex;
    std::list<SysRouteEntry> sysRtTable;
    std::shared_mutex candyRtTableMutex;
    std::unordered_map<uint32_t, CandyRouteEntry> candyRtTable;
    int32_t routeCost;
};

} // namespace Candy

#endif

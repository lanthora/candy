// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_DISPATCHER_H
#define CANDY_PEER_DISPATCHER_H

#include "peer/peer.h"
#include <any>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <string>
#include <thread>

namespace Candy {

// 管理对端连接,需要完成一下功能
// 1. 数据加密后发送
// 2. 收据接收后解密,并校验数据来源
// 3. 通过心跳维持和各个对端的连接
class Dispatcher {
public:
    // 绑定 UDP 端口
    Dispatcher();
    ~Dispatcher();

    // 用于获取映射后的公网地址和端口
    // 参数格式: stun://stun.cloudflare.com[:3478]
    int setStun(const std::string &stun);

    // 用于校验接收报文的目的地址是否为本机
    int setTunIP(uint32_t ip);

    // 设置口令,口令用来生成对称加密解密的密钥
    int setPassword(const std::string &password);

    // 1. 周期调用 tick
    // 2. 处理 socket 收到的消息
    int run();
    // 关闭 tick 线程
    int shutdown();

    // 从 STUN 服务端获取公网地址和端口
    int fetchPublicInfo(uint32_t &pubIp, uint16_t &pubPort);

    // 收到对端发送的公网信息,连接状态切换为 CONNECTING, 并开始向对方发包尝试建立连接,
    int updatePeerPublicInfo(uint32_t tunIp, uint32_t pubIp, uint16_t pubPort, uint8_t forceSync);

    // 状态从 INIT 切换到 PREPARING,只在对端为 INIT 状态的时候从 STUN 获取自己的公网信息并发送给对方,
    // PREPARING 状态时不再从 STUN 服务器获取公网信息.
    int updatePeerState(uint32_t tunIp);

    // Client 获取对端状态,当状态为 INIT 时,调用 fetchPublicInfo 获取本机地址,并通过服务端发送给目标机器,尝试建立连接.
    // 只有状态为 CONNECTED 时,直接发送,否则都要通过 Server 转发.
    PeerConnState getPeerState(uint32_t ip);

    // 读写原始的 IP 报文,也只允许通过对等连接传输这类信息,控制类的信息只能通过服务端转发
    int write(std::string &buffer);
    // 除了正常的转发消息,还可能读到心跳.如果读到的是心跳,更新连接状态后,返回 0
    int read(std::string &buffer);

private:
    // 完成重复性动作,向 CONNECTED 和 CONNECTING 状态的连接发送心跳, CONNECTING 根据执行次数决定是否进入 FAILED 状态.
    // 对于 CONNECTED 但连续多次 tick 没有收到心跳的连接切换为 INIT. tick 由外部调用
    int tick();

    std::string encrypt(const std::string &key, const std::string &plaintext);
    std::string decrypt(const std::string &key, const std::string &ciphertext);

    int sendRawUdp(uint32_t ip, uint16_t port, const std::string &msg);
    int recvRawUdp(uint32_t &ip, uint16_t &port, std::string &msg);

    int handleUdpMessage();
    int handleStunResponse(const std::string &msg);
    int handleHeartbeatMsg(const std::string &msg, uint32_t pubIp, uint16_t pubPort);
    int handleForwardMsg(const std::string &msg, uint32_t pubIp, uint16_t pubPort);

private:
    // UDP 不需要处理连接状态,所以用一个 socket 就能处理和所有对端的通信.
    // 不同操作系统表示 socket 的方式不同,在 Linux/MacOS 中为 int.
    std::any socket;
    std::string stun;
    std::string password;
    uint32_t tunIp;

    // 记录 stun 服务端ip:port,收到来自这个地址的 UDP 报文时按照 stun 解析
    uint32_t stunIp;
    uint16_t stunPort;

    bool stunResponded;
    uint32_t pubIp;
    uint16_t pubPort;
    std::mutex pubMutex;
    std::condition_variable pubCondition;

    std::string key;
    bool running;

    std::map<uint32_t, Peer> ipPeerMap;
    std::shared_mutex ipPeerMapMutex;

    std::queue<std::string> queue;
    std::mutex queueMutex;
    std::condition_variable queueCondition;

    std::thread tickThread;
    std::thread udpMessageThread;

    const size_t AES_256_GCM_IV_LEN = 12;
    const size_t AES_256_GCM_TAG_LEN = 16;
    const size_t AES_256_GCM_KEY_LEN = 32;
};

}; // namespace Candy

#endif

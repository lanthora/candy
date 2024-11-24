// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_PEER_H
#define CANDY_PEER_PEER_H

#include "core/message.h"
#include "core/net.h"
#include "peer/info.h"
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace Candy {

class Client;

class Peer {
public:
    int setPassword(const std::string &password);
    int setStun(const std::string &stun);
    int setDiscoveryInterval(int interval);
    int setForwardCost(int cost);
    int setPort(int port);
    int setLocalhost(const std::string &ip);

    int run(Client *client);
    int shutdown();

private:
    // 处理来自消息队列的数据
    void handlePeerQueue();
    void handlePacket(Msg msg);
    void handleTryP2P(Msg msg);

    std::thread msgThread;

    // 处理 PACKET 报文,并判断目标是否可达
    int sendTo(IP4 dst, const Msg &msg);
    // 通过指定的 info 向对端发送 data, 此时的 data 是明文
    int sendTo(PeerInfo &info, const std::string &data);

private:
    std::shared_mutex ipPeerMutex;
    std::unordered_map<IP4, PeerInfo> ipPeerMap;

    std::shared_mutex rtTableMutex;
    std::unordered_map<IP4, IP4> rtTableMap;

private:
    Client *client;
};

} // namespace Candy

#endif

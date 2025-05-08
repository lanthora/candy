// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_MANAGER_H
#define CANDY_PEER_MANAGER_H

#include "core/message.h"
#include "core/net.h"
#include "peer/connector.h"
#include "peer/message.h"
#include "peer/peer.h"
#include <Poco/Net/DatagramSocket.h>
#include <Poco/Net/PollSet.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/StreamSocket.h>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace Candy {

using Poco::Net::SocketAddress;

class Client;

struct Stun {
    std::string uri;
    SocketAddress address;
    bool needed = false;
    IP4 ip;
    uint16_t port;
};

class PeerManager {
public:
    int setPassword(const std::string &password);
    int setStun(const std::string &stun);
    int setDiscoveryInterval(int interval);
    int setForwardCost(int cost);
    int setPort(int port);
    int setLocalhost(const std::string &ip);
    int setTransport(const std::vector<std::string> &transport);

    int run(Client *client);
    int shutdown();

    std::string getPassword();

private:
    std::string password;
    IP4 localhost;

public:
    int sendPubInfo(CoreMsg::PubInfo info);
    IP4 getTunIp();

private:
    // 处理来自消息队列的数据
    void handlePeerQueue();
    void handlePacket(Msg msg);
    void handleTunAddr(Msg msg);
    void handleTryP2P(Msg msg);
    void handlePubInfo(Msg msg);

    std::thread msgThread;

    int sendPacket(IP4 dst, const Msg &msg);
    int sendPacketDirect(IP4 dst, const Msg &msg);
    int sendPacketRelay(IP4 dst, const Msg &msg);

    Address tunAddr;

private:
    void tick();
    std::thread tickThread;

private:
    std::shared_mutex ipPeerMutex;
    std::unordered_map<IP4, Peer> ipPeerMap;

    std::shared_mutex rtTableMutex;
    std::unordered_map<IP4, std::shared_ptr<Connector>> rtTableMap;

public:
    Stun udpStun;
    std::atomic<bool> localP2PDisabled;

private:
    int initSocket();
    void sendUdpStunRequest();
    void handleUdpStunResponse(const std::string &buffer);
    void handleUdp4Message(std::string &buffer, const SocketAddress &address);
    void handleUdp4HeartbeatMessage(std::string &buffer, const SocketAddress &address);
    void handleUdp4ForwardMessage(std::string &buffer, const SocketAddress &address);
    void handleUdp4DelayMessage(std::string &buffer, const SocketAddress &address);
    void handleUdp4RouteMessage(std::string &buffer, const SocketAddress &address);
    void poll();

    std::optional<std::string> decrypt(const std::string &ciphertext);
    std::shared_ptr<EVP_CIPHER_CTX> decryptCtx;
    std::mutex decryptCtxMutex;
    std::string key;

    // 默认监听端口,如果不配置,随机监听
    uint16_t listenPort = 0;

public:
    // 维护用于监听的 socket, 读操作统一在外部完成, 写操作给到 PeerInfo
    Poco::Net::DatagramSocket udp4socket, udp6socket;
    Poco::Net::ServerSocket tcp4socket, tcp6socket;
    Poco::Net::PollSet pollSet;

private:
    std::thread pollThread;

public:
    std::vector<std::string> getTransport();
    Client &getClient();

private:
    std::vector<std::string> transport;
    Client *client;
};

} // namespace Candy

#endif

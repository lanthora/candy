// SPDX-License-Identifier: MIT
#ifndef CANDY_NETSTACK_NETSTACK_H
#define CANDY_NETSTACK_NETSTACK_H

#include "core/message.h"
#include "core/net.h"
#include <string>

#include "netstack/ip.h"
#include "netstack/tcp.h"
#include "netstack/udp.h"
#include <Poco/Net/DatagramSocket.h>
#include <Poco/Net/PollSet.h>
#include <Poco/Net/StreamSocket.h>
#include <cstdint>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace candy {

class Client;

struct TcpProxy {
    std::unique_ptr<TcpStream> stream;
    std::unique_ptr<Poco::Net::StreamSocket> sock;
    bool closed;
};

struct UdpProxy {
    std::unique_ptr<Poco::Net::DatagramSocket> sock;
    IP4 dstIp;
    uint16_t dstPort;
    IP4 srcIp;
    uint16_t srcPort;
    uint32_t lastActive;
};

class Netstack {
public:
    Netstack();
    ~Netstack();

    int run(Client *client);
    int wait();

private:
    Client *client;

    int handlePacket(Msg msg);
    void sendIPIP(const std::string &innerPkt);

    void pollProxies();
    void pollTcpProxies();
    void pollUdpProxies();

    Client &getClient();

    std::thread msgThread;
    std::thread lwipThread;

    // Hand-off queue between msgThread (dispatch) and lwipThread (lwIP work).
    std::deque<Msg> pendingPackets;
    std::mutex pendingMutex;
    std::condition_variable pendingCv;

    std::unique_ptr<IpStack> ip;
    std::unique_ptr<TcpListener> tcpListener;
    std::unique_ptr<UdpSocket> udpSocket;

    IP4 peerIp;

    std::list<TcpProxy> tcpProxies;
    std::mutex tcpProxyMutex;
    Poco::Net::PollSet pollSet;
    std::map<Poco::Net::SocketImpl *, void *> socketMap;

    std::list<UdpProxy> udpProxies;
    std::mutex udpProxyMutex;
};

} // namespace candy

#endif

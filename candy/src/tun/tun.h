// SPDX-License-Identifier: MIT
#ifndef CANDY_TUN_TUN_H
#define CANDY_TUN_TUN_H

#include "core/message.h"
#include "core/net.h"
#include <list>
#include <memory>
#include <shared_mutex>
#include <string>
#include <thread>

namespace candy {

class Client;

class Tun {
public:
    Tun();
    ~Tun();

    int setName(const std::string &name);
    int setMTU(int mtu);

    int run(Client *client);
    int wait();

    IP4 getIP() const;
    IP4 getMask() const;

private:
    int setAddress(const std::string &cidr);
    bool inTunNetwork(IP4 addr) const;
    bool invalidSrcDst(const IP4Header &header) const;

    // Process data from the TUN device
    int handleTunDevice();

    // Process data from the message queue
    int handleTunQueue();
    int handlePacket(Msg msg);
    int handleTunAddr(Msg msg);
    int handleSysRt(Msg msg);

    std::string tunAddress;
    std::thread tunThread;
    std::thread msgThread;

private:
    int up();
    int down();

    int read(std::string &buffer);
    int write(const std::string &buffer);

    int setSysRtTable(const SysRouteEntry &entry);
    int setSysRtTable(IP4 dst, IP4 mask, IP4 nexthop);

    std::shared_mutex sysRtMutex;
    std::list<SysRouteEntry> sysRtTable;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
    IP4 ip;
    IP4 mask;

private:
    Client &getClient();
    Client *client;
};

} // namespace candy

#endif

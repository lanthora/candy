// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_CLIENT_H
#define CANDY_CORE_CLIENT_H

#include "core/message.h"
#include "peer/manager.h"
#include "tun/tun.h"
#include "utils/atomic.h"
#include "websocket/client.h"
#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>

namespace candy {

class MsgQueue {
public:
    Msg read();
    void write(Msg msg);
    void clear();

private:
    std::queue<Msg> msgQueue;
    std::mutex msgMutex;
    std::condition_variable msgCondition;
};

class Client {
public:
    void setName(const std::string &name);
    void setPassword(const std::string &password);
    void setWebSocket(const std::string &uri);
    void setTunAddress(const std::string &cidr);
    void setStun(const std::string &stun);
    void setDiscoveryInterval(int interval);
    void setRouteCost(int cost);
    void setPort(int port);
    void setLocalhost(std::string ip);
    void setMtu(int mtu);

    void setExptTunAddress(const std::string &cidr);
    void setVirtualMac(const std::string &vmac);

    void run();
    bool isRunning();
    void shutdown();

    std::string getName() const;
    std::string getTunCidr() const;
    IP4 address();

private:
    Utils::Atomic<bool> running;

public:
    MsgQueue &getTunMsgQueue();
    MsgQueue &getPeerMsgQueue();
    MsgQueue &getWsMsgQueue();

private:
    MsgQueue tunMsgQueue, peerMsgQueue, wsMsgQueue;

    Tun tun;
    PeerManager peerManager;
    WebSocketClient ws;

private:
    std::string tunName;
};

} // namespace candy

#endif

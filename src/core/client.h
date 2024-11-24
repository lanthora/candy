// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_CLIENT_H
#define CANDY_CORE_CLIENT_H

#include "core/message.h"
#include "peer/manager.h"
#include "tun/tun.h"
#include "websocket/client.h"
#include <condition_variable>
#include <queue>
#include <string>

namespace Candy {

void shutdown(Client *client);

class MsgQueue {
public:
    Msg read();
    void write(Msg msg);

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
    void setTunUpdateCallback(std::function<int(const std::string &)> callback);

    void setExptTunAddress(const std::string &cidr);
    void setVirtualMac(const std::string &vmac);

    void run();
    void shutdown();

    bool running = false;

    std::string getName() const;
    IP4 address();

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

} // namespace Candy

#endif

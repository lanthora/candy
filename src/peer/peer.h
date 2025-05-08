// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_PEER_H
#define CANDY_PEER_PEER_H

#include "core/net.h"
#include "peer/tcp.h"
#include "peer/udp.h"
#include <cstdint>
#include <map>
#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <string>

namespace Candy {

class PeerManager;

class Peer {
public:
    Peer(const IP4 &addr, PeerManager *peerManager);
    ~Peer();

public:
    std::shared_ptr<Candy::Connector> findConnector();
    void tryConnecct();
    void tick();

    void handleUdp4Conn(IP4 ip, uint16_t port, bool local = false);
    void handleUdpStunResponse();

    PeerManager &getManager();
    IP4 getAddr();

private:
    // 对端虚拟地址
    IP4 addr;
    PeerManager *peerManager;

public:
    // 所有对等连接使用统一的加密方式, 为了解决 TCP 无法分包的问题,
    // 加密使用的 IV 前两个字节用于表示报文长度, 由于 MTU 的限制, 两个字节大小足够
    std::optional<std::string> encrypt(const std::string &plaintext);

private:
    std::shared_ptr<EVP_CIPHER_CTX> encryptCtx;
    std::mutex encryptCtxMutex;
    std::string key;

public:
    std::shared_ptr<UDP4> Udp4();
    std::shared_ptr<UDP6> Udp6();
    std::shared_ptr<TCP4> Tcp4();
    std::shared_ptr<TCP6> Tcp6();

private:
    std::map<std::string, std::shared_ptr<Connector>> connectors;
};

} // namespace Candy

#endif

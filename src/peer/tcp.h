// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_TCP_H
#define CANDY_PEER_TCP_H

#include "peer/connector.h"

namespace Candy {

class TCP : public Connector {
public:
    TCP(Peer *peer) : Connector(peer) {}

    std::optional<int32_t> isConnected() const;
    bool tryToConnect();
};

class TCP4 : public TCP {
public:
    TCP4(Peer *peer) : TCP(peer) {}
    std::string getName();
    void tick();

private:
    int send(const std::string &buffer);
};

class TCP6 : public TCP {
public:
    TCP6(Peer *peer) : TCP(peer) {}
    std::string getName();
    void tick();

private:
    int send(const std::string &buffer);
};

} // namespace Candy

#endif

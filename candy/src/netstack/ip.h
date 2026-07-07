// SPDX-License-Identifier: MIT
#ifndef CANDY_IP_H
#define CANDY_IP_H

#include "core/net.h"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

struct tcp_pcb;
struct udp_pcb;

namespace candy {

struct Config {
    IP4 addr{"198.18.0.1"};
    uint16_t listenPort = 19818;
    int mtu = 1500;
};

class IpStack {
public:
    class Impl {
    protected:
        Impl() = default;

    public:
        virtual ~Impl() = default;
    };

    // Factory; returns nullptr on init failure (e.g. netif_add failed).
    static std::unique_ptr<IpStack> create(const Config &cfg);
    ~IpStack();
    IpStack(const IpStack &) = delete;
    IpStack &operator=(const IpStack &) = delete;

    void send(const std::string &rawIpPacket);
    std::optional<std::string> recv();

    void bindTcpPretendListener(struct tcp_pcb *pcb);
    void bindUdpPretendSocket(struct udp_pcb *pcb);

private:
    IpStack();
    std::unique_ptr<Impl> impl;
};

void checkTimeouts();

IP4 lwipToIP4(const void *addr);

IP4 fromLwipHostOrder(uint32_t hostOrder);

} // namespace candy

#endif

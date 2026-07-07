// SPDX-License-Identifier: MIT
#ifndef CANDY_IPSTACK_UDP_H
#define CANDY_IPSTACK_UDP_H

#include "core/net.h"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace candy {

class IpStack;

class UdpSocket {
public:
    class Impl {
    protected:
        Impl() = default;

    public:
        virtual ~Impl() = default;
    };

    struct Packet {
        std::string data;
        IP4 srcAddr;
        uint16_t srcPort;
        IP4 dstAddr;
        uint16_t dstPort;
    };

    static std::unique_ptr<UdpSocket> bind(IpStack &ip, IP4 addr, uint16_t port);
    ~UdpSocket();
    UdpSocket(const UdpSocket &) = delete;
    UdpSocket &operator=(const UdpSocket &) = delete;

    std::optional<Packet> recv();
    void send(const std::string &data, IP4 srcAddr, uint16_t srcPort, IP4 dstAddr, uint16_t dstPort);

    // Drop flow PCBs idle for longer than maxAgeMs. Call periodically to
    // prevent flowPcbs from growing without bound.
    void sweep(uint32_t maxAgeMs);

private:
    UdpSocket();
    std::unique_ptr<Impl> impl;
};

} // namespace candy

#endif

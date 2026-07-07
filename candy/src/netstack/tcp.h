// SPDX-License-Identifier: MIT
#ifndef CANDY_IPSTACK_TCP_H
#define CANDY_IPSTACK_TCP_H

#include "core/net.h"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace candy {

class IpStack;

class TcpStream {
public:
    class Impl {
    protected:
        Impl() = default;

    public:
        virtual ~Impl() = default;
    };

    ~TcpStream();
    TcpStream(const TcpStream &) = delete;
    TcpStream &operator=(const TcpStream &) = delete;

    static std::unique_ptr<TcpStream> create(std::unique_ptr<Impl> impl);

    std::optional<std::string> read();
    void write(const std::string &data);
    void close();
    bool isClosed() const;

private:
    TcpStream();
    std::unique_ptr<Impl> impl;
};

class TcpListener {
public:
    class Impl {
    protected:
        Impl() = default;

    public:
        virtual ~Impl() = default;
    };

    struct AcceptResult {
        std::unique_ptr<TcpStream> stream;
        IP4 srcAddr;
        uint16_t srcPort;
        IP4 dstAddr;
        uint16_t dstPort;
    };

    static std::unique_ptr<TcpListener> bind(IpStack &ip, IP4 addr, uint16_t port);
    ~TcpListener();
    TcpListener(const TcpListener &) = delete;
    TcpListener &operator=(const TcpListener &) = delete;

    std::optional<AcceptResult> accept();

private:
    TcpListener();
    std::unique_ptr<Impl> impl;
};

} // namespace candy

#endif

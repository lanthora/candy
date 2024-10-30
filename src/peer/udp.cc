#include "peer/udp.h"
#include "utility/address.h"
#include <Poco/Net/DatagramSocket.h>
#include <Poco/Net/NetworkInterface.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/SocketDefs.h>
#include <spdlog/spdlog.h>

namespace Candy {

int UdpHolder::init() {
    try {
        this->socket = Poco::Net::DatagramSocket(Poco::Net::SocketAddress(this->port), true, true);
        this->socket.setBlocking(false);
        this->address = socket.address();
    } catch (std::exception &e) {
        spdlog::critical("udp holder init failed: {}", e.what());
        return -1;
    }
    return 0;
}

void UdpHolder::reset() {
    try {
        this->socket.close();
        this->port = 0;
        this->ip = 0;
    } catch (std::exception &e) {
        spdlog::warn("udp holder reset failed: {}", e.what());
    }
}

void UdpHolder::setPort(uint16_t port) {
    this->port = port;
}

void UdpHolder::setIP(uint32_t ip) {
    this->ip = ip;
}

uint16_t UdpHolder::Port() {
    return this->address.port();
}

uint32_t UdpHolder::IP() {
    if (!this->ip) {
        try {
            for (const auto &iface : Poco::Net::NetworkInterface::list()) {
                if (iface.supportsIPv4() && !iface.isLoopback() && !iface.isPointToPoint() &&
                    iface.type() != iface.NI_TYPE_OTHER) {
                    auto firstAddress = iface.firstAddress(Poco::Net::IPAddress::IPv4);
                    memcpy(&this->ip, firstAddress.addr(), sizeof(this->ip));
                    this->ip = ntohl(this->ip);
                    break;
                }
            }
        } catch (std::exception &e) {
            spdlog::warn("local ip failed: {}", e.what());
        }
    }
    return this->ip;
}

size_t UdpHolder::read(UdpMessage &message) {
    try {
        if (this->socket.available()) {
            std::string buffer(1500, 0);
            Poco::Net::SocketAddress address;
            int size = this->socket.receiveFrom(buffer.data(), buffer.size(), address);
            if (size >= 0) {
                buffer.resize(size);
                message.buffer = std::move(buffer);
                message.port = address.port();
                memcpy(&message.ip, address.host().addr(), sizeof(message.ip));
                message.ip = Address::netToHost(message.ip);
                return size;
            }
        }

        this->socket.poll(Poco::Timespan(1, 0), Poco::Net::Socket::SELECT_READ);
    } catch (std::exception &e) {
        spdlog::debug("udp holder read failed: {}", e.what());
    }
    return 0;
}

size_t UdpHolder::write(const UdpMessage &message) {
    try {
        Poco::Net::SocketAddress address(Address::ipToStr(message.ip), message.port);
        return this->socket.sendTo(message.buffer.data(), message.buffer.size(), address);
    } catch (std::exception &e) {
        spdlog::debug("udp holder write failed: {}", e.what());
    }
    return 0;
}

} // namespace Candy

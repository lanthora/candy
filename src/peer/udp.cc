#include "peer/udp.h"
#include "core/client.h"
#include "core/message.h"
#include "peer/manager.h"
#include "peer/peer.h"
#include <Poco/Net/IPAddress.h>
#include <Poco/Net/SocketAddress.h>
#include <algorithm>
#include <spdlog/spdlog.h>

namespace {

using namespace Poco::Net;

bool isIPv4Local(uint32_t ipv4_host) {
    return ((ipv4_host & 0xFF000000) == 0x0A000000) || // 10.0.0.0/8
           ((ipv4_host & 0xFFF00000) == 0xAC100000) || // 172.16.0.0/12
           ((ipv4_host & 0xFFFF0000) == 0xC0A80000) || // 192.168.0.0/16
           ((ipv4_host & 0xFF000000) == 0x7F000000) || // 127.0.0.0/8
           ((ipv4_host & 0xFFFF0000) == 0xA9FE0000);   // 169.254.0.0/16
}

bool isLocalNetwork(const SocketAddress &addr) {
    IPAddress ip = addr.host();

    if (ip.isV4()) {
        uint32_t ipv4_net;
        std::memcpy(&ipv4_net, ip.addr(), 4);
        return isIPv4Local(Candy::ntoh(ipv4_net));
    } else if (ip.isV6()) {
        // TODO: 添加 IPv6 支持
        spdlog::error("unexpected ipv6 local address");
    }

    return false;
}

} // namespace

namespace Candy {

std::optional<int32_t> UDP::isConnected() const {
    if (this->state == UdpPeerState::CONNECTED) {
        return this->rtt;
    }
    return std::nullopt;
}

bool UDP::tryToConnect() {
    if (this->state == UdpPeerState::INIT) {
        updateState(UdpPeerState::PREPARING);
        return true;
    }
    return false;
}

bool UDP::updateState(UdpPeerState state) {
    this->refreshActiveTime();
    if (this->state == state) {
        return false;
    }

    spdlog::debug("state: {} {} {} => {}", getPeerAddress().toString(), getName(), stateString(), stateString(state));

    if (state == UdpPeerState::INIT || state == UdpPeerState::WAITING || state == UdpPeerState::FAILED) {
        resetState();
    }

    if (this->state == UdpPeerState::WAITING && state == UdpPeerState::INIT) {
        this->retry = std::min(this->retry * 2, RETRY_MAX);
    } else if (state == UdpPeerState::INIT || state == UdpPeerState::FAILED) {
        this->retry = RETRY_MIN;
    }

    this->state = state;
    return true;
}

std::string UDP::stateString() const {
    return this->stateString(this->state);
}

std::string UDP::stateString(UdpPeerState state) const {
    switch (state) {
    case UdpPeerState::INIT:
        return "INIT";
    case UdpPeerState::PREPARING:
        return "PREPARING";
    case UdpPeerState::SYNCHRONIZING:
        return "SYNCHRONIZING";
    case UdpPeerState::CONNECTING:
        return "CONNECTING";
    case UdpPeerState::CONNECTED:
        return "CONNECTED";
    case UdpPeerState::WAITING:
        return "WAITING";
    case UdpPeerState::FAILED:
        return "FAILED";
    default:
        return "UNKNOWN";
    }
}

std::string UDP4::getName() {
    return "UDP4";
}

void UDP4::updateInfo(IP4 ip, uint16_t port, bool local) {
    if (local) {
        this->local = SocketAddress(ip.toString(), port);
        return;
    }

    this->wide = SocketAddress(ip.toString(), port);

    if (this->state == UdpPeerState::CONNECTED) {
        return;
    }

    if (this->state == UdpPeerState::SYNCHRONIZING) {
        updateState(UdpPeerState::CONNECTING);
        return;
    }

    if (this->state != UdpPeerState::CONNECTING) {
        updateState(UdpPeerState::PREPARING);
        CoreMsg::PubInfo info = {.dst = this->getPeerAddress(), .local = true};
        getPeerManager().sendPubInfo(info);
        return;
    }
}

void UDP4::handleStunResponse() {
    if (this->state != UdpPeerState::PREPARING) {
        return;
    }
    if (this->wide == std::nullopt) {
        updateState(UdpPeerState::SYNCHRONIZING);
    } else {
        updateState(UdpPeerState::CONNECTING);
    }
    CoreMsg::PubInfo info = {.dst = this->getPeerAddress()};
    getPeerManager().sendPubInfo(info);
}

void UDP4::tick() {
    switch (this->state) {
    case UdpPeerState::INIT:
        break;
    case UdpPeerState::PREPARING:
        if (isActiveIn(std::chrono::seconds(10))) {
            getPeerManager().udpStun.needed = true;
        } else {
            updateState(UdpPeerState::FAILED);
        }
        break;
    case UdpPeerState::SYNCHRONIZING:
        if (isActiveIn(std::chrono::seconds(10))) {
            sendHeartbeat();
        } else {
            updateState(UdpPeerState::FAILED);
        }
        break;
    case UdpPeerState::CONNECTING:
        if (isActiveIn(std::chrono::seconds(10))) {
            sendHeartbeat();
        } else {
            updateState(UdpPeerState::WAITING);
        }
        break;
    case UdpPeerState::CONNECTED:
        // 进行超时检测,超时后清空对端信息,否则发送心跳
        if (isActiveIn(std::chrono::seconds(3))) {
            sendHeartbeat();
            // TODO: 检测延迟
        } else {
            updateState(UdpPeerState::INIT);
            // TODO: 广播断开连接事件
        }
        break;
    case UdpPeerState::WAITING:
        if (!isActiveIn(std::chrono::seconds(this->retry))) {
            updateState(UdpPeerState::INIT);
        }
        break;
    case UdpPeerState::FAILED:
        break;
    default:
        break;
    }
}

void UDP4::handleHeartbeatMessage(const SocketAddress &address, uint8_t heartbeatAck) {
    if (this->state == UdpPeerState::INIT || this->state == UdpPeerState::WAITING || this->state == UdpPeerState::FAILED) {
        spdlog::debug("heartbeat peer state invalid: {} {}", this->getPeerAddress().toString(), stateString());
        return;
    }

    if (!isLocalNetwork(address)) {
        this->wide = address;
    } else if (!getPeerManager().localP2PDisabled) {
        this->local = address;
    } else {
        return;
    }

    if (!this->real || isLocalNetwork(address) || !isLocalNetwork(*this->real)) {
        this->real = address;
    }

    if (!this->ack) {
        this->ack = 1;
    }

    if (heartbeatAck && updateState(UdpPeerState::CONNECTED)) {
        // TODO: 发送 Delay 报文
    }
}

int UDP4::send(const std::string &buffer) {
    if (this->real) {
        try {
            if (buffer.size() == getPeerManager().udp4socket.sendTo(buffer.data(), buffer.size(), *this->real)) {
                return 0;
            }
        } catch (std::exception &e) {
            spdlog::debug("udp4 send failed: {}", e.what());
        }
    }
    return -1;
}

void UDP4::sendHeartbeat() {
    PeerMsg::Heartbeat heartbeat;
    heartbeat.kind = PeerMsgKind::HEARTBEAT;
    heartbeat.tunip = getPeerManager().getTunIp();
    heartbeat.ack = this->ack;

    auto buffer = this->peer->encrypt(std::string((char *)&heartbeat, sizeof(heartbeat)));
    if (!buffer) {
        return;
    }

    using Poco::Net::SocketAddress;
    if (this->real && (this->state == UdpPeerState::CONNECTED)) {
        getPeerManager().udp4socket.sendTo(buffer->data(), buffer->size(), *this->real);
    }

    if (this->wide && (this->state == UdpPeerState::CONNECTING)) {
        getPeerManager().udp4socket.sendTo(buffer->data(), buffer->size(), *this->wide);
    }

    if (this->local && (this->state == UdpPeerState::PREPARING || this->state == UdpPeerState::SYNCHRONIZING ||
                        this->state == UdpPeerState::CONNECTING)) {
        getPeerManager().udp4socket.sendTo(buffer->data(), buffer->size(), *this->local);
    }
}

void UDP4::resetState() {
    this->wide = std::nullopt;
    this->local = std::nullopt;
    this->real = std::nullopt;
    this->ack = 0;
    this->rtt = RTT_LIMIT;
}

std::string UDP6::getName() {
    return "UDP6";
}

void UDP6::tick() {
    // TODO: UDP6 tick
}

int UDP6::send(const std::string &buffer) {
    // TODO: UDP6 send
    return -1;
}

} // namespace Candy

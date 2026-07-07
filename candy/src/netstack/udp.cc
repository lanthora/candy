// SPDX-License-Identifier: MIT
#include "netstack/udp.h"
#include "netstack/ip.h"

#include <chrono>
#include <deque>
#include <memory>
#include <spdlog/spdlog.h>
#include <unordered_map>

extern "C" {
#include <lwip/pbuf.h>
#include <lwip/udp.h>
}

namespace candy {

namespace {
uint32_t timestampMs() {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch());
    return (uint32_t)ms.count();
}
} // namespace

struct PbufDeleter {
    void operator()(struct pbuf *p) const {
        if (p)
            pbuf_free(p);
    }
};

using PbufPtr = std::unique_ptr<struct pbuf, PbufDeleter>;

struct UdpPcbDeleter {
    void operator()(struct udp_pcb *pcb) const {
        if (pcb) {
            udp_recv(pcb, nullptr, nullptr);
            udp_remove(pcb);
        }
    }
};

using UdpPcbPtr = std::unique_ptr<struct udp_pcb, UdpPcbDeleter>;

struct FlowEntry {
    UdpPcbPtr pcb;
    uint32_t lastActive;
};

struct UdpSocketImpl : public UdpSocket::Impl {
    UdpPcbPtr pcb;
    std::deque<UdpSocket::Packet> recvQ;
    std::unordered_map<uint64_t, FlowEntry> flowPcbs;
    IpStack *ip = nullptr;

    static uint64_t flowKey(IP4 clientIp, uint16_t clientPort) {
        return ((uint64_t)(uint32_t)clientIp << 16) | clientPort;
    }

    static void recvCb(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *, u16_t) {
        auto *self = (UdpSocketImpl *)arg;
        if (!p)
            return;

        auto clientIp = lwipToIP4(ip_2_ip4(&upcb->remote_ip));
        uint16_t clientPort = upcb->remote_port;
        // NB: read destination from upcb->local_ip/local_port, NOT from the
        // callback's last two args. The heiher/lwip fork is inconsistent —
        // udp.c:454 (PRETEND fallback) passes dest as those args, but
        // udp.c:412/414 (regular match) passes src. lwIP does, however,
        // overwrite upcb->local_ip/local_port with the packet's dest
        // (udp.c:410-411) just before invoking us, so the PCB fields are
        // always authoritative.
        auto realDstIp = lwipToIP4(ip_2_ip4(&upcb->local_ip));
        uint16_t realDstPort = upcb->local_port;

        if (upcb->local_port == 0) {
            // First packet for this flow: lwIP just created upcb via its
            // PRETEND fallback (udp.c:446-454). Cache it, attach our recv
            // callback so future packets route here, then return WITHOUT
            // freeing p — lwIP will goto again and redeliver through upcb
            // (now matching at udp.c:258-264), at which point local_port will
            // be set and we queue the payload below.
            auto key = flowKey(clientIp, clientPort);
            self->flowPcbs[key] = FlowEntry{UdpPcbPtr(upcb), timestampMs()};
            udp_recv(upcb, UdpSocketImpl::recvCb, self);
            return;
        }

        UdpSocket::Packet pkt;
        pkt.data.assign((const char *)p->payload, p->len);
        pkt.srcAddr = clientIp;
        pkt.srcPort = clientPort;
        pkt.dstAddr = realDstIp;
        pkt.dstPort = realDstPort;
        self->recvQ.push_back(std::move(pkt));
        pbuf_free(p);
    }

    std::optional<UdpSocket::Packet> recv() {
        if (recvQ.empty())
            return std::nullopt;
        auto p = std::move(recvQ.front());
        recvQ.pop_front();
        return p;
    }

    void send(const std::string &data, IP4 srcAddr, uint16_t srcPort, IP4 dstAddr, uint16_t dstPort) {

        auto key = flowKey(dstAddr, dstPort);
        struct udp_pcb *flowPcb = nullptr;
        auto it = flowPcbs.find(key);
        if (it != flowPcbs.end()) {
            flowPcb = it->second.pcb.get();
            it->second.lastActive = timestampMs();
        }

        if (!flowPcb) {
            flowPcb = udp_new();
            if (!flowPcb) {
                spdlog::error("udp new failed");
                return;
            }
            ip->bindUdpPretendSocket(flowPcb);

            ip4_addr_t remote, local;
            ip4_addr_set_u32(&remote, (uint32_t)dstAddr);
            ip4_addr_set_u32(&local, (uint32_t)srcAddr);
            ip_addr_set_ipaddr(&flowPcb->remote_ip, &remote);
            ip_addr_set_ipaddr(&flowPcb->local_ip, &local);
            flowPcb->remote_port = dstPort;
            flowPcb->local_port = srcPort;
            flowPcbs[key] = FlowEntry{UdpPcbPtr(flowPcb), timestampMs()};
        }

        PbufPtr pb(pbuf_alloc(PBUF_TRANSPORT, data.size(), PBUF_POOL));
        if (!pb) {
            spdlog::error("pbuf alloc failed");
            return;
        }
        memcpy(pb->payload, data.data(), data.size());
        udp_send(flowPcb, pb.get());
    }

    void sweep(uint32_t maxAgeMs) {
        uint32_t now = timestampMs();
        for (auto it = flowPcbs.begin(); it != flowPcbs.end();) {
            if (now - it->second.lastActive > maxAgeMs) {
                it = flowPcbs.erase(it);
            } else {
                ++it;
            }
        }
    }
};

UdpSocket::UdpSocket() : impl(new UdpSocketImpl()) {}
UdpSocket::~UdpSocket() = default;

std::unique_ptr<UdpSocket> UdpSocket::bind(IpStack &ip, IP4 /*addr*/, uint16_t /*port*/) {
    auto s = std::unique_ptr<UdpSocket>(new UdpSocket());
    auto *ui = static_cast<UdpSocketImpl *>(s->impl.get());
    ui->ip = &ip;

    struct udp_pcb *rawPcb = udp_new();
    if (!rawPcb)
        return nullptr;

    ip.bindUdpPretendSocket(rawPcb);
    udp_recv(rawPcb, UdpSocketImpl::recvCb, ui);
    ui->pcb.reset(rawPcb);
    return s;
}

std::optional<UdpSocket::Packet> UdpSocket::recv() {
    return static_cast<UdpSocketImpl *>(impl.get())->recv();
}

void UdpSocket::send(const std::string &data, IP4 srcAddr, uint16_t srcPort, IP4 dstAddr, uint16_t dstPort) {
    static_cast<UdpSocketImpl *>(impl.get())->send(data, srcAddr, srcPort, dstAddr, dstPort);
}

void UdpSocket::sweep(uint32_t maxAgeMs) {
    static_cast<UdpSocketImpl *>(impl.get())->sweep(maxAgeMs);
}

} // namespace candy

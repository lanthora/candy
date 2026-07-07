// SPDX-License-Identifier: MIT
#include "netstack/ip.h"

#include <chrono>
#include <cstring>
#include <deque>
#include <memory>
#include <spdlog/spdlog.h>
#include <stdexcept>

extern "C" {
#include <lwip/init.h>
#include <lwip/ip4.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <lwip/udp.h>

u32_t sys_now(void) {
    return (u32_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}
}

namespace candy {

struct PbufDeleter {
    void operator()(struct pbuf *p) const {
        if (p)
            pbuf_free(p);
    }
};
using PbufPtr = std::unique_ptr<struct pbuf, PbufDeleter>;

IP4 fromLwipHostOrder(uint32_t hostOrder) {
    return IP4((hostOrder >> 24) & 0xFF, (hostOrder >> 16) & 0xFF, (hostOrder >> 8) & 0xFF, hostOrder & 0xFF);
}

IP4 lwipToIP4(const void *addr) {
    auto *a = (const ip4_addr_t *)addr;
    return fromLwipHostOrder(lwip_ntohl(ip4_addr_get_u32(a)));
}

struct NetifDeleter {
    void operator()(struct netif *nif) const {
        if (nif) {
            netif_set_down(nif);
            netif_remove(nif);
            free(nif);
        }
    }
};

struct IpStackImpl : public IpStack::Impl {
    Config cfg;
    std::unique_ptr<struct netif, NetifDeleter> netif;
    std::deque<std::string> outQ;

    explicit IpStackImpl(const Config &c);
    ~IpStackImpl();
    void send(const std::string &pk);
    std::optional<std::string> recv();
    struct netif *getNetif() {
        return netif.get();
    }
    static err_t netifOutput(struct netif *nif, struct pbuf *p, const ip4_addr_t *);
};

IpStackImpl::IpStackImpl(const Config &c) : cfg(c) {
    lwip_init();

    ip_addr_t ipaddr, netmask, gw;
    ip4_addr_set_u32(&ipaddr, (uint32_t)cfg.addr);
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gw, 198, 18, 0, 1);

    struct netif *rawNetif = (struct netif *)calloc(1, sizeof(struct netif));
    auto initFn = [](struct netif *nif) -> err_t {
        auto *self = (IpStackImpl *)nif->state;
        nif->output = &IpStackImpl::netifOutput;
        nif->mtu = (u16_t)self->cfg.mtu;
        nif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_UP | NETIF_FLAG_LINK_UP | NETIF_FLAG_PRETEND;
        return ERR_OK;
    };
    if (!netif_add(rawNetif, &ipaddr, &netmask, &gw, this, initFn, nullptr)) {
        spdlog::error("netif_add failed");
        free(rawNetif);
        throw std::runtime_error("IpStack: netif_add failed");
    }
    netif.reset(rawNetif);
    netif_set_default(netif.get());
    netif_set_up(netif.get());
}

IpStackImpl::~IpStackImpl() {}

void IpStackImpl::send(const std::string &pk) {
    PbufPtr pb(pbuf_alloc(PBUF_RAW, pk.size(), PBUF_POOL));
    if (!pb) {
        spdlog::error("pbuf_alloc failed");
        return;
    }
    if (pbuf_take(pb.get(), pk.data(), pk.size()) != ERR_OK) {
        spdlog::error("pbuf_take failed");
        return;
    }
    err_t ret = ip4_input(pb.get(), netif.get());
    if (ret != ERR_OK)
        return;
    pb.release();
}

std::optional<std::string> IpStackImpl::recv() {
    if (outQ.empty())
        return std::nullopt;
    auto pkt = std::move(outQ.front());
    outQ.pop_front();
    return pkt;
}

err_t IpStackImpl::netifOutput(struct netif *nif, struct pbuf *p, const ip4_addr_t *) {
    auto *self = (IpStackImpl *)nif->state;
    std::string pkt(p->tot_len, 0);
    pbuf_copy_partial(p, pkt.data(), p->tot_len, 0);
    self->outQ.push_back(std::move(pkt));
    return ERR_OK;
}

IpStack::IpStack() : impl(nullptr) {}

std::unique_ptr<IpStack> IpStack::create(const Config &cfg) {
    try {
        auto stack = std::unique_ptr<IpStack>(new IpStack());
        stack->impl = std::unique_ptr<Impl>(new IpStackImpl(cfg));
        return stack;
    } catch (const std::exception &e) {
        spdlog::error("IpStack::create failed: {}", e.what());
        return nullptr;
    }
}

IpStack::~IpStack() = default;

void IpStack::send(const std::string &p) {
    static_cast<IpStackImpl *>(impl.get())->send(p);
}

std::optional<std::string> IpStack::recv() {
    return static_cast<IpStackImpl *>(impl.get())->recv();
}

void IpStack::bindTcpPretendListener(struct tcp_pcb *pcb) {
    auto *self = static_cast<IpStackImpl *>(impl.get());
    tcp_bind_netif(pcb, self->netif.get());
    tcp_bind(pcb, NULL, 0);
}

void IpStack::bindUdpPretendSocket(struct udp_pcb *pcb) {
    auto *self = static_cast<IpStackImpl *>(impl.get());
    udp_bind_netif(pcb, self->netif.get());
    udp_bind(pcb, NULL, 0);
}

void checkTimeouts() {
    sys_check_timeouts();
}

} // namespace candy

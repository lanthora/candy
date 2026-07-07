// SPDX-License-Identifier: MIT
#include "netstack/tcp.h"
#include "netstack/ip.h"

#include <deque>
#include <memory>
#include <spdlog/spdlog.h>

extern "C" {
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
}

namespace candy {

struct TcpPcbDeleter {
    void operator()(struct tcp_pcb *pcb) const {
        if (pcb) {
            tcp_arg(pcb, nullptr);
            tcp_recv(pcb, nullptr);
            tcp_sent(pcb, nullptr);
            tcp_err(pcb, nullptr);
            tcp_close(pcb);
        }
    }
};

using TcpPcbPtr = std::unique_ptr<struct tcp_pcb, TcpPcbDeleter>;

struct TcpListenPcbDeleter {
    void operator()(struct tcp_pcb *pcb) const {
        if (pcb) {
            tcp_accept(pcb, nullptr);
            tcp_close(pcb);
        }
    }
};

using TcpListenPcbPtr = std::unique_ptr<struct tcp_pcb, TcpListenPcbDeleter>;

struct TcpStreamImpl : public TcpStream::Impl {
    TcpPcbPtr pcb;
    std::deque<std::string> readQ;
    std::string sendBuf;
    bool closed = false;

    void write(const std::string &data) {
        if (!pcb || closed)
            return;
        auto *raw = pcb.get();
        if (!sendBuf.empty()) {
            if (tcp_write(raw, sendBuf.data(), sendBuf.size(), TCP_WRITE_FLAG_COPY) == ERR_OK) {
                sendBuf.clear();
                tcp_output(raw);
            } else {
                sendBuf += data;
                return;
            }
        }
        err_t ret = tcp_write(raw, data.data(), data.size(), TCP_WRITE_FLAG_COPY);
        if (ret == ERR_OK) {
            tcp_output(raw);
        } else {
            sendBuf = data;
        }
    }

    void close() {
        if (pcb && !closed) {
            closed = true;
            pcb.reset();
        }
    }

    bool isClosed() const {
        return closed;
    }

    std::optional<std::string> read() {
        if (closed && readQ.empty())
            return std::string();
        if (readQ.empty())
            return std::nullopt;
        auto s = std::move(readQ.front());
        readQ.pop_front();
        return s;
    }

    void onSent() {
        if (!sendBuf.empty() && pcb) {
            auto *raw = pcb.get();
            if (tcp_write(raw, sendBuf.data(), sendBuf.size(), TCP_WRITE_FLAG_COPY) == ERR_OK) {
                sendBuf.clear();
                tcp_output(raw);
            }
        }
    }
};

struct TcpListenerImpl : public TcpListener::Impl {
    TcpListenPcbPtr pcb;
    std::deque<TcpListener::AcceptResult> acceptQ;

    static err_t acceptCb(void *arg, struct tcp_pcb *newpcb, err_t) {
        auto *self = (TcpListenerImpl *)arg;
        if (!newpcb)
            return ERR_ABRT;

        auto srcIp = lwipToIP4(ip_2_ip4(&newpcb->remote_ip));
        auto dstIp = lwipToIP4(ip_2_ip4(&newpcb->local_ip));
        auto dstPort = newpcb->local_port;

        auto s = std::make_unique<TcpStreamImpl>();
        auto *rawS = s.get();
        s->pcb.reset(newpcb);

        tcp_arg(newpcb, rawS);
        tcp_recv(newpcb, recvCb);
        tcp_sent(newpcb, sentCb);
        tcp_err(newpcb, errCb);

        TcpListener::AcceptResult r;
        r.stream = TcpStream::create(std::unique_ptr<TcpStream::Impl>(s.release()));
        r.srcAddr = srcIp;
        r.srcPort = newpcb->remote_port;
        r.dstAddr = dstIp;
        r.dstPort = dstPort;

        self->acceptQ.push_back(std::move(r));
        return ERR_OK;
    }

    static err_t recvCb(void *arg, struct tcp_pcb *, struct pbuf *p, err_t) {
        auto *s = (TcpStreamImpl *)arg;
        if (!p) {
            s->closed = true;
            return ERR_OK;
        }
        std::string data(p->tot_len, 0);
        pbuf_copy_partial(p, data.data(), p->tot_len, 0);
        s->readQ.push_back(std::move(data));
        tcp_recved(s->pcb.get(), p->tot_len);
        pbuf_free(p);
        return ERR_OK;
    }

    static err_t sentCb(void *arg, struct tcp_pcb *, u16_t) {
        ((TcpStreamImpl *)arg)->onSent();
        return ERR_OK;
    }

    static void errCb(void *arg, err_t) {
        ((TcpStreamImpl *)arg)->closed = true;
        ((TcpStreamImpl *)arg)->pcb.release();
    }

    std::optional<TcpListener::AcceptResult> accept() {
        if (acceptQ.empty())
            return std::nullopt;
        auto r = std::move(acceptQ.front());
        acceptQ.pop_front();
        return r;
    }
};

TcpStream::TcpStream() : impl(nullptr) {}
TcpStream::~TcpStream() = default;

std::unique_ptr<TcpStream> TcpStream::create(std::unique_ptr<Impl> impl) {
    auto s = std::unique_ptr<TcpStream>(new TcpStream());
    s->impl = std::move(impl);
    return s;
}

std::optional<std::string> TcpStream::read() {
    return static_cast<TcpStreamImpl *>(impl.get())->read();
}

void TcpStream::write(const std::string &d) {
    static_cast<TcpStreamImpl *>(impl.get())->write(d);
}

void TcpStream::close() {
    static_cast<TcpStreamImpl *>(impl.get())->close();
}

bool TcpStream::isClosed() const {
    return static_cast<TcpStreamImpl *>(impl.get())->isClosed();
}

TcpListener::TcpListener() : impl(new TcpListenerImpl()) {}
TcpListener::~TcpListener() = default;

std::unique_ptr<TcpListener> TcpListener::bind(IpStack &ip, IP4 /*addr*/, uint16_t /*port*/) {
    auto l = std::unique_ptr<TcpListener>(new TcpListener());
    auto *li = static_cast<TcpListenerImpl *>(l->impl.get());

    struct tcp_pcb *rawPcb = tcp_new();
    if (!rawPcb)
        return nullptr;
    ip.bindTcpPretendListener(rawPcb);
    rawPcb = tcp_listen(rawPcb);
    if (!rawPcb)
        return nullptr;

    li->pcb.reset(rawPcb);
    tcp_accept(li->pcb.get(), TcpListenerImpl::acceptCb);
    tcp_arg(li->pcb.get(), li);
    return l;
}

std::optional<TcpListener::AcceptResult> TcpListener::accept() {
    return static_cast<TcpListenerImpl *>(impl.get())->accept();
}

} // namespace candy

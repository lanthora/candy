// SPDX-License-Identifier: MIT
#include "websocket/server.h"
#include "core/net.h"
#include "utils/hex.h"
#include "utils/log.h"
#include "utils/time.h"
#include "websocket/message.h"
#include <Poco/Format.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/WebSocket.h>
#include <Poco/Timespan.h>
#include <Poco/URI.h>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sstream>

/**
 * Poco 的 WebSocket 服务端接口有点难用,简单封装一下,并对外提供一个回调函数,回调函数的参数表示独立的
 * WebSocket客户端,函数返回会释放连接
 */
namespace {

using WebSocketHandler = std::function<void(Poco::Net::WebSocket &ws)>;

class HTTPRequestHandler : public Poco::Net::HTTPRequestHandler {
public:
    HTTPRequestHandler(WebSocketHandler wsHandler) : wsHandler(wsHandler) {}
    void handleRequest(Poco::Net::HTTPServerRequest &request, Poco::Net::HTTPServerResponse &response) {
        try {
            Poco::Net::WebSocket ws(request, response);
            wsHandler(ws);
            ws.close();
        } catch (const std::exception &e) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
            response.setReason("Forbidden");
            response.setContentLength(0);
            response.send();
        }
    }

private:
    WebSocketHandler wsHandler;
};

class HTTPRequestHandlerFactory : public Poco::Net::HTTPRequestHandlerFactory {
public:
    HTTPRequestHandlerFactory(WebSocketHandler wsHandler) : wsHandler(wsHandler) {}

    Poco::Net::HTTPRequestHandler *createRequestHandler(const Poco::Net::HTTPServerRequest &request) {
        return new HTTPRequestHandler(wsHandler);
    }

private:
    WebSocketHandler wsHandler;
};

}; // namespace

namespace candy {

void WsCtx::sendFrame(const std::string &frame, int flags) {
    this->ws->sendFrame(frame.data(), frame.size(), flags);
}

int WebSocketServer::setWebSocket(const std::string &uri) {
    try {
        Poco::URI parser(uri);
        if (parser.getScheme() != "ws") {
            candy::logger().fatal("websocket server only support ws");
            return -1;
        }
        this->host = parser.getHost();
        this->port = parser.getPort();
        return 0;
    } catch (std::exception &e) {
        candy::logger().fatal(Poco::format("invalid websocket uri: %s: %s", uri, std::string(e.what())));
        return -1;
    }
}

int WebSocketServer::setPassword(const std::string &password) {
    this->password = password;
    return 0;
}

int WebSocketServer::setDHCP(const std::string &cidr) {
    if (cidr.empty()) {
        return 0;
    }
    return this->dhcp.fromCidr(cidr);
}

int WebSocketServer::setSdwan(const std::string &sdwan) {
    if (sdwan.empty()) {
        return 0;
    }
    std::string route;
    std::stringstream stream(sdwan);
    while (std::getline(stream, route, ';')) {
        std::string addr;
        SysRoute rt;
        std::stringstream ss(route);
        // dev
        if (!std::getline(ss, addr, ',') || rt.dev.fromCidr(addr) || rt.dev.Host() != rt.dev.Net()) {
            candy::logger().fatal(Poco::format("invalid route device: %s", route));
            return -1;
        }
        // dst
        if (!std::getline(ss, addr, ',') || rt.dst.fromCidr(addr) || rt.dst.Host() != rt.dst.Net()) {
            candy::logger().fatal(Poco::format("invalid route dest: %s", route));
            return -1;
        }
        // next
        if (!std::getline(ss, addr, ',') || rt.next.fromString(addr)) {
            candy::logger().fatal(Poco::format("invalid route nexthop: %s", route));
            return -1;
        }
        candy::logger().information(
            Poco::format("route: dev=%s dst=%s next=%s", rt.dev.toCidr(), rt.dst.toCidr(), rt.next.toString()));
        this->routes.push_back(rt);
    }
    return 0;
}

int WebSocketServer::run() {
    listen();
    return 0;
}

int WebSocketServer::shutdown() {
    this->running = false;
    if (this->httpServer) {
        this->httpServer->stopAll();
    }
    this->routes.clear();
    return 0;
}

void WebSocketServer::handleMsg(WsCtx &ctx) {
    uint8_t msgKind = ctx.buffer.front();
    switch (msgKind) {
    case WsMsgKind::AUTH:
        handleAuthMsg(ctx);
        break;
    case WsMsgKind::FORWARD:
        handleForwardMsg(ctx);
        break;
    case WsMsgKind::EXPTTUN:
        handleExptTunMsg(ctx);
        break;
    case WsMsgKind::UDP4CONN:
        handleUdp4ConnMsg(ctx);
        break;
    case WsMsgKind::VMAC:
        handleVMacMsg(ctx);
        break;
    case WsMsgKind::DISCOVERY:
        handleDiscoveryMsg(ctx);
        break;
    case WsMsgKind::GENERAL:
        HandleGeneralMsg(ctx);
        break;
    }
}

void WebSocketServer::handleAuthMsg(WsCtx &ctx) {
    if (ctx.buffer.length() < sizeof(WsMsg::Auth)) {
        candy::logger().warning(Poco::format("invalid auth message: len %zu", ctx.buffer.length()));
        ctx.status = -1;
        return;
    }

    WsMsg::Auth *header = (WsMsg::Auth *)ctx.buffer.data();
    if (!header->check(this->password)) {
        candy::logger().warning(Poco::format("auth header check failed: buffer %s", to_hex(ctx.buffer)));
        ctx.status = -1;
        return;
    }

    ctx.ip = header->ip;

    {
        std::unique_lock lock(ipCtxMutex);
        auto it = ipCtxMap.find(header->ip);
        if (it != ipCtxMap.end()) {
            it->second->status = -1;
            candy::logger().information(Poco::format("reconnect: %s", it->second->ip.toString()));
        } else {
            candy::logger().information(Poco::format("connect: %s", ctx.ip.toString()));
        }
        ipCtxMap[header->ip] = &ctx;
    }

    updateSysRoute(ctx);
}

void WebSocketServer::handleForwardMsg(WsCtx &ctx) {
    if (ctx.ip.empty()) {
        candy::logger().debug("unauthorized forward websocket client");
        ctx.status = -1;
        return;
    }

    if (ctx.buffer.length() < sizeof(WsMsg::Forward)) {
        candy::logger().debug(Poco::format("invalid forawrd message: len %zu", ctx.buffer.length()));
        ctx.status = -1;
        return;
    }

    WsMsg::Forward *header = (WsMsg::Forward *)ctx.buffer.data();

    {
        std::shared_lock lock(this->ipCtxMutex);
        auto it = this->ipCtxMap.find(header->iph.daddr);
        if (it != this->ipCtxMap.end()) {
            it->second->sendFrame(ctx.buffer);
            return;
        }
    }

    bool broadcast = [&] {
        // 多播地址
        if ((header->iph.daddr & IP4("240.0.0.0")) == IP4("224.0.0.0")) {
            return true;
        }
        // 广播
        if (header->iph.daddr == IP4("255.255.255.255")) {
            return true;
        }
        // 服务端没有配置动态分配地址的范围,没法检查是否为定向广播
        if (this->dhcp.empty()) {
            return false;
        }
        // 网络号不同,不是定向广播
        if ((this->dhcp.Mask() & header->iph.daddr) != this->dhcp.Net()) {
            return false;
        }
        // 主机号部分不全为 1,不是定向广播
        if (~((header->iph.daddr & ~this->dhcp.Mask()) ^ this->dhcp.Mask())) {
            return false;
        }
        return true;
    }();

    if (broadcast) {
        std::shared_lock lock(this->ipCtxMutex);
        for (auto c : this->ipCtxMap) {
            if (c.second->ip != ctx.ip) {
                c.second->sendFrame(ctx.buffer);
            }
        }
        return;
    }

    candy::logger().debug(
        Poco::format("forward failed: source %s dest %s", header->iph.saddr.toString(), header->iph.daddr.toString()));
    return;
}

void WebSocketServer::handleExptTunMsg(WsCtx &ctx) {
    if (ctx.buffer.length() < sizeof(WsMsg::ExptTun)) {
        candy::logger().warning(Poco::format("invalid dynamic address message: len %zu", ctx.buffer.length()));
        ctx.status = -1;
        return;
    }
    WsMsg::ExptTun *header = (WsMsg::ExptTun *)ctx.buffer.data();
    if (!header->check(this->password)) {
        candy::logger().warning(Poco::format("dynamic address header check failed: buffer %s", to_hex(ctx.buffer)));
        ctx.status = -1;
        return;
    }
    if (this->dhcp.empty()) {
        candy::logger().warning("unable to allocate dynamic address");
        ctx.status = -1;
        return;
    }
    Address exptTun;
    if (exptTun.fromCidr(header->cidr)) {
        candy::logger().warning(Poco::format("dynamic address header cidr invalid: buffer %s", to_hex(ctx.buffer)));
        ctx.status = -1;
        return;
    }
    // 判断能否直接使用申请的地址
    bool direct = [&]() {
        if (dhcp.Net() != exptTun.Net()) {
            return false;
        }
        std::shared_lock lock(this->ipCtxMutex);
        auto oldCtx = this->ipCtxMap.find(exptTun.Host());
        if (oldCtx == this->ipCtxMap.end()) {
            return true;
        }
        return ctx.vmac == oldCtx->second->vmac;
    }();
    if (!direct) {
        exptTun = this->dhcp;
        std::shared_lock lock(this->ipCtxMutex);
        do {
            exptTun = exptTun.Next();
            if (exptTun.Host() == this->dhcp.Host()) {
                candy::logger().warning("all addresses in the network are assigned");
                ctx.status = -1;
                return;
            }
        } while (!exptTun.isValid() && this->ipCtxMap.find(exptTun.Host()) != this->ipCtxMap.end());
        this->dhcp = exptTun;
    }
    header->timestamp = hton(unixTime());
    std::strcpy(header->cidr, exptTun.toCidr().c_str());
    header->updateHash(this->password);
    ctx.sendFrame(ctx.buffer);
}

void WebSocketServer::handleUdp4ConnMsg(WsCtx &ctx) {
    if (ctx.ip.empty()) {
        candy::logger().debug("unauthorized peer websocket client");
        ctx.status = -1;
        return;
    }

    if (ctx.buffer.length() < sizeof(WsMsg::Conn)) {
        candy::logger().warning(Poco::format("invalid peer conn message: len %zu", ctx.buffer.length()));
        ctx.status = -1;
        return;
    }

    WsMsg::Conn *header = (WsMsg::Conn *)ctx.buffer.data();
    if (ctx.ip != header->src) {
        candy::logger().debug(
            Poco::format("peer source address does not match: auth %s source %s", ctx.ip.toString(), header->src.toString()));
        ctx.status = -1;
        return;
    }
    std::shared_lock lock(this->ipCtxMutex);
    auto it = this->ipCtxMap.find(header->dst);
    if (it == this->ipCtxMap.end()) {
        candy::logger().debug(
            Poco::format("peer dest address not logged in: source %s dst %s", header->src.toString(), header->dst.toString()));
        return;
    }
    it->second->sendFrame(ctx.buffer);
    return;
}

void WebSocketServer::handleVMacMsg(WsCtx &ctx) {
    if (ctx.buffer.length() < sizeof(WsMsg::VMac)) {
        candy::logger().warning(Poco::format("invalid vmac message: len %zu", ctx.buffer.length()));
        ctx.status = -1;
        return;
    }

    WsMsg::VMac *header = (WsMsg::VMac *)ctx.buffer.data();
    if (!header->check(this->password)) {
        candy::logger().warning(Poco::format("vmac message check failed: buffer %s", to_hex(ctx.buffer)));
        ctx.status = -1;
        return;
    }

    ctx.vmac.assign((char *)header->vmac, sizeof(header->vmac));
    return;
}

void WebSocketServer::handleDiscoveryMsg(WsCtx &ctx) {
    if (ctx.ip.empty()) {
        candy::logger().debug("unauthorized discovery websocket client");
        ctx.status = -1;
        return;
    }

    if (ctx.buffer.length() < sizeof(WsMsg::Discovery)) {
        candy::logger().debug(Poco::format("invalid discovery message: len %zu", ctx.buffer.length()));
        ctx.status = -1;
        return;
    }

    WsMsg::Discovery *header = (WsMsg::Discovery *)ctx.buffer.data();
    if (ctx.ip != header->src) {
        candy::logger().debug(Poco::format("discovery source address does not match: auth %s source %s", ctx.ip.toString(),
                                           header->src.toString()));
        ctx.status = -1;
        return;
    }

    std::shared_lock lock(this->ipCtxMutex);
    if (header->dst == IP4("255.255.255.255")) {
        for (auto c : this->ipCtxMap) {
            if (c.first != header->src) {
                c.second->sendFrame(ctx.buffer);
            }
        }
        return;
    }
    auto it = this->ipCtxMap.find(header->dst);
    if (it != this->ipCtxMap.end()) {
        it->second->sendFrame(ctx.buffer);
        return;
    }
}

void WebSocketServer::HandleGeneralMsg(WsCtx &ctx) {
    if (ctx.ip.empty()) {
        candy::logger().debug("unauthorized general websocket client");
        ctx.status = -1;
        return;
    }

    if (ctx.buffer.length() < sizeof(WsMsg::General)) {
        candy::logger().debug(Poco::format("invalid general message: len %zu", ctx.buffer.length()));
        ctx.status = -1;
        return;
    }

    WsMsg::General *header = (WsMsg::General *)ctx.buffer.data();

    if (ctx.ip != header->src) {
        candy::logger().debug(
            Poco::format("general source address does not match: auth %s source %s", ctx.ip.toString(), header->src.toString()));
        ctx.status = -1;
        return;
    }

    std::shared_lock lock(this->ipCtxMutex);
    if (header->dst == IP4("255.255.255.255")) {
        for (auto c : this->ipCtxMap) {
            if (c.first != header->src) {
                c.second->sendFrame(ctx.buffer);
            }
        }
        return;
    }
    auto it = this->ipCtxMap.find(header->dst);
    if (it != this->ipCtxMap.end()) {
        it->second->sendFrame(ctx.buffer);
        return;
    }
}

void WebSocketServer::updateSysRoute(WsCtx &ctx) {
    ctx.buffer.resize(sizeof(WsMsg::SysRoute));
    WsMsg::SysRoute *header = (WsMsg::SysRoute *)ctx.buffer.data();
    memset(header, 0, sizeof(WsMsg::SysRoute));
    header->type = WsMsgKind::ROUTE;

    for (auto rt : this->routes) {
        if ((rt.dev.Mask() & ctx.ip) == rt.dev.Host()) {
            SysRouteEntry item;
            item.dst = rt.dst.Net();
            item.mask = rt.dst.Mask();
            item.nexthop = rt.next;
            ctx.buffer.append((char *)(&item), sizeof(item));
            header->size += 1;
        }
        // 100 条路由报文大小是 1204 字节,超过 100 条后分批发送
        if (header->size > 100) {
            ctx.sendFrame(ctx.buffer);
            ctx.buffer.resize(sizeof(WsMsg::SysRoute));
            header->size = 0;
        }
    }

    if (header->size > 0) {
        ctx.sendFrame(ctx.buffer);
    }
}

int WebSocketServer::listen() {
    try {
        Poco::Net::ServerSocket socket(Poco::Net::SocketAddress(host, port));

        Poco::Net::HTTPServerParams *params = new Poco::Net::HTTPServerParams();
        params->setMaxThreads(0x00FFFFFF);

        this->running = true;
        WebSocketHandler wsHandler = [this](Poco::Net::WebSocket &ws) { handleWebsocket(ws); };
        this->httpServer = std::make_shared<Poco::Net::HTTPServer>(new HTTPRequestHandlerFactory(wsHandler), socket, params);
        this->httpServer->start();
        candy::logger().information(Poco::format("listen on: %s:%d", host, port));
        return 0;
    } catch (std::exception &e) {
        candy::logger().fatal(Poco::format("listen failed: %s", std::string(e.what())));
        return -1;
    }
}

void WebSocketServer::handleWebsocket(Poco::Net::WebSocket &ws) {
    ws.setReceiveTimeout(Poco::Timespan(1, 0));
    WsCtx ctx = {.ws = &ws};

    int flags = 0;
    int length = 0;
    std::string buffer;
    while (this->running && ctx.status == 0) {
        try {
            buffer.resize(1500);
            length = ws.receiveFrame(buffer.data(), buffer.size(), flags);
            int frameOp = flags & Poco::Net::WebSocket::FRAME_OP_BITMASK;

            // 响应 Ping 报文
            if (frameOp == Poco::Net::WebSocket::FRAME_OP_PING) {
                flags = (int)Poco::Net::WebSocket::FRAME_FLAG_FIN | (int)Poco::Net::WebSocket::FRAME_OP_PONG;
                ws.sendFrame(buffer.data(), buffer.size(), flags);
                continue;
            }

            // 客户端主动关闭连接
            if ((length == 0 && flags == 0) || frameOp == Poco::Net::WebSocket::FRAME_OP_CLOSE) {
                break;
            }

            if (frameOp == Poco::Net::WebSocket::FRAME_OP_BINARY && length > 0) {
                // 调整 buffer 为真实大小并移动到 ctx
                buffer.resize(length);
                ctx.buffer = std::move(buffer);

                // 处理客户端请求
                handleMsg(ctx);

                // 重新初始化 buffer
                buffer = std::string();
            }
        } catch (Poco::TimeoutException const &e) {
            // 超时异常,不做处理
            continue;
        } catch (std::exception &e) {
            // 未知异常,退出这个客户端
            candy::logger().debug(Poco::format("handle websocket failed: %s", std::string(e.what())));
            break;
        }
    }

    {
        std::unique_lock lock(ipCtxMutex);
        auto it = ipCtxMap.find(ctx.ip);
        if (it != ipCtxMap.end() && it->second == &ctx) {
            ipCtxMap.erase(it);
            candy::logger().information(Poco::format("disconnect: %s", ctx.ip.toString()));
        }
    }
}

} // namespace candy

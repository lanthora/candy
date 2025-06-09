// SPDX-License-Identifier: MIT
#include "websocket/client.h"
#include "core/client.h"
#include "core/message.h"
#include "core/net.h"
#include "core/version.h"
#include "utils/time.h"
#include "websocket/message.h"
#include <Poco/Net/HTTPMessage.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Timespan.h>
#include <Poco/URI.h>
#include <memory>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

namespace Candy {

int WebSocketClient::setName(const std::string &name) {
    this->name = name;
    return 0;
}

int WebSocketClient::setPassword(const std::string &password) {
    this->password = password;
    return 0;
}

int WebSocketClient::setWsServerUri(const std::string &uri) {
    this->wsServerUri = uri;
    return 0;
}

int WebSocketClient::setExptTunAddress(const std::string &cidr) {
    this->exptTunCidr = cidr;
    return 0;
}

int WebSocketClient::setAddress(const std::string &cidr) {
    this->tunCidr = cidr;
    return 0;
}

int WebSocketClient::setVirtualMac(const std::string &vmac) {
    this->vmac = vmac;
    return 0;
}

int WebSocketClient::setTunUpdateCallback(std::function<int(const std::string &)> callback) {
    this->addressUpdateCallback = callback;
    return 0;
}

int WebSocketClient::run(Client *client) {
    this->client = client;

    if (connect()) {
        spdlog::critical("websocket client connect failed");
        Candy::shutdown(this->client);
        return -1;
    }

    sendVirtualMacMsg();
    if (this->tunCidr.empty()) {
        sendExptTunMsg();
    } else {
        sendAuthMsg();
    }

    this->msgThread = std::thread([&] {
        spdlog::info("start thread: websocket client msg");
        while (this->client->running) {
            handleWsQueue();
        }
        spdlog::info("stop thread: websocket client msg");
    });

    this->wsThread = std::thread([&] {
        spdlog::info("start thread: websocket client ws");
        while (this->client->running) {
            if (handleWsConn()) {
                Candy::shutdown(this->client);
                break;
            }
        }
        spdlog::info("stop thread: websocket client ws");
    });

    return 0;
}

int WebSocketClient::shutdown() {
    if (this->msgThread.joinable()) {
        this->msgThread.join();
    }
    if (this->wsThread.joinable()) {
        this->wsThread.join();
    }

    return 0;
}

void WebSocketClient::handleWsQueue() {
    Msg msg = this->client->getWsMsgQueue().read();
    switch (msg.kind) {
    case MsgKind::TIMEOUT:
        break;
    case MsgKind::PACKET:
        handlePacket(std::move(msg));
        break;
    case MsgKind::PUBINFO:
        handlePubInfo(std::move(msg));
        break;
    case MsgKind::DISCOVERY:
        handleDiscovery(std::move(msg));
        break;
    default:
        spdlog::warn("unexcepted websocket message type: {}", static_cast<int>(msg.kind));
        break;
    }
}

void WebSocketClient::handlePacket(Msg msg) {
    IP4Header *header = (IP4Header *)msg.data.data();

    msg.data.insert(0, 1, WsMsgKind::FORWARD);
    sendFrame(msg.data);
}

void WebSocketClient::handlePubInfo(Msg msg) {
    CoreMsg::PubInfo *info = (CoreMsg::PubInfo *)(msg.data.data());
    if (info->local) {
        WsMsg::ConnLocal buffer;
        buffer.ge.src = info->src;
        buffer.ge.dst = info->dst;
        buffer.ip = info->ip;
        buffer.port = hton(info->port);
        sendFrame(&buffer, sizeof(buffer));
    } else {
        WsMsg::Conn buffer;
        buffer.src = info->src;
        buffer.dst = info->dst;
        buffer.ip = info->ip;
        buffer.port = hton(info->port);
        sendFrame(&buffer, sizeof(buffer));
    }
}

void WebSocketClient::handleDiscovery(Msg msg) {
    sendDiscoveryMsg(IP4("255.255.255.255"));
}

int WebSocketClient::handleWsConn() {
    try {
        std::string buffer;
        int flags = 0;

        // receiveFrame 会对 ws 加锁,影响写操作,需要先确定可读
        if (!this->ws->poll(Poco::Timespan(1, 0), Poco::Net::Socket::SELECT_READ)) {
            if (bootTime() - this->timestamp > 30000) {
                spdlog::warn("websocket pong timeout");
                return -1;
            }
            if (bootTime() - this->timestamp > 15000) {
                sendPingMessage();
            }
            return 0;
        }

        buffer.resize(1500);
        int length = this->ws->receiveFrame(buffer.data(), buffer.size(), flags);
        if (length == 0 && flags == 0) {
            spdlog::info("abnormal disconnect");
            return -1;
        }
        if ((flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) == Poco::Net::WebSocket::FRAME_OP_PING) {
            this->timestamp = bootTime();
            flags = (int)Poco::Net::WebSocket::FRAME_FLAG_FIN | (int)Poco::Net::WebSocket::FRAME_OP_PONG;
            sendFrame(buffer.data(), length, flags);
            return 0;
        }
        if ((flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) == Poco::Net::WebSocket::FRAME_OP_PONG) {
            this->timestamp = bootTime();
            return 0;
        }
        if ((flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) == Poco::Net::WebSocket::FRAME_OP_CLOSE) {
            spdlog::info("websocket close: {}", buffer);
            return -1;
        }
        if (length > 0) {
            this->timestamp = bootTime();
            buffer.resize(length);
            handleWsMsg(std::move(buffer));
            return 0;
        }
        return 0;
    } catch (std::exception &e) {
        spdlog::warn("handle ws conn failed: {}", e.what());
        return -1;
    }
}

void WebSocketClient::handleWsMsg(std::string buffer) {
    uint8_t msgKind = buffer.front();
    switch (msgKind) {
    case WsMsgKind::FORWARD:
        handleForwardMsg(std::move(buffer));
        break;
    case WsMsgKind::EXPTTUN:
        handleExptTunMsg(std::move(buffer));
        break;
    case WsMsgKind::UDP4CONN:
        handleUdp4ConnMsg(std::move(buffer));
        break;
    case WsMsgKind::DISCOVERY:
        handleDiscoveryMsg(std::move(buffer));
        break;
    case WsMsgKind::ROUTE:
        handleRouteMsg(std::move(buffer));
        break;
    case WsMsgKind::GENERAL:
        handleGeneralMsg(std::move(buffer));
        break;
    default:
        spdlog::debug("unknown websocket message kind: {}", msgKind);
        break;
    }
}

void WebSocketClient::handleForwardMsg(std::string buffer) {
    if (buffer.size() < sizeof(WsMsg::Forward)) {
        spdlog::warn("invalid forward message: {:n}", spdlog::to_hex(buffer));
        return;
    }
    // 移除一个字节的类型
    buffer.erase(0, 1);
    // 尝试与源地址建立对等连接
    IP4Header *header = (IP4Header *)buffer.data();
    // 每次通过服务端转发收到报文都触发一次尝试 P2P 连接, 用于暗示通过服务端转发是个非常耗时的操作
    this->client->getPeerMsgQueue().write(Msg(MsgKind::TRYP2P, header->saddr.toString()));
    // 最后把报文移动到 TUN 模块, 因为有移动操作所以必须在最后执行
    this->client->getTunMsgQueue().write(Msg(MsgKind::PACKET, std::move(buffer)));
}

void WebSocketClient::handleExptTunMsg(std::string buffer) {
    if (buffer.size() < sizeof(WsMsg::ExptTun)) {
        spdlog::warn("invalid expt tun message: {:n}", spdlog::to_hex(buffer));
        return;
    }
    WsMsg::ExptTun *header = (WsMsg::ExptTun *)buffer.data();
    Address exptTun(header->cidr);
    this->tunCidr = exptTun.toCidr();
    sendAuthMsg();
}

void WebSocketClient::handleUdp4ConnMsg(std::string buffer) {
    if (buffer.size() < sizeof(WsMsg::Conn)) {
        spdlog::warn("invalid udp4conn message: {:n}", spdlog::to_hex(buffer));
        return;
    }
    WsMsg::Conn *header = (WsMsg::Conn *)buffer.data();
    CoreMsg::PubInfo info = {.src = header->src, .dst = header->dst, .ip = header->ip, .port = ntoh(header->port)};
    this->client->getPeerMsgQueue().write(Msg(MsgKind::PUBINFO, std::string((char *)(&info), sizeof(info))));
}

void WebSocketClient::handleDiscoveryMsg(std::string buffer) {
    if (buffer.size() < sizeof(WsMsg::Discovery)) {
        spdlog::warn("invalid discovery message: {:n}", spdlog::to_hex(buffer));
        return;
    }
    WsMsg::Discovery *header = (WsMsg::Discovery *)buffer.data();
    if (header->dst == IP4("255.255.255.255")) {
        sendDiscoveryMsg(header->src);
    }
    this->client->getPeerMsgQueue().write(Msg(MsgKind::TRYP2P, header->src.toString()));
}

void WebSocketClient::handleRouteMsg(std::string buffer) {
    if (buffer.size() < sizeof(WsMsg::SysRoute)) {
        spdlog::warn("invalid route message: {:n}", spdlog::to_hex(buffer));
        return;
    }
    WsMsg::SysRoute *header = (WsMsg::SysRoute *)buffer.data();
    SysRouteEntry *rt = header->rtTable;
    for (uint8_t idx = 0; idx < header->size; ++idx) {
        this->client->getTunMsgQueue().write(Msg(MsgKind::SYSRT, std::string((char *)(rt + idx), sizeof(SysRouteEntry))));
        this->client->getPeerMsgQueue().write(Msg(MsgKind::SYSRT));
    }
}

void WebSocketClient::handleGeneralMsg(std::string buffer) {
    if (buffer.size() < sizeof(WsMsg::ConnLocal)) {
        spdlog::warn("invalid udp4conn local message: {:n}", spdlog::to_hex(buffer));
        return;
    }
    WsMsg::ConnLocal *header = (WsMsg::ConnLocal *)buffer.data();
    CoreMsg::PubInfo info = {
        .src = header->ge.src,
        .dst = header->ge.dst,
        .ip = header->ip,
        .port = ntoh(header->port),
        .local = true,
    };
    this->client->getPeerMsgQueue().write(Msg(MsgKind::PUBINFO, std::string((char *)(&info), sizeof(info))));
}

void WebSocketClient::sendFrame(const std::string &buffer, int flags) {
    sendFrame(buffer.c_str(), buffer.size(), flags);
}

void WebSocketClient::sendFrame(const void *buffer, int length, int flags) {
    if (this->ws) {
        try {
            this->ws->sendFrame(buffer, length, flags);
        } catch (std::exception &e) {
            spdlog::critical("websocket send frame failed: {}", e.what());
        }
    }
}

void WebSocketClient::sendVirtualMacMsg() {
    WsMsg::VMac buffer(this->vmac);
    buffer.updateHash(this->password);
    sendFrame(&buffer, sizeof(buffer));
}

void WebSocketClient::sendExptTunMsg() {
    Address exptTun(this->exptTunCidr);
    WsMsg::ExptTun buffer(exptTun.toCidr());
    buffer.updateHash(this->password);
    sendFrame(&buffer, sizeof(buffer));
}

void WebSocketClient::sendAuthMsg() {
    Address address(this->tunCidr);
    WsMsg::Auth buffer(address.Host());
    buffer.updateHash(this->password);
    sendFrame(&buffer, sizeof(buffer));
    this->client->getTunMsgQueue().write(Msg(MsgKind::TUNADDR, address.toCidr()));
    this->client->getPeerMsgQueue().write(Msg(MsgKind::TUNADDR, address.toCidr()));
    if (addressUpdateCallback) {
        addressUpdateCallback(address.toCidr());
    }
    sendPingMessage();
}

void WebSocketClient::sendDiscoveryMsg(IP4 dst) {
    Address address(this->tunCidr);

    WsMsg::Discovery buffer;
    buffer.dst = dst;
    buffer.src = address.Host();

    sendFrame(&buffer, sizeof(buffer));
}

std::string WebSocketClient::hostName() {
    char hostname[64] = {0};
    if (!gethostname(hostname, sizeof(hostname))) {
        return std::string(hostname, strnlen(hostname, sizeof(hostname)));
    }
    return "";
}

void WebSocketClient::sendPingMessage() {
    int flags = (int)Poco::Net::WebSocket::FRAME_FLAG_FIN | (int)Poco::Net::WebSocket::FRAME_OP_PING;
    sendFrame(pingMessage, flags);
}

int WebSocketClient::connect() {
    std::shared_ptr<Poco::URI> uri;
    try {
        uri = std::make_shared<Poco::URI>(wsServerUri);
    } catch (std::exception &e) {
        spdlog::critical("invalid websocket server: {}: {}", wsServerUri, e.what());
        return -1;
    }

    try {
        const std::string path = uri->getPath().empty() ? "/" : uri->getPath();
        Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_GET, path, Poco::Net::HTTPMessage::HTTP_1_1);
        Poco::Net::HTTPResponse response;
        if (uri->getScheme() == "wss") {
            using Poco::Net::Context;
            Context::Ptr context = new Context(Context::TLS_CLIENT_USE, "", "", "", Context::VERIFY_NONE);
            Poco::Net::HTTPSClientSession cs(uri->getHost(), uri->getPort(), context);
            this->ws = std::make_shared<Poco::Net::WebSocket>(cs, request, response);
        } else if (uri->getScheme() == "ws") {
            Poco::Net::HTTPClientSession cs(uri->getHost(), uri->getPort());
            this->ws = std::make_shared<Poco::Net::WebSocket>(cs, request, response);
        } else {
            spdlog::critical("invalid websocket scheme: {}", wsServerUri);
            return -1;
        }
        this->timestamp = bootTime();
        this->pingMessage = fmt::format("candy::{}::{}::{}", CANDY_SYSTEM, CANDY_VERSION, hostName());
        spdlog::debug("client info: {}", this->pingMessage);
        return 0;
    } catch (std::exception &e) {
        spdlog::critical("websocket connect failed: {}", e.what());
        return -1;
    }
}

int WebSocketClient::disconnect() {
    try {
        if (this->ws) {
            this->ws->shutdown();
            this->ws->close();
            this->ws.reset();
        }
    } catch (std::exception &e) {
        spdlog::debug("websocket disconnect failed: {}", e.what());
    }
    return 0;
}

} // namespace Candy

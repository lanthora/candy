// SPDX-License-Identifier: MIT
#include "websocket/client.h"
#include "core/client.h"
#include "core/message.h"
#include "core/net.h"
#include "core/version.h"
#include "utility/time.h"
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
    this->msgThread = std::thread([&] {
        while (this->client->running) {
            handleWsQueue();
        }
    });

    if (connect()) {
        spdlog::critical("websocket client connect failed");
        Candy::shutdown(this->client);
    }

    sendVirtualMacMsg();
    if (this->tunCidr.empty()) {
        sendExptTunMsg();
    } else {
        sendAuthMsg();
    }

    this->wsThread = std::thread([&] {
        while (this->client->running) {
            handleWsConn();
        }
        spdlog::debug("websocket client thread exit");
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
    Msg msg = this->client->wsMsgQueue.read();
    switch (msg.kind) {
    case MsgKind::TIMEOUT:
        break;
    case MsgKind::PACKET:
        handlePacket(std::move(msg));
        break;
    default:
        spdlog::warn("unexcepted websocket message type: {}", static_cast<int>(msg.kind));
        break;
    }
}

void WebSocketClient::handlePacket(Msg msg) {
    IP4Header *header = (IP4Header *)msg.data.data();

    msg.data.insert(0, 1, WsMsgKind::FORWARD);
    sendFrame(msg.data, Poco::Net::WebSocket::FRAME_BINARY);
}

void WebSocketClient::handleWsConn() {
    try {
        std::string buffer;
        int flags = 0;

        // receiveFrame 会对 ws 加锁,影响写操作,需要先确定可读
        if (!this->ws->poll(Poco::Timespan(1, 0), Poco::Net::Socket::SELECT_READ)) {
            if (bootTime() - this->timestamp > 30000) {
                spdlog::warn("websocket pong timeout");
                Candy::shutdown(this->client);
                return;
            }
            if (bootTime() - this->timestamp > 15000) {
                sendPingMessage();
            }
            return;
        }

        buffer.resize(1500);
        int length = this->ws->receiveFrame(buffer.data(), buffer.size(), flags);
        if (length == 0 && flags == 0) {
            spdlog::info("abnormal disconnect");
            Candy::shutdown(this->client);
            return;
        }
        if ((flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) == Poco::Net::WebSocket::FRAME_OP_PING) {
            this->timestamp = bootTime();
            flags = (int)Poco::Net::WebSocket::FRAME_FLAG_FIN | (int)Poco::Net::WebSocket::FRAME_OP_PONG;
            sendFrame(buffer.data(), length, flags);
            return;
        }
        if ((flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) == Poco::Net::WebSocket::FRAME_OP_PONG) {
            this->timestamp = bootTime();
            return;
        }
        if ((flags & Poco::Net::WebSocket::FRAME_OP_BITMASK) == Poco::Net::WebSocket::FRAME_OP_CLOSE) {
            spdlog::info("websocket close: {}", buffer);
            Candy::shutdown(this->client);
            return;
        }
        if (length > 0) {
            this->timestamp = bootTime();
            buffer.resize(length);
            handleWsMsg(std::move(buffer));
            return;
        }
    } catch (std::exception &e) {
        spdlog::warn("handle ws conn failed: {}", e.what());
        Candy::shutdown(this->client);
        return;
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
        break;
    case WsMsgKind::DISCOVERY:
        handleDiscoveryMsg(std::move(buffer));
        break;
    case WsMsgKind::ROUTE:
        handleRouteMsg(std::move(buffer));
        break;
    case WsMsgKind::GENERAL:
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
    this->client->peerMsgQueue.write(Msg(MsgKind::TRYP2P, header->saddr.toString()));
    // 最后把报文移动到 TUN 模块,因为有移动操作所以必须在最后执行
    this->client->tunMsgQueue.write(Msg(MsgKind::PACKET, std::move(buffer)));
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

void WebSocketClient::handleDiscoveryMsg(std::string buffer) {
    if (buffer.size() < sizeof(WsMsg::Discovery)) {
        spdlog::warn("invalid discovery message: {:n}", spdlog::to_hex(buffer));
        return;
    }
    WsMsg::Discovery *header = (WsMsg::Discovery *)buffer.data();
    if (header->dst == IP4("255.255.255.255")) {
        sendDiscoveryMsg(header->src);
    }
    this->client->peerMsgQueue.write(Msg(MsgKind::TRYP2P, header->src.toString()));
}

void WebSocketClient::handleRouteMsg(std::string buffer) {
    if (buffer.size() < sizeof(WsMsg::SysRoute)) {
        spdlog::warn("invalid expt tun message: {:n}", spdlog::to_hex(buffer));
        return;
    }
    WsMsg::SysRoute *header = (WsMsg::SysRoute *)buffer.data();
    SysRouteEntry *rt = header->rtTable;
    for (uint8_t idx = 0; idx < header->size; ++idx) {
        this->client->tunMsgQueue.write(Msg(MsgKind::SYSRT, std::string((char *)(rt + idx), sizeof(SysRouteEntry))));
    }
}

void WebSocketClient::sendFrame(const std::string &buffer, int flags) {
    sendFrame(buffer.c_str(), buffer.size(), flags);
}

void WebSocketClient::sendFrame(const void *buffer, int length, int flags) {
    this->ws->sendFrame(buffer, length, flags);
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
    this->client->tunMsgQueue.write(Msg(MsgKind::TUNADDR, address.toCidr()));
    if (addressUpdateCallback) {
        addressUpdateCallback(address.toCidr());
    }
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

// SPDX-License-Identifier: MIT
#include "websocket/server.h"
#include "websocket/common.h"
#include <functional>
#include <ixwebsocket/IXHttp.h>
#include <ixwebsocket/IXHttpServer.h>
#include <ixwebsocket/IXWebSocketMessage.h>
#include <ixwebsocket/IXWebSocketServer.h>
#include <memory>
#include <queue>
#include <spdlog/spdlog.h>

namespace {

using namespace Candy;

class WebSockeServerImpl {
private:
    int timeout;
    std::mutex mutex;
    std::condition_variable condition;
    std::queue<WebSocketMessage> queue;

    std::shared_ptr<ix::HttpServer> ixHttpServer;

public:
    int listen(const std::string &ipStr, uint16_t port) {
        using namespace std::placeholders;

        this->ixHttpServer = std::make_shared<ix::HttpServer>(port, ipStr);
        this->ixHttpServer->setOnConnectionCallback(std::bind(&WebSockeServerImpl::handleHttpConnection, this, _1, _2));

        auto ixWsServer = std::dynamic_pointer_cast<ix::WebSocketServer>(this->ixHttpServer);
        ixWsServer->setOnConnectionCallback(std::bind(&WebSockeServerImpl::handleWsConnection, this, _1, _2));
        ixWsServer->disablePerMessageDeflate();

        if (!this->ixHttpServer->listen().first) {
            spdlog::critical("ixwebsocket server listen failed");
            return -1;
        }
        this->ixHttpServer->start();
        return 0;
    }

    int stop() {
        this->ixHttpServer->stop();
        return 0;
    }

    int setTimeout(int timeout) {
        this->timeout = timeout;
        return 0;
    }

    int read(WebSocketMessage &message) {
        std::unique_lock<std::mutex> lock(this->mutex);
        if (this->condition.wait_for(lock, std::chrono::seconds(this->timeout), [&] { return !this->queue.empty(); })) {
            message = this->queue.front();
            this->queue.pop();
            return 1;
        }
        return 0;
    }

    int write(const WebSocketMessage &message) {
        std::weak_ptr<ix::WebSocket> weakConn = std::any_cast<std::weak_ptr<ix::WebSocket>>(message.conn.conn);
        auto ws = weakConn.lock();
        if (ws) {
            ws->sendBinary(message.buffer);
        }
        return 0;
    }

    int close(WebSocketConn conn) {
        std::weak_ptr<ix::WebSocket> weakConn = std::any_cast<std::weak_ptr<ix::WebSocket>>(conn.conn);
        auto ws = weakConn.lock();
        if (ws) {
            ws->close();
        }
        return 0;
    }

private:
    ix::HttpResponsePtr handleHttpConnection(ix::HttpRequestPtr request, std::shared_ptr<ix::ConnectionState> connectionState) {
        std::string ip = [&] -> std::string {
            ix::WebSocketHttpHeaders::iterator it;
            it = request->headers.find("X-Real-IP");
            if (it != request->headers.end() && !it->second.empty()) {
                return it->second;
            }
            it = request->headers.find("True-Client-IP");
            if (it != request->headers.end() && !it->second.empty()) {
                return it->second;
            }
            it = request->headers.find("X-Forwarded-For");
            if (it != request->headers.end() && !it->second.empty()) {
                return it->second;
            }
            return connectionState->getRemoteIp();
        }();
        spdlog::info("unexpected http request: {} {} {}", ip, request->method, request->uri);

        ix::WebSocketHttpHeaders responseHeaders;
        responseHeaders["Location"] = "https://github.com/lanthora/candy";
        return std::make_shared<ix::HttpResponse>(302, "Found", ix::HttpErrorCode::Ok, responseHeaders);
    }

    void handleWsConnection(std::weak_ptr<ix::WebSocket> webSocket, std::shared_ptr<ix::ConnectionState> connectionState) {
        using namespace std::placeholders;
        auto ws = webSocket.lock();
        if (ws) {
            ws->setOnMessageCallback(std::bind(&WebSockeServerImpl::handleWsMessage, this, webSocket, connectionState, _1));
        }
    }

    void handleWsMessage(std::weak_ptr<ix::WebSocket> webSocket, std::shared_ptr<ix::ConnectionState> connectionState,
                         const ix::WebSocketMessagePtr &ixWsMsg) {
        WebSocketMessage msg;
        switch (ixWsMsg->type) {
        case ix::WebSocketMessageType::Message:
            msg.type = WebSocketMessageType::Message;
            msg.buffer = ixWsMsg->str;
            msg.conn.conn = webSocket;
            break;
        case ix::WebSocketMessageType::Open:
            msg.type = WebSocketMessageType::Open;
            msg.buffer = ixWsMsg->openInfo.uri;
            msg.conn.conn = webSocket;
            break;
        case ix::WebSocketMessageType::Close:
            msg.type = WebSocketMessageType::Close;
            msg.buffer = ixWsMsg->closeInfo.reason;
            msg.conn.conn = webSocket;
            break;
        case ix::WebSocketMessageType::Error:
            msg.type = WebSocketMessageType::Error;
            msg.buffer = ixWsMsg->errorInfo.reason;
            msg.conn.conn = webSocket;
            break;
        default:
            return;
        }

        {
            std::lock_guard<std::mutex> lock(this->mutex);
            this->queue.push(msg);
        }
        this->condition.notify_all();
    }
};

} // namespace

namespace Candy {

WebSocketServer::WebSocketServer() {
    this->impl = std::make_shared<WebSockeServerImpl>();
    return;
}

WebSocketServer::~WebSocketServer() {
    this->impl.reset();
    return;
}

int WebSocketServer::listen(const std::string &ipStr, uint16_t port) {
    std::shared_ptr<WebSockeServerImpl> server;
    server = std::any_cast<std::shared_ptr<WebSockeServerImpl>>(this->impl);
    return server->listen(ipStr, port);
}

int WebSocketServer::stop() {
    std::shared_ptr<WebSockeServerImpl> server;
    server = std::any_cast<std::shared_ptr<WebSockeServerImpl>>(this->impl);
    return server->stop();
}

int WebSocketServer::setTimeout(int timeout) {
    std::shared_ptr<WebSockeServerImpl> server;
    server = std::any_cast<std::shared_ptr<WebSockeServerImpl>>(this->impl);
    return server->setTimeout(timeout);
}

int WebSocketServer::read(WebSocketMessage &message) {
    std::shared_ptr<WebSockeServerImpl> server;
    server = std::any_cast<std::shared_ptr<WebSockeServerImpl>>(this->impl);
    return server->read(message);
}

int WebSocketServer::write(const WebSocketMessage &message) {
    std::shared_ptr<WebSockeServerImpl> server;
    server = std::any_cast<std::shared_ptr<WebSockeServerImpl>>(this->impl);
    return server->write(message);
}

int WebSocketServer::close(WebSocketConn conn) {
    std::shared_ptr<WebSockeServerImpl> server;
    server = std::any_cast<std::shared_ptr<WebSockeServerImpl>>(this->impl);
    return server->close(conn);
}

} // namespace Candy

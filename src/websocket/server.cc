// SPDX-License-Identifier: MIT
#include "websocket/server.h"
#include "websocket/common.h"
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/WebSocket.h>
#include <Poco/Timespan.h>
#include <spdlog/spdlog.h>

namespace {

using namespace Candy;

class WebSocketHandler : public Poco::Net::HTTPRequestHandler {
public:
    WebSocketHandler(WebSocketServer *server) {
        this->server = server;
    }
    void handleRequest(Poco::Net::HTTPServerRequest &request, Poco::Net::HTTPServerResponse &response) {
        std::shared_ptr<Poco::Net::WebSocket> ws = std::make_shared<Poco::Net::WebSocket>(request, response);
        ws->setReceiveTimeout(Poco::Timespan(this->server->timeout, 0));

        char buffer[1500] = {0};
        int length = 0;
        int flags = 0;

        while (this->server->running) {
            try {
                length = ws->receiveFrame(buffer, sizeof(buffer), flags);
                int frameOp = flags & Poco::Net::WebSocket::FRAME_OP_BITMASK;

                if (frameOp == Poco::Net::WebSocket::FRAME_OP_PING) {
                    flags = (int)Poco::Net::WebSocket::FRAME_FLAG_FIN | (int)Poco::Net::WebSocket::FRAME_OP_PONG;
                    ws->sendFrame(buffer, length, flags);
                    continue;
                }

                if ((length == 0 && flags == 0) || frameOp == Poco::Net::WebSocket::FRAME_OP_CLOSE) {
                    WebSocketMessage msg;
                    msg.type = WebSocketMessageType::Close;
                    msg.buffer.assign(buffer, length);
                    msg.conn.ws = std::weak_ptr<Poco::Net::WebSocket>(ws);
                    this->server->push(msg);
                    break;
                }

                if (frameOp == Poco::Net::WebSocket::FRAME_OP_BINARY && length > 0) {
                    WebSocketMessage msg;
                    msg.type = WebSocketMessageType::Message;
                    msg.buffer.assign(buffer, length);
                    msg.conn.ws = std::weak_ptr<Poco::Net::WebSocket>(ws);
                    this->server->push(msg);
                    continue;
                }
            } catch (Poco::TimeoutException const &e) {
                continue;
            } catch (std::exception &e) {
                WebSocketMessage msg;
                msg.type = WebSocketMessageType::Close;
                msg.buffer = e.what();
                msg.conn.ws = std::weak_ptr<Poco::Net::WebSocket>(ws);
                this->server->push(msg);
                break;
            }
            spdlog::debug("unknown websocket request: length {} flags {}", length, flags);
        }
        ws->close();
    }

private:
    WebSocketServer *server = nullptr;
};

class ForbiddenHandler : public Poco::Net::HTTPRequestHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest &request, Poco::Net::HTTPServerResponse &response) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
        response.setReason("Forbidden");
        response.setContentLength(0);
        response.send();
    }
};

class WebSocketHandlerFactory : public Poco::Net::HTTPRequestHandlerFactory {
public:
    WebSocketHandlerFactory(WebSocketServer *server) {
        this->server = server;
    }
    Poco::Net::HTTPRequestHandler *createRequestHandler(const Poco::Net::HTTPServerRequest &request) {
        if (request.get("Upgrade", "") == "websocket") {
            return new WebSocketHandler(this->server);
        } else {
            return new ForbiddenHandler();
        }
    }

private:
    WebSocketServer *server = nullptr;
};

} // namespace

namespace Candy {

int WebSocketServer::listen(const std::string &host, uint16_t port) {
    try {
        Poco::Net::ServerSocket socket(Poco::Net::SocketAddress(host, port));
        Poco::Net::HTTPServerParams *params = new Poco::Net::HTTPServerParams();
        params->setMaxThreads(0x00FFFFFF);
        this->server = std::make_shared<Poco::Net::HTTPServer>(new WebSocketHandlerFactory(this), socket, params);
        this->running = true;
        this->server->start();
        return 0;
    } catch (std::exception &e) {
        spdlog::critical("listen failed: {}", e.what());
        return -1;
    }
}

int WebSocketServer::stop() {
    this->running = false;
    if (this->server) {
        this->server->stop();
        this->server->stopAll();
    }
    return 0;
}

int WebSocketServer::setTimeout(int timeout) {
    this->timeout = timeout;
    return 0;
}

int WebSocketServer::read(WebSocketMessage &message) {
    std::unique_lock<std::mutex> lock(this->mutex);
    if (this->condition.wait_for(lock, std::chrono::seconds(this->timeout), [&] { return !this->queue.empty(); })) {
        message = this->queue.front();
        this->queue.pop();
        return 1;
    }
    return 0;
}

int WebSocketServer::write(const WebSocketMessage &message) {
    auto ws = message.conn.ws.lock();
    if (ws) {
        try {
            ws->sendFrame(message.buffer.c_str(), message.buffer.size(), Poco::Net::WebSocket::FRAME_BINARY);
        } catch (std::exception &e) {
            spdlog::warn("websocket server write failed: {}", e.what());
        }
    }
    return 0;
}

int WebSocketServer::close(WebSocketConn conn) {
    auto ws = conn.ws.lock();
    if (ws) {
        ws->close();
    }
    return 0;
}

void WebSocketServer::push(const WebSocketMessage &msg) {
    {
        std::lock_guard<std::mutex> lock(this->mutex);
        this->queue.push(msg);
    }
    this->condition.notify_all();
}

} // namespace Candy

// SPDX-License-Identifier: MIT
#include "websocket/client.h"
#include <condition_variable>
#include <functional>
#include <ixwebsocket/IXWebSocket.h>
#include <memory>
#include <mutex>
#include <queue>

namespace {

using namespace Candy;

class WebSocketClientImpl {
private:
    int timeout;
    std::mutex mutex;
    std::condition_variable condition;
    std::queue<WebSocketMessage> queue;

    std::shared_ptr<ix::WebSocket> ixWs;

public:
    int connect(const std::string &address) {
        this->ixWs = std::make_shared<ix::WebSocket>();
        this->ixWs->setUrl(address);
        this->ixWs->setPingInterval(30);
        this->ixWs->disablePerMessageDeflate();
        this->ixWs->setOnMessageCallback(std::bind(&WebSocketClientImpl::handleMessage, this, std::placeholders::_1));
        this->ixWs->disableAutomaticReconnection();
        this->ixWs->setAutoThreadName(false);
        this->ixWs->start();

        return 0;
    }

    int disconnect() {
        this->ixWs->stop();
        {
            std::lock_guard<std::mutex> lock(this->mutex);
            this->queue = std::queue<WebSocketMessage>();
        }
        this->condition.notify_all();

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
        ix::IXWebSocketSendData data = ix::IXWebSocketSendData(message.buffer.c_str(), message.buffer.length());
        this->ixWs->sendBinary(data);
        return 0;
    }

private:
    void handleMessage(const ix::WebSocketMessagePtr &ixWsMsg) {
        WebSocketMessage msg;

        // 把 ixwebsocket 定义的类型转换成外部公开的类型,对外不暴露
        // ixwebsocket,这里的实现是再次赋值,值是一样的,这样做是为了与 ixwebsocket 解耦
        switch (ixWsMsg->type) {
        case ix::WebSocketMessageType::Message:
            msg.type = WebSocketMessageType::Message;
            msg.buffer = ixWsMsg->str;
            break;
        case ix::WebSocketMessageType::Open:
            msg.type = WebSocketMessageType::Open;
            msg.buffer = ixWsMsg->openInfo.uri;
            break;
        case ix::WebSocketMessageType::Close:
            msg.type = WebSocketMessageType::Close;
            msg.buffer = ixWsMsg->closeInfo.reason;
            break;
        case ix::WebSocketMessageType::Error:
            msg.type = WebSocketMessageType::Error;
            msg.buffer = ixWsMsg->errorInfo.reason;
            break;
        default:
            // 退出函数不做其他处理,只有预期的类型产生的事件放入队列,其他事件只需要内部处理,无需对外暴露.
            return;
        }

        {
            std::lock_guard<std::mutex> lock(this->mutex);
            this->queue.push(msg);
        }
        this->condition.notify_all();
    }
};

}; // namespace

namespace Candy {

WebSocketClient::WebSocketClient() {
    this->impl = std::make_shared<WebSocketClientImpl>();
    return;
}

WebSocketClient::~WebSocketClient() {
    this->impl.reset();
    return;
}

int WebSocketClient::connect(const std::string &address) {
    std::shared_ptr<WebSocketClientImpl> client;
    client = std::any_cast<std::shared_ptr<WebSocketClientImpl>>(this->impl);
    return client->connect(address);
}

int WebSocketClient::disconnect() {
    std::shared_ptr<WebSocketClientImpl> client;
    client = std::any_cast<std::shared_ptr<WebSocketClientImpl>>(this->impl);
    return client->disconnect();
}

int WebSocketClient::setTimeout(int timeout) {
    std::shared_ptr<WebSocketClientImpl> client;
    client = std::any_cast<std::shared_ptr<WebSocketClientImpl>>(this->impl);
    return client->setTimeout(timeout);
}

int WebSocketClient::read(WebSocketMessage &message) {
    std::shared_ptr<WebSocketClientImpl> client;
    client = std::any_cast<std::shared_ptr<WebSocketClientImpl>>(this->impl);
    return client->read(message);
}

int WebSocketClient::write(const WebSocketMessage &message) {
    std::shared_ptr<WebSocketClientImpl> client;
    client = std::any_cast<std::shared_ptr<WebSocketClientImpl>>(this->impl);
    return client->write(message);
}

}; // namespace Candy

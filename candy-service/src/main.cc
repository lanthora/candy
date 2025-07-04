#include "candy/client.h"
#include <Poco/Exception.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/StreamCopier.h>
#include <Poco/Timestamp.h>
#include <Poco/Util/HelpFormatter.h>
#include <Poco/Util/Option.h>
#include <Poco/Util/OptionSet.h>
#include <Poco/Util/ServerApplication.h>
#include <iostream>
#include <iterator>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>

std::mutex threadMutex;
std::map<std::string, std::thread> threadMap;

class BaseJSONHandler : public Poco::Net::HTTPRequestHandler {
protected:
    Poco::JSON::Object::Ptr readRequest(Poco::Net::HTTPServerRequest &request) {
        Poco::JSON::Parser parser;
        Poco::Dynamic::Var result = parser.parse(request.stream());
        return result.extract<Poco::JSON::Object::Ptr>();
    }

    void sendResponse(Poco::Net::HTTPServerResponse &response, const Poco::JSON::Object::Ptr &json) {
        response.setChunkedTransferEncoding(true);
        response.setContentType("application/json");
        Poco::JSON::Stringifier::stringify(json, response.send());
    }
};

class RunHandler : public BaseJSONHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest &request, Poco::Net::HTTPServerResponse &response) override {
        if (request.getMethod() != Poco::Net::HTTPRequest::HTTP_POST) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_METHOD_NOT_ALLOWED);
            return;
        }

        auto json = readRequest(request);
        auto id = json->getValue<std::string>("id");
        auto config = json->getObject("config");
        json->remove("config");

        std::lock_guard lock(threadMutex);
        auto it = threadMap.find(id);
        if (it != threadMap.end()) {
            json->set("message", "id already exists");
        } else {
            auto thread = std::thread([=]() { candy::client::run(id, *config); });
            threadMap.insert({id, std::move(thread)});
            json->set("message", "success");
        }

        sendResponse(response, json);
    }
};

class StatusHandler : public BaseJSONHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest &request, Poco::Net::HTTPServerResponse &response) override {
        if (request.getMethod() != Poco::Net::HTTPRequest::HTTP_POST) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_METHOD_NOT_ALLOWED);
            return;
        }

        auto json = readRequest(request);
        auto id = json->getValue<std::string>("id");

        std::lock_guard lock(threadMutex);
        auto it = threadMap.find(id);
        if (it != threadMap.end()) {
            if (auto status = candy::client::status(id)) {
                json->set("status", *status);
                json->set("message", "success");
            } else {
                json->set("message", "unable to get status");
            }
        } else {
            json->set("message", "id does not exist");
        }

        sendResponse(response, json);
    }
};

class ShutdownHandler : public BaseJSONHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest &request, Poco::Net::HTTPServerResponse &response) override {
        if (request.getMethod() != Poco::Net::HTTPRequest::HTTP_POST) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_METHOD_NOT_ALLOWED);
            return;
        }

        auto json = readRequest(request);
        auto id = json->getValue<std::string>("id");
        candy::client::shutdown(id);

        std::lock_guard lock(threadMutex);
        auto it = threadMap.find(id);
        if (it != threadMap.end()) {
            it->second.detach();
            threadMap.erase(it);
            json->set("message", "success");
        } else {
            json->set("message", "id does not exist");
        }

        sendResponse(response, json);
    }
};

class JSONRequestHandlerFactory : public Poco::Net::HTTPRequestHandlerFactory {
public:
    Poco::Net::HTTPRequestHandler *createRequestHandler(const Poco::Net::HTTPServerRequest &request) override {
        const std::string &uri = request.getURI();

        if (uri == "/api/run") {
            return new RunHandler;
        } else if (uri == "/api/status") {
            return new StatusHandler;
        } else if (uri == "/api/shutdown") {
            return new ShutdownHandler;
        }

        return nullptr;
    }
};

class CandyServiceApp : public Poco::Util::ServerApplication {
protected:
    std::string bindAddress;
    int port = 0;
    bool helpRequested = false;

    void initialize(Poco::Util::Application &self) override {
        loadConfiguration();
        Poco::Util::ServerApplication::initialize(self);
    }

    void defineOptions(Poco::Util::OptionSet &options) override {
        Poco::Util::ServerApplication::defineOptions(options);

        options.addOption(Poco::Util::Option("help", "", "Display help information")
                              .required(false)
                              .repeatable(false)
                              .callback(Poco::Util::OptionCallback<CandyServiceApp>(this, &CandyServiceApp::handleHelp)));

        options.addOption(Poco::Util::Option("bind", "", "Bind address and port (address:port)")
                              .required(false)
                              .repeatable(false)
                              .argument("address:port")
                              .callback(Poco::Util::OptionCallback<CandyServiceApp>(this, &CandyServiceApp::handleBind)));
    }

    void handleHelp(const std::string &name, const std::string &value) {
        helpRequested = true;
        displayHelp();
        stopOptionsProcessing();
    }

    void handleBind(const std::string &name, const std::string &value) {
        size_t pos = value.find(':');
        if (pos == std::string::npos) {
            std::cerr << "Invalid bind format. Use address:port (e.g., 0.0.0.0:26817)" << std::endl;
            std::exit(EXIT_FAILURE);
        }

        bindAddress = value.substr(0, pos);
        try {
            port = std::stoi(value.substr(pos + 1));
        } catch (const std::exception &e) {
            std::cerr << "Invalid port number: " << e.what() << std::endl;
            std::exit(EXIT_FAILURE);
        }
    }

    void displayHelp() {
        Poco::Util::HelpFormatter helpFormatter(options());
        helpFormatter.setCommand(commandName());
        helpFormatter.format(std::cout);
    }

    int main(const std::vector<std::string> &args) override {
        if (helpRequested) {
            return Poco::Util::Application::EXIT_OK;
        }

        if (bindAddress.empty()) {
            bindAddress = "localhost";
            port = 26817;
        }

        try {
            Poco::Net::ServerSocket socket;
            socket.bind(Poco::Net::SocketAddress(bindAddress, port));
            socket.listen();

            Poco::Net::HTTPServerParams *params = new Poco::Net::HTTPServerParams;
            params->setMaxQueued(10);
            params->setMaxThreads(1);

            Poco::Net::HTTPServer server(new JSONRequestHandlerFactory, socket, params);

            server.start();
            std::cout << "candy-service bind: " << bindAddress << ":" << port << std::endl;

            waitForTerminationRequest();
            server.stop();

            std::lock_guard lock(threadMutex);
            for (auto &[id, thread] : threadMap) {
                candy::client::shutdown(id);
                if (thread.joinable()) {
                    thread.join();
                }
            }

        } catch (const Poco::Exception &exc) {
            std::cerr << "Fatal error: " << exc.displayText() << std::endl;
            return Poco::Util::Application::EXIT_SOFTWARE;
        } catch (const std::exception &e) {
            std::cerr << "Fatal error: " << e.what() << std::endl;
            return Poco::Util::Application::EXIT_SOFTWARE;
        }

        return Poco::Util::Application::EXIT_OK;
    }
};

int main(int argc, char **argv) {
    CandyServiceApp app;
    return app.run(argc, argv);
}

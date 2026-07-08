// SPDX-License-Identifier: MIT
#include "config.h"
#include "argparse.h"
#include "candy/candy.h"
#include "utils/log.h"
#include <Poco/ConsoleChannel.h>
#include <Poco/Format.h>
#include <Poco/FormattingChannel.h>
#include <Poco/JSON/Object.h>
#include <Poco/Logger.h>
#include <Poco/Message.h>
#include <Poco/PatternFormatter.h>
#include <Poco/Platform.h>
#include <Poco/String.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

Poco::JSON::Object arguments::json() {
    Poco::JSON::Object config;
    config.set("mode", this->mode);
    config.set("websocket", this->websocket);
    config.set("password", this->password);

    if (this->mode == "client") {
        config.set("name", this->name);
        config.set("tun", this->tun);
        config.set("stun", this->stun);
        config.set("localhost", this->localhost);
        config.set("discovery", this->discovery);
        config.set("route", this->routeCost);
        config.set("mtu", this->mtu);
        config.set("port", this->port);
        config.set("vmac", virtualMac(this->name));
        config.set("expt", loadTunAddress(this->name));
    }

    if (this->mode == "server") {
        config.set("dhcp", this->dhcp);
        config.set("sdwan", this->sdwan);
    }

    return config;
}

int arguments::parse(int argc, char *argv[]) {
    argparse::ArgumentParser program("candy", candy::version());

    program.add_description("A simple P2P VPN / SD-WAN networking tool.");

    program.add_argument("-c", "--config").help("config file path (key=value format, same keys as CLI args)").metavar("<path>");

    program.add_argument("-m", "--mode").help("working mode: \"client\" or \"server\"").metavar("<mode>");

    program.add_argument("-w", "--websocket")
        .help("WebSocket signaling address (e.g. \"ws://host:port/ws\").\n"
              "Client supports ws:// and wss://; server supports ws:// only.")
        .metavar("<url>");

    program.add_argument("-p", "--password")
        .help("pre-shared key for authentication and P2P encryption.\n"
              "Password is never transmitted in plaintext; only HMAC-SHA256 hashes are sent.")
        .metavar("<secret>");

    program.add_group("Client options");

    program.add_argument("-n", "--name")
        .help("TUN interface name suffix. Device will be named \"candy-<name>\".\n"
              "Useful when running multiple clients on one host. (client only)")
        .metavar("<iface>");

    program.add_argument("-t", "--tun")
        .help("static TUN address in CIDR notation (e.g. \"192.168.202.1/24\").\n"
              "If omitted, the client requests a dynamic address from the server via DHCP. (client only)")
        .metavar("<cidr>");

    program.add_argument("-s", "--stun")
        .help("STUN server address for NAT traversal (e.g. \"stun://stun.example.org\").\n"
              "If omitted: P2P works only on the local network (LAN);\n"
              "public internet peer-to-peer connections will fail.\n"
              "Also disables periodic discovery broadcasts. (client only)")
        .metavar("<url>");

    program.add_argument("--port")
        .help("local UDP port for P2P communication.\n"
              "Default is 0 (OS assigns a random port).\n"
              "Specify a fixed port when firewall rules require it. (client only)")
        .metavar("<int>")
        .scan<'i', int>()
        .default_value(0)
        .nargs(1);

    program.add_argument("--mtu")
        .help("maximum transmission unit for the TUN device.\n"
              "Default is 1400. (client only)")
        .metavar("<int>")
        .scan<'i', int>()
        .default_value(1400)
        .nargs(1);

    program.add_argument("-r", "--route")
        .help("routing cost (0-1000), added to measured RTT when advertising routes.\n"
              "Default is 0 (relay disabled): this node does not forward traffic for other peers.\n"
              "Set > 0 to enable relay mode. (client only)")
        .metavar("<int>")
        .scan<'i', int>()
        .default_value(0)
        .nargs(1);

    program.add_argument("--discovery")
        .help("periodic P2P discovery interval in seconds.\n"
              "Default is 0 (disabled). Requires STUN to be configured.\n"
              "When enabled, periodically broadcasts discovery to trigger P2P attempts. (client only)")
        .metavar("<int>")
        .scan<'i', int>()
        .default_value(0)
        .nargs(1);

    program.add_argument("--localhost")
        .help("local IPv4 address used for P2P peering.\n"
              "If omitted, auto-detected from the first physical network interface. (client only)")
        .metavar("<ip>");

    program.add_group("Server options");

    program.add_argument("-d", "--dhcp")
        .help("DHCP address pool for dynamic client address allocation\n"
              "(e.g. \"192.168.202.0/24\"). Also enables directed broadcast detection.\n"
              "If omitted, clients must use a static --tun address. (server only)")
        .metavar("<cidr>");

    program.add_argument("--sdwan")
        .help("software-defined routing rules.\n"
              "Format: \"dev_cidr,dst_cidr,nexthop;...\" (semicolon-separated).\n"
              "Pushes sys route entries to matching clients on connect. (server only)")
        .metavar("<rules>");

    program.add_group("Logging options");

    program.add_argument("--no-timestamp")
        .help("omit timestamps from log output (shows only log level and message).")
        .implicit_value(true);

    program.add_argument("--debug").help("enable debug-level logging.").implicit_value(true);

    program.add_epilog("Examples:\n"
                       "  Client with static address:\n"
                       "    candy -m client -w wss://server.example.com/ws -p mysecret -t 192.168.202.1/24\n"
                       "  Client with DHCP (dynamic address):\n"
                       "    candy -m client -w wss://server.example.com/ws -p mysecret -s stun://stun.example.com\n"
                       "  Server:\n"
                       "    candy -m server -w ws://0.0.0.0:8080/ws -p mysecret -d 192.168.202.0/24\n"
                       "  Using config file:\n"
                       "    candy -c candy.cfg");

    try {
        program.parse_args(argc, argv);
        if (program.is_used("--config")) {
            parseFile(program.get<std::string>("--config"));
        }

        if (program.is_used("--mode")) {
            this->mode = program.get<std::string>("--mode");
        }

        program.set_if_used("--mode", this->mode);
        program.set_if_used("--websocket", this->websocket);
        program.set_if_used("--password", this->password);
        program.set_if_used("--no-timestamp", this->noTimestamp);
        program.set_if_used("--debug", this->debug);
        program.set_if_used("--dhcp", this->dhcp);
        program.set_if_used("--sdwan", this->sdwan);
        program.set_if_used("--name", this->name);
        program.set_if_used("--tun", this->tun);
        program.set_if_used("--stun", this->stun);
        program.set_if_used("--localhost", this->localhost);
        program.set_if_used("--port", this->port);
        program.set_if_used("--mtu", this->mtu);
        program.set_if_used("--discovery", this->discovery);
        program.set_if_used("--route", this->routeCost);

        bool needShowUsage = [&]() {
            if (this->mode != "client" && this->mode != "server")
                return true;
            if (this->websocket.empty())
                return true;

            return false;
        }();

        if (needShowUsage) {
            std::cout << program.usage() << std::endl;
            exit(1);
        }

        // Set up default console channel with pattern
        if (this->noTimestamp) {
            Poco::AutoPtr<Poco::PatternFormatter> pFormatter = new Poco::PatternFormatter("[%q] %t");
            Poco::AutoPtr<Poco::FormattingChannel> pFormattingChannel = new Poco::FormattingChannel(pFormatter);
            Poco::AutoPtr<Poco::ConsoleChannel> pConsoleChannel = new Poco::ConsoleChannel;
            pFormattingChannel->setChannel(pConsoleChannel);
            Poco::Logger::root().setChannel(pFormattingChannel);
        } else {
            Poco::AutoPtr<Poco::PatternFormatter> pFormatter = new Poco::PatternFormatter("%Y-%m-%d %H:%M:%S [%q] %t");
            Poco::AutoPtr<Poco::FormattingChannel> pFormattingChannel = new Poco::FormattingChannel(pFormatter);
            Poco::AutoPtr<Poco::ConsoleChannel> pConsoleChannel = new Poco::ConsoleChannel;
            pFormattingChannel->setChannel(pConsoleChannel);
            Poco::Logger::root().setChannel(pFormattingChannel);
        }

        if (this->debug) {
            Poco::Logger::root().setLevel(Poco::Message::PRIO_DEBUG);
        }
        return 0;
    } catch (const std::exception &e) {
        std::cout << program.usage() << std::endl;
        exit(1);
    }
}

void arguments::parseFile(std::string cfgFile) {
    try {
        std::map<std::string, std::function<void(const std::string &)>> cfgHandlers = {
            {"mode", [&](const std::string &value) { this->mode = value; }},
            {"websocket", [&](const std::string &value) { this->websocket = value; }},
            {"password", [&](const std::string &value) { this->password = value; }},
            {"debug", [&](const std::string &value) { this->debug = (value == "true"); }},
            {"dhcp", [&](const std::string &value) { this->dhcp = value; }},
            {"sdwan", [&](const std::string &value) { this->sdwan = value; }},
            {"tun", [&](const std::string &value) { this->tun = value; }},
            {"stun", [&](const std::string &value) { this->stun = value; }},
            {"name", [&](const std::string &value) { this->name = value; }},
            {"discovery", [&](const std::string &value) { this->discovery = std::stoi(value); }},
            {"route", [&](const std::string &value) { this->routeCost = std::stoi(value); }},
            {"port", [&](const std::string &value) { this->port = std::stoi(value); }},
            {"mtu", [&](const std::string &value) { this->mtu = std::stoi(value); }},
            {"localhost", [&](const std::string &value) { this->localhost = value; }},
        };
        auto trim = [](std::string str) {
            if (str.length() >= 2 && str.front() == '\"' && str.back() == '\"') {
                return str.substr(1, str.length() - 2);
            }
            return str;
        };
        auto configs = fileToKvMap(cfgFile);
        for (auto cfg : configs) {
            auto handler = cfgHandlers.find(cfg.first);
            if (handler != cfgHandlers.end()) {
                handler->second(trim(cfg.second));
            } else {
                candy::logger().warning(Poco::format("unknown config: %s=%s", cfg.first, cfg.second));
            }
        }
    } catch (std::exception &e) {
        candy::logger().error(Poco::format("parse config file failed: %s", std::string(e.what())));
        exit(1);
    }
}

std::map<std::string, std::string> arguments::fileToKvMap(const std::string &filename) {
    std::map<std::string, std::string> config;
    std::ifstream file(filename);
    std::string line;

    while (std::getline(file, line)) {
        line = Poco::trimLeft(line);
        if (line.empty() || line.front() == '#')
            continue;
        line.erase(line.find_last_not_of(" \t;") + 1);
        std::size_t delimiterPos = line.find('=');
        if (delimiterPos != std::string::npos) {
            std::string key = Poco::trim(line.substr(0, delimiterPos));
            std::string value = Poco::trim(line.substr(delimiterPos + 1));
            config[key] = value;
        }
    }
    return config;
}

int saveTunAddress(const std::string &name, const std::string &cidr) {
    try {
        std::string cache = storageDirectory("address/");
        cache += name.empty() ? "__noname__" : name;
        std::filesystem::create_directories(std::filesystem::path(cache).parent_path());
        std::ofstream ofs(cache);
        if (ofs.is_open()) {
            ofs << cidr;
            ofs.close();
        }
        return 0;
    } catch (std::exception &e) {
        candy::logger().fatal(Poco::format("save latest address failed: %s", std::string(e.what())));
        return -1;
    }
}

std::string loadTunAddress(const std::string &name) {
    std::string cache = storageDirectory("address/");
    cache += name.empty() ? "__noname__" : name;
    std::ifstream ifs(cache);
    if (ifs.is_open()) {
        std::stringstream ss;
        ss << ifs.rdbuf();
        ifs.close();
        return ss.str();
    }
    return "0.0.0.0/0";
}

std::string virtualMacHelper(std::string name = "") {
    try {
        std::string path = storageDirectory("vmac/");
        path += name.empty() ? "__noname__" : name;
        char buffer[candy::VMAC_SIZE];
        std::stringstream ss;
        std::ifstream ifs(path);
        if (ifs.is_open()) {
            ifs.read(buffer, sizeof(buffer));
            if (ifs) {
                for (int i = 0; i < (int)sizeof(buffer); i++) {
                    ss << std::hex << buffer[i];
                }
            }
            ifs.close();
            return ss.str();
        }
        return "";
    } catch (std::exception &e) {
        return "";
    }
}

std::string initVirtualMac() {
    try {
        std::string path = storageDirectory("vmac/__noname__");
        std::filesystem::create_directories(std::filesystem::path(path).parent_path());
        std::string vmac = candy::create_vmac();
        std::ofstream ofs(path);
        if (ofs.is_open()) {
            ofs << vmac;
            ofs.close();
        }
        return vmac;
    } catch (std::exception &e) {
        candy::logger().fatal(Poco::format("init vmac failed: %s", std::string(e.what())));
        return "";
    }
}

std::string virtualMac(const std::string &name) {
    std::string path;
    // 兼容老版本,优先获取与配置网卡名对应的 vmac
    path = virtualMacHelper(name);
    if (!path.empty()) {
        return path;
    }
    // 获取网卡名无关的全局 vmac
    path = virtualMacHelper();
    if (!path.empty()) {
        return path;
    }
    // 初次启动,生成全局 vmac
    return initVirtualMac();
}

bool starts_with(const std::string &str, const std::string &prefix) {
    return str.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), str.begin());
}

#if POCO_OS == POCO_OS_WINDOWS_NT
std::string storageDirectory(std::string subdir) {
    return "C:/ProgramData/Candy/" + subdir;
}
#else
std::string storageDirectory(std::string subdir) {
    return "/var/lib/candy/" + subdir;
}
#endif

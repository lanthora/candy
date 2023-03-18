#include "util.h"
#include <spdlog/spdlog.h>
#include <arpa/inet.h>

namespace candy {

std::string CIDR::networkPrefixToSubnetMask(std::string prefix) {
    int num = std::stoi(prefix);
    if (num > 32 || num < 0) {
        spdlog::critical("cidr prefix exception. value: {0}", num);
        exit(1);
    }

    struct in_addr addr;
    memset(&addr, 0, sizeof(addr));
    for (int idx = 0; idx < num; ++idx) {
        addr.s_addr |= 0x80000000 >> idx;
    }

    addr.s_addr = htonl(addr.s_addr);
    return inet_ntoa(addr);
}

WsUriParser::WsUriParser(const std::string &uri) {
    _uri = uri;
    std::size_t pos;
    pos = _uri.find(":");
    if (pos == std::string::npos)
        return;

    _scheme = _uri.substr(0, pos);
    if (_scheme == "ws") {
        _port = "80";
    } else if (_scheme == "wss") {
        _port = "443";
    } else {
        return;
    }
    _uri.erase(0, pos + 1);

    if (!_uri.starts_with("//"))
        return;
    _uri.erase(0, 2);
    pos = _uri.find(":");
    if (pos != std::string::npos) {
        _port = _uri.substr(pos + 1);
        _uri.erase(pos);
    }

    if (std::stoi(_port) <= 0 || std::stoi(_port) >= 65443)
        return;

    _host = _uri;
    _uri.clear();
    return;
}

bool WsUriParser::isValid() {
    return _uri.empty();
}

bool INet::isIpv4Address(std::string address) {
    struct in_addr sin_addr;
    return inet_pton(AF_INET, address.data(), &sin_addr) == 1;
}

std::string INet::ipToString(uint32_t ip) {
    struct in_addr sin_addr;
    sin_addr.s_addr = ip;
    return inet_ntoa(sin_addr);
}

void AuthHeader::calculateHash(const std::string &password) {
    std::string data = password;
    data.append((char *)&tunIp, sizeof(tunIp));
    data.append((char *)&timestamp, sizeof(timestamp));
    SHA256((unsigned char *)data.data(), data.size(), _hash);
}

bool AuthHeader::checkHash(const std::string &password) {
    uint8_t calculated[SHA256_DIGEST_LENGTH];
    std::string data = password;
    data.append((char *)&tunIp, sizeof(tunIp));
    data.append((char *)&timestamp, sizeof(timestamp));
    SHA256((unsigned char *)data.data(), data.size(), calculated);

    return memcmp(calculated, _hash, SHA256_DIGEST_LENGTH) == 0;
}

}; // namespace candy

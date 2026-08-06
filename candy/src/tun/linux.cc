// SPDX-License-Identifier: MIT
#include <Poco/Platform.h>
#if POCO_OS == POCO_OS_LINUX

#include "core/net.h"
#include "tun/tun.h"
#include "utils/log.h"
#include <Poco/Format.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <memory>
#include <net/if.h>
#include <net/route.h>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>

namespace candy {

struct Tun::Impl {
    int setName(const std::string &name) {
        this->name = name.empty() ? "candy" : "candy-" + name;
        return 0;
    }

    int setMTU(int mtu) {
        this->mtu = mtu;
        return 0;
    }

    // Configure the interface and set up routing
    int up(IP4 ip, IP4 mask) {
        this->tunFd = open("/dev/net/tun", O_RDWR);
        if (this->tunFd < 0) {
            candy::logger().fatal(Poco::format("open /dev/net/tun failed: %s", std::string(strerror(errno))));
            close(this->tunFd);
            return -1;
        }
        int flags = fcntl(this->tunFd, F_GETFL, 0);
        if (flags < 0) {
            candy::logger().error(Poco::format("get tun flags failed: %s", std::string(strerror(errno))));
            close(this->tunFd);
            return -1;
        }
        flags |= O_NONBLOCK;
        if (fcntl(this->tunFd, F_SETFL, flags) < 0) {
            candy::logger().error(Poco::format("set non-blocking tun failed: %s", std::string(strerror(errno))));
            close(this->tunFd);
            return -1;
        }

        // Set device name
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, this->name.c_str(), IFNAMSIZ);
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if (ioctl(this->tunFd, TUNSETIFF, &ifr) == -1) {
            candy::logger().fatal(Poco::format("set tun interface failed: %s", std::string(strerror(errno))));
            close(this->tunFd);
            return -1;
        }

        // Create a socket for configuring additional interface settings
        struct sockaddr_in *addr;
        addr = (struct sockaddr_in *)&ifr.ifr_addr;
        addr->sin_family = AF_INET;
        int sockfd = socket(addr->sin_family, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            candy::logger().fatal("create socket failed");
            close(this->tunFd);
            return -1;
        }

        // Set address
        addr->sin_addr.s_addr = ip;
        if (ioctl(sockfd, SIOCSIFADDR, (caddr_t)&ifr) == -1) {
            candy::logger().fatal(Poco::format("set ip address failed: ip %s", ip.toString()));
            close(sockfd);
            close(this->tunFd);
            return -1;
        }

        // Set mask
        addr->sin_addr.s_addr = mask;
        if (ioctl(sockfd, SIOCSIFNETMASK, (caddr_t)&ifr) == -1) {
            candy::logger().fatal(Poco::format("set mask failed: mask %s", mask.toString()));
            close(sockfd);
            close(this->tunFd);
            return -1;
        }

        // Set MTU
        ifr.ifr_mtu = this->mtu;
        if (ioctl(sockfd, SIOCSIFMTU, (caddr_t)&ifr) == -1) {
            candy::logger().fatal(Poco::format("set mtu failed: mtu %d", this->mtu));
            close(sockfd);
            close(this->tunFd);
            return -1;
        }

        // Set flags
        if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
            candy::logger().fatal("get interface flags failed");
            close(sockfd);
            close(this->tunFd);
            return -1;
        }
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1) {
            candy::logger().fatal("set interface flags failed");
            close(sockfd);
            close(this->tunFd);
            return -1;
        }

        close(sockfd);

        return 0;
    }

    int down() {
        close(this->tunFd);
        return 0;
    }

    int read(std::string &buffer) {
        buffer.resize(this->mtu);
        int n = ::read(this->tunFd, buffer.data(), buffer.size());
        if (n >= 0) {
            buffer.resize(n);
            return n;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct timeval timeout = {.tv_sec = 1};
            fd_set set;

            FD_ZERO(&set);
            FD_SET(this->tunFd, &set);

            select(this->tunFd + 1, &set, NULL, NULL, &timeout);
            return 0;
        }
        candy::logger().warning(Poco::format("tun read failed: %s", std::string(strerror(errno))));
        return -1;
    }

    int write(const std::string &buffer) {
        return ::write(this->tunFd, buffer.c_str(), buffer.size());
    }

    int setSysRtTable(IP4 dst, IP4 mask, IP4 nexthop) {
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            candy::logger().error("set route failed: create socket failed");
            return -1;
        }

        struct sockaddr_in *addr;
        struct rtentry route;
        memset(&route, 0, sizeof(route));

        addr = (struct sockaddr_in *)&route.rt_dst;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = dst;

        addr = (struct sockaddr_in *)&route.rt_genmask;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = mask;

        addr = (struct sockaddr_in *)&route.rt_gateway;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = nexthop;

        route.rt_flags = RTF_UP | RTF_GATEWAY;
        if (ioctl(sockfd, SIOCADDRT, &route) == -1) {
            candy::logger().error("set route failed: ioctl failed");
            close(sockfd);
            return -1;
        }

        close(sockfd);
        return 0;
    }

private:
    std::string name;
    int mtu;
    int tunFd;
};

Tun::Tun() {
    this->impl = std::make_unique<Impl>();
}

Tun::~Tun() {}

int Tun::setName(const std::string &name) {
    return this->impl->setName(name);
}

int Tun::setMTU(int mtu) {
    return this->impl->setMTU(mtu);
}

int Tun::up() {
    return this->impl->up(this->ip, this->mask);
}

int Tun::down() {
    return this->impl->down();
}

int Tun::read(std::string &buffer) {
    return this->impl->read(buffer);
}

int Tun::write(const std::string &buffer) {
    return this->impl->write(buffer);
}

int Tun::setSysRtTable(IP4 dst, IP4 mask, IP4 nexthop) {
    return this->impl->setSysRtTable(dst, mask, nexthop);
}

} // namespace candy

#endif

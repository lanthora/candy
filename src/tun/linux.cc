// SPDX-License-Identifier: MIT
#include <Poco/Platform.h>
#if POCO_OS == POCO_OS_LINUX

#include "core/net.h"
#include "tun/tun.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <memory>
#include <net/if.h>
#include <net/route.h>
#include <spdlog/spdlog.h>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {

class LinuxTun {
public:
    int setName(const std::string &name) {
        this->name = name.empty() ? "candy" : "candy-" + name;
        return 0;
    }

    int setIP(Candy::IP4 ip) {
        this->ip = ip;
        return 0;
    }

    Candy::IP4 getIP() {
        return this->ip;
    }

    int setMask(Candy::IP4 mask) {
        this->mask = mask;
        return 0;
    }

    int setMTU(int mtu) {
        this->mtu = mtu;
        return 0;
    }

    // 配置网卡,设置路由
    int up() {
        this->tunFd = open("/dev/net/tun", O_RDWR);
        if (this->tunFd < 0) {
            spdlog::critical("open /dev/net/tun failed: {}", strerror(errno));
            return -1;
        }
        int flags = fcntl(this->tunFd, F_GETFL, 0);
        if (flags < 0) {
            spdlog::error("get tun flags failed: {}", strerror(errno));
            return -1;
        }
        flags |= O_NONBLOCK;
        if (fcntl(this->tunFd, F_SETFL, flags) < 0) {
            spdlog::error("set non-blocking tun failed: {}", strerror(errno));
            return -1;
        }

        // 设置设备名
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, this->name.c_str(), IFNAMSIZ);
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if (ioctl(this->tunFd, TUNSETIFF, &ifr) == -1) {
            spdlog::critical("set tun interface failed: {}", strerror(errno));
            return -1;
        }

        // 创建 socket, 并通过这个 socket 更新网卡的其他配置
        struct sockaddr_in *addr;
        addr = (struct sockaddr_in *)&ifr.ifr_addr;
        addr->sin_family = AF_INET;
        int sockfd = socket(addr->sin_family, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            spdlog::critical("create socket failed");
            return -1;
        }

        // 设置地址
        addr->sin_addr.s_addr = this->ip;
        if (ioctl(sockfd, SIOCSIFADDR, (caddr_t)&ifr) == -1) {
            spdlog::critical("set ip address failed: ip {}", this->ip.toString());
            close(sockfd);
            return -1;
        }

        // 设置掩码
        addr->sin_addr.s_addr = this->mask;
        if (ioctl(sockfd, SIOCSIFNETMASK, (caddr_t)&ifr) == -1) {
            spdlog::critical("set mask failed: mask {}", this->mask.toString());
            close(sockfd);
            return -1;
        }

        // 设置 MTU
        ifr.ifr_mtu = this->mtu;
        if (ioctl(sockfd, SIOCSIFMTU, (caddr_t)&ifr) == -1) {
            spdlog::critical("set mtu failed: mtu {}", this->mtu);
            close(sockfd);
            return -1;
        }

        // 设置 flags
        if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
            spdlog::critical("get interface flags failed");
            close(sockfd);
            return -1;
        }
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1) {
            spdlog::critical("set interface flags failed");
            close(sockfd);
            return -1;
        }

        // 设置路由
        struct rtentry route;
        memset(&route, 0, sizeof(route));

        addr = (struct sockaddr_in *)&route.rt_dst;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = this->ip;

        addr = (struct sockaddr_in *)&route.rt_genmask;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = this->mask;

        route.rt_dev = (char *)this->name.c_str();
        route.rt_flags = RTF_UP | RTF_HOST;
        if (ioctl(sockfd, SIOCADDRT, &route) == -1) {
            spdlog::critical("set route failed");
            close(sockfd);
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
        spdlog::warn("tun read failed: {}", strerror(errno));
        return -1;
    }

    int write(const std::string &buffer) {
        return ::write(this->tunFd, buffer.c_str(), buffer.size());
    }

    int setSysRtTable(Candy::IP4 dst, Candy::IP4 mask, Candy::IP4 nexthop) {
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            spdlog::error("set route failed: create socket failed");
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
            spdlog::error("set route failed: ioctl failed");
            close(sockfd);
            return -1;
        }

        close(sockfd);
        return 0;
    }

private:
    std::string name;
    Candy::IP4 ip;
    Candy::IP4 mask;
    int mtu;
    int timeout;
    int tunFd;
};

} // namespace

namespace Candy {

Tun::Tun() {
    this->impl = std::make_shared<LinuxTun>();
}

Tun::~Tun() {
    this->impl.reset();
}

int Tun::setName(const std::string &name) {
    std::shared_ptr<LinuxTun> tun;

    tun = std::any_cast<std::shared_ptr<LinuxTun>>(this->impl);
    tun->setName(name);
    return 0;
}

int Tun::setAddress(const std::string &cidr) {
    std::shared_ptr<LinuxTun> tun;
    Address address;

    if (address.fromCidr(cidr)) {
        return -1;
    }
    spdlog::info("client address: {}", address.toCidr());
    tun = std::any_cast<std::shared_ptr<LinuxTun>>(this->impl);
    if (tun->setIP(address.Host())) {
        return -1;
    }
    if (tun->setMask(address.Mask())) {
        return -1;
    }
    this->tunAddress = cidr;
    return 0;
}

IP4 Tun::getIP() {
    std::shared_ptr<LinuxTun> tun;
    tun = std::any_cast<std::shared_ptr<LinuxTun>>(this->impl);
    return tun->getIP();
}

int Tun::setMTU(int mtu) {
    std::shared_ptr<LinuxTun> tun;
    tun = std::any_cast<std::shared_ptr<LinuxTun>>(this->impl);
    if (tun->setMTU(mtu)) {
        return -1;
    }
    return 0;
}

int Tun::up() {
    std::shared_ptr<LinuxTun> tun;
    tun = std::any_cast<std::shared_ptr<LinuxTun>>(this->impl);
    return tun->up();
}

int Tun::down() {
    std::shared_ptr<LinuxTun> tun;
    tun = std::any_cast<std::shared_ptr<LinuxTun>>(this->impl);
    return tun->down();
}

int Tun::read(std::string &buffer) {
    std::shared_ptr<LinuxTun> tun;
    tun = std::any_cast<std::shared_ptr<LinuxTun>>(this->impl);
    return tun->read(buffer);
}

int Tun::write(const std::string &buffer) {
    std::shared_ptr<LinuxTun> tun;
    tun = std::any_cast<std::shared_ptr<LinuxTun>>(this->impl);
    return tun->write(buffer);
}

int Tun::setSysRtTable(IP4 dst, IP4 mask, IP4 nexthop) {
    std::shared_ptr<LinuxTun> tun;
    tun = std::any_cast<std::shared_ptr<LinuxTun>>(this->impl);
    return tun->setSysRtTable(dst, mask, nexthop);
}

} // namespace Candy

#endif

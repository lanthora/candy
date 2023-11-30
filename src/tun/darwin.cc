// SPDX-License-Identifier: MIT
#if defined(__APPLE__) || defined(__MACH__)

#include "tun/tun.h"
#include "utility/address.h"
#include <errno.h>
#include <memory>
#include <net/if.h>
#include <net/if_utun.h>
#include <net/route.h>
#include <netinet/in.h>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/uio.h>
#include <unistd.h>

namespace {
class DarwinTun {
public:
    int setName(const std::string &name) {
        this->name = name.empty() ? "candy" : "candy-" + name;
        return 0;
    }

    int setIP(uint32_t ip) {
        this->ip = ip;
        return 0;
    }

    int getIP() {
        return this->ip;
    }

    int setMask(uint32_t mask) {
        this->mask = mask;
        return 0;
    }

    int setMTU(int mtu) {
        this->mtu = mtu;
        return 0;
    }

    int setTimeout(int timeout) {
        this->timeout = timeout;
        return 0;
    }

    int up() {
        // 创建设备,操作系统不允许自定义设备名,只能由内核分配
        this->tunFd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (this->tunFd < 0) {
            spdlog::critical("create socket failed: {}", strerror(errno));
            return -1;
        }

        struct ctl_info info;
        memset(&info, 0, sizeof(info));
        strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);
        if (ioctl(this->tunFd, CTLIOCGINFO, &info) == -1) {
            spdlog::critical("get control id failed: {}", strerror(errno));
            return -1;
        }

        struct sockaddr_ctl ctl;
        memset(&ctl, 0, sizeof(ctl));
        ctl.sc_len = sizeof(ctl);
        ctl.sc_family = AF_SYSTEM;
        ctl.ss_sysaddr = AF_SYS_CONTROL;
        ctl.sc_id = info.ctl_id;
        ctl.sc_unit = 0;
        if (connect(this->tunFd, (struct sockaddr *)&ctl, sizeof(ctl)) == -1) {
            spdlog::critical("connect to control failed: {}", strerror(errno));
            return -1;
        }

        char ifname[IFNAMSIZ];
        socklen_t ifname_len = sizeof(ifname);
        if (getsockopt(this->tunFd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) == -1) {
            spdlog::critical("get interface name failed: {}", strerror(errno));
            return -1;
        }

        spdlog::info("created utun interface: {}", ifname);

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

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
        addr->sin_addr.s_addr = Candy::Address::hostToNet(this->ip);
        if (ioctl(sockfd, SIOCSIFADDR, (caddr_t)&ifr) == -1) {
            spdlog::critical("set ip address failed: ip {:08x}", this->ip);
            close(sockfd);
            exit(1);
        }

        // 设置掩码
        addr->sin_addr.s_addr = Candy::Address::hostToNet(this->mask);
        if (ioctl(sockfd, SIOCSIFNETMASK, (caddr_t)&ifr) == -1) {
            spdlog::critical("set mask failed: mask {:08x}", this->mask);
            close(sockfd);
            return -1;
        }

        // 设置 MTU
        ifr.ifr_mtu = this->mtu;
        if (ioctl(sockfd, SIOCSIFMTU, (caddr_t)&ifr) == -1) {
            spdlog::critical("set mtu failed: mtu {}", this->mtu);
            close(sockfd);
            exit(1);
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
        close(sockfd);

        // 设置路由
        struct {
            struct rt_msghdr msghdr;
            struct sockaddr_in addr[3];
        } msg;

        memset(&msg, 0, sizeof(msg));
        msg.msghdr.rtm_msglen = sizeof(msg);
        msg.msghdr.rtm_version = RTM_VERSION;
        msg.msghdr.rtm_type = RTM_ADD;
        msg.msghdr.rtm_index = if_nametoindex(ifname);
        msg.msghdr.rtm_pid = 0;
        msg.msghdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
        msg.msghdr.rtm_seq = 1;
        msg.msghdr.rtm_errno = 0;
        msg.msghdr.rtm_flags = RTF_UP | RTA_GATEWAY;
        for (int idx = 0; idx < (int)(sizeof(msg.addr) / sizeof(msg.addr[0])); ++idx) {
            msg.addr[idx].sin_len = sizeof(msg.addr[0]);
            msg.addr[idx].sin_family = AF_INET;
        }
        msg.addr[0].sin_addr.s_addr = Candy::Address::hostToNet(this->ip & this->mask);
        msg.addr[1].sin_addr.s_addr = Candy::Address::hostToNet(this->ip);
        msg.addr[2].sin_addr.s_addr = Candy::Address::hostToNet(this->mask);

        int routefd = socket(AF_ROUTE, SOCK_RAW, 0);
        if (routefd < 0) {
            spdlog::critical("create route fd failed: {}", strerror(routefd));
            return -1;
        }
        if (::write(routefd, &msg, sizeof(msg)) == -1) {
            spdlog::critical("add route failed: {}", strerror(errno));
            close(routefd);
            return -1;
        }
        close(routefd);
        return 0;
    }

    int down() {
        close(this->tunFd);
        return 0;
    }

    int read(std::string &buffer) {
        struct timeval timeout = {.tv_sec = this->timeout};
        fd_set set;

        FD_ZERO(&set);
        FD_SET(this->tunFd, &set);

        int ret = select(this->tunFd + 1, &set, NULL, NULL, &timeout);
        if (ret < 0) {
            spdlog::error("select failed: error {}", ret);
            return -1;
        }
        if (ret == 0) {
            return 0;
        }

        buffer.resize(this->mtu);
        struct iovec iov[2];
        iov[0].iov_base = &this->packetinfo;
        iov[0].iov_len = sizeof(this->packetinfo);
        iov[1].iov_base = buffer.data();
        iov[1].iov_len = buffer.size();

        int n = ::readv(this->tunFd, iov, sizeof(iov) / sizeof(iov[0]));
        if (n <= 0) {
            spdlog::warn("tun read failed: error {}", n);
            return -1;
        }

        buffer.resize(n - sizeof(this->packetinfo));
        return n;
    }

    int write(const std::string &buffer) {
        struct iovec iov[2];
        iov[0].iov_base = &this->packetinfo;
        iov[0].iov_len = sizeof(this->packetinfo);
        iov[1].iov_base = (void *)buffer.data();
        iov[1].iov_len = buffer.size();
        return ::writev(this->tunFd, iov, sizeof(iov) / sizeof(iov[0])) - sizeof(sizeof(this->packetinfo));
    }

private:
    std::string name;
    uint32_t ip;
    uint32_t mask;
    int mtu;
    int timeout;
    int tunFd;

    uint8_t packetinfo[4] = {0x00, 0x00, 0x00, 0x02};
};
} // namespace

namespace Candy {

Tun::Tun() {
    this->impl = std::make_shared<DarwinTun>();
}

Tun::~Tun() {
    this->impl.reset();
}

int Tun::setName(const std::string &name) {
    std::shared_ptr<DarwinTun> tun;

    tun = std::any_cast<std::shared_ptr<DarwinTun>>(this->impl);
    tun->setName(name);
    return 0;
}

int Tun::setAddress(const std::string &cidr) {
    std::shared_ptr<DarwinTun> tun;
    Address address;

    if (address.cidrUpdate(cidr)) {
        return -1;
    }
    spdlog::info("client tun address: {}", address.getCidr());
    tun = std::any_cast<std::shared_ptr<DarwinTun>>(this->impl);
    if (tun->setIP(address.getIp())) {
        return -1;
    }
    if (tun->setMask(address.getMask())) {
        return -1;
    }
    return 0;
}

uint32_t Tun::getIP() {
    std::shared_ptr<DarwinTun> tun;
    tun = std::any_cast<std::shared_ptr<DarwinTun>>(this->impl);
    return tun->getIP();
}

int Tun::setMTU(int mtu) {
    std::shared_ptr<DarwinTun> tun;
    tun = std::any_cast<std::shared_ptr<DarwinTun>>(this->impl);
    if (tun->setMTU(mtu)) {
        return -1;
    }
    return 0;
}

int Tun::setTimeout(int timeout) {
    std::shared_ptr<DarwinTun> tun;
    tun = std::any_cast<std::shared_ptr<DarwinTun>>(this->impl);
    if (tun->setTimeout(timeout)) {
        return -1;
    }
    return 0;
}

int Tun::up() {
    std::shared_ptr<DarwinTun> tun;
    tun = std::any_cast<std::shared_ptr<DarwinTun>>(this->impl);
    return tun->up();
}

int Tun::down() {
    std::shared_ptr<DarwinTun> tun;
    tun = std::any_cast<std::shared_ptr<DarwinTun>>(this->impl);
    return tun->down();
}

int Tun::read(std::string &buffer) {
    std::shared_ptr<DarwinTun> tun;
    tun = std::any_cast<std::shared_ptr<DarwinTun>>(this->impl);
    return tun->read(buffer);
}

int Tun::write(const std::string &buffer) {
    std::shared_ptr<DarwinTun> tun;
    tun = std::any_cast<std::shared_ptr<DarwinTun>>(this->impl);
    return tun->write(buffer);
}

} // namespace Candy

#endif

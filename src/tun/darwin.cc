// SPDX-License-Identifier: MIT
#if defined(__APPLE__) || defined(__MACH__)

// TODO: 实现 DarwinTun
#include "tun/tun.h"
#include "utility/address.h"
#include <memory>
#include <spdlog/spdlog.h>
#include <string>

namespace {
class DarwinTun {
public:
    int setName(const std::string &name) {
        this->name = name;
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
        // TODO: 创建设备
        // TODO: 设置设备名
        // TODO: 设置地址
        // TODO: 设置掩码
        // TODO: 设置 MTU
        // TODO: 启动网卡
        // TODO: 设置路由
        return 0;
    }

    int down() {
        // TODO: 关闭设备,同时要清除路由信息
        return 0;
    }

    int read(std::string &buffer) {
        // TODO: 从 TUN 设备读数据,写入 buffer,返回写入的大小,返回 0 表示超时,超时时间为 1 秒
        return 0;
    }

    int write(const std::string &buffer) {
        // TODO: buffer 中的数据写入 TUN 设备
        return 0;
    }

private:
    std::string name;
    uint32_t ip;
    uint32_t mask;
    int mtu;
    int timeout;
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

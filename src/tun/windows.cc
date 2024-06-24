// SPDX-License-Identifier: MIT
#if defined(_WIN32) || defined(_WIN64)

#include "tun/tun.h"
#include "utility/address.h"
#include <codecvt>
#include <memory>
#include <openssl/sha.h>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>
#include <string>
// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <guiddef.h>
#include <mstcpip.h>
#include <winternl.h>
#include <netioapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
// clang-format on
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#include <wintun.h>
#pragma GCC diagnostic pop

namespace {

WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
WINTUN_START_SESSION_FUNC *WintunStartSession;
WINTUN_END_SESSION_FUNC *WintunEndSession;
WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

class Holder {
public:
    static bool Ok() {
        static Holder instance;
        return instance.wintun;
    }

private:
    Holder() {
        this->wintun = LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!this->wintun) {
            spdlog::critical("load wintun.dll failed");
            return;
        }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(this->wintun, #Name)) == NULL)
        if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
            X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
            X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
            X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
#pragma GCC diagnostic pop
        {
            spdlog::critical("get function from wintun.dll failed");
            FreeLibrary(this->wintun);
            this->wintun = NULL;
            return;
        }
    }

    ~Holder() {
        if (this->wintun) {
            WintunDeleteDriver();
            FreeLibrary(this->wintun);
            this->wintun = NULL;
        }
    }

    HMODULE wintun = NULL;
};

class WindowsTun {
public:
    int setName(const std::string &name) {
        this->name = name.empty() ? "candy" : name;
        return 0;
    }

    int setIP(uint32_t ip) {
        this->ip = ip;
        return 0;
    }

    int getIP() {
        return this->ip;
    }

    int setPrefix(uint32_t prefix) {
        this->prefix = prefix;
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
        if (!Holder::Ok()) {
            spdlog::critical("init wintun failed");
            return -1;
        }

        GUID Guid;
        std::string data = "CandyGuid" + this->name;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char *)data.c_str(), data.size(), hash);
        memcpy(&Guid, hash, sizeof(Guid));
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        this->adapter = WintunCreateAdapter(converter.from_bytes(this->name).c_str(), L"Candy", &Guid);
        if (!this->adapter) {
            spdlog::critical("create wintun adapter failed: {}", GetLastError());
            return -1;
        }
        int Error;
        MIB_UNICASTIPADDRESS_ROW AddressRow;
        InitializeUnicastIpAddressEntry(&AddressRow);
        WintunGetAdapterLUID(this->adapter, &AddressRow.InterfaceLuid);
        AddressRow.Address.Ipv4.sin_family = AF_INET;
        AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = Candy::Address::hostToNet(this->ip);
        AddressRow.OnLinkPrefixLength = this->prefix;
        AddressRow.DadState = IpDadStatePreferred;
        Error = CreateUnicastIpAddressEntry(&AddressRow);
        if (Error != ERROR_SUCCESS) {
            spdlog::critical("create unicast ip address entry failed: {}", Error);
            return -1;
        }

        MIB_IPINTERFACE_ROW Interface = {0};
        Interface.Family = AF_INET;
        Interface.InterfaceLuid = AddressRow.InterfaceLuid;
        Error = GetIpInterfaceEntry(&Interface);
        if (Error != NO_ERROR) {
            spdlog::critical("get ip interface entry failed: {}", Error);
            return -1;
        }
        Interface.SitePrefixLength = 0;
        Interface.NlMtu = this->mtu;
        Error = SetIpInterfaceEntry(&Interface);
        if (Error != NO_ERROR) {
            spdlog::critical("set ip interface entry failed: {}", Error);
            return -1;
        }

        this->session = WintunStartSession(this->adapter, WINTUN_MIN_RING_CAPACITY);
        if (!this->session) {
            spdlog::critical("start wintun session failed: {}", GetLastError());
            return -1;
        }
        return 0;
    }

    int down() {
        if (this->session) {
            WintunEndSession(this->session);
            this->session = NULL;
        }
        if (this->adapter) {
            WintunCloseAdapter(this->adapter);
            this->adapter = NULL;
        }
        return 0;
    }

    int read(std::string &buffer) {
        DWORD size;
        BYTE *packet = WintunReceivePacket(this->session, &size);
        if (packet) {
            buffer.assign((char *)packet, size);
            WintunReleaseReceivePacket(this->session, packet);
            return size;
        }
        if (GetLastError() == ERROR_NO_MORE_ITEMS) {
            WaitForSingleObject(WintunGetReadWaitEvent(this->session), this->timeout * 1000);
            return 0;
        }
        spdlog::error("wintun read failed: {}", GetLastError());
        return -1;
    }

    int write(const std::string &buffer) {
        BYTE *packet = WintunAllocateSendPacket(this->session, buffer.size());
        if (packet) {
            memcpy(packet, buffer.c_str(), buffer.size());
            WintunSendPacket(this->session, packet);
            return buffer.size();
        }
        if (GetLastError() == ERROR_BUFFER_OVERFLOW) {
            return 0;
        }
        spdlog::error("wintun write failed: {}", GetLastError());
        return -1;
    }

private:
    std::string name;
    uint32_t ip;
    uint32_t prefix;
    int mtu;
    int timeout;

    WINTUN_ADAPTER_HANDLE adapter = NULL;
    WINTUN_SESSION_HANDLE session = NULL;
};
} // namespace

namespace Candy {

Tun::Tun() {
    this->impl = std::make_shared<WindowsTun>();
}

Tun::~Tun() {
    this->impl.reset();
}

int Tun::setName(const std::string &name) {
    std::shared_ptr<WindowsTun> tun;

    tun = std::any_cast<std::shared_ptr<WindowsTun>>(this->impl);
    tun->setName(name);
    return 0;
}

int Tun::setAddress(const std::string &cidr) {
    std::shared_ptr<WindowsTun> tun;
    Address address;

    if (address.cidrUpdate(cidr)) {
        return -1;
    }
    spdlog::info("client address: {}", address.getCidr());
    tun = std::any_cast<std::shared_ptr<WindowsTun>>(this->impl);
    if (tun->setIP(address.getIp())) {
        return -1;
    }
    if (tun->setPrefix(address.getPrefix())) {
        return -1;
    }
    return 0;
}

uint32_t Tun::getIP() {
    std::shared_ptr<WindowsTun> tun;
    tun = std::any_cast<std::shared_ptr<WindowsTun>>(this->impl);
    return tun->getIP();
}

int Tun::setMTU(int mtu) {
    std::shared_ptr<WindowsTun> tun;
    tun = std::any_cast<std::shared_ptr<WindowsTun>>(this->impl);
    if (tun->setMTU(mtu)) {
        return -1;
    }
    return 0;
}

int Tun::setTimeout(int timeout) {
    std::shared_ptr<WindowsTun> tun;
    tun = std::any_cast<std::shared_ptr<WindowsTun>>(this->impl);
    if (tun->setTimeout(timeout)) {
        return -1;
    }
    return 0;
}

int Tun::up() {
    std::shared_ptr<WindowsTun> tun;
    tun = std::any_cast<std::shared_ptr<WindowsTun>>(this->impl);
    return tun->up();
}

int Tun::down() {
    std::shared_ptr<WindowsTun> tun;
    tun = std::any_cast<std::shared_ptr<WindowsTun>>(this->impl);
    return tun->down();
}

int Tun::read(std::string &buffer) {
    std::shared_ptr<WindowsTun> tun;
    tun = std::any_cast<std::shared_ptr<WindowsTun>>(this->impl);
    return tun->read(buffer);
}

int Tun::write(const std::string &buffer) {
    std::shared_ptr<WindowsTun> tun;
    tun = std::any_cast<std::shared_ptr<WindowsTun>>(this->impl);
    return tun->write(buffer);
}

void Tun::setSysRtTable(uint32_t dst, uint32_t mask, uint32_t nexthop) {
    // TODO(windows): 设置系统路由表
    std::string dstStr = Address::ipToStr(dst);
    std::string maskStr = Address::ipToStr(mask);
    std::string nextStr = Address::ipToStr(nexthop);
    spdlog::info("system route: dst={} mask={} next={}", dstStr, maskStr, nextStr);
}

} // namespace Candy

#endif

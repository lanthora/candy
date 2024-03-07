# Candy

另一个支持对等连接的虚拟专用网络工具.

## 如何安装

这个项目编译出的命令行版本可执行文件根据参数区分以服务端模式运行还是客户端模式运行,因此安装不区分客户端与服务端.

### Linux

#### Docker

建议使用 Docker 镜像,已上传到 [Docker Hub](https://hub.docker.com/r/lanthora/candy) 和 [Github Packages](https://github.com/lanthora/candy/pkgs/container/candy).

Candy 会缓存上次从服务端分配到的地址,并在下次启动时优先申请使用这个地址,地址保存在 `/var/lib/candy` 目录下,启动容器服务前需要在 Host 创建一个目录用于映射,否则容器重启丢失数据将导致重新分配地址.创建与容器内相同的目录以方便理解.

```bash
mkdir -p /var/lib/candy
```

容器需要管理员权限读取设备创建虚拟网卡并设置路由,同时需要 Host 网络命名空间共享虚拟网卡.

```bash
docker run --rm --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy docker.io/lanthora/candy:latest
```

#### Arch Linux

使用 [AUR](https://aur.archlinux.org/packages/candy) 或者 [Arch Linux CN Community Repository](https://github.com/archlinuxcn/repo/tree/master/archlinuxcn/candy).

#### Gentoo

使用 [guru overlay](https://github.com/gentoo/guru/tree/master/net-vpn/candy)：

```bash
# 需要安装 eselect-repository
sudo eselect repository enable guru
sudo emerge --sync guru && sudo emerge -av candy
```

#### openSUSE 

使用 [OBS](https://software.opensuse.org/package/candy)：

```bash
pushd /etc/zypp/repos.d/
# 根据系统版本修改下载地址,以 Leap15.5 为例
sudo wget https://download.opensuse.org/repositories/home:/lanthora:/candy/15.5/home:lanthora:candy.repo
# 更新仓库缓存时选择信任签名
sudo zypper refresh && sudo zypper in candy
```

### MacOS

请参考 [Homebrew](https://github.com/lanthora/homebrew-repo) 仓库中提供的方法安装.

Mac 默认的睡眠策略是: 1.在关闭屏幕一段时间后睡眠; 2.睡眠时收到网络包唤醒. Candy 运行过程中每 30 秒产生一个心跳,这会导致机器被频繁唤醒.对于作为服务器长期开机的 Mac 设备来说,可以关闭睡眠功能;对于作为普通设备的笔记本来说,可以关闭网络唤醒功能.参考苹果官网[睡眠与唤醒](https://support.apple.com/zh-cn/guide/mac-help/mchle41a6ccd/mac)完成设置.

### Windows

通过 Web 服务提供[安装包下载](https://dl.icandy.one/).

对于无人值守的设备: 1.请确认系统不会休眠; 2.进程启动需要管理员权限设置虚拟网卡,请确认进程不会因为用户账户控制无法正常开机启动.

### 从源码构建

可以参考 [Github Actions](.github/workflows/check.yaml) 和 [Dockerfile](dockerfile) 了解各系统构建时所需的环境.

## 如何使用

### 接入测试网络

上述客户端的[默认配置](candy.conf)会连到测试网络 172.16.0.0/16, 并被随机分配一个地址.

网络中部署了两个用于测试的客户端. 172.16.0.1 的 80 端口部署了 Web 服务. 172.16.0.2 的 1080 端口部署了的 socks5 服务.

接入网络后,除非你主动访问其他客户端,否则什么都不会发生.

### 部署私有网络

私有部署需要了解可配置的参数,下文有两个配置示例分别说明服务端和客户端的可用参数.

```bash
candy --help
```

参数可以由命令行指定.也可以通过配置文件指定.使用配置文件时需要指定路径.推荐使用配置文件,可以在不重建容器的情况下修改配置.

```bash
# 进程启动时指定配置文件路径
candy -c /path/to/candy.conf
```

#### 服务端

监听所有网卡的 80 端口,客户端连接后自动在 10.0.0.0/24 子网分配地址,并设置登录口令为 123456

```bash
candy -m "server" -w "ws://0.0.0.0:80" -d "10.0.0.0/24" -p "123456"
```

对应的配置文件内容为

```bash
mode = "server"
# 服务端不支持 wss, 需要由外部的服务加密,例如 nginx/caddy, 公网服务建议使用 wss
websocket = "ws://0.0.0.0:80"
# 不配置此项时,客户端需要指定静态地址
dhcp = "10.0.0.0/24"
# 不配置此项时,口令为空
password = "123456"
```

#### 客户端

```bash
candy -m "client" -w "ws://127.0.0.1:80" -p "123456"
# 启用对等连接
candy -m "client" -w "ws://127.0.0.1:80" -p "123456" -s "stun://stun.qq.com"
# 指定静态地址
candy -m "client" -w "ws://127.0.0.1:80" -p "123456" -t "10.0.0.1/24"
# 设置网卡名
candy -m "client" -w "ws://127.0.0.1:80" -p "123456" -n "test"
```

对应的配置文件内容为

```bash
mode = "client"
# 客户端支持 wss 协议
websocket = "ws://127.0.0.1:80"
# 服务端配置 dhcp 时,客户端可以不配置静态地址
tun = "10.0.0.1/24"
# 需要与服务端配置保持一致
password = "123456"
# 网卡名,区分单个机器上的多个客户端,仅一个客户端时可不配置
name = "test"
# 对等连接服务器,不配置此项标识不启用对等连接
stun = "stun://stun.qq.com"
```

关于路由的配置

```bash
# 路由功能在对等连接的基础上工作,对等连接是被动启动,
# 有些设备本可以作为中继,但由于此前没有与中继设备的流量导致无法使用路由.
# 此配置以秒为单位周期性的尝试让网络中的其他设备与本设备建立对等连接.
# 不添加此配置或者配置为 0 表示不启用主动发现.
discovery = 300

# 当消息通过本机作为中继转发时在本机内部消耗的代价.
# 此配置以毫秒为单位与直连设备间的真实时延求和作为以本机为路由的代价广播.
# 不配置或者配置配置为 0 表示不启用路由加速.
route = 5
```

关于局域网内建立 P2P 的配置

```bash
# 向对方发送的用于建立对等连接的本机局域网 IP 地址,
# 不配置此项使用默认路由网卡对应的地址.
localhost = "127.0.0.1"
```

## 未来的发展方向

除了正常的安全更新和问题修复,短期内不计划新增功能,希望这个软件可以像空气一样,让用户意识不到它的存在.

## 相似产品

- [WireGuard](https://www.wireguard.com/): fast, modern, secure VPN tunnel
- [n2n](https://github.com/ntop/n2n): Peer-to-peer VPN
- [ZeroTier](https://www.zerotier.com/): Global Area Networking
- [Tailscale](https://tailscale.com/): Best VPN Service for Secure Networks
- [vnt](https://github.com/lbl8603/vnt): A virtual network tool (or VPN),简便高效的异地组网、内网穿透工具

## 联系我们

[Telegram Group](https://t.me/CandyUserGroup)

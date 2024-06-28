# Candy

一个高可用,低时延,反审查的组网工具.

## 如何安装

这个项目编译出的命令行版本可执行文件根据参数区分以服务端模式运行还是客户端模式运行,因此安装不区分客户端与服务端.

### Linux

针对 Linux 环境差异,提供多种安装方式.请选择适合自己的方式安装.

#### Docker

建议使用 Docker 镜像,已上传到 [Docker Hub](https://hub.docker.com/r/lanthora/candy) 和 [Github Packages](https://github.com/lanthora/candy/pkgs/container/candy).

容器需要管理员权限读取设备创建虚拟网卡并设置路由,同时需要 Host 网络命名空间共享虚拟网卡.

```bash
docker run --rm --privileged=true --net=host docker.io/lanthora/candy:latest --help
```

#### Arch Linux

使用 [AUR](https://aur.archlinux.org/packages/candy) 或者 [archlinuxcn](https://github.com/archlinuxcn/repo/tree/master/archlinuxcn/candy) 仓库

```bash
# AUR
paru candy
# archlinuxcn
pacman -S candy
```

#### Gentoo

使用 [GURU](https://github.com/gentoo/guru/tree/master/net-vpn/candy) 仓库

```bash
eselect repository enable guru
emerge --sync guru && emerge -av candy
```

#### openSUSE 

使用 [OBS](https://software.opensuse.org/download/package?package=candy&project=home:lanthora:candy) 仓库

```bash
# 以 Tumbleweed 为例,更新仓库缓存时选择信任签名
zypper addrepo https://download.opensuse.org/repositories/home:lanthora:candy/openSUSE_Tumbleweed/home:lanthora:candy.repo
zypper refresh && zypper install candy
```

#### Debian/Ubuntu

下载 [DEB](https://github.com/lanthora/candy/releases/latest) 安装包后通过以下命令安装

```bash
apt install --fix-broken ./xxx.deb
```

#### 单文件可执行程序

当上述所有方式都不适用时,尝试[单文件可执行程序](https://github.com/lanthora/candy/releases/latest).

该程序由[交叉编译脚本](scripts/build-standalone.sh)构建.

### macOS

请参考 [Homebrew](https://github.com/lanthora/homebrew-repo) 中提供的方法安装.

### Windows

#### 图形用户界面

以本项目作为依赖构建 [Cake](https://github.com/lanthora/cake) 提供[图形用户界面](https://github.com/lanthora/cake/releases/latest).

#### 命令行

本项目仅提供[命令行版本](https://github.com/lanthora/candy/releases/latest),用户可以在此基础上自行定制.

### 从源码构建

#### 构建本机单文件可执行程序

依赖 `C++20` 的编译器.

```bash
cmake -B build -DCANDY_STATIC=1
cmake --build build
cmake --install build
```

#### 交叉编译 Linux 单文件可执行程序

根据实际情况设置以下环境变量,查看[受支持的系统和架构](scripts/standalone.json).

```bash
# 下载和编译所用目录的绝对路径
export CANDY_WORKSPACE=$HOME/workspace
# 操作系统
export CANDY_OS=linux
# 目标文件的架构
export CANDY_ARCH=x86_64
```

执行构建脚本.构建时将下载编译工具链及依赖库,请确保网络通畅.

```bash
scripts/build-standalone.sh
```

生成的二进制文件为 `$CANDY_WORKSPACE/output/$CANDY_OS-$CANDY_ARCH/candy`.

## 如何使用

### 接入测试网络

客户端的[默认配置](candy.cfg)会连到测试网络并被随机分配一个地址.

客户端会缓存服务端分配的地址,并在下次启动时优先申请使用这个地址,地址保存在 `/var/lib/candy` 目录下,启动容器服务前需要在 Host 创建一个目录用于映射,否则容器重启丢失数据将导致重新分配地址.

创建与容器内相同的目录以方便理解.

```bash
mkdir -p /var/lib/candy
```

以容器的方式接入测试网络

```bash
docker run --rm --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy docker.io/lanthora/candy:latest
```

当成功部署两个及以上客户端后,客户端之间可以相互访问.得益于路由功能,网络中的客户端数量越多,访问时延越低.

### 部署私有网络

参数可以由命令行指定

```bash
# 查看可用的命令行参数
candy --help
```

也可以通过配置文件指定.使用配置文件时需要指定路径.推荐使用配置文件,可以在不重建容器的情况下修改配置.

```bash
# 指定配置文件路径
candy -c /path/to/candy.cfg
```

#### 服务端

监听所有网卡的 80 端口,客户端连接后自动在 10.0.0.0/24 子网分配地址,并设置登录口令为 123456

```bash
# 以服务端模式工作
mode = "server"
# 服务端不支持 wss, 需要由外部的服务加密,例如 nginx/caddy, 生产环境建议使用 wss
websocket = "ws://0.0.0.0:80"
# 不配置此项时,客户端需要指定静态地址
dhcp = "10.0.0.0/24"
# 不配置此项时,口令为空
password = "123456"
```

#### 客户端

与上述服务端匹配的客户端配置

```bash
# 以客户端模式工作
mode = "client"
# 示例以 ws 传输明文,客户端支持 wss 协议
websocket = "ws://127.0.0.1:80"
# 需要与服务端配置保持一致
password = "123456"

# 静态地址,服务端配置 dhcp 的情况下可以不配置此项,由服务端随机分配地址
tun = "10.0.0.1/24"
# 网卡名,区分单个机器上的多个客户端,同一台主机的网卡名不能冲突,不配置此项表示使用默认网卡名 candy
name = "test"
# STUN 服务器,用于获取建立对等连接所需的公网信息,不配置此项表示不启用对等连接
stun = "stun://stun.canets.org"
# 指定对等连接监听的本地 UDP 端口,不配置此项表示由操作系统随机分配
port = 0
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

关于局域网内建立对等的配置

```bash
# 用于建立对等连接的本机局域网 IP 地址,不配置此项时将尝试自动获取.
# 有多个物理网卡时建议手动配置.
localhost = "127.0.0.1"
```

## 未来规划

目前已经达成了最初的目标: __让装了客户端的设备之间可以通过虚拟 IP 相互访问__.对于 C++ 版本,将尽可能维持稳定,不添加新功能.

## 相关项目

- [Cucurbita](https://hub.docker.com/r/lanthora/cucurbita): Candy Server with Web Control Interface
- [EasyTier](https://github.com/EasyTier/EasyTier): A simple, decentralized mesh VPN with WireGuard support

## 交流群

- TG: [Click to Join](https://t.me/CandyUserGroup)
- QQ: 768305206

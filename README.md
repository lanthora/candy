# Candy

<p>
<a href="https://github.com/lanthora/candy/releases/latest"><img src="https://img.shields.io/github/release/lanthora/candy" /></a>
<a href="https://github.com/lanthora/candy/actions/workflows/release.yaml"><img src="https://img.shields.io/github/actions/workflow/status/lanthora/candy/release.yaml" /></a>
<a href="https://github.com/lanthora/candy/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/lanthora/candy" /></a>
<a href="https://github.com/lanthora/candy/issues"><img src="https://img.shields.io/github/issues-raw/lanthora/candy" /></a>
<a href="https://github.com/lanthora/candy/pulls"><img src="https://img.shields.io/github/issues-pr-raw/lanthora/candy" /></a>
</p>

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

详细用法请参考[配置文件](candy.cfg)和[文档](https://docs.canets.org).

### 接入测试网络

使用默认配置启动即可接入测试网络.客户端会缓存服务端分配的地址,并在下次启动时优先申请使用这个地址,地址保存在 `/var/lib/candy` 目录下,启动容器服务前需要在 Host 创建一个目录用于映射,否则容器重启丢失数据将导致重新分配地址.

创建与容器内相同的目录以方便理解.

```bash
mkdir -p /var/lib/candy
```

以容器的方式接入测试网络

```bash
docker run --detach --restart=always --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy docker.io/lanthora/candy:latest
```

以 Linux 发行版 [Service](candy.service) 的方式接入测试网络

```bash
systemctl enable --now candy
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

#### 服务端基本配置

监听所有网卡的 80 端口,客户端连接后自动在 10.0.0.0/24 子网分配地址,并设置登录口令为 123456

```ini
# 以服务端模式工作
mode = "server"
# 服务端不支持 wss, 需要由外部的服务加密,例如 nginx/caddy, 生产环境建议使用 wss
websocket = "ws://0.0.0.0:80"
# 不配置此项时,客户端需要指定静态地址
dhcp = "10.0.0.0/24"
# 不配置此项时,口令为空
password = "123456"
```

#### 客户端基本配置

与上述服务端匹配的客户端配置

```ini
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
```

## 相关项目

- [Cake](https://github.com/lanthora/cake): Candy GUI desktop application implemented by Qt
- [EasyTier](https://github.com/EasyTier/EasyTier): A simple, decentralized mesh VPN with WireGuard support
- [Vnt](https://github.com/vnt-dev/vnt): A virtual network tool (VPN)

## 交流群

- TG: [Click to Join](https://t.me/CandyUserGroup)
- QQ: 768305206

## 赞助

如果这个产品对您有帮助,请考虑赞助.您的支持将帮助这个项目更好地发展,持续改进和提供更多有价值的功能.感谢您的支持.

<p>
<img src=docs/images/alipay.png width="128px" />
<img src=docs/images/wechat.png width="128px" />
</p>

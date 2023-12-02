# Candy

- 简介
- [协议规范](specification.md)
- [服务端转发原理](forward.md)
- [对等连接](peer-to-peer.md)

## 组网工具而非代理工具

Candy 是组网工具 VPN, 而非代理工具 Proxy.

虚拟专用网络是一种利用公共网络(如互联网)构建专用网络的技术.允许远程用户通过加密隧道连接到企业或组织的内部网络,并访问内部资源和服务.

代理是一种常见的网络安全工具.其作用是在用户和目标服务器之间建立一个中介服务,从而隐藏用户的真实IP地址和位置信息,增强网络访问的私密性和安全性.

## 为什么要再开发一款 VPN

典型的 VPN 有 OpenVPN 和 IPSec, 以及最近几年出现的 WireGuard. 它们能满足用户的绝大多数场景.我曾是 WireGuard 用户,但在国内众所周知的网络环境下,它们的设计存在明显的"缺陷",即明显的协议特征.这原本不是 VPN 需要考虑的问题,但当流量通过防火墙时,存在被丢包的风险.我就是在 WireGuard 被丢包后才决定实现一款不容易被防火墙探测的 VPN.

## 如何安装

### Linux

建议 Linux 用户使用 Docker 镜像,镜像已上传到 [Docker Hub](https://hub.docker.com/r/lanthora/candy) 和 [Github Packages](https://github.com/lanthora/candy/pkgs/container/candy).

Candy 会缓存上次从服务端分配到的地址,并在下次启动时优先申请使用这个地址,地址保存在 `/var/lib/candy` 目录下,启动容器服务前需要在 Host 创建一个目录用于映射,否则容器重启丢失数据将导致重新分配地址.方便理解创建与容器内相同的目录.

```bash
mkdir -p /var/lib/candy
```

容器需要管理员权限读取设备创建虚拟网卡并设置路由,同时需要 Host 网络命名空间共享虚拟网卡.

```bash
docker run --rm --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy docker.io/lanthora/candy:latest
```

如果你是 Arch Linux 用户,并且不喜欢容器化部署,可以使用 [AUR](https://aur.archlinux.org/packages/candy).

### MacOS

请参考 [Homebrew](https://github.com/lanthora/homebrew-repo) 仓库中提供的方法安装.

### Windows

目前已经编译出可直接运行的二进制,由于没有找到可靠的打包和服务管理方式还没有达到发布统一部署方式的完成度. Windows 版本不接受命令行参数,启动时直接读取安装目录的配置文件.

### 从源码构建

代码托管在 [Github](https://github.com/lanthora/candy).你可以从源码构建.

## 如何使用

这是能够启动 Linux 和 Mac 客户端的最简单命令.此时会连接到公开的测试服务器环境.虚拟网络的地址范围是 172.16.0.0/16, 请确保网络没有冲突.

```bash
candy -m client -w wss://zone.icandy.one/demo
```

如果要使用客户端之间的对等连接.可以配置 [STUN](https://en.wikipedia.org/wiki/STUN) 服务器.这也是容器启动的默认命令.

```bash
candy -m client -w wss://zone.icandy.one/demo -s stun://stun.qq.com
```

更多使用使用细节参考

```bash
candy --help
```

# 联系我们

[Telegram Group](https://t.me/CandyUserGroup)

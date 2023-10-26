# Candy

- 简介
- [协议规范](specification.md)
- [服务端转发原理](forward.md)
- [对等连接](peer-to-peer.md)

## 组网工具而非代理工具

Candy 是一款易部署并支持对等连接的组网工具,而非代理工具.

VPN 是"虚拟专用网络"的缩写,是一种利用公共网络(如互联网)构建专用网络的技术. VPN 允许远程用户通过加密隧道连接到企业或组织的内部网络,并访问内部资源和服务.

代理是一种常见的网络安全工具.其作用是在用户和目标服务器之间建立一个中介服务,从而隐藏用户的真实IP地址和位置信息,增强网络访问的私密性和安全性.

## 为什么要再开发一款 VPN

典型的 VPN 有 OpenVPN 和 IPSec, 以及最近几年出现的 WireGuard. 它们能满足用户的绝大多数场景.我曾是 WireGuard 用户,但在国内众所周知的网络环境下,它们的设计存在明显的"缺陷",即明显的协议特征.这原本不是 VPN 需要考虑的问题,但当流量通过防火墙时,存在被丢包的风险.我就是在 WireGuard 被丢包后才决定实现一款不容易被防火墙探测的 VPN.

## 如何安装

### Docker

镜像已上传到 [Docker Hub](https://hub.docker.com/r/lanthora/candy) 和 [Github Packages](https://github.com/lanthora/candy/pkgs/container/candy), 我们建议 Linux 用户使用 Docker 镜像.

### AUR

如果你是 Arch Linux 用户,并且不喜欢容器化部署,推荐使用 [AUR](https://aur.archlinux.org/packages/candy).

### Homebrew

如果你是 Mac 用户,可以使用 Homebrew 安装.

```bash
# 添加第三方用户仓库
brew tap lanthora/repo
# 安装
brew install candy
```

### 从源码构建

你也可以从源码构建,代码托管在 [Github](https://github.com/lanthora/candy).

## 如何使用

能够启动客户端的最简单命令.此时会连接到我们公开的测试服务器环境.虚拟网络的地址范围是 172.16.0.0/16, 你的客户端会被随机分配一个地址,请确保没有地址冲突.

```bash
candy -m client -w wss://zone.icandy.one/demo
```

如果要使用客户端之间的对等连接.可以配置 [STUN](https://en.wikipedia.org/wiki/STUN) 服务器.这也是 Docker 容器启动的默认命令.

```bash
candy -m client -w wss://zone.icandy.one/demo -s stun://stun.qq.com
```

更多使用使用细节参考

```bash
candy --help
```

或者加入 [Telegram Group](https://t.me/CandyUserGroup) 直接反馈.

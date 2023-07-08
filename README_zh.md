# Candy

[English](README.md)

一款基于 WebSocket 和 TUN 的 Linux VPN

这个项目旨在解决传统 VPN 流量被防火墙轻易识别和屏蔽的问题.

## 使用方法

请确保服务器和客户端的时间同步在 30 秒以内,否则连接会失败.服务器在连接失败时不会发送任何反馈,以避免被检测.

你只需一个命令,就可以加入我们的虚拟私人网络.

```bash
docker run --rm --privileged=true --net=host --device /dev/net/tun --volume /var/lib/candy:/var/lib/candy lanthora/candy
```

如果你想搭建自己的虚拟私人网络也很简单.具体步骤请参考帮助文档.

```bash
docker run --rm lanthora/candy --help
```

我们也欢迎你加入我们的 [Telegram Group](https://t.me/+xR4K-Asvjz0zMjU1), 和我们分享你的反馈意见.

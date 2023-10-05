# Candy

中文 | [English](README_en.md)

一款易部署,可穿透防火墙,支持对等连接的虚拟专用网络工具.

## 使用方法

一行命令即可加入我们的网络.

```bash
docker run --rm --privileged=true --net=host --device /dev/net/tun docker.io/lanthora/candy:latest
```

你可以轻松搭建自己的网络,具体方法参考帮助文档.

```bash
docker run --rm docker.io/lanthora/candy:latest --help
```

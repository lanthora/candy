# Candy

中文 | [English](README_en.md)

一款易部署并支持对等连接的虚拟专用网络工具.

## 使用方法

我们提供了一个用于测试的网络 172.16.0.0/16, 接入后自动分配地址,一行命令就可加入这个网络.更多用法请参考[文档](https://icandy.one).

```bash
docker run --rm --privileged=true --net=host docker.io/lanthora/candy:latest
```

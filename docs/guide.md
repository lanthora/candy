# 如何使用

详细用法请参考[配置文件](https://github.com/lanthora/candy/blob/master/candy.cfg).

## 接入官方网络

使用默认配置启动即可接入官方网络.客户端会缓存服务端分配的地址,并在下次启动时优先申请使用这个地址,地址保存在 `/var/lib/candy` 目录下,启动容器服务前需要在 Host 创建一个目录用于映射,否则容器重启丢失数据将导致重新分配地址.

创建与容器内相同的目录以方便理解.

```bash
mkdir -p /var/lib/candy
```

以容器的方式接入官方网络

```bash
docker run --detach --restart=always --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy docker.io/lanthora/candy:latest
```

以 Linux 发行版 [Service](candy.service) 的方式接入官方网络

```bash
systemctl enable --now candy
```

当成功部署两个及以上客户端后,客户端之间可以相互访问.得益于路由功能,网络中的客户端数量越多,访问时延越低.

## 部署私有网络

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

### 服务端基本配置

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

### 客户端基本配置

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

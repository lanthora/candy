# candy-service

Candy 客户端的另一个实现.

- **无状态**: 进程本身不持久化任何数据, 进程重启后数据丢失，需要外部维护网络配置信息
- **API 交互**: 对外提供 HTTP API 交互接口,可以远程控制和访问

## API

### 帮助

Linux

```bash
candy-service -h
```

Windows 
  
```bat
candy-service \h
```

请求响应中的 **id** 用于标识网络连接, 通过不同标识可以同时加入多个网络, 这个标识用于查看状态和关闭网络.

### Run

启动参数的含义与[配置文件](../candy.cfg)相同,此外还有两个额外的配置项.

- vmac: 用于标识唯一设备,当同一网络中有两台不同 vmac 的设备申请相同 IP 地址时, 后者会报告 IP 冲突. 为 16 个字符的随机数字字母字符串, 需要持久化存储, 建议在首次启动进程时生成.
- expt: 期望使用的 IP 地址, 这个参数用于实现有优先分配曾经使用过的地址, 由客户端主动向服务器报告, 可以为空. 建议由服务端随机分配地址的情况下, 通过 `/api/status` 查看分配的地址并保存, 下次连接时携带这个地址.

`POST /api/run`

```json
{
  "id": "test",
  "config": {
    "mode": "client",
    "websocket": "wss://canets.org",
    "password": "",
    "name": "",
    "tun": "",
    "stun": "stun://stun.canets.org",
    "discovery": 300,
    "route": 5,
    "port": 0,
    "localhost": "",
    "mtu": 1400,
    "expt": "",
    "vmac": "16-char rand str"
  }
}
```

```json
{
    "id": "test",
    "message": "success"
}
```

### Status

`POST /api/status`

```json
{
  "id": "test"
}
```

```json
{
  "id": "test",
  "message": "sucess",
  "status": {
    "address": "192.168.202.1/24"
  }
}
```

### Shutdown

`POST /api/shutdown`

```json
{
  "id": "test"
}
```

```json
{
    "id": "test",
    "message": "success"
}
```

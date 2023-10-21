# Peer to Peer

- [简介](index.md)
- [协议规范](specification.md)
- [服务端转发基本原理](forward.md)
- 对等连接状态机

## 状态机

### INIT

当收到服务器通过 WebSocket 转发的 IPv4 报文时,检查源地址是否处于 INIT 状态.如果是,则进入 PREPARING 状态.如果点对点连接功能未启用,则切换到 FAILED 状态。忽略其他状态.

### PREPARING

固定周期检查是否有处于 PREPARING 状态的对端.如果有,则在遍历所有对端后发送 STUN 请求.当收到 STUN 响应时,将其公共网络信息发送给所有处于 PREPARING 状态的对端.如果没有对端的公网信息,则状态切换为S YNCHRONIZING, 否则切换为 CONNECTING. STUN 是 UDP,可能会丢包，因此只要有处于 PREPARING 状态的对端,它就会不断发送 STUN 请求.

### SYNCHRONIZING

该状态表示已经成功获取了本机的公网信息,但尚未收到对端的公网信息.此时发送不带 ACK 的心跳.对方可能正在发送,或版本不支持,或未启用对等连接.超时后,进入 FAILED 状态.

### CONNECTING

该状态表示自己拥有对端的公网信息,此时发送带 ACK 的心跳.收到对方发送的带有 ACK 的心跳表示连接成功,进入 CONNECTED 状态.超时未成功则进入WAITTING 状态.

### CONNECTED

TUN 接收数据时,如果对端处于 CONNECTED 状态,则直接通过UDP发送.周期性的向对端发送心跳,并检查最近是否收到对端的心跳.如果长时间没有收到对端心跳,则进入 INIT 状态.当 UDP 接收到对等方的心跳时,会重置心跳超时计数.

### WAITTING

使用指数退避算法在特定时间后重新进入 INIT 状态.重试时间间隔从 30 秒逐步增大到 1 小时.

### FAILED

FAILED 状态表示对端不支持对等连接,在此状态下的对端不采取任何主动措施.但如果收到对端的连接消息,就会被动进入 PREPARING 状态.这对应着对端从不支持对等连接的客户端切换到支持对等连接的客户端的情况.

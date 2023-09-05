# Peer to Peer

- [x] WebSocket: 收到转发包,判断源地址的状态是否为 INIT,是则进入 PREPARING 状态,其他状态忽略
- [x] Tick: 遍历所有虚拟地址到公网信息映射中的元素,如果有 PREPARING 状态的元素,在遍历结束后发送一次 STUN 请求
- [x] UDP: 收到 STUN 响应后,向所有 PREPARING 状态的对端发送自己的公网信息,如果当前不持有对端的公网信息就将状态修改为 SYNCHRONIZING,如果当前持有对端公网信息,就将状态调整为 CONNECTING
- [x] WebSocket: 收到对端发来的公网信息,更新对端信息并调整状态,如果当前状态为 SYNCHRONIZING, 调整为 CONNECTING, 否则调整为 PREPARING
- [x] Tick: CONNECTING 状态下,进行超时检测,超时后设置为 FAILED,否则发送心跳
- [x] UDP: 收到对端的心跳,检查地址,更新端口,并将状态调整为 CONNECTED
- [x] Tick: CONNECTED 状态下,进行超时检测,超时后清空对端信息,否则发送心跳
- [x] TUN: 发包时检查对端是否为 CONNECTED,是的话直接发送,否则走服务端转发
- [x] UDP: 收到 IPv4 报文后,数据发送给 TUN

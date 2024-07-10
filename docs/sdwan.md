# 多局域网组网

## 需求

在多地有多个 __地址相互不冲突__ 的局域网时,希望能够让本局域网内的设备通过其他局域网的地址直接访问对方的设备,__就像在同一个广域网中__,并且无需在所有设备上部署 Candy 客户端.

## 示例

此处假设你已经:

- 成功部署服务端
- 在网关 (Gateway) 上部署 Candy 并分配了虚拟地址

以 LAN A 为例解释表格含义.

- 局域网 (Network) 地址为 `192.168.1.0/24`, 这个地址不能与 B,C 冲突
- 网关 (Gateway) 可以是路由器,也可以是局域网中任意一台 Linux 系统,但需要能够部署 Candy 客户端,假设它在局域网中的地址是 `192.168.1.1`. 通过给局域网中的设备配置路由,确保流量能够进入网关
- Candy 客户端部署在网关上,它在虚拟网络中的地址是 `10.0.0.1`

| LAN     | A              | B              | C              |
| :------ | :------------- | :------------- | :------------- |
| Network | 192.168.1.0/24 | 192.168.2.0/24 | 192.168.3.0/24 |
| Gateway | 192.168.1.1    | 192.168.2.1    | 192.168.3.1    |
| Candy   | 10.0.0.1       | 10.0.0.2       | 10.0.0.3       |

当 `192.168.1.x` 访问 `192.168.2.x` 时,希望流量可以通过以下方式送达:

```txt
192.168.1.x => 10.0.0.1 => 10.0.0.2 => 192.168.2.x
```

接下来以这条链路为例解释配置过程.其他链路配置方法相同.

### 在 Candy 服务端配置路由

服务端追加以下配置,此配置会修改网关上的系统路由.

```ini
sdwan = "10.0.0.1/32,192.168.2.0/24,10.0.0.2"
```

| Device   | Device Mask     | Dest Net    | Dest Mask     | Gateway  |
| :------- | :-------------- | :---------- | :------------ | :------- |
| 10.0.0.1 | 255.255.255.255 | 192.168.2.0 | 255.255.255.0 | 10.0.0.2 |

添加系统路由后, `10.0.0.1` 的客户端将能收到发往 `192.168.2.x` 的 IP 报文. Candy 负责将本报文转发到 `10.0.0.2`

### 流量转发到网关

如果网关是路由器,不需要任何操作,流量就应该能够进入网关.

否则需要在非网关设备上配置流量转发到网关的路由.

- 目的网络: 192.168.2.0/24
- 网关: 192.168.1.1
  
### 允许网关转发流量

如果你的网关是路由器,应该能够轻易的配置出允许转发.否则需要手动添加转发相关的配置.

开启内核流量转发功能

```bash
sysctl -w net.ipv4.ip_forward=1
```

判断流量进入网关的网口,这里假设是 `ethX`, 并假设 candy 使用的网口名是 `candy-gw`.

```bash
iptables -t nat -A POSTROUTING -o candy-gw -j MASQUERADE
iptables -A FORWARD -i ethX -o candy-gw -j ACCEPT
iptables -A FORWARD -i candy-gw -o ethX -m state --state RELATED,ESTABLISHED -j ACCEPT
```

### 测试

在 `192.168.1.x` 用 ping 命令发包, `192.168.2.x` 上抓包预期可以看到对应数据包.
如果要看到 ping 命令的回包.需要按照上述操作完成回程的配置.

## 常见问题

### 无法访问 NAT 虚拟机

在宿主机上通过虚拟机 IP 可以直接访问,但是其他机器通过宿主机的虚拟 IP 转发就不能访问.
这大概率是防火墙的问题,以 libvirt 为例,如果虚拟机使用的是 NAT 网络,那么 libvirt 会添加只允许宿主机 IP 访问的防火墙规则.

可以通过以下命令查看宿主机规则.

```bash
nft list ruleset
```

其中可以看到已经有 reject 命中.

```txt
table ip libvirt_network {
    chain guest_output {
        ip saddr 192.168.100.0/24 iif "virbr0" counter packets 3568 bytes 541261 accept
        iif "virbr0" counter packets 0 bytes 0 reject
    }

    chain guest_input {
        oif "virbr0" ip daddr 192.168.100.0/24 ct state established,related counter packets 3237 bytes 290974 accept
        oif "virbr0" counter packets 8 bytes 844 reject
    }
}
```

现在只需要解决防火墙问题,我选择的方式是添加两条优先级更高的规则,不再让 reject 命中.

```bash
nft insert rule ip libvirt_network guest_output iif "virbr0" accept
nft insert rule ip libvirt_network guest_input oif "virbr0" accept
```

再次查看规则会在开始位置多出两个 accpet, 此时不出意外网络应该能够正常访问.

```txt
table ip libvirt_network {
    chain guest_output {
        iif "virbr0" accept
        ip saddr 192.168.100.0/24 iif "virbr0" counter packets 3568 bytes 541261 accept
        iif "virbr0" counter packets 0 bytes 0 reject
    }

    chain guest_input {
        oif "virbr0" accept
        oif "virbr0" ip daddr 192.168.100.0/24 ct state established,related counter packets 3237 bytes 290974 accept
        oif "virbr0" counter packets 8 bytes 844 reject
    }
}
```

在整个过程中, [pwru](https://github.com/cilium/pwru) 在内核层面帮助确定了 netfilter 防火墙规则的存在.

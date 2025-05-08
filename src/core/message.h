// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_MESSAGE_H
#define CANDY_CORE_MESSAGE_H

#include "core/net.h"
#include <cstring>
#include <string>

namespace Candy {

/* 内部模块之间通过消息通信.消息类型在这里定义 */
enum class MsgKind {
    TIMEOUT, // 读操作超时
    PACKET,  // 模块间转发 IP 报文
    TUNADDR, // 通知 TUN 模块设置地址
    SYSRT,   // 设置系统路由
    TRYP2P,  // 尝试建立对等连接
    PUBINFO, // 模块间传递对端公网信息
};

/* 内部模块间的消息只包含类型和可选的数据,模块之间传输信息只允许移动,不允许复制 */
struct Msg {
    MsgKind kind;
    std::string data;

    // 禁用拷贝构造和拷贝赋值
    Msg(const Msg &) = delete;
    Msg &operator=(const Msg &) = delete;

    // 默认构造,移动构造和移动赋值
    Msg(MsgKind kind = MsgKind::TIMEOUT, std::string = "");
    Msg(Msg &&packet);
    Msg &operator=(Msg &&packet);
};

// 仅在程序内部使用,修改结构体不影响外部协议
namespace CoreMsg {

struct PubInfo {
    IP4 src;
    IP4 dst;
    IP4 ip;
    uint16_t port;
    bool v6 = false;    // 默认 ipv4
    bool tcp = false;   // 默认 udp
    bool local = false; // 默认公网信息
};

} // namespace CoreMsg

} // namespace Candy

#endif

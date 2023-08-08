// SPDX-License-Identifier: MIT
#ifndef CANDY_CORE_COMMON_H
#define CANDY_CORE_COMMON_H

// 各个系统需要独立实现以下函数
namespace Candy {

// 调用 Candy::shutdown() 后客户端和服务端应当正常退出.
// Linux 在主函数所在文件实现,模拟产生 SIGQUIT 信号,并在信号处理函数中调用客户端和服务端的 shutdown 函数.
void shutdown();

}; // namespace Candy

#endif

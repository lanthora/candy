// SPDX-License-Identifier: MIT
#if defined(__APPLE__) || defined(__MACH__)

#include "core/client.h"

namespace Candy {
void shutdown() {
    // TODO(macos): 补充全局退出函数,调用这个函数后,进程应该正常回收资源并退出
}
} // namespace Candy

// TODO(macos): 实现 MacOS 的主函数
int main() {
    Candy::Client client;
    client.setWebSocketServer("wss://zone.icandy.one/demo");
    client.setName("candy-demo");
    client.run();
    return 0;
}

#endif

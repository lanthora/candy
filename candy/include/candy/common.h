// SPDX-License-Identifier: MIT
#ifndef CANDY_COMMON_H
#define CANDY_COMMON_H

#include <string>

namespace candy {
static const int VMAC_SIZE = 16;

std::string version();
std::string create_vmac();
} // namespace candy

#endif

#ifndef CANDY_ARCH_CC_H
#define CANDY_ARCH_CC_H

// Include lwipopts.h here so that any change to it triggers
// recompilation of all lwIP source files via the dependency chain:
//   lwip/arch.h -> arch/cc.h -> lwipopts.h
#include "lwipopts.h"

#define LWIP_PROVIDE_ERRNO 1

#define LWIP_NO_STDDEF_H 0
#define LWIP_NO_STDINT_H 0
#define LWIP_NO_INTTYPES_H 0
#define LWIP_NO_LIMITS_H 0

#endif

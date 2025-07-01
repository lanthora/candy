#include "candy/common.h"
#include "core/version.h"
#include "utils/random.h"
#include <string>

namespace candy {

std::string version() {
    return CANDY_VERSION;
}

std::string create_vmac() {
    return randomHexString(VMAC_SIZE);
}

} // namespace candy
// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILS_HOSTNAME_H
#define CANDY_UTILS_HOSTNAME_H

#include <string>

namespace candy {

// Returns the local hostname encoded as UTF-8, or an empty string on failure.
//
// Windows reports the hostname in the ANSI code page (GBK on Chinese systems),
// so it is read as Unicode and converted to UTF-8. POSIX keeps whatever bytes
// were passed to sethostname(): valid UTF-8 is returned as is, and invalid
// bytes are replaced with U+FFFD so the server always receives valid UTF-8.
std::string hostnameUtf8();

} // namespace candy

#endif

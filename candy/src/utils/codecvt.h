// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILS_CODECVT_H
#define CANDY_UTILS_CODECVT_H

#include <string>

namespace candy {

std::string UTF16ToUTF8(const std::wstring &utf16Str);
std::wstring UTF8ToUTF16(const std::string &utf8Str);

} // namespace candy

#endif

#include <Poco/Platform.h>
#if POCO_OS == POCO_OS_WINDOWS_NT
#include "utils/codecvt.h"
#include <windows.h>

namespace candy {

std::string UTF16ToUTF8(const std::wstring &utf16Str) {
    if (utf16Str.empty())
        return "";

    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, utf16Str.c_str(), -1, nullptr, 0, nullptr, nullptr);

    if (utf8Size == 0) {
        return "";
    }

    std::string utf8Str(utf8Size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, utf16Str.c_str(), -1, &utf8Str[0], utf8Size, nullptr, nullptr);

    utf8Str.resize(utf8Size - 1);
    return utf8Str;
}

std::wstring UTF8ToUTF16(const std::string &utf8Str) {
    if (utf8Str.empty())
        return L"";

    int utf16Size = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, nullptr, 0);

    if (utf16Size == 0) {
        return L"";
    }

    std::wstring utf16Str(utf16Size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, &utf16Str[0], utf16Size);

    utf16Str.resize(utf16Size - 1);
    return utf16Str;
}

} // namespace candy

#endif

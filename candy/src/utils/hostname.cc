// SPDX-License-Identifier: MIT
#include "utils/hostname.h"
#include <Poco/Platform.h>
#include <string>

#if POCO_OS == POCO_OS_WINDOWS_NT
#include "utils/codecvt.h"
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace candy {
namespace {

// The hostname is embedded in a WebSocket PING frame, whose payload is limited
// to 125 bytes. Keep the 64 byte semantics of the previous implementation while
// leaving room for multi-byte UTF-8 characters.
constexpr size_t MAX_HOSTNAME_BYTES = 63;

// Returns the length of the valid UTF-8 sequence starting at pos, or 0 if the
// byte at pos cannot start a valid sequence.
size_t utf8SequenceLength(const std::string &text, size_t pos) {
    const size_t size = text.size() - pos;
    const auto byteAt = [&](size_t offset) { return static_cast<unsigned char>(text[pos + offset]); };
    const auto inRange = [&](size_t offset, unsigned char low, unsigned char high) {
        return offset < size && byteAt(offset) >= low && byteAt(offset) <= high;
    };

    const unsigned char first = byteAt(0);
    if (first < 0x80) {
        return 1;
    }
    if (first >= 0xC2 && first <= 0xDF) {
        return inRange(1, 0x80, 0xBF) ? 2 : 0;
    }
    if (first == 0xE0) {
        return inRange(1, 0xA0, 0xBF) && inRange(2, 0x80, 0xBF) ? 3 : 0;
    }
    if (first >= 0xE1 && first <= 0xEC) {
        return inRange(1, 0x80, 0xBF) && inRange(2, 0x80, 0xBF) ? 3 : 0;
    }
    if (first == 0xED) {
        // Excludes the UTF-16 surrogate range.
        return inRange(1, 0x80, 0x9F) && inRange(2, 0x80, 0xBF) ? 3 : 0;
    }
    if (first >= 0xEE && first <= 0xEF) {
        return inRange(1, 0x80, 0xBF) && inRange(2, 0x80, 0xBF) ? 3 : 0;
    }
    if (first == 0xF0) {
        return inRange(1, 0x90, 0xBF) && inRange(2, 0x80, 0xBF) && inRange(3, 0x80, 0xBF) ? 4 : 0;
    }
    if (first >= 0xF1 && first <= 0xF3) {
        return inRange(1, 0x80, 0xBF) && inRange(2, 0x80, 0xBF) && inRange(3, 0x80, 0xBF) ? 4 : 0;
    }
    if (first == 0xF4) {
        return inRange(1, 0x80, 0x8F) && inRange(2, 0x80, 0xBF) && inRange(3, 0x80, 0xBF) ? 4 : 0;
    }
    return 0;
}

// Truncates on a UTF-8 character boundary so the result stays valid UTF-8.
std::string truncateUtf8(const std::string &text, size_t maxBytes) {
    if (text.size() <= maxBytes) {
        return text;
    }
    size_t pos = 0;
    while (pos < text.size()) {
        size_t length = utf8SequenceLength(text, pos);
        if (length == 0 || pos + length > maxBytes) {
            break;
        }
        pos += length;
    }
    return text.substr(0, pos);
}

#if POCO_OS == POCO_OS_WINDOWS_NT

std::string readHostname() {
    // gethostname() returns the hostname in the ANSI code page on Windows, which
    // is GBK on Chinese systems. GetComputerNameExW() returns the same DNS
    // hostname as Unicode, so it can be converted to UTF-8 without loss.
    wchar_t buffer[256] = {0};
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, buffer, &size)) {
        return UTF16ToUTF8(std::wstring(buffer, size));
    }
    // GetComputerNameW() returns the NetBIOS name, which may be truncated to 15
    // characters. Only use it as a fallback because it is always available.
    size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    if (GetComputerNameW(buffer, &size)) {
        return UTF16ToUTF8(std::wstring(buffer, size));
    }
    return "";
}

#else

bool isValidUtf8(const std::string &text) {
    for (size_t pos = 0; pos < text.size();) {
        size_t length = utf8SequenceLength(text, pos);
        if (length == 0) {
            return false;
        }
        pos += length;
    }
    return true;
}

std::string replaceInvalidUtf8(const std::string &text) {
    static const std::string REPLACEMENT = "\xEF\xBF\xBD"; // U+FFFD
    std::string result;
    result.reserve(text.size());
    for (size_t pos = 0; pos < text.size();) {
        size_t length = utf8SequenceLength(text, pos);
        if (length == 0) {
            result.append(REPLACEMENT);
            pos += 1;
        } else {
            result.append(text, pos, length);
            pos += length;
        }
    }
    return result;
}

std::string normalizeUtf8(const std::string &raw) {
    if (isValidUtf8(raw)) {
        return raw;
    }
    // POSIX hostnames may use a legacy encoding such as GBK. Decoding those
    // encodings is intentionally not attempted here to avoid a charset
    // conversion dependency, so invalid bytes are replaced with U+FFFD to keep
    // the reported value valid UTF-8.
    return replaceInvalidUtf8(raw);
}

std::string readHostname() {
    char buffer[256] = {0};
    if (gethostname(buffer, sizeof(buffer)) != 0) {
        return "";
    }
    buffer[sizeof(buffer) - 1] = '\0';
    return std::string(buffer);
}

#endif

} // namespace

std::string hostnameUtf8() {
    std::string name = readHostname();
    if (name.empty()) {
        return "";
    }
#if POCO_OS != POCO_OS_WINDOWS_NT
    name = normalizeUtf8(name);
#endif
    return truncateUtf8(name, MAX_HOSTNAME_BYTES);
}

} // namespace candy

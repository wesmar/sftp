#pragma once
// ============================================================
//  Plugin version, used by sftpplug.rc (VERSIONINFO) and the code.
//  rc.exe does not join adjacent string literals, so the strings cannot
//  be built from the numbers; the check below keeps them in step.
// ============================================================

#define VER_MAJOR       10
#define VER_MINOR       3
#define VER_PATCH       1
#define VER_BUILD       0

// Comma-separated form for FILEVERSION / PRODUCTVERSION
#define VER_FILEVERSION         VER_MAJOR, VER_MINOR, VER_PATCH, VER_BUILD

// Dot-separated strings for StringFileInfo VALUE fields
#define VER_FILEVERSION_STR     "10.3.1.0"
#define VER_PRODUCTVERSION_STR  "10.3.1.0"

// Wide-string variant for C++ runtime use
#define VER_FILEVERSION_WSTR    L"10.3.1.0"

#if defined(__cplusplus) && !defined(RC_INVOKED)
#include <string_view>

namespace version_detail {

// Whether `text` reads "a.b.c.d" with exactly these four numbers.
template <class Char>
constexpr bool Spells(std::basic_string_view<Char> text, const int (&parts)[4])
{
    size_t pos = 0;
    for (int i = 0; i < 4; ++i) {
        const size_t start = pos;
        int value = 0;
        while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9')
            value = value * 10 + (text[pos++] - '0');
        if (pos == start || value != parts[i])
            return false;
        if (i < 3) {
            if (pos >= text.size() || text[pos] != '.')
                return false;
            ++pos;
        }
    }
    return pos == text.size();
}

} // namespace version_detail

static_assert(version_detail::Spells(std::string_view(VER_FILEVERSION_STR), { VER_MAJOR, VER_MINOR, VER_PATCH, VER_BUILD }) &&
              version_detail::Spells(std::string_view(VER_PRODUCTVERSION_STR), { VER_MAJOR, VER_MINOR, VER_PATCH, VER_BUILD }) &&
              version_detail::Spells(std::wstring_view(VER_FILEVERSION_WSTR), { VER_MAJOR, VER_MINOR, VER_PATCH, VER_BUILD }),
              "version strings in version.h do not match the version numbers");
#endif

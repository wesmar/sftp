#include "VanDykeIniParser.h"

#include <charconv>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace sftp {

namespace {

// Load the whole file at `path` (assumed UTF-8, possibly with BOM) into `out`.
// Returns false on any I/O error. Caller uses "empty out on failure" as the
// convention.
bool ReadFileToString(const std::string& path, std::string& out)
{
    // Path can contain non-ANSI codepoints; go through wide API.
    const int wchars = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (wchars <= 0)
        return false;
    std::wstring wpath(static_cast<size_t>(wchars - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), wchars);

    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart > (10 * 1024 * 1024)) {
        // Cap at 10 MB — VanDyke session files are ~10-30 KB in practice.
        CloseHandle(h);
        return false;
    }

    out.assign(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    const BOOL ok = ReadFile(h, out.data(), static_cast<DWORD>(size.QuadPart),
                              &read, nullptr);
    CloseHandle(h);
    if (!ok || read != size.QuadPart)
        return false;
    return true;
}

// Decode 8 hex digits into a uint32_t. Returns 0 on malformed input.
uint32_t ParseHexDWord(std::string_view s) noexcept
{
    uint32_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v, 16);
    if (ec != std::errc{})
        return 0;
    return v;
}

}  // namespace

VanDykeFile ParseVanDykeContent(std::string_view content)
{
    VanDykeFile out;

    // Strip UTF-8 BOM if present.
    if (content.size() >= 3 &&
        static_cast<unsigned char>(content[0]) == 0xEF &&
        static_cast<unsigned char>(content[1]) == 0xBB &&
        static_cast<unsigned char>(content[2]) == 0xBF)
    {
        content.remove_prefix(3);
    }

    // Iterate lines. Handles both CRLF and LF; a trailing \r on any line is
    // stripped explicitly.
    size_t pos = 0;
    while (pos <= content.size()) {
        const size_t nl = content.find('\n', pos);
        std::string_view line = (nl == std::string_view::npos)
            ? content.substr(pos)
            : content.substr(pos, nl - pos);
        pos = (nl == std::string_view::npos) ? content.size() + 1 : nl + 1;

        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (line.empty())
            continue;

        // Continuation lines (payload of a preceding B: or Z: entry) start
        // with whitespace. We do not need the payload, so skip.
        if (line.front() == ' ' || line.front() == '\t')
            continue;

        // Minimum valid line: T:"k"=  → 6 chars.
        if (line.size() < 6)
            continue;

        const char typeChar = line[0];
        VanDykeValueType type;
        switch (typeChar) {
            case 'S': type = VanDykeValueType::String; break;
            case 'D': type = VanDykeValueType::DWord;  break;
            case 'Z': type = VanDykeValueType::Zero;   break;
            case 'B': type = VanDykeValueType::Blob;   break;
            default: continue;
        }

        if (line[1] != ':' || line[2] != '"')
            continue;

        // Find closing double-quote and the '=' that must immediately follow.
        const size_t keyEnd = line.find('"', 3);
        if (keyEnd == std::string_view::npos)
            continue;
        if (keyEnd + 1 >= line.size() || line[keyEnd + 1] != '=')
            continue;

        std::string        key(line.substr(3, keyEnd - 3));
        std::string_view   valView = line.substr(keyEnd + 2);

        VanDykeEntry entry;
        entry.type = type;
        // For Z:/B: we drop the payload — only the type marker is retained.
        if (type == VanDykeValueType::String || type == VanDykeValueType::DWord)
            entry.value.assign(valView);

        out.insert_or_assign(std::move(key), std::move(entry));
    }

    return out;
}

VanDykeFile ParseVanDykeFile(const std::string& path)
{
    std::string content;
    if (!ReadFileToString(path, content))
        return {};
    return ParseVanDykeContent(content);
}

std::string GetString(const VanDykeFile& file, std::string_view key,
                      std::string_view defaultValue) noexcept
{
    const auto it = file.find(std::string(key));
    if (it == file.end() || it->second.type != VanDykeValueType::String)
        return std::string(defaultValue);
    return it->second.value;
}

uint32_t GetDWord(const VanDykeFile& file, std::string_view key,
                  uint32_t defaultValue) noexcept
{
    const auto it = file.find(std::string(key));
    if (it == file.end() || it->second.type != VanDykeValueType::DWord)
        return defaultValue;
    return ParseHexDWord(it->second.value);
}

}  // namespace sftp

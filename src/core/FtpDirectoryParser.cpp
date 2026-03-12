#include <windows.h>
#include "CoreUtils.h"
#include "FtpDirectoryParser.h"
#include <array>
#include <cwctype>
#include <string_view>
#include <vector>
#include <optional>
#include <cstdlib>
#include <cwchar>

namespace {

// Month abbreviations indexed so that ((i-1) % 12) + 1 yields the correct month number.
// Indices 1-12: English (JAN-DEC). Indices 13+: German and French alternatives placed
// at positions with the same ((i-1) % 12) + 1 result (e.g. MRZ at 27 → (26%12)+1 = 3 = March).
// Empty strings are skipped during matching.
constexpr std::wstring_view MonthNames[] = {
    L"", L"JAN", L"FEB", L"MAR", L"APR", L"MAY", L"JUN",
    L"JUL", L"AUG", L"SEP", L"OCT", L"NOV", L"DEC",
    L"", L"", L"M?R", L"", L"MAI", L"", L"", L"", L"", L"OKT", L"", L"DEZ",
    L"", L"FEV", L"MRZ", L"AVR", L"", L"JUI", L"", L"", L"", L"", L"", L""
};

constexpr std::wstring_view TrimSpaces(std::wstring_view sv) noexcept
{
    const auto start = sv.find_first_not_of(L" \t\r\n");
    if (start == std::wstring_view::npos)
        return {};
    const auto end = sv.find_last_not_of(L" \t\r\n");
    return sv.substr(start, end - start + 1);
}

constexpr bool IsDigit(wchar_t ch) noexcept
{
    return ch >= L'0' && ch <= L'9';
}

constexpr int ParseTwoDigits(std::wstring_view sv, size_t offset) noexcept
{
    if (offset + 1 >= sv.size() || !IsDigit(sv[offset]) || !IsDigit(sv[offset + 1]))
        return 0;
    return (sv[offset] - L'0') * 10 + (sv[offset + 1] - L'0');
}

constexpr int ParseFourDigits(std::wstring_view sv, size_t offset) noexcept
{
    if (offset + 3 >= sv.size())
        return 0;
    int result = 0;
    for (int i = 0; i < 4; ++i) {
        if (!IsDigit(sv[offset + i]))
            return 0;
        result = result * 10 + (sv[offset + i] - L'0');
    }
    return result;
}

std::optional<int> ParseMonth(std::wstring_view token) noexcept
{
    // Compare uppercased 3-char prefixes, locale-independently.
    // MonthNames is indexed 1-12 for English names, with additional entries beyond
    // index 12 for German/French abbreviations placed at positions where (i-1) % 12 + 1
    // yields the correct month number.
    if (token.size() > 3)
        token = token.substr(0, 3);
    std::array<wchar_t, 4> upperToken{ L'\0', L'\0', L'\0', L'\0' };
    for (size_t i = 0; i < token.size() && i < 3; ++i)
        upperToken[i] = static_cast<wchar_t>(std::towupper(token[i]));

    for (size_t i = 1; i < std::size(MonthNames); ++i) {
        if (MonthNames[i].empty())
            continue;
        std::array<wchar_t, 4> upperMonth{ L'\0', L'\0', L'\0', L'\0' };
        const auto monthToken = MonthNames[i].size() > 3 ? MonthNames[i].substr(0, 3) : MonthNames[i];
        for (size_t j = 0; j < monthToken.size() && j < 3; ++j)
            upperMonth[j] = static_cast<wchar_t>(std::towupper(monthToken[j]));
        if (upperToken == upperMonth)
            return static_cast<int>(((i - 1) % 12) + 1); // maps indices 1-12 and 13-24 to months 1-12
    }
    return std::nullopt;
}

std::optional<int> ParseIntToken(std::wstring_view token) noexcept
{
    if (token.empty())
        return std::nullopt;
    std::wstring tmp(token);
    wchar_t* endPtr = nullptr;
    const long value = std::wcstol(tmp.c_str(), &endPtr, 10);
    if (!endPtr || endPtr == tmp.c_str() || *endPtr != L'\0')
        return std::nullopt;
    return static_cast<int>(value);
}

bool ParseTimeToken(std::wstring_view token, WORD& hour, WORD& minute, WORD& second) noexcept
{
    // Accept HH:MM and HH:MM:SS.
    std::array<wchar_t, 16> tmp{};
    if (token.empty() || token.size() >= tmp.size())
        return false;
    std::wmemcpy(tmp.data(), token.data(), token.size());
    tmp[token.size()] = L'\0';

    wchar_t* p = tmp.data();
    wchar_t* firstColon = std::wcschr(p, L':');
    if (!firstColon)
        return false;
    *firstColon = L'\0';

    wchar_t* secondPart = firstColon + 1;
    wchar_t* secondColon = std::wcschr(secondPart, L':');
    wchar_t* thirdPart = nullptr;
    if (secondColon) {
        *secondColon = L'\0';
        thirdPart = secondColon + 1;
    }

    wchar_t* end = nullptr;
    const long h = std::wcstol(p, &end, 10);
    if (!end || *end != L'\0')
        return false;
    const long m = std::wcstol(secondPart, &end, 10);
    if (!end || *end != L'\0')
        return false;

    long s = 0;
    if (thirdPart && *thirdPart) {
        s = std::wcstol(thirdPart, &end, 10);
        if (!end || *end != L'\0')
            return false;
    }

    if (h < 0 || h > 23 || m < 0 || m > 59 || s < 0 || s > 59)
        return false;
    hour = static_cast<WORD>(h);
    minute = static_cast<WORD>(m);
    second = static_cast<WORD>(s);
    return true;
}

struct ParsedLine {
    std::wstring name;
    int64_t size = 0;
    FILETIME lastWriteTime{};
    bool hasLastWriteTime = false;
    DWORD attributes = 0;
    DWORD unixMode = 0;
};

// Parses one line from a Unix "ls -l" listing into a ParsedLine.
// Returns nullopt if the line is not a recognizable file/dir/link entry.
std::optional<ParsedLine> ParseUnixLine(std::wstring_view line, int flags)
{
    line = TrimSpaces(line);
    if (line.size() < 10)
        return std::nullopt;

    // First character: '-' = file, 'd' = directory, 'l' = symlink, others = special
    wchar_t typeChar = line[0];
    if (typeChar != L'-' && typeChar != L'd' && typeChar != L'l' &&
        typeChar != L'b' && typeChar != L'c' && typeChar != L'p' && typeChar != L's')
        return std::nullopt;

    std::wstring_view perms = line.substr(0, 10);

    DWORD unixMode = 0;
    // Simple permission parsing (can be extended)
    for (int i = 1; i < 10; ++i) {
        if (perms[i] != L'-')
            unixMode |= (1 << (9 - i));
    }

    DWORD attributes = 0;
    if (typeChar == L'd')
        attributes |= FILE_ATTRIBUTE_DIRECTORY;
    else if (typeChar == L'l')
        attributes |= FILE_ATTRIBUTE_REPARSE_POINT; // or use falink

    // Tokenize by spaces
    std::vector<std::wstring_view> tokens;
    size_t pos = 10; // after permissions
    while (pos < line.size()) {
        while (pos < line.size() && std::iswspace(line[pos]))
            ++pos;
        if (pos >= line.size())
            break;
        size_t start = pos;
        while (pos < line.size() && !std::iswspace(line[pos]))
            ++pos;
        tokens.push_back(line.substr(start, pos - start));
    }

    // Expected columns: perms links owner group size month day time/year name...
    // Column positions vary by server (owner/group length differs), so we locate
    // the month token by scanning rather than assuming a fixed column index.
    if (tokens.size() < 8)
        return std::nullopt;

    size_t monthIndex = std::wstring_view::npos;
    int month = 0;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (const auto m = ParseMonth(tokens[i])) {
            monthIndex = i;
            month = *m;
            break;
        }
    }
    if (monthIndex == std::wstring_view::npos || monthIndex + 3 > tokens.size())
        return std::nullopt;

    // The token immediately before the month is the file size.
    int64_t size = 0;
    if (monthIndex > 0) {
        if (const auto parsedSize = ParseIntToken(tokens[monthIndex - 1])) {
            if (*parsedSize >= 0)
                size = static_cast<int64_t>(*parsedSize);
        }
    }

    // After month: day, then time (HH:MM or HH:MM:SS) or year, then filename(s).
    const size_t nameStart = monthIndex + 3;
    if (nameStart > tokens.size())
        return std::nullopt;

    std::wstring name;
    for (size_t i = nameStart; i < tokens.size(); ++i) {
        if (!name.empty())
            name += L' ';
        name += tokens[i];
    }

    // Remove symlink arrow if present
    size_t arrow = name.find(L" -> ");
    if (arrow != std::wstring::npos)
        name.resize(arrow);

    if (name.empty())
        return std::nullopt;

    ParsedLine result;
    result.name = std::move(name);
    result.size = size;
    result.attributes = attributes;
    result.unixMode = unixMode;

    // Parse date fields: "<month> <day> <hh:mm|year>" with optional seconds.
    const auto dayOpt = ParseIntToken(tokens[monthIndex + 1]);
    if (!dayOpt || *dayOpt < 1 || *dayOpt > 31)
        return std::nullopt;

    SYSTEMTIME nowLocal{};
    GetLocalTime(&nowLocal);
    const WORD currentYear = nowLocal.wYear;

    SYSTEMTIME st{};
    st.wYear = currentYear;
    st.wMonth = static_cast<WORD>(month);
    st.wDay = static_cast<WORD>(*dayOpt);
    st.wHour = 0;
    st.wMinute = 0;
    st.wSecond = 0;

    const auto timeOrYear = tokens[monthIndex + 2];
    bool hasClockTime = false;
    WORD hh = 0, mm = 0, ss = 0;
    if (ParseTimeToken(timeOrYear, hh, mm, ss)) {
        hasClockTime = true;
        st.wYear = currentYear;
        st.wHour = hh;
        st.wMinute = mm;
        st.wSecond = ss;
    } else if (const auto yearOpt = ParseIntToken(timeOrYear)) {
        int y = *yearOpt;
        if (y >= 0 && y < 100)
            y += (y >= 70) ? 1900 : 2000;
        if (y < 1601 || y > 9999)
            return std::nullopt;
        st.wYear = static_cast<WORD>(y);
    } else {
        return std::nullopt;
    }

    if (ConvSysTimeToFileTime(&st, &result.lastWriteTime)) {
        result.hasLastWriteTime = true;

        // Typical "ls -l" format omits year for recent files; with clock time it can refer to last year.
        if (hasClockTime) {
            FILETIME nowFt{};
            GetSystemTimeAsFileTime(&nowFt);
            ULARGE_INTEGER parsedUi{};
            ULARGE_INTEGER nowUi{};
            parsedUi.LowPart = result.lastWriteTime.dwLowDateTime;
            parsedUi.HighPart = result.lastWriteTime.dwHighDateTime;
            nowUi.LowPart = nowFt.dwLowDateTime;
            nowUi.HighPart = nowFt.dwHighDateTime;

            // If timestamp is clearly in the future, treat it as previous year.
            constexpr ULONGLONG kOneDay100ns = 24ULL * 60ULL * 60ULL * 10000000ULL;
            if (parsedUi.QuadPart > nowUi.QuadPart + kOneDay100ns && st.wYear > 1601) {
                st.wYear = static_cast<WORD>(st.wYear - 1);
                ConvSysTimeToFileTime(&st, &result.lastWriteTime);
            }
        }
    }

    return result;
}

} // anonymous namespace

bool ReadDirLineUNIX(LPWSTR lpStr, LPWSTR name, int maxlen, int64_t* sizefile,
                     LPFILETIME datetime, PDWORD attr, PDWORD UnixAttr, int flags)
{
    if (!lpStr || !name || maxlen <= 0 || !sizefile || !datetime || !attr || !UnixAttr)
        return false;

    auto parsed = ParseUnixLine(lpStr, flags);
    if (!parsed)
        return false;

    // Copy name with explicit truncation and terminator.
    const size_t dstCapacity = static_cast<size_t>(maxlen);
    const size_t copyLen = (std::min)(parsed->name.size(), dstCapacity - 1);
    std::wmemcpy(name, parsed->name.data(), copyLen);
    name[copyLen] = L'\0';

    *sizefile = parsed->size;
    *attr = parsed->attributes;
    *UnixAttr = parsed->unixMode;

    if (parsed->hasLastWriteTime)
        *datetime = parsed->lastWriteTime;
    else
        SetInt64ToFileTime(datetime, FS_TIME_UNKNOWN);

    return true;
}

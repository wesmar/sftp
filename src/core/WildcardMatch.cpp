#include "global.h"
#include <windows.h>
#include <algorithm>
#include <string>
#include <string_view>
#include <vector>
#include "WildcardMatch.h"

namespace {

std::vector<std::wstring_view> SplitPatterns(std::wstring_view list)
{
    std::vector<std::wstring_view> patterns;
    size_t i = 0;
    while (i < list.size()) {
        if (list[i] == L' ' || list[i] == L';') {
            ++i;
        } else if (list[i] == L'"') {
            const size_t close = list.find(L'"', i + 1);
            const size_t end = close == std::wstring_view::npos ? list.size() : close;
            patterns.push_back(list.substr(i + 1, end - i - 1));
            i = end == list.size() ? end : end + 1;
        } else {
            const size_t end = (std::min)(list.find_first_of(L" ;", i), list.size());
            patterns.push_back(list.substr(i, end - i));
            i = end;
        }
    }
    return patterns;
}

} // namespace

bool WildcardMatch(std::wstring_view patternIn, std::wstring_view nameIn)
{
    std::wstring pattern(patternIn);
    std::wstring name(nameIn);
    if (pattern.size() > MAXDWORD || name.size() > MAXDWORD)
        return false;
    CharUpperBuffW(pattern.data(), static_cast<DWORD>(pattern.size()));
    CharUpperBuffW(name.data(), static_cast<DWORD>(name.size()));

    constexpr size_t kNoStar = std::wstring::npos;
    size_t p = 0;
    size_t n = 0;
    size_t afterStar = kNoStar; // pattern position just past the last '*'
    size_t starFrom = 0;        // name position that '*' currently starts at
    for (;;) {
        if (p == pattern.size() && n == name.size())
            return true;
        if (p < pattern.size() && pattern[p] == L'*') {
            afterStar = ++p;
            starFrom = n;
            if (p == pattern.size())
                return true;
            continue;
        }
        if (p < pattern.size() && n < name.size() && (pattern[p] == L'?' || pattern[p] == name[n])) {
            ++p;
            ++n;
            continue;
        }
        if (n == name.size() && p < pattern.size() && pattern[p] == L'.') {
            const std::wstring_view rest = std::wstring_view(pattern).substr(p);
            if (rest == L".*")
                return true;
            if (rest == L".")
                return std::ranges::count(name, L'.') ==
                       std::count(pattern.begin(), pattern.begin() + static_cast<ptrdiff_t>(p), L'.');
        }
        // Let the last '*' take one more character and try again.
        if (afterStar == kNoStar || starFrom >= name.size())
            return false;
        p = afterStar;
        n = ++starFrom;
    }
}

bool MultiFileMatchW(LPCWSTR patterns, LPCWSTR name)
{
    if (!patterns || !name)
        return false;
    const std::wstring_view list(patterns);
    const size_t bar = list.find(L'|');
    const auto anyMatches = [name](const std::vector<std::wstring_view>& candidates) {
        return std::ranges::any_of(candidates, [name](std::wstring_view p) { return WildcardMatch(p, name); });
    };

    const auto included = SplitPatterns(list.substr(0, bar));
    const bool in = included.empty() ? bar != std::wstring_view::npos : anyMatches(included);
    if (!in || bar == std::wstring_view::npos)
        return in;
    return !anyMatches(SplitPatterns(list.substr(bar + 1)));
}

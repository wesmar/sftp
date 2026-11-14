#pragma once

#include <windows.h>
#include <string_view>

// Total Commander's wildcard rules, without regard to case: '*' matches any
// run of characters and '?' any one; "name.*" also matches "name"; and a
// pattern that ends in '.' matches only names with as many dots as the
// pattern has before that one.
[[nodiscard]] bool WildcardMatch(std::wstring_view pattern, std::wstring_view name);

// A pattern list in Total Commander's syntax: patterns separated by blanks
// or ';', a pattern holding blanks in double quotes, and after '|' patterns
// that exclude names again. With nothing before the '|' every name is
// included first, so "|*.bak" means all names but those.
[[nodiscard]] bool MultiFileMatchW(LPCWSTR patterns, LPCWSTR name);

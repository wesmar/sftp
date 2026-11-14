#include "Test.h"
#include "WildcardMatch.h"

#include <string>

TEST_CASE("wildcard: star, question mark and case")
{
    CHECK(WildcardMatch(L"*.txt", L"a.txt"));
    CHECK(WildcardMatch(L"*.txt", L"A.TXT"));
    CHECK(!WildcardMatch(L"*.txt", L"a.txt.bak"));
    CHECK(WildcardMatch(L"?", L"a"));
    CHECK(!WildcardMatch(L"?", L""));
    CHECK(!WildcardMatch(L"?", L"ab"));
    CHECK(WildcardMatch(L"a*b*c", L"aXXbYYc"));
    CHECK(WildcardMatch(L"a*b*c", L"abc"));
    CHECK(!WildcardMatch(L"a*b*c", L"acb"));
    CHECK(WildcardMatch(L"*", L""));
    CHECK(WildcardMatch(L"", L""));
    CHECK(!WildcardMatch(L"", L"a"));
}

TEST_CASE("wildcard: case folding covers more than ASCII")
{
    CHECK(WildcardMatch(L"*.ĄB", L"x.ąb"));      // Ą / ą
    CHECK(WildcardMatch(L"Ж*", L"жук")); // Ж / жук
}

TEST_CASE("wildcard: Total Commander's dot rules")
{
    CHECK(WildcardMatch(L"name.*", L"name"));
    CHECK(WildcardMatch(L"name.*", L"name.ext"));
    CHECK(WildcardMatch(L"*.", L"README"));
    CHECK(!WildcardMatch(L"*.", L"a.b"));
    CHECK(WildcardMatch(L"*.*.", L"a.b"));
    CHECK(!WildcardMatch(L"*.*.", L"a.b.c"));
}

TEST_CASE("wildcard: long patterns and names do not overflow")
{
    const std::wstring stars(5000, L'*');
    const std::wstring name(4000, L'a');
    CHECK(WildcardMatch(stars + L"a", name));
    CHECK(!WildcardMatch(stars + L"b", name));
    CHECK(WildcardMatch(std::wstring(L"*") + name, name));
}

TEST_CASE("wildcard: pattern lists with quotes and exclusions")
{
    CHECK(MultiFileMatchW(L"*.txt *.ini", L"a.ini"));
    CHECK(MultiFileMatchW(L"*.txt;*.ini", L"b.txt"));
    CHECK(!MultiFileMatchW(L"*.txt;*.ini", L"b.cfg"));
    CHECK(MultiFileMatchW(L"\"my file*\" *.c", L"my file 1"));
    CHECK(!MultiFileMatchW(L"*.* | *.bak", L"x.bak"));
    CHECK(MultiFileMatchW(L"*.*|*.bak", L"x.txt"));
    CHECK(MultiFileMatchW(L"|*.bak", L"x.txt"));
    CHECK(!MultiFileMatchW(L"|*.bak", L"x.bak"));
    CHECK(!MultiFileMatchW(L"", L"x"));
    CHECK(!MultiFileMatchW(nullptr, L"x"));
}

#pragma once

// Minimal self-registering test harness: no third-party dependency, so the
// unit tests build with nothing but the compiler the plugin already needs.

#include <cstdio>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace test {

struct Case {
    const char* name;
    std::function<void()> body;
};

inline std::vector<Case>& Registry()
{
    static std::vector<Case> cases;
    return cases;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> body) { Registry().push_back({name, std::move(body)}); }
};

struct Failure {
    std::string message;
};

inline int& CheckCount()
{
    static int count = 0;
    return count;
}

[[noreturn]] inline void Fail(const char* file, int line, const std::string& what)
{
    throw Failure{std::string(file) + ":" + std::to_string(line) + ": " + what};
}

// Printable form of a byte string for failure messages: \r, \n, \0 and other
// control bytes are escaped so line-ending bugs are visible.
inline std::string Escape(const std::string& s)
{
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
        case '\r': out += "\\r"; break;
        case '\n': out += "\\n"; break;
        case '\0': out += "\\0"; break;
        case '\\': out += "\\\\"; break;
        default:
            if (c < 0x20 || c >= 0x7f) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\x%02x", c);
                out += buf;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    return out;
}

// Deterministic PRNG (SplitMix64): property tests must reproduce exactly.
class Rng {
public:
    explicit Rng(uint64_t seed) : state_(seed) {}
    uint64_t Next()
    {
        uint64_t z = (state_ += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    size_t Below(size_t bound) { return bound ? static_cast<size_t>(Next() % bound) : 0; }

private:
    uint64_t state_;
};

} // namespace test

#define TEST_CONCAT_INNER(a, b) a##b
#define TEST_CONCAT(a, b) TEST_CONCAT_INNER(a, b)

#define TEST_CASE(name)                                                                  \
    static void TEST_CONCAT(test_body_, __LINE__)();                                     \
    static test::Registrar TEST_CONCAT(test_reg_, __LINE__)(name, &TEST_CONCAT(test_body_, __LINE__)); \
    static void TEST_CONCAT(test_body_, __LINE__)()

#define CHECK(cond)                                                                      \
    do {                                                                                 \
        ++test::CheckCount();                                                            \
        if (!(cond)) test::Fail(__FILE__, __LINE__, "CHECK(" #cond ") failed");          \
    } while (0)

#define CHECK_EQ(actual, expected)                                                       \
    do {                                                                                 \
        ++test::CheckCount();                                                            \
        const auto& test_a_ = (actual);                                                  \
        const auto& test_e_ = (expected);                                                \
        if (!(test_a_ == test_e_))                                                       \
            test::Fail(__FILE__, __LINE__, "CHECK_EQ(" #actual ", " #expected ") failed"); \
    } while (0)

#define CHECK_BYTES(actual, expected)                                                    \
    do {                                                                                 \
        ++test::CheckCount();                                                            \
        const std::string test_a_ = (actual);                                            \
        const std::string test_e_ = (expected);                                          \
        if (test_a_ != test_e_)                                                          \
            test::Fail(__FILE__, __LINE__, "got \"" + test::Escape(test_a_) +            \
                                           "\", expected \"" + test::Escape(test_e_) + "\""); \
    } while (0)

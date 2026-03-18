#include "global.h"
#include "KittyDecrypt.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <string_view>

namespace {

// KiTTY's custom base64 alphabet (shuffled relative to standard).
constexpr std::string_view kBaseAlphabet =
    "AZERTYUIOPQSDFGHJKLMWXCVBNazertyuiopqsdfghjklmwxcvbn0123456789+/";

// Returns the number of leading non-null characters, capped at max_len.
[[nodiscard]] constexpr size_t CStrLen(std::string_view sv,
                                       size_t           max_len) noexcept {
    return (std::min)(sv.size(), max_len);
}

// Validates that a pattern is a permutation of unique printable bytes
// with no newline characters.
[[nodiscard]] bool IsValidPattern(std::string_view pattern) noexcept {
    if (pattern.size() <= 1) return false;
    std::array<bool, 256> seen{};
    for (const unsigned char c : pattern) {
        if (c == '\n' || c == '\r') return false;
        if (seen[c])                return false;
        seen[c] = true;
    }
    return true;
}

// Fisher-Yates-style scramble driven by the bytes of `key`.
void ScramblePattern(std::string& pattern, std::string_view key) noexcept {
    const size_t plen = pattern.size();
    const size_t klen = key.size();
    if (plen == 0 || klen == 0) return;

    const size_t passes = (klen / 2 / plen) + 1;
    size_t k = 0;
    for (size_t pass = 0; pass < passes; ++pass) {
        for (size_t i = 0; i < plen; ++i) {
            const auto  kb  = static_cast<int8_t>(key[k]);
            const auto  sum = static_cast<uint32_t>(static_cast<int32_t>(kb)
                                                  + static_cast<int32_t>(i));
            const size_t j  = static_cast<size_t>(sum % plen);
            std::swap(pattern[i], pattern[j]);
            if (++k >= klen) k = 0;
        }
    }
}

// Linear search in the current pattern for byte c.
[[nodiscard]] int IndexInPattern(std::string_view pattern,
                                 unsigned char    c) noexcept {
    const auto it = std::find(pattern.begin(), pattern.end(), static_cast<char>(c));
    return (it != pattern.end())
        ? static_cast<int>(std::distance(pattern.begin(), it))
        : -1;
}

[[nodiscard]] bool KittyDecryptBase64(const std::string& enc,
                                      const std::string& key,
                                      std::string&       out) {
    out.clear();
    if (enc.empty()) return false;

    std::string pattern(kBaseAlphabet);
    if (!IsValidPattern(pattern)) return false;

    const size_t seedLen = CStrLen(enc, 5);
    if (seedLen > 0)
        ScramblePattern(pattern, std::string_view(enc).substr(0, seedLen));

    const std::string_view keyView(key);
    const size_t           encLen = enc.size();
    size_t idx     = 5;
    int    counter = 0;

    while (idx < encLen) {
        if (pattern.empty()) break;

        unsigned char c = static_cast<unsigned char>(enc[idx]);

        if (c == '\n') { ++idx; continue; }

        unsigned char markerByte = static_cast<unsigned char>(pattern.back());
        unsigned char offset     = 0;

        while (c == markerByte && !pattern.empty()) {
            offset = static_cast<unsigned char>(
                offset + static_cast<unsigned char>(pattern.size() - 1));
            if (!keyView.empty())
                ScramblePattern(pattern, keyView);
            ++idx;
            while (idx < encLen && enc[idx] == '\n') ++idx;
            if (idx >= encLen) break;
            c          = static_cast<unsigned char>(enc[idx]);
            markerByte = pattern.empty()
                ? 0u
                : static_cast<unsigned char>(pattern.back());
        }
        if (idx >= encLen || pattern.empty()) break;

        const int index = IndexInPattern(pattern, c);
        if (index < 0) { ++idx; continue; }

        out.push_back(static_cast<char>(
            static_cast<unsigned char>(offset) +
            static_cast<unsigned char>(index)));

        if (++counter >= static_cast<int>(pattern.size())) {
            counter = 0;
            if (!keyView.empty())
                ScramblePattern(pattern, keyView);
        }
        ++idx;
    }

    return !out.empty();
}

constexpr std::string_view kKittySuffix = "KiTTY";

[[nodiscard]] std::string DeriveKey(int mode, const std::string& host,
                                    const std::string& term) {
    if (mode != 0) return std::string(kKittySuffix);
    return host + term + std::string(kKittySuffix);
}

[[nodiscard]] bool TryDecrypt(const std::string& enc, const std::string& key,
                              std::string& out) {
    return !enc.empty() && !key.empty() && KittyDecryptBase64(enc, key, out);
}

} // namespace

bool DecryptKittyPassword(const std::string& enc, const std::string& host,
                     const std::string& term, std::string& out) {
    return TryDecrypt(enc, DeriveKey(0, host, term), out) ||
           TryDecrypt(enc, DeriveKey(1, host, term), out);
}

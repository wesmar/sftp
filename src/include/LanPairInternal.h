#pragma once
// LanPairInternal.h — shared crypto and socket primitives for LanPair.cpp / LanPairSession.cpp.
//
// NOT part of the public API.  Include ONLY from those two translation units.
//
// Every definition here is marked `inline` so the header may be included from
// multiple TUs without ODR violations (C++17 inline variables / functions).
// The `static inline` members of WsaScope give a single process-wide reference
// count, which is correct: WSAStartup/WSACleanup are themselves reference-counted
// by Windows, and the plugin always runs in one process.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace lanpair_internal {

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

inline constexpr size_t kNonceSize       = 16;
inline constexpr size_t kSaltSize        = 16;
inline constexpr size_t kDerivedKeySize  = 32;
inline constexpr ULONG  kPbkdf2Iterations = 120'000;

// ---------------------------------------------------------------------------
// WsaScope — reference-counted WSAStartup / WSACleanup guard
// ---------------------------------------------------------------------------

class WsaScope {
public:
    WsaScope() {
        std::lock_guard<std::mutex> lk(mu_);
        if (refCount_++ == 0) {
            WSADATA wsa{};
            ok_      = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
            started_ = ok_;
        } else {
            ok_ = started_;
        }
    }

    ~WsaScope() {
        std::lock_guard<std::mutex> lk(mu_);
        if (refCount_ == 0) return;
        if (--refCount_ == 0 && started_) {
            WSACleanup();
            started_ = false;
        }
    }

    WsaScope(const WsaScope&)            = delete;
    WsaScope& operator=(const WsaScope&) = delete;

    bool ok() const noexcept { return ok_; }

private:
    bool ok_ = false;

    static inline std::mutex mu_;
    static inline int        refCount_ = 0;
    static inline bool       started_  = false;
};

// ---------------------------------------------------------------------------
// Hex encoding / decoding
// ---------------------------------------------------------------------------

inline std::string hexEncode(const uint8_t* data, size_t len) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out(len * 2, '\0');
    for (size_t i = 0; i < len; ++i) {
        out[2 * i]     = kHex[(data[i] >> 4) & 0x0F];
        out[2 * i + 1] = kHex[ data[i]       & 0x0F];
    }
    return out;
}

inline std::optional<std::vector<uint8_t>> hexDecode(std::string_view in) {
    if (in.size() % 2 != 0) return std::nullopt;

    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    std::vector<uint8_t> out(in.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        const int hi = val(in[2 * i]);
        const int lo = val(in[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Cryptographic primitives
// ---------------------------------------------------------------------------

inline bool randomBytes(uint8_t* out, size_t len) {
    return BCryptGenRandom(nullptr, out, static_cast<ULONG>(len),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

inline std::optional<std::vector<uint8_t>> hmacSha256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data)
{
    BCRYPT_ALG_HANDLE  alg   = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD objLen = 0, cb = 0, hashLen = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return std::nullopt;

    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen),
                          &cb, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                          reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen),
                          &cb, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }

    std::vector<uint8_t> hashObj(objLen);
    std::vector<uint8_t> out(hashLen);

    if (BCryptCreateHash(alg, &hHash,
                         hashObj.data(), objLen,
                         const_cast<PUCHAR>(key.data()),
                         static_cast<ULONG>(key.size()), 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }

    const NTSTATUS h1 = BCryptHashData(hHash,
                                       const_cast<PUCHAR>(data.data()),
                                       static_cast<ULONG>(data.size()), 0);
    const NTSTATUS h2 = BCryptFinishHash(hHash, out.data(),
                                         static_cast<ULONG>(out.size()), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(alg, 0);

    if (h1 != 0 || h2 != 0) return std::nullopt;
    return out;
}

inline std::optional<std::vector<uint8_t>> deriveKeyPbkdf2(
    std::string_view password,
    std::span<const uint8_t> salt,
    size_t keyLen)
{
    if (keyLen == 0) return std::vector<uint8_t>{};

    const std::vector<uint8_t> passBytes(password.begin(), password.end());
    if (passBytes.empty()) return std::nullopt;

    constexpr size_t hLen = 32; // SHA-256 output size
    const size_t blockCount = (keyLen + hLen - 1) / hLen;

    std::vector<uint8_t> derived;
    derived.reserve(blockCount * hLen);

    for (size_t block = 1; block <= blockCount; ++block) {
        // PRF input: salt || INT(block)  (RFC 2898 §5.2)
        std::vector<uint8_t> saltBlock(salt.begin(), salt.end());
        saltBlock.push_back(static_cast<uint8_t>((block >> 24) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>((block >> 16) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>((block >>  8) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>( block        & 0xFF));

        auto u = hmacSha256(passBytes, saltBlock);
        if (!u) return std::nullopt;

        std::vector<uint8_t> t = *u;
        for (ULONG i = 2; i <= kPbkdf2Iterations; ++i) {
            u = hmacSha256(passBytes,
                           std::span<const uint8_t>(u->data(), u->size()));
            if (!u) return std::nullopt;
            for (size_t j = 0; j < t.size(); ++j)
                t[j] ^= (*u)[j];
        }
        derived.insert(derived.end(), t.begin(), t.end());
    }

    derived.resize(keyLen);
    return derived;
}

// ---------------------------------------------------------------------------
// Key / token helpers
// ---------------------------------------------------------------------------

// Sanitise an arbitrary string so it can be used as a filename component
// or DPAPI key discriminator.
inline std::string sanitizeKey(std::string_view key) {
    std::string out;
    out.reserve(key.size());
    for (char c : key) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-')
            out.push_back(c);
        else
            out.push_back('_');
    }
    return out.empty() ? "default" : out;
}

inline std::string trustKeyForServer(std::string_view serverPeerId,
                                     std::string_view clientPeerId) {
    return "lanpair_trust_srv_" + sanitizeKey(serverPeerId)
         + "__" + sanitizeKey(clientPeerId);
}

inline std::string trustKeyForClient(std::string_view serverPeerId,
                                     std::string_view clientPeerId) {
    return "lanpair_trust_cli_" + sanitizeKey(serverPeerId)
         + "__" + sanitizeKey(clientPeerId);
}

// Percent-encode a token for the PAIR1 wire protocol.
inline std::string escapeToken(std::string_view in) {
    std::ostringstream oss;
    for (unsigned char c : in) {
        if (std::isalnum(c) || c == '_' || c == '-' || c == '.') {
            oss << static_cast<char>(c);
        } else {
            oss << '%' << std::uppercase << std::hex;
            if (c < 16) oss << '0';
            oss << static_cast<int>(c) << std::nouppercase << std::dec;
        }
    }
    return oss.str();
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

inline bool setSocketTimeout(SOCKET s, DWORD ms) {
    return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                      reinterpret_cast<const char*>(&ms), sizeof(ms)) == 0
        && setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
                      reinterpret_cast<const char*>(&ms), sizeof(ms)) == 0;
}

inline bool sendAll(SOCKET s, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        const int n = send(s,
                           reinterpret_cast<const char*>(data + sent),
                           static_cast<int>(len - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

inline bool recvLine(SOCKET s, std::string* out, size_t maxLen = 4096) {
    out->clear();
    char c = 0;
    while (out->size() < maxLen) {
        const int n = recv(s, &c, 1, 0);
        if (n <= 0)    return false;
        if (c == '\n') return true;
        if (c != '\r') out->push_back(c);
    }
    return false;
}

inline bool sendLine(SOCKET s, const std::string& line) {
    return sendAll(s, reinterpret_cast<const uint8_t*>(line.data()), line.size())
        && sendAll(s, reinterpret_cast<const uint8_t*>("\n"), 1);
}

inline std::vector<std::string> splitBySpace(const std::string& line) {
    std::istringstream iss(line);
    std::vector<std::string> parts;
    for (std::string tok; iss >> tok;)
        parts.push_back(std::move(tok));
    return parts;
}

} // namespace lanpair_internal

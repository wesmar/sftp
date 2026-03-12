// ============================================================
// LanPairSession.cpp
// File-transfer session layer on top of the PAIR1 auth protocol.
// After PAIR1 the same TCP socket is kept open and a simple
// line-based command protocol (LAN2) is spoken on it.
// ============================================================

#include "LanPairSession.h"
#include "LanPair.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <fileapi.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <algorithm>
#include <thread>
#include <vector>
#include <string>
#include <sstream>
#include <span>
#include <array>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <optional>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

// fsplugin constants used for getFile / putFile return codes
#define FS_FILE_OK          0
#define FS_FILE_EXISTS      1
#define FS_FILE_NOTFOUND    2
#define FS_FILE_READERROR   3
#define FS_FILE_WRITEERROR  4
#define FS_FILE_USERABORT   5

// ============================================================
// Anonymous-namespace helpers (duplicated from LanPair.cpp
// because those are in an anonymous namespace there)
// ============================================================
namespace {

constexpr size_t kNonceSize      = 16;
constexpr size_t kSaltSize       = 16;
constexpr size_t kDerivedKeySize = 32;
constexpr ULONG  kPbkdf2Iters   = 120000;

// ---------- WSA reference-counted scope ----------

class WsaScope {
public:
    WsaScope() {
        std::lock_guard<std::mutex> lk(mu_);
        if (refCount_++ == 0) {
            WSADATA wsa{};
            ok_ = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
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
    bool ok() const noexcept { return ok_; }
private:
    bool ok_ = false;
    static inline std::mutex mu_;
    static inline int  refCount_ = 0;
    static inline bool started_  = false;
};

// ---------- crypto helpers ----------

std::string hexEncode(const uint8_t* data, size_t len) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out(len * 2, '\0');
    for (size_t i = 0; i < len; ++i) {
        out[2 * i]     = kHex[(data[i] >> 4) & 0x0F];
        out[2 * i + 1] = kHex[data[i]        & 0x0F];
    }
    return out;
}

std::optional<std::vector<uint8_t>> hexDecode(std::string_view in) {
    if (in.size() % 2 != 0) return std::nullopt;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    std::vector<uint8_t> out(in.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = val(in[2 * i]), lo = val(in[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

bool randomBytes(uint8_t* out, size_t len) {
    return BCryptGenRandom(nullptr, out, static_cast<ULONG>(len),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

std::optional<std::vector<uint8_t>> hmacSha256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data)
{
    BCRYPT_ALG_HANDLE  alg   = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD objLen = 0, cb = 0, hashLen = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return std::nullopt;

    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                      reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cb, 0);
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                      reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cb, 0);

    std::vector<uint8_t> hashObj(objLen), out(hashLen);

    if (BCryptCreateHash(alg, &hHash, hashObj.data(), objLen,
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

std::optional<std::vector<uint8_t>> deriveKeyPbkdf2(
    std::string_view password,
    std::span<const uint8_t> salt,
    size_t keyLen)
{
    if (keyLen == 0) return std::vector<uint8_t>{};
    const std::vector<uint8_t> passBytes(password.begin(), password.end());
    if (passBytes.empty()) return std::nullopt;

    constexpr size_t hLen = 32;
    const size_t blockCount = (keyLen + hLen - 1) / hLen;
    std::vector<uint8_t> derived;
    derived.reserve(blockCount * hLen);

    for (size_t block = 1; block <= blockCount; ++block) {
        std::vector<uint8_t> saltBlock(salt.begin(), salt.end());
        saltBlock.push_back(static_cast<uint8_t>((block >> 24) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>((block >> 16) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>((block >>  8) & 0xFF));
        saltBlock.push_back(static_cast<uint8_t>( block        & 0xFF));

        auto u = hmacSha256(passBytes, saltBlock);
        if (!u) return std::nullopt;
        std::vector<uint8_t> t = *u;

        for (ULONG i = 2; i <= kPbkdf2Iters; ++i) {
            u = hmacSha256(passBytes, std::span<const uint8_t>(u->data(), u->size()));
            if (!u) return std::nullopt;
            for (size_t j = 0; j < t.size(); ++j) t[j] ^= (*u)[j];
        }
        derived.insert(derived.end(), t.begin(), t.end());
    }
    derived.resize(keyLen);
    return derived;
}

// Sanitise a peer ID so it can be used as a filename component.
std::string sanitizeKey(std::string_view key) {
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

std::string trustKeyForServer(std::string_view serverPeerId, std::string_view clientPeerId) {
    return "lanpair_trust_srv_" + sanitizeKey(serverPeerId)
         + "__" + sanitizeKey(clientPeerId);
}

std::string trustKeyForClient(std::string_view serverPeerId, std::string_view clientPeerId) {
    return "lanpair_trust_cli_" + sanitizeKey(serverPeerId)
         + "__" + sanitizeKey(clientPeerId);
}

// ---------------------------------------------------------------------------
// Pre-derive trust keys from shared password and store in DPAPI.
// Called when a LAN Pair profile is saved.  Both machines save independently
// using the same password -> same key bytes -> PAIR1 AUTH works without
// any password exchange at connection time.
// ---------------------------------------------------------------------------
std::string roleToString(smb::PairRole role) {
    switch (role) {
    case smb::PairRole::Donor:    return "donor";
    case smb::PairRole::Receiver: return "receiver";
    default:                      return "dual";
    }
}

smb::PairRole roleFromString(const std::string& s) {
    if (s == "donor")    return smb::PairRole::Donor;
    if (s == "receiver") return smb::PairRole::Receiver;
    return smb::PairRole::Dual;
}

std::string escapeToken(std::string_view in) {
    std::ostringstream oss;
    for (unsigned char c : in) {
        if (std::isalnum(c) || c == '_' || c == '-' || c == '.') {
            oss << static_cast<char>(c);
        } else {
            oss << '%' << std::uppercase << std::hex;
            if (c < 16) oss << '0';
            oss << static_cast<int>(c)
                << std::nouppercase << std::dec;
        }
    }
    return oss.str();
}

// ---------- socket helpers ----------

bool setSocketTimeout(SOCKET s, DWORD ms) {
    return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                      reinterpret_cast<const char*>(&ms), sizeof(ms)) == 0
        && setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
                      reinterpret_cast<const char*>(&ms), sizeof(ms)) == 0;
}

bool sendAll(SOCKET s, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, reinterpret_cast<const char*>(data + sent),
                     static_cast<int>(len - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool recvAll(SOCKET s, uint8_t* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = recv(s, reinterpret_cast<char*>(buf + got),
                     static_cast<int>(len - got), 0);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

bool recvLine(SOCKET s, std::string* out, size_t maxLen = 4096) {
    out->clear();
    char c = 0;
    while (out->size() < maxLen) {
        int n = recv(s, &c, 1, 0);
        if (n <= 0)    return false;
        if (c == '\n') return true;
        if (c != '\r') out->push_back(c);
    }
    return false;
}

bool sendLine(SOCKET s, const std::string& line) {
    return sendAll(s, reinterpret_cast<const uint8_t*>(line.data()), line.size())
        && sendAll(s, reinterpret_cast<const uint8_t*>("\n"), 1);
}

std::vector<std::string> splitBySpace(const std::string& line) {
    std::istringstream iss(line);
    std::vector<std::string> parts;
    for (std::string tok; iss >> tok;)
        parts.push_back(std::move(tok));
    return parts;
}

// ---------- base64 ----------

static constexpr char kB64Table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64Encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        uint32_t v = (static_cast<uint32_t>(data[i])     << 16)
                   | (static_cast<uint32_t>(data[i + 1]) <<  8)
                   |  static_cast<uint32_t>(data[i + 2]);
        out.push_back(kB64Table[(v >> 18) & 0x3F]);
        out.push_back(kB64Table[(v >> 12) & 0x3F]);
        out.push_back(kB64Table[(v >>  6) & 0x3F]);
        out.push_back(kB64Table[ v        & 0x3F]);
    }
    if (i + 1 == len) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(kB64Table[(v >> 18) & 0x3F]);
        out.push_back(kB64Table[(v >> 12) & 0x3F]);
        out.push_back('='); out.push_back('=');
    } else if (i + 2 == len) {
        uint32_t v = (static_cast<uint32_t>(data[i])     << 16)
                   | (static_cast<uint32_t>(data[i + 1]) <<  8);
        out.push_back(kB64Table[(v >> 18) & 0x3F]);
        out.push_back(kB64Table[(v >> 12) & 0x3F]);
        out.push_back(kB64Table[(v >>  6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

std::string b64EncodeStr(const std::string& s) {
    return b64Encode(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::optional<std::vector<uint8_t>> b64Decode(std::string_view in) {
    // Build reverse table
    static const uint8_t* kInv = []() -> const uint8_t* {
        static uint8_t t[256];
        for (int i = 0; i < 256; ++i) t[i] = 0xFF;
        for (int i = 0; i < 64; ++i)
            t[static_cast<unsigned char>(kB64Table[i])] = static_cast<uint8_t>(i);
        t[static_cast<unsigned char>('=')] = 0;
        return t;
    }();
    // Strip whitespace
    std::string stripped;
    stripped.reserve(in.size());
    for (char c : in)
        if (c != '\r' && c != '\n' && c != ' ') stripped.push_back(c);

    if (stripped.size() % 4 != 0) return std::nullopt;
    std::vector<uint8_t> out;
    out.reserve(stripped.size() / 4 * 3);
    for (size_t i = 0; i < stripped.size(); i += 4) {
        uint8_t a = kInv[static_cast<unsigned char>(stripped[i])];
        uint8_t b = kInv[static_cast<unsigned char>(stripped[i+1])];
        uint8_t c = kInv[static_cast<unsigned char>(stripped[i+2])];
        uint8_t d = kInv[static_cast<unsigned char>(stripped[i+3])];
        if (a == 0xFF || b == 0xFF || c == 0xFF || d == 0xFF) return std::nullopt;
        out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
        if (stripped[i+2] != '=') out.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
        if (stripped[i+3] != '=') out.push_back(static_cast<uint8_t>((c << 6) |  d));
    }
    return out;
}

std::string b64DecodeStr(const std::string& in) {
    auto v = b64Decode(in);
    if (!v) return {};
    return std::string(v->begin(), v->end());
}

// ---------- Wide<->UTF-8 helpers ----------

std::string wideToUtf8(LPCWSTR wide) {
    if (!wide || !*wide) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
                                static_cast<int>(utf8.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
                        static_cast<int>(utf8.size()), out.data(), n);
    return out;
}

// ---------- PAIR1 client-side auth (returns open socket + key on success) ----------

struct AuthResult {
    SOCKET         sock = INVALID_SOCKET;
    std::vector<uint8_t> key;
};

// Performs full PAIR1 handshake as client.
// Returns open, authenticated socket (caller owns it) plus the shared key.
// On failure sock == INVALID_SOCKET.
AuthResult pair1Connect(
    const std::string& targetIp,
    uint16_t           targetPort,
    const std::string& localPeerId,
    const std::string& remotePeerId,
    const std::string& password,
    smb::PairError* err) noexcept
{
    AuthResult result;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        if (err) { err->code = WSAGetLastError(); err->message = "Cannot create socket"; }
        return result;
    }

    setSocketTimeout(s, 8000);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(targetPort);
    if (inet_pton(AF_INET, targetIp.c_str(), &addr.sin_addr) != 1) {
        closesocket(s);
        if (err) { err->code = ERROR_INVALID_ADDRESS; err->message = "Invalid target IP"; }
        return result;
    }

    if (connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        int code = WSAGetLastError();
        closesocket(s);
        if (err) { err->code = code; err->message = "connect() failed"; }
        return result;
    }

    // Enable TCP keepalive to prevent connection timeout during idle periods
    const BOOL keepAlive = TRUE;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&keepAlive), sizeof(keepAlive));

    // Generate client nonce
    std::array<uint8_t, kNonceSize> clientNonce{};
    if (!randomBytes(clientNonce.data(), clientNonce.size())) {
        closesocket(s);
        if (err) { err->code = GetLastError(); err->message = "randomBytes failed"; }
        return result;
    }
    const std::string clientNonceHex = hexEncode(clientNonce.data(), clientNonce.size());

    // Send HELLO
    std::ostringstream hello;
    hello << "PAIR1 HELLO " << localPeerId << " "
          << roleToString(smb::PairRole::Donor) << " " << clientNonceHex;
    if (!sendLine(s, hello.str())) {
        closesocket(s);
        if (err) { err->code = WSAGetLastError(); err->message = "Cannot send HELLO"; }
        return result;
    }

    // Receive CHALLENGE
    std::string line;
    if (!recvLine(s, &line)) {
        closesocket(s);
        if (err) { err->code = WSAGetLastError(); err->message = "No CHALLENGE received"; }
        return result;
    }
    const auto ch = splitBySpace(line);
    if (ch.size() != 7 || ch[0] != "PAIR1" || ch[1] != "CHALLENGE") {
        closesocket(s);
        if (err) { err->code = ERROR_INVALID_DATA; err->message = "Invalid CHALLENGE"; }
        return result;
    }

    const std::string serverPeerId = ch[2];
    // Validate against expected remote peer id if caller provided one
    if (!remotePeerId.empty() && serverPeerId != remotePeerId) {
        closesocket(s);
        if (err) { err->code = ERROR_ACCESS_DENIED; err->message = "Peer ID mismatch"; }
        return result;
    }

    const auto salt        = hexDecode(ch[5]);
    const auto serverNonce = hexDecode(ch[6]);
    if (!salt || !serverNonce ||
        salt->size() != kSaltSize || serverNonce->size() != kNonceSize) {
        closesocket(s);
        if (err) { err->code = ERROR_INVALID_DATA; err->message = "Bad challenge nonce/salt"; }
        return result;
    }

    const std::string proofMaterial  = "C|" + clientNonceHex + "|" + ch[6] + "|" + localPeerId + "|" + serverPeerId;
    const std::string srvProofMaterial = "S|" + clientNonceHex + "|" + ch[6] + "|" + localPeerId + "|" + serverPeerId;

    std::vector<uint8_t> key;

    auto sendAuthAndGetKey = [&]() -> bool {
        std::string trustSecret;
        const std::string trustKey = trustKeyForClient(serverPeerId, localPeerId);
        if (smb::DpapiSecretStore::loadSecret(trustKey, &trustSecret, nullptr)) {
            key.assign(trustSecret.begin(), trustSecret.end());
            auto proof = hmacSha256(key,
                std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(proofMaterial.data()),
                    proofMaterial.size()));
            if (!proof) return false;
            std::ostringstream auth;
            auth << "PAIR1 AUTH " << hexEncode(proof->data(), proof->size());
            return sendLine(s, auth.str());
        }
        return sendLine(s, "PAIR1 TRUSTNEW");
    };

    if (!sendAuthAndGetKey()) {
        closesocket(s);
        if (err) { err->code = WSAGetLastError(); err->message = "Cannot send AUTH"; }
        return result;
    }

    // Receive OK / OKTRUST
    if (!recvLine(s, &line)) {
        closesocket(s);
        if (err) { err->code = WSAGetLastError(); err->message = "No OK response"; }
        return result;
    }
    const auto ok = splitBySpace(line);
    if (ok.size() < 3 || ok[0] != "PAIR1" || (ok[1] != "OK" && ok[1] != "OKTRUST")) {
        closesocket(s);
        if (err) { err->code = ERROR_ACCESS_DENIED;
                   err->message = line.empty() ? "Auth failed" : line; }
        return result;
    }

    if (ok[1] == "OKTRUST") {
        if (ok.size() != 4) {
            closesocket(s);
            if (err) { err->code = ERROR_INVALID_DATA; err->message = "Bad OKTRUST"; }
            return result;
        }
        auto trustBytes = hexDecode(ok[3]);
        if (!trustBytes || trustBytes->empty()) {
            closesocket(s);
            if (err) { err->code = ERROR_INVALID_DATA; err->message = "Bad trust token"; }
            return result;
        }
        key.assign(trustBytes->begin(), trustBytes->end());
        const std::string trustKey = trustKeyForClient(serverPeerId, localPeerId);
        std::string raw(reinterpret_cast<const char*>(trustBytes->data()), trustBytes->size());
        smb::DpapiSecretStore::saveSecret(trustKey, raw, nullptr);
    }

    // Verify server proof
    auto expectedSrvProof = hmacSha256(key,
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(srvProofMaterial.data()),
            srvProofMaterial.size()));
    if (!expectedSrvProof ||
        hexEncode(expectedSrvProof->data(), expectedSrvProof->size()) != ok[2]) {
        closesocket(s);
        if (err) { err->code = ERROR_ACCESS_DENIED; err->message = "Server proof mismatch"; }
        return result;
    }

    result.sock = s;
    result.key  = std::move(key);
    return result;
}

// ---------- LAN2 command helpers ----------

// Send a single LAN2 command token and an optional base64-encoded path argument.
bool lan2SendCmd(SOCKET s, const std::string& cmd) {
    return sendLine(s, cmd);
}

// Read a response line and check its first token.
// Returns the full split response or empty on failure/error.
std::vector<std::string> lan2ReadResponse(SOCKET s) {
    std::string line;
    if (!recvLine(s, &line)) return {};
    return splitBySpace(line);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// PrepareLanPairTrustKeys — public API, outside anonymous namespace
// ---------------------------------------------------------------------------
bool PrepareLanPairTrustKeys(const std::string& localPeerId,
                              const std::string& remotePeerId,
                              const std::string& password) noexcept
{
    std::string combined = localPeerId + "<>" + remotePeerId;
    std::vector<uint8_t> salt(16, 0);
    auto h = hmacSha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>("LANPAIR"), 7), 
                        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(combined.data()), combined.size()));
    if (h && h->size() >= 16) {
        for(size_t i = 0; i < 16; ++i) salt[i] = (*h)[i];
    } else {
        memcpy(salt.data(), "sftpplug-pair...", 16);
    }

    auto key = deriveKeyPbkdf2(password,
                    std::span<const uint8_t>(salt.data(), salt.size()),
                    kDerivedKeySize);
    if (!key) return false;
    const std::string raw(reinterpret_cast<const char*>(key->data()), key->size());

    smb::DpapiSecretStore::saveSecret(
        trustKeyForClient(remotePeerId, localPeerId), raw, nullptr);
    smb::DpapiSecretStore::saveSecret(
        trustKeyForServer(localPeerId, remotePeerId), raw, nullptr);
    return true;
}

// ============================================================
// LanPairSession::Impl
// ============================================================

struct LanPairSession::Impl {
    WsaScope wsa;
    SOCKET   sock_       = INVALID_SOCKET;
    bool     connected_  = false;
    int      timeoutMin_ = 0;
    std::chrono::steady_clock::time_point sessionStart_ = std::chrono::steady_clock::now();

    bool isTimedOut() const noexcept {
        if (timeoutMin_ <= 0) return false;
        return std::chrono::steady_clock::now() - sessionStart_
               >= std::chrono::minutes(timeoutMin_);
    }

    void close() noexcept {
        if (sock_ != INVALID_SOCKET) {
            // Best-effort QUIT
            sendLine(sock_, "QUIT");
            closesocket(sock_);
            sock_ = INVALID_SOCKET;
        }
        connected_ = false;
    }

    // Helper: send a command line and get the response parts back.
    // Returns empty vector on I/O failure or session timeout.
    std::vector<std::string> cmd(const std::string& line) noexcept {
        if (isTimedOut()) {
            close();
            return {};
        }
        if (!sendLine(sock_, line)) {
            close();
            return {};
        }
        std::string resp;
        if (!recvLine(sock_, &resp)) {
            close();
            return {};
        }
        return splitBySpace(resp);
    }
};

// ============================================================
// LanPairSession public API
// ============================================================

LanPairSession::LanPairSession(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

LanPairSession::~LanPairSession() {
    disconnect();
}

/*static*/
std::unique_ptr<LanPairSession> LanPairSession::connect(
    const std::string& targetIp,
    uint16_t           targetPort,
    const std::string& localPeerId,
    const std::string& remotePeerId,
    const std::string& password,
    smb::PairError* err) noexcept
{
    auto impl = std::make_unique<Impl>();
    if (!impl->wsa.ok()) {
        if (err) { err->code = WSAGetLastError(); err->message = "WSAStartup failed"; }
        return nullptr;
    }

    SFTP_LOG("LAN2", "connect() -> pair1Connect %s:%u local=%s remote=%s",
             targetIp.c_str(), targetPort, localPeerId.c_str(), remotePeerId.c_str());
    AuthResult ar = pair1Connect(targetIp, targetPort,
                                 localPeerId, remotePeerId, password, err);
    if (ar.sock == INVALID_SOCKET) {
        SFTP_LOG("LAN2", "pair1Connect FAILED: %s", err ? err->message.c_str() : "?");
        return nullptr;
    }
    SFTP_LOG("LAN2", "pair1Connect OK, sending LAN2 HELLO");

    // Upgrade to LAN2 command channel
    if (!sendLine(ar.sock, "LAN2 HELLO")) {
        closesocket(ar.sock);
        if (err) { err->code = WSAGetLastError(); err->message = "Cannot send LAN2 HELLO"; }
        return nullptr;
    }
    std::string ready;
    if (!recvLine(ar.sock, &ready) || splitBySpace(ready).size() < 2
        || splitBySpace(ready)[0] != "LAN2" || splitBySpace(ready)[1] != "READY") {
        SFTP_LOG("LAN2", "No LAN2 READY, got: %s", ready.c_str());
        closesocket(ar.sock);
        if (err) { err->code = ERROR_INVALID_DATA; err->message = "No LAN2 READY response"; }
        return nullptr;
    }

    SFTP_LOG("LAN2", "LAN2 session established OK");
    impl->sock_      = ar.sock;
    impl->connected_ = true;
    return std::unique_ptr<LanPairSession>(new LanPairSession(std::move(impl)));
}

bool LanPairSession::isConnected() const noexcept {
    return impl_ && impl_->connected_;
}

void LanPairSession::disconnect() noexcept {
    if (impl_) impl_->close();
}

void LanPairSession::setTimeoutMin(int minutes) noexcept {
    if (impl_) impl_->timeoutMin_ = minutes;
}

bool LanPairSession::listRoots(std::vector<std::string>& roots) noexcept {
    if (!isConnected()) return false;
    roots.clear();

    SFTP_LOG("LAN2", "listRoots: sending ROOTS");
    const auto resp = impl_->cmd("ROOTS");
    SFTP_LOG("LAN2", "listRoots: resp[0]=%s count=%s",
             resp.empty() ? "(empty)" : resp[0].c_str(),
             resp.size() >= 2 ? resp[1].c_str() : "?");
    if (resp.empty() || resp[0] != "OK" || resp.size() < 2) return false;

    const int count = std::atoi(resp[1].c_str());
    for (int i = 0; i < count; ++i) {
        std::string line;
        if (!recvLine(impl_->sock_, &line)) { impl_->close(); return false; }
        roots.push_back(std::move(line));
    }
    return true;
}

bool LanPairSession::listDirectory(const std::string&     path,
                                   std::vector<DirEntry>& entries) noexcept
{
    if (!isConnected()) return false;
    entries.clear();

    const std::string cmd = "LIST " + b64EncodeStr(path);
    SFTP_LOG("LAN2", "listDirectory: path=%s", path.c_str());
    const auto resp = impl_->cmd(cmd);
    SFTP_LOG("LAN2", "listDirectory: resp[0]=%s count=%s",
             resp.empty() ? "(empty)" : resp[0].c_str(),
             resp.size() >= 2 ? resp[1].c_str() : "?");
    if (resp.empty() || resp[0] != "OK" || resp.size() < 2) return false;

    const int count = std::atoi(resp[1].c_str());
    for (int i = 0; i < count; ++i) {
        std::string line;
        if (!recvLine(impl_->sock_, &line)) { impl_->close(); return false; }
        // Format: <F|D> <size> <mtime_uint64> <attrs_hex> <b64_name>
        const auto parts = splitBySpace(line);
        if (parts.size() < 5) continue;

        DirEntry e;
        e.isDir    = (parts[0] == "D");
        e.size     = static_cast<int64_t>(std::strtoll(parts[1].c_str(), nullptr, 10));
        const uint64_t ft64 = std::strtoull(parts[2].c_str(), nullptr, 10);
        e.lastWrite.dwLowDateTime  = static_cast<DWORD>(ft64 & 0xFFFFFFFFu);
        e.lastWrite.dwHighDateTime = static_cast<DWORD>(ft64 >> 32);
        e.winAttrs = static_cast<DWORD>(std::strtoul(parts[3].c_str(), nullptr, 16));
        e.name     = b64DecodeStr(parts[4]);
        entries.push_back(std::move(e));
    }
    return true;
}

bool LanPairSession::getFile(const std::string& remotePath,
                             LPCWSTR            localPath,
                             int64_t            /*remoteSize*/,
                             const FILETIME* ft,
                             bool               overwrite,
                             bool               resume,
                             int* fsResult) noexcept
{
    if (fsResult) *fsResult = FS_FILE_READERROR;
    if (!isConnected()) return false;

    // Determine resume offset
    int64_t offset = 0;
    if (resume) {
        HANDLE hExist = CreateFileW(localPath, GENERIC_READ, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING, 0, nullptr);
        if (hExist != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz{};
            if (GetFileSizeEx(hExist, &sz)) offset = sz.QuadPart;
            CloseHandle(hExist);
        }
    }

    // Send GET command
    std::ostringstream req;
    req << "GET " << b64EncodeStr(remotePath) << " " << offset;
    const auto resp = impl_->cmd(req.str());
    if (resp.empty() || resp[0] != "OK" || resp.size() < 2) {
        if (fsResult) *fsResult = FS_FILE_READERROR;
        return false;
    }

    const int64_t dataSize = static_cast<int64_t>(
        std::strtoll(resp[1].c_str(), nullptr, 10));

    // Open local file
    const DWORD createDisp = resume ? OPEN_ALWAYS : (overwrite ? CREATE_ALWAYS : CREATE_NEW);
    HANDLE hLocal = CreateFileW(localPath, GENERIC_WRITE, 0, nullptr,
                                createDisp, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hLocal == INVALID_HANDLE_VALUE) {
        if (fsResult) *fsResult =
            (GetLastError() == ERROR_FILE_EXISTS) ? FS_FILE_EXISTS : FS_FILE_WRITEERROR;
        // Server already started sending; drain is impractical - close connection
        impl_->close();
        return false;
    }

    if (resume && offset > 0) {
        LARGE_INTEGER li{}; li.QuadPart = offset;
        SetFilePointerEx(hLocal, li, nullptr, FILE_END);
    }

    // Stream data
    constexpr size_t kChunk = 65536;
    std::vector<uint8_t> buf(kChunk);
    int64_t remaining = dataSize;
    bool ok = true;

    while (remaining > 0) {
        const size_t want = static_cast<size_t>(
            std::min<int64_t>(remaining, static_cast<int64_t>(kChunk)));
        if (!recvAll(impl_->sock_, buf.data(), want)) {
            ok = false;
            if (fsResult) *fsResult = FS_FILE_READERROR;
            break;
        }
        DWORD written = 0;
        if (!WriteFile(hLocal, buf.data(), static_cast<DWORD>(want), &written, nullptr)
            || written != static_cast<DWORD>(want)) {
            ok = false;
            if (fsResult) *fsResult = FS_FILE_WRITEERROR;
            break;
        }
        remaining -= static_cast<int64_t>(want);
    }

    if (ok && ft) {
        SetFileTime(hLocal, nullptr, nullptr, ft);
    }
    CloseHandle(hLocal);

    if (!ok) {
        impl_->close();
        DeleteFileW(localPath);
        return false;
    }

    if (fsResult) *fsResult = FS_FILE_OK;
    return true;
}

bool LanPairSession::putFile(LPCWSTR            localPath,
                             const std::string& remotePath,
                             bool               /*overwrite*/,
                             bool               /*resume*/,
                             int* fsResult) noexcept
{
    if (fsResult) *fsResult = FS_FILE_READERROR;
    if (!isConnected()) return false;

    HANDLE hLocal = CreateFileW(localPath, GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (hLocal == INVALID_HANDLE_VALUE) {
        if (fsResult) *fsResult = FS_FILE_NOTFOUND;
        return false;
    }

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(hLocal, &sz)) {
        CloseHandle(hLocal);
        if (fsResult) *fsResult = FS_FILE_READERROR;
        return false;
    }
    const int64_t fileSize = sz.QuadPart;

    // Send PUT command
    std::ostringstream req;
    req << "PUT " << b64EncodeStr(remotePath) << " " << fileSize;
    const auto resp = impl_->cmd(req.str());
    if (resp.empty() || resp[0] != "OK") {
        CloseHandle(hLocal);
        if (fsResult) *fsResult = FS_FILE_WRITEERROR;
        return false;
    }

    // Stream data
    constexpr size_t kChunk = 65536;
    std::vector<uint8_t> buf(kChunk);
    int64_t remaining = fileSize;
    bool ok = true;

    while (remaining > 0) {
        const DWORD want = static_cast<DWORD>(
            std::min<int64_t>(remaining, static_cast<int64_t>(kChunk)));
        DWORD bytesRead = 0;
        if (!ReadFile(hLocal, buf.data(), want, &bytesRead, nullptr) || bytesRead == 0) {
            ok = false;
            if (fsResult) *fsResult = FS_FILE_READERROR;
            break;
        }
        if (!sendAll(impl_->sock_, buf.data(), bytesRead)) {
            ok = false;
            if (fsResult) *fsResult = FS_FILE_WRITEERROR;
            break;
        }
        remaining -= static_cast<int64_t>(bytesRead);
    }
    CloseHandle(hLocal);

    if (!ok) { impl_->close(); return false; }

    // Await DONE from server
    std::string doneResp;
    if (!recvLine(impl_->sock_, &doneResp) || splitBySpace(doneResp)[0] != "DONE") {
        impl_->close();
        if (fsResult) *fsResult = FS_FILE_WRITEERROR;
        return false;
    }

    if (fsResult) *fsResult = FS_FILE_OK;
    return true;
}

bool LanPairSession::mkdir(const std::string& path) noexcept {
    if (!isConnected()) return false;
    const auto resp = impl_->cmd("MKDIR " + b64EncodeStr(path));
    return !resp.empty() && resp[0] == "OK";
}

bool LanPairSession::remove(const std::string& path) noexcept {
    if (!isConnected()) return false;
    const auto resp = impl_->cmd("DEL " + b64EncodeStr(path));
    return !resp.empty() && resp[0] == "OK";
}

bool LanPairSession::rename(const std::string& oldPath,
                            const std::string& newPath) noexcept {
    if (!isConnected()) return false;
    const std::string line = "REN " + b64EncodeStr(oldPath)
                           + " "   + b64EncodeStr(newPath);
    const auto resp = impl_->cmd(line);
    return !resp.empty() && resp[0] == "OK";
}

// ============================================================
// LanFileServer::Impl - server-side command loop
// ============================================================

struct LanFileServer::Impl : public std::enable_shared_from_this<Impl> {
    WsaScope            wsa;
    std::atomic<bool>   running_{false};
    SOCKET              listenSock_ = INVALID_SOCKET;
    std::thread         acceptThread_;
    std::string         serverPeerId_;
    uint16_t            port_         = 45846;
    mutable std::mutex  passwordMu_;
    std::string         password_;
    
    // Thread tracking for proper cleanup
    std::mutex          clientThreadsMu_;
    std::vector<std::thread> clientThreads_;

    // Per-connection server-side peer ID for trust-key lookup.
    static constexpr char kDefaultPeerId[] = "lanfilesrv";

    void closeListen() noexcept {
        running_ = false;
        if (listenSock_ != INVALID_SOCKET) {
            closesocket(listenSock_);
            listenSock_ = INVALID_SOCKET;
        }
        // Note: client threads manage their own sockets via shared_from_this
    }

    bool authenticateClient(SOCKET s, std::string& clientPeerId) noexcept {
        std::string line;
        if (!recvLine(s, &line)) return false;

        const auto hello = splitBySpace(line);
        if (hello.size() != 5 || hello[0] != "PAIR1" || hello[1] != "HELLO")
            return false;

        clientPeerId             = hello[2];
        const auto clientNonceHex = hello[4];
        const auto clientNonce    = hexDecode(clientNonceHex);
        if (!clientNonce || clientNonce->size() != kNonceSize) return false;

        std::array<uint8_t, kSaltSize>  salt{};
        std::array<uint8_t, kNonceSize> serverNonce{};
        if (!randomBytes(salt.data(), salt.size()) ||
            !randomBytes(serverNonce.data(), serverNonce.size()))
            return false;

        std::ostringstream ch;
        ch << "PAIR1 CHALLENGE "
           << serverPeerId_ << " "
           << escapeToken(serverPeerId_) << " "
           << roleToString(smb::PairRole::Receiver) << " "
           << hexEncode(salt.data(), salt.size()) << " "
           << hexEncode(serverNonce.data(), serverNonce.size());
        if (!sendLine(s, ch.str())) return false;

        if (!recvLine(s, &line)) return false;
        const auto auth = splitBySpace(line);

        const std::string serverNonceHex = hexEncode(serverNonce.data(), serverNonce.size());
        const std::string material    = "C|" + clientNonceHex + "|" + serverNonceHex
                                      + "|" + clientPeerId + "|" + serverPeerId_;
        const std::string materialSrv = "S|" + clientNonceHex + "|" + serverNonceHex
                                      + "|" + clientPeerId + "|" + serverPeerId_;

        std::vector<uint8_t> key;
        std::string issuedTrustHex;

        const std::string trustKey = trustKeyForServer(serverPeerId_, clientPeerId);

        if (auth.size() == 3 && auth[0] == "PAIR1" && auth[1] == "AUTH") {
            const auto verifyProof = [&](const std::vector<uint8_t>& k) -> bool {
                const auto expected = hmacSha256(k,
                    std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t*>(material.data()), material.size()));
                return expected && hexEncode(expected->data(), expected->size()) == auth[2];
            };

            std::string storedSecret;
            if (!smb::DpapiSecretStore::loadSecret(trustKey, &storedSecret, nullptr)) {
                sendLine(s, "PAIR1 FAIL trust-unknown");
                return false;
            }
            key.assign(storedSecret.begin(), storedSecret.end());
            if (!verifyProof(key)) {
                sendLine(s, "PAIR1 FAIL bad-auth");
                return false;
            }
        } else if (auth.size() == 2 && auth[0] == "PAIR1" && auth[1] == "TRUSTNEW") {
            std::array<uint8_t, kDerivedKeySize> fresh{};
            if (!randomBytes(fresh.data(), fresh.size())) return false;
            key.assign(fresh.begin(), fresh.end());
            issuedTrustHex = hexEncode(fresh.data(), fresh.size());
            std::string raw(reinterpret_cast<const char*>(fresh.data()), fresh.size());
            smb::DpapiSecretStore::saveSecret(trustKey, raw, nullptr);
        } else {
            sendLine(s, "PAIR1 FAIL bad-auth");
            return false;
        }

        const auto serverProof = hmacSha256(key,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(materialSrv.data()), materialSrv.size()));
        if (!serverProof) return false;

        std::ostringstream ok;
        if (!issuedTrustHex.empty()) {
            ok << "PAIR1 OKTRUST "
               << hexEncode(serverProof->data(), serverProof->size())
               << " " << issuedTrustHex;
        } else {
            ok << "PAIR1 OK " << hexEncode(serverProof->data(), serverProof->size());
        }
        return sendLine(s, ok.str());
    }

    void serveCommands(SOCKET s) noexcept {
        std::string line;
        while (recvLine(s, &line)) {
            const auto parts = splitBySpace(line);
            if (parts.empty()) continue;

            const std::string& cmd = parts[0];

            if (cmd == "QUIT") {
                sendLine(s, "BYE");
                break;
            }

            if (cmd == "ROOTS") {
                cmdRoots(s);
            } else if (cmd == "LIST" && parts.size() >= 2) {
                cmdList(s, b64DecodeStr(parts[1]));
            } else if (cmd == "GET" && parts.size() >= 3) {
                const int64_t offset = static_cast<int64_t>(
                    std::strtoll(parts[2].c_str(), nullptr, 10));
                cmdGet(s, b64DecodeStr(parts[1]), offset);
            } else if (cmd == "PUT" && parts.size() >= 3) {
                const int64_t size = static_cast<int64_t>(
                    std::strtoll(parts[2].c_str(), nullptr, 10));
                cmdPut(s, b64DecodeStr(parts[1]), size);
            } else if (cmd == "MKDIR" && parts.size() >= 2) {
                cmdMkdir(s, b64DecodeStr(parts[1]));
            } else if (cmd == "DEL" && parts.size() >= 2) {
                cmdDel(s, b64DecodeStr(parts[1]));
            } else if (cmd == "REN" && parts.size() >= 3) {
                cmdRen(s, b64DecodeStr(parts[1]), b64DecodeStr(parts[2]));
            } else {
                sendLine(s, "ERR unknown-command");
            }
        }
    }

    // Bezpieczna normalizacja ścieżki
    static std::string normPath(const std::string& p) {
        std::string res = p;
        std::replace(res.begin(), res.end(), '/', '\\');
        // Zabezpieczenie przed ucieczką z katalogu (Path Traversal)
        if (res.find("..") != std::string::npos) {
            return "C:\\INVALID_PATH_TRAVERSAL_DETECTED";
        }
        size_t i = 0;
        while (i < res.size() && res[i] == '\\') ++i;
        return res.substr(i);
    }

    void cmdRoots(SOCKET s) noexcept {
        const DWORD mask = GetLogicalDrives();
        std::vector<std::string> drives;
        for (int i = 0; i < 26; ++i) {
            if (mask & (1u << i)) {
                char drv[4] = { static_cast<char>('A' + i), ':', '\\', '\0' };
                drives.emplace_back(drv);
            }
        }
        std::ostringstream oss;
        oss << "OK " << drives.size();
        sendLine(s, oss.str());
        for (const auto& d : drives)
            sendLine(s, d);
    }

    void cmdList(SOCKET s, const std::string& path) noexcept {
        const std::wstring wpath = utf8ToWide(normPath(path));
        std::wstring glob = wpath;
        if (!glob.empty() && glob.back() != L'\\') glob += L'\\';
        glob += L'*';

        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(glob.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) {
            sendLine(s, "ERR not-found");
            return;
        }

        std::vector<std::string> lines;
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                 continue;

            const bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const int64_t size = isDir ? 0 :
                (static_cast<int64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
            const uint64_t ft64 =
                (static_cast<uint64_t>(fd.ftLastWriteTime.dwHighDateTime) << 32) |
                 fd.ftLastWriteTime.dwLowDateTime;

            std::string nameUtf8 = wideToUtf8(fd.cFileName);
            char attrBuf[16]{};
            sprintf_s(attrBuf, sizeof(attrBuf), "%X", fd.dwFileAttributes);

            std::ostringstream entry;
            entry << (isDir ? "D" : "F") << " "
                  << size << " "
                  << ft64 << " "
                  << attrBuf << " "
                  << b64EncodeStr(nameUtf8);
            lines.push_back(entry.str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);

        std::ostringstream hdr;
        hdr << "OK " << lines.size();
        sendLine(s, hdr.str());
        for (const auto& l : lines)
            sendLine(s, l);
    }

    void cmdGet(SOCKET s, const std::string& path, int64_t offset) noexcept {
        const std::wstring wpath = utf8ToWide(normPath(path));
        HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            sendLine(s, "ERR not-found");
            return;
        }

        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(h, &sz)) {
            CloseHandle(h);
            sendLine(s, "ERR stat-failed");
            return;
        }

        if (offset > 0) {
            LARGE_INTEGER li{}; li.QuadPart = offset;
            if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) {
                CloseHandle(h);
                sendLine(s, "ERR seek-failed");
                return;
            }
        }

        const int64_t dataSize = sz.QuadPart - offset;
        if (dataSize < 0) {
            CloseHandle(h);
            sendLine(s, "ERR bad-offset");
            return;
        }

        std::ostringstream resp;
        resp << "OK " << dataSize;
        if (!sendLine(s, resp.str())) { CloseHandle(h); return; }

        constexpr size_t kChunk = 65536;
        std::vector<uint8_t> buf(kChunk);
        int64_t remaining = dataSize;

        while (remaining > 0) {
            const DWORD want = static_cast<DWORD>(
                std::min<int64_t>(remaining, static_cast<int64_t>(kChunk)));
            DWORD bytesRead = 0;
            if (!ReadFile(h, buf.data(), want, &bytesRead, nullptr) || bytesRead == 0)
                break;
            if (!sendAll(s, buf.data(), bytesRead)) break;
            remaining -= static_cast<int64_t>(bytesRead);
        }
        CloseHandle(h);
    }

    void cmdPut(SOCKET s, const std::string& path, int64_t size) noexcept {
        const std::wstring wpath = utf8ToWide(normPath(path));
        HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            sendLine(s, "ERR open-failed");
            constexpr size_t kChunk = 65536;
            std::vector<uint8_t> discard(kChunk);
            int64_t rem = size;
            while (rem > 0) {
                const size_t want = static_cast<size_t>(
                    std::min<int64_t>(rem, static_cast<int64_t>(kChunk)));
                if (!recvAll(s, discard.data(), want)) return;
                rem -= static_cast<int64_t>(want);
            }
            return;
        }

        sendLine(s, "OK");

        constexpr size_t kChunk = 65536;
        std::vector<uint8_t> buf(kChunk);
        int64_t remaining = size;
        bool ok = true;

        while (remaining > 0) {
            const size_t want = static_cast<size_t>(
                std::min<int64_t>(remaining, static_cast<int64_t>(kChunk)));
            if (!recvAll(s, buf.data(), want)) { ok = false; break; }
            DWORD written = 0;
            if (!WriteFile(h, buf.data(), static_cast<DWORD>(want),
                           &written, nullptr) || written != static_cast<DWORD>(want)) {
                ok = false; break;
            }
            remaining -= static_cast<int64_t>(want);
        }
        CloseHandle(h);

        if (ok)
            sendLine(s, "DONE");
        else
            sendLine(s, "ERR write-failed");
    }

    void cmdMkdir(SOCKET s, const std::string& path) noexcept {
        const std::wstring wpath = utf8ToWide(normPath(path));
        if (CreateDirectoryW(wpath.c_str(), nullptr))
            sendLine(s, "OK");
        else
            sendLine(s, "ERR mkdir-failed");
    }

    void cmdDel(SOCKET s, const std::string& path) noexcept {
        const std::wstring wpath = utf8ToWide(normPath(path));
        const DWORD attr = GetFileAttributesW(wpath.c_str());
        bool ok = false;
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
            ok = (RemoveDirectoryW(wpath.c_str()) != 0);
        else
            ok = (DeleteFileW(wpath.c_str()) != 0);
        sendLine(s, ok ? "OK" : "ERR delete-failed");
    }

    void cmdRen(SOCKET s, const std::string& oldPath,
                          const std::string& newPath) noexcept {
        const std::wstring wold = utf8ToWide(normPath(oldPath));
        const std::wstring wnew = utf8ToWide(normPath(newPath));
        if (MoveFileExW(wold.c_str(), wnew.c_str(), MOVEFILE_REPLACE_EXISTING))
            sendLine(s, "OK");
        else
            sendLine(s, "ERR rename-failed");
    }

    // Entry point for each accepted connection (called on its own thread).
    void handleClient(SOCKET client) noexcept {
        // Enable TCP keepalive to prevent connection timeout during idle periods
        const BOOL keepAlive = TRUE;
        setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&keepAlive), sizeof(keepAlive));
        
        // Set longer timeout for file operations (5 minutes instead of 30s)
        setSocketTimeout(client, 300000);

        std::string clientPeerId;
        if (!authenticateClient(client, clientPeerId)) {
            closesocket(client);
            return;
        }

        // Wait for LAN2 HELLO from client before sending LAN2 READY.
        std::string helloLine;
        if (!recvLine(client, &helloLine)) { closesocket(client); return; }
        const auto hp = splitBySpace(helloLine);
        if (hp.size() < 2 || hp[0] != "LAN2" || hp[1] != "HELLO") {
            closesocket(client);
            return;
        }

        if (!sendLine(client, "LAN2 READY")) {
            closesocket(client);
            return;
        }

        serveCommands(client);
        closesocket(client);
    }

    void runAcceptLoop() noexcept {
        while (running_.load(std::memory_order_relaxed)) {
            sockaddr_in from{};
            int fromLen = sizeof(from);
            SOCKET client = accept(listenSock_,
                                   reinterpret_cast<sockaddr*>(&from), &fromLen);
            if (client == INVALID_SOCKET) continue;

            // Clean up finished threads before adding new one
            {
                std::lock_guard<std::mutex> lk(clientThreadsMu_);
                clientThreads_.erase(
                    std::remove_if(clientThreads_.begin(), clientThreads_.end(),
                                   [](std::thread& t) { return !t.joinable(); }),
                    clientThreads_.end());
            }

            // Use shared_from_this to prevent use-after-free
            auto self = shared_from_this();
            std::lock_guard<std::mutex> lk(clientThreadsMu_);
            clientThreads_.emplace_back([self, client] { 
                self->handleClient(client); 
            });
        }
    }
    
    // Join all client handler threads - called from stop()
    void joinClientThreads() noexcept {
        std::lock_guard<std::mutex> lk(clientThreadsMu_);
        for (auto& t : clientThreads_) {
            if (t.joinable())
                t.join();
        }
        clientThreads_.clear();
    }
};

// ============================================================
// LanFileServer public API
// ============================================================

LanFileServer::LanFileServer()
    : impl_(std::make_unique<Impl>()) {}

LanFileServer::~LanFileServer() { stop(); }

bool LanFileServer::start(uint16_t port, smb::PairError* err) noexcept {
    stop();

    if (!impl_->wsa.ok()) {
        if (err) { err->code = WSAGetLastError(); err->message = "WSAStartup failed"; }
        return false;
    }

    impl_->port_ = port;
    // Use machine hostname as peer ID — must match what discovery broadcasts.
    char host[256] = {};
    gethostname(host, static_cast<int>(sizeof(host) - 1));
    impl_->serverPeerId_ = host[0] ? std::string(host) : Impl::kDefaultPeerId;

    impl_->listenSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (impl_->listenSock_ == INVALID_SOCKET) {
        if (err) { err->code = WSAGetLastError(); err->message = "Cannot create listen socket"; }
        return false;
    }

    const BOOL yes = TRUE;
    setsockopt(impl_->listenSock_, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in bindAddr{};
    bindAddr.sin_family      = AF_INET;
    bindAddr.sin_port        = htons(port);
    bindAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(impl_->listenSock_,
             reinterpret_cast<const sockaddr*>(&bindAddr), sizeof(bindAddr)) != 0) {
        if (err) { err->code = WSAGetLastError(); err->message = "bind() failed"; }
        impl_->closeListen();
        return false;
    }

    if (listen(impl_->listenSock_, SOMAXCONN) != 0) {
        if (err) { err->code = WSAGetLastError(); err->message = "listen() failed"; }
        impl_->closeListen();
        return false;
    }

    impl_->running_ = true;
    impl_->acceptThread_ = std::thread([this] { impl_->runAcceptLoop(); });
    return true;
}

void LanFileServer::stop() noexcept {
    if (!impl_) return;
    impl_->running_ = false;
    impl_->closeListen();
    if (impl_->acceptThread_.joinable())
        impl_->acceptThread_.join();
    // Join all client handler threads to prevent use-after-free
    impl_->joinClientThreads();
}

bool LanFileServer::isRunning() const noexcept {
    return impl_ && impl_->running_.load(std::memory_order_relaxed);
}

void LanFileServer::setPassword(const std::string& password) noexcept {
    if (!impl_) return;
    std::lock_guard<std::mutex> lk(impl_->passwordMu_);
    impl_->password_ = password;
}

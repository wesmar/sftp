// ============================================================
// LanPairSession.cpp
// File-transfer session layer on top of the PAIR3 handshake
// (LanPairProtocol.h). After it the same TCP connection, now
// encrypted, carries a simple line-based command protocol (LAN2).
// ============================================================

#include "LanPairSession.h"
#include "LanPair.h"
#include "LanPairInternal.h"
#include "LanPairProtocol.h"
#include "DllExceptionBarrier.h"
#include "TrustedInstallerToken.h"

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
#include <memory>
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

namespace {

// Pull in all shared crypto / socket primitives.
using namespace lanpair_internal;

// ---- base64 ----

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
    static const uint8_t* kInv = []() -> const uint8_t* {
        static uint8_t t[256];
        for (int i = 0; i < 256; ++i) t[i] = 0xFF;
        for (int i = 0; i < 64; ++i)
            t[static_cast<unsigned char>(kB64Table[i])] = static_cast<uint8_t>(i);
        t[static_cast<unsigned char>('=')] = 0;
        return t;
    }();

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

// ---- Wide <-> UTF-8 helpers ----

std::string wideToUtf8(LPCWSTR wide) {
    if (!wide || !*wide) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, wide, -1,
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0,
                                      utf8.data(), static_cast<int>(utf8.size()),
                                      nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0,
                        utf8.data(), static_cast<int>(utf8.size()),
                        out.data(), n);
    return out;
}

// ---- PAIR3 client side ----
// Connects and runs the PAIR3 handshake (LanPairProtocol.h). The key comes
// from the password when there is one, otherwise from DPAPI, where an
// earlier session left it - and it is stored only once the peer has proved
// it knows the same key.
std::unique_ptr<lanpair_proto::Channel> pair3Connect(
    const std::string& targetIp,
    uint16_t           targetPort,
    const std::string& localPeerId,
    const std::string& remotePeerId,
    const std::string& password,
    lanpair::PairError* err) noexcept
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        if (err) { err->code = WSAGetLastError(); err->message = "Cannot create socket"; }
        return nullptr;
    }
    auto ch = std::make_unique<lanpair_proto::Channel>(s);
    setSocketTimeout(s, 8000);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(targetPort);
    if (inet_pton(AF_INET, targetIp.c_str(), &addr.sin_addr) != 1) {
        if (err) { err->code = ERROR_INVALID_ADDRESS; err->message = "Invalid target IP"; }
        return nullptr;
    }
    if (::connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        if (err) { err->code = WSAGetLastError(); err->message = "connect() failed"; }
        return nullptr;
    }
    const BOOL keepAlive = TRUE;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
               reinterpret_cast<const char*>(&keepAlive), sizeof(keepAlive));

    std::optional<lanpair_proto::KeyBytes> usedKey;
    const auto keyFor = [&](const std::string& serverId) -> std::optional<lanpair_proto::KeyBytes> {
        if (!password.empty()) {
            usedKey = derivePairKey(password, localPeerId, serverId);
            return usedKey;
        }
        std::string stored;
        if (lanpair::DpapiSecretStore::loadSecret(trustKeyForClient(serverId, localPeerId), &stored, nullptr) &&
            !stored.empty()) {
            usedKey = lanpair_proto::KeyBytes(stored.begin(), stored.end());
            SecureZeroMemory(stored.data(), stored.size());
        }
        return usedKey;
    };
    lanpair_proto::PeerInfo server;
    if (!lanpair_proto::ClientHandshake(*ch, localPeerId, lanpair::PairRole::Donor, remotePeerId, keyFor,
                                        &server, err))
        return nullptr;
    if (usedKey && !password.empty()) {
        const std::string raw(usedKey->begin(), usedKey->end());
        lanpair::DpapiSecretStore::saveSecret(trustKeyForClient(server.peerId, localPeerId), raw, nullptr);
    }
    return ch;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// PrepareLanPairTrustKeys — public API, outside anonymous namespace
// ---------------------------------------------------------------------------
bool PrepareLanPairTrustKeys(const std::string& localPeerId,
                              const std::string& remotePeerId,
                              const std::string& password) noexcept
{
    using namespace lanpair_internal;

    auto key = derivePairKey(password, localPeerId, remotePeerId);
    if (!key) return false;

    const std::string raw(reinterpret_cast<const char*>(key->data()), key->size());
    lanpair::DpapiSecretStore::saveSecret(trustKeyForClient(remotePeerId, localPeerId), raw, nullptr);
    lanpair::DpapiSecretStore::saveSecret(trustKeyForServer(localPeerId, remotePeerId), raw, nullptr);
    return true;
}

// ============================================================
// LanPairSession::Impl
// ============================================================

struct LanPairSession::Impl {
    lanpair_internal::WsaScope wsa;
    std::unique_ptr<lanpair_proto::Channel> ch_;
    bool     connected_  = false;
    int      timeoutMin_ = 0;
    std::chrono::steady_clock::time_point sessionStart_ = std::chrono::steady_clock::now();
    bool     trustedInstaller_ = false;

    bool isTimedOut() const noexcept {
        if (timeoutMin_ <= 0) return false;
        return std::chrono::steady_clock::now() - sessionStart_
               >= std::chrono::minutes(timeoutMin_);
    }

    void close() noexcept {
        if (ch_) {
            if (connected_)
                ch_->sendLine("QUIT"); // best-effort
            ch_.reset();
        }
        connected_ = false;
    }

    // Send a command line and return the response tokens.
    // Returns empty vector on I/O failure or session timeout.
    std::vector<std::string> cmd(const std::string& line) noexcept {
        if (isTimedOut()) { close(); return {}; }
        if (!ch_->sendLine(line)) { close(); return {}; }
        std::string resp;
        if (!ch_->recvLine(&resp)) { close(); return {}; }
        return splitBySpace(resp);
    }

    bool recvLine(std::string* out) noexcept {
        if (ch_ && ch_->recvLine(out))
            return true;
        close();
        return false;
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
    lanpair::PairError* err) noexcept
{
    auto impl = std::make_unique<Impl>();
    if (!impl->wsa.ok()) {
        if (err) { err->code = WSAGetLastError(); err->message = "WSAStartup failed"; }
        return nullptr;
    }

    SFTP_LOG("LAN2", "connect() -> PAIR3 %s:%u local=%s remote=%s",
             targetIp.c_str(), targetPort, localPeerId.c_str(), remotePeerId.c_str());
    auto ch = pair3Connect(targetIp, targetPort, localPeerId, remotePeerId, password, err);
    if (!ch) {
        SFTP_LOG("LAN2", "PAIR3 FAILED: %s", err ? err->message.c_str() : "?");
        return nullptr;
    }
    SFTP_LOG("LAN2", "PAIR3 OK, sending LAN2 HELLO");

    std::string ready;
    if (!ch->sendLine("LAN2 HELLO")) {
        if (err) { err->code = WSAGetLastError(); err->message = "Cannot send LAN2 HELLO"; }
        return nullptr;
    }
    const auto readyTokens = ch->recvLine(&ready) ? splitBySpace(ready) : std::vector<std::string>{};
    if (readyTokens.size() < 2 || readyTokens[0] != "LAN2" || readyTokens[1] != "READY") {
        SFTP_LOG("LAN2", "No LAN2 READY, got: %s", ready.c_str());
        if (err) { err->code = ERROR_INVALID_DATA; err->message = "No LAN2 READY response"; }
        return nullptr;
    }

    SFTP_LOG("LAN2", "LAN2 session established OK");
    impl->ch_        = std::move(ch);
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

void LanPairSession::setTrustedInstaller(bool enabled) noexcept {
    if (impl_) impl_->trustedInstaller_ = enabled;
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
        if (!impl_->recvLine(&line)) return false;
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
        if (!impl_->recvLine(&line)) return false;
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
                             const FILETIME*    ft,
                             bool               overwrite,
                             bool               resume,
                             int*               fsResult) noexcept
{
    if (fsResult) *fsResult = FS_FILE_READERROR;
    if (!isConnected()) return false;

    const bool tiAcquired = (impl_ && impl_->trustedInstaller_) && AcquireTrustedInstallerToken();
    struct TiScope { bool a; ~TiScope() { if (a) ReleaseTrustedInstallerToken(); } } tiScope{tiAcquired};

    int64_t offset = 0;
    if (resume) {
        HANDLE hExist = CreateFileW(localPath, GENERIC_READ, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (hExist != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz{};
            if (GetFileSizeEx(hExist, &sz)) offset = sz.QuadPart;
            CloseHandle(hExist);
        }
    }

    std::ostringstream req;
    req << "GET " << b64EncodeStr(remotePath) << " " << offset;
    const auto resp = impl_->cmd(req.str());
    if (resp.empty() || resp[0] != "OK" || resp.size() < 2) {
        if (fsResult) *fsResult = FS_FILE_READERROR;
        return false;
    }

    const int64_t dataSize = static_cast<int64_t>(
        std::strtoll(resp[1].c_str(), nullptr, 10));

    const DWORD createDisp = resume ? OPEN_ALWAYS : (overwrite ? CREATE_ALWAYS : CREATE_NEW);
    HANDLE hLocal = CreateFileW(localPath, GENERIC_WRITE, 0, nullptr,
                                createDisp, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hLocal == INVALID_HANDLE_VALUE) {
        if (fsResult) *fsResult =
            (GetLastError() == ERROR_FILE_EXISTS) ? FS_FILE_EXISTS : FS_FILE_WRITEERROR;
        impl_->close();
        return false;
    }

    // The peer sends from `offset` on, so writing resumes right there, at the
    // end of what the local file already holds.
    if (resume && offset > 0) {
        LARGE_INTEGER li{}; li.QuadPart = offset;
        if (!SetFilePointerEx(hLocal, li, nullptr, FILE_BEGIN)) {
            CloseHandle(hLocal);
            impl_->close();
            if (fsResult) *fsResult = FS_FILE_WRITEERROR;
            return false;
        }
    }

    constexpr size_t kChunk = 65536;
    std::vector<uint8_t> buf(kChunk);
    int64_t remaining = dataSize;
    bool ok = true;

    while (remaining > 0) {
        const size_t want = static_cast<size_t>(
            std::min<int64_t>(remaining, static_cast<int64_t>(kChunk)));
        if (!impl_->ch_->recvAll(buf.data(), want)) {
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

    if (ok && ft) SetFileTime(hLocal, nullptr, nullptr, ft);
    CloseHandle(hLocal);

    if (!ok) {
        impl_->close();
        // A file being resumed was there before this transfer and is the
        // user's; only one this transfer created is taken away.
        if (!resume)
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
                             int*               fsResult) noexcept
{
    if (fsResult) *fsResult = FS_FILE_READERROR;
    if (!isConnected()) return false;

    const bool tiAcquired = (impl_ && impl_->trustedInstaller_) && AcquireTrustedInstallerToken();
    struct TiScope { bool a; ~TiScope() { if (a) ReleaseTrustedInstallerToken(); } } tiScope{tiAcquired};

    HANDLE hLocal = CreateFileW(localPath, GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
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

    std::ostringstream req;
    req << "PUT " << b64EncodeStr(remotePath) << " " << fileSize;
    const auto resp = impl_->cmd(req.str());
    if (resp.empty() || resp[0] != "OK") {
        CloseHandle(hLocal);
        if (fsResult) *fsResult = FS_FILE_WRITEERROR;
        return false;
    }

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
        if (!impl_->ch_->sendAll(buf.data(), bytesRead)) {
            ok = false;
            if (fsResult) *fsResult = FS_FILE_WRITEERROR;
            break;
        }
        remaining -= static_cast<int64_t>(bytesRead);
    }
    CloseHandle(hLocal);

    if (!ok) { impl_->close(); return false; }

    std::string doneResp;
    if (!impl_->ch_->recvLine(&doneResp) || doneResp.rfind("DONE", 0) != 0) {
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
                            const std::string& newPath,
                            bool               overwrite,
                            bool*              exists) noexcept {
    if (exists) *exists = false;
    if (!isConnected()) return false;
    // The trailing flag says whether a taken destination may be replaced.
    // A peer that predates it ignores the extra token and replaces as it
    // always did.
    const std::string line = "REN " + b64EncodeStr(oldPath)
                           + " "   + b64EncodeStr(newPath)
                           + (overwrite ? " 1" : " 0");
    const auto resp = impl_->cmd(line);
    if (!resp.empty() && resp[0] == "OK")
        return true;
    if (exists && resp.size() >= 2 && resp[0] == "ERR" && resp[1] == "exists")
        *exists = true;
    return false;
}

// ============================================================
// LanFileServer::Impl - server-side command loop
// ============================================================

struct LanFileServer::Impl : public std::enable_shared_from_this<Impl> {
    lanpair_internal::WsaScope wsa;
    std::atomic<bool>   running_{false};
    SOCKET              listenSock_ = INVALID_SOCKET;
    std::thread         acceptThread_;
    std::string         serverPeerId_;
    uint16_t            port_         = 45846;
    mutable std::mutex  passwordMu_;
    std::string         password_;
    std::atomic<bool>   trustedInstaller_{false};

    // A finished std::thread stays joinable until someone joins it, so the
    // thread object cannot say on its own whether the work is over. The flag
    // does, and the accept loop uses it to clear out the ones that are done.
    struct ClientWorker {
        std::thread                        thread;
        std::shared_ptr<std::atomic<bool>> done;
    };

    std::mutex                clientThreadsMu_;
    std::vector<ClientWorker> clientThreads_;

    static constexpr char kDefaultPeerId[] = "lanfilesrv";

    void closeListen() {
        running_ = false;
        if (listenSock_ != INVALID_SOCKET) {
            closesocket(listenSock_);
            listenSock_ = INVALID_SOCKET;
        }
    }

    // PAIR3: the client proves the pair key and gets an encrypted channel.
    // The key stored for this peer comes first - pairing keeps it current -
    // and the password set for this server stands in when there is none.
    bool authenticateClient(lanpair_proto::Channel& ch, std::string& clientPeerId) {
        std::optional<lanpair_proto::KeyBytes> usedKey;
        bool fromPassword = false;
        const auto keyFor = [&](const std::string& peerId) -> std::optional<lanpair_proto::KeyBytes> {
            std::string stored;
            if (lanpair::DpapiSecretStore::loadSecret(trustKeyForServer(serverPeerId_, peerId), &stored, nullptr) &&
                !stored.empty()) {
                usedKey = lanpair_proto::KeyBytes(stored.begin(), stored.end());
                SecureZeroMemory(stored.data(), stored.size());
                return usedKey;
            }
            std::lock_guard<std::mutex> lk(passwordMu_);
            if (!password_.empty()) {
                usedKey = derivePairKey(password_, serverPeerId_, peerId);
                fromPassword = usedKey.has_value();
            }
            return usedKey;
        };
        lanpair_proto::PeerInfo client;
        if (!lanpair_proto::ServerHandshake(ch, serverPeerId_, serverPeerId_, lanpair::PairRole::Receiver,
                                            keyFor, &client))
            return false;
        if (fromPassword) {
            const std::string raw(usedKey->begin(), usedKey->end());
            lanpair::DpapiSecretStore::saveSecret(trustKeyForServer(serverPeerId_, client.peerId), raw, nullptr);
        }
        clientPeerId = client.peerId;
        return true;
    }

    void serveCommands(lanpair_proto::Channel& ch) {
        std::string line;
        while (ch.recvLine(&line)) {
            const auto parts = splitBySpace(line);
            if (parts.empty()) continue;

            const std::string& cmd = parts[0];

            if (cmd == "QUIT") {
                ch.sendLine("BYE");
                break;
            } else if (cmd == "ROOTS") {
                cmdRoots(ch);
            } else if (cmd == "LIST" && parts.size() >= 2) {
                cmdList(ch, b64DecodeStr(parts[1]));
            } else if (cmd == "GET" && parts.size() >= 3) {
                const int64_t offset = static_cast<int64_t>(
                    std::strtoll(parts[2].c_str(), nullptr, 10));
                cmdGet(ch, b64DecodeStr(parts[1]), offset);
            } else if (cmd == "PUT" && parts.size() >= 3) {
                const int64_t size = static_cast<int64_t>(
                    std::strtoll(parts[2].c_str(), nullptr, 10));
                cmdPut(ch, b64DecodeStr(parts[1]), size);
            } else if (cmd == "MKDIR" && parts.size() >= 2) {
                cmdMkdir(ch, b64DecodeStr(parts[1]));
            } else if (cmd == "DEL" && parts.size() >= 2) {
                cmdDel(ch, b64DecodeStr(parts[1]));
            } else if (cmd == "REN" && parts.size() >= 3) {
                // Replacing needs the flag spelled out; a client too old to
                // send it never asked the user, so it gets a refusal.
                const bool replace = parts.size() >= 4 && parts[3] == "1";
                cmdRen(ch, b64DecodeStr(parts[1]), b64DecodeStr(parts[2]), replace);
            } else {
                ch.sendLine("ERR unknown-command");
            }
        }
    }

    // Safe path normalization — blocks path traversal.
    static std::string normPath(const std::string& p) {
        std::string res = p;
        std::replace(res.begin(), res.end(), '/', '\\');
        if (res.find("..") != std::string::npos)
            return "C:\\INVALID_PATH_TRAVERSAL_DETECTED";
        size_t i = 0;
        while (i < res.size() && res[i] == '\\') ++i;
        return res.substr(i);
    }

    void cmdRoots(lanpair_proto::Channel& ch) {
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
        ch.sendLine(oss.str());
        for (const auto& d : drives) ch.sendLine(d);
    }

    void cmdList(lanpair_proto::Channel& ch, const std::string& path) {
        const std::wstring wpath = utf8ToWide(normPath(path));
        std::wstring glob = wpath;
        if (!glob.empty() && glob.back() != L'\\') glob += L'\\';
        glob += L'*';

        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(glob.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) {
            ch.sendLine("ERR not-found");
            return;
        }

        std::vector<std::string> lines;
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                continue;

            const bool    isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const int64_t size  = isDir ? 0 :
                (static_cast<int64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
            const uint64_t ft64 =
                (static_cast<uint64_t>(fd.ftLastWriteTime.dwHighDateTime) << 32) |
                 fd.ftLastWriteTime.dwLowDateTime;

            char attrBuf[16]{};
            sprintf_s(attrBuf, sizeof(attrBuf), "%X", fd.dwFileAttributes);

            std::ostringstream entry;
            entry << (isDir ? "D" : "F") << " "
                  << size << " " << ft64 << " "
                  << attrBuf << " "
                  << b64EncodeStr(wideToUtf8(fd.cFileName));
            lines.push_back(entry.str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);

        std::ostringstream hdr;
        hdr << "OK " << lines.size();
        ch.sendLine(hdr.str());
        for (const auto& l : lines) ch.sendLine(l);
    }

    void cmdGet(lanpair_proto::Channel& ch, const std::string& path, int64_t offset) {
        const std::wstring wpath = utf8ToWide(normPath(path));
        HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (h == INVALID_HANDLE_VALUE) { ch.sendLine("ERR not-found"); return; }

        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); ch.sendLine("ERR stat-failed"); return; }

        if (offset > 0) {
            LARGE_INTEGER li{}; li.QuadPart = offset;
            if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) {
                CloseHandle(h); ch.sendLine("ERR seek-failed"); return;
            }
        }

        const int64_t dataSize = sz.QuadPart - offset;
        if (dataSize < 0) { CloseHandle(h); ch.sendLine("ERR bad-offset"); return; }

        std::ostringstream resp;
        resp << "OK " << dataSize;
        if (!ch.sendLine(resp.str())) { CloseHandle(h); return; }

        constexpr size_t kChunk = 65536;
        std::vector<uint8_t> buf(kChunk);
        int64_t remaining = dataSize;
        while (remaining > 0) {
            const DWORD want = static_cast<DWORD>(
                std::min<int64_t>(remaining, static_cast<int64_t>(kChunk)));
            DWORD bytesRead = 0;
            if (!ReadFile(h, buf.data(), want, &bytesRead, nullptr) || bytesRead == 0) break;
            if (!ch.sendAll(buf.data(), bytesRead)) break;
            remaining -= static_cast<int64_t>(bytesRead);
        }
        CloseHandle(h);
    }

    void cmdPut(lanpair_proto::Channel& ch, const std::string& path, int64_t size) {
        const std::wstring wpath = utf8ToWide(normPath(path));
        HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            // Client sends data only AFTER receiving "OK", so nothing to drain here.
            ch.sendLine("ERR open-failed");
            return;
        }

        ch.sendLine("OK");

        constexpr size_t kChunk = 65536;
        std::vector<uint8_t> buf(kChunk);
        int64_t remaining = size;
        bool ok = true;
        while (remaining > 0) {
            const size_t want = static_cast<size_t>(
                std::min<int64_t>(remaining, static_cast<int64_t>(kChunk)));
            if (!ch.recvAll(buf.data(), want)) { ok = false; break; }
            DWORD written = 0;
            if (!WriteFile(h, buf.data(), static_cast<DWORD>(want),
                           &written, nullptr) || written != static_cast<DWORD>(want)) {
                ok = false; break;
            }
            remaining -= static_cast<int64_t>(want);
        }
        CloseHandle(h);
        ch.sendLine(ok ? "DONE" : "ERR write-failed");
    }

    void cmdMkdir(lanpair_proto::Channel& ch, const std::string& path) {
        const std::wstring wpath = utf8ToWide(normPath(path));
        ch.sendLine(CreateDirectoryW(wpath.c_str(), nullptr) ? "OK" : "ERR mkdir-failed");
    }

    void cmdDel(lanpair_proto::Channel& ch, const std::string& path) {
        const std::wstring wpath = utf8ToWide(normPath(path));
        const DWORD attr = GetFileAttributesW(wpath.c_str());
        bool ok = false;
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
            ok = (RemoveDirectoryW(wpath.c_str()) != 0);
        else
            ok = (DeleteFileW(wpath.c_str()) != 0);
        ch.sendLine(ok ? "OK" : "ERR delete-failed");
    }

    void cmdRen(lanpair_proto::Channel& ch, const std::string& oldPath,
                          const std::string& newPath, bool replace) noexcept {
        const std::wstring wold = utf8ToWide(normPath(oldPath));
        const std::wstring wnew = utf8ToWide(normPath(newPath));
        if (MoveFileExW(wold.c_str(), wnew.c_str(), replace ? MOVEFILE_REPLACE_EXISTING : 0)) {
            ch.sendLine("OK");
            return;
        }
        const DWORD err = GetLastError();
        ch.sendLine((!replace && (err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS))
                        ? "ERR exists" : "ERR rename-failed");
    }

    void handleClient(SOCKET client) {
        lanpair_proto::Channel ch(client); // closes the socket when done
        const BOOL keepAlive = TRUE;
        setsockopt(client, SOL_SOCKET, SO_KEEPALIVE,
                   reinterpret_cast<const char*>(&keepAlive), sizeof(keepAlive));
        setSocketTimeout(client, 300000); // 5 minutes for file operations

        // The handshake runs as the user, whose DPAPI holds the pair keys;
        // TrustedInstaller, when enabled, is for the file operations only.
        std::string clientPeerId;
        if (!authenticateClient(ch, clientPeerId))
            return;

        std::string helloLine;
        if (!ch.recvLine(&helloLine)) return;
        const auto hp = splitBySpace(helloLine);
        if (hp.size() < 2 || hp[0] != "LAN2" || hp[1] != "HELLO")
            return;
        if (!ch.sendLine("LAN2 READY")) return;

        // RevertToSelf, not ReleaseTrustedInstallerToken: that one clears a
        // process-wide flag other threads may still be impersonating under.
        const bool ti = trustedInstaller_.load(std::memory_order_relaxed) && AcquireTrustedInstallerToken();
        serveCommands(ch);
        if (ti)
            RevertToSelf();
    }
    void runAcceptLoop() {
        while (running_.load(std::memory_order_relaxed)) {
            sockaddr_in from{};
            int fromLen = sizeof(from);
            SOCKET client = accept(listenSock_,
                                   reinterpret_cast<sockaddr*>(&from), &fromLen);
            if (client == INVALID_SOCKET) continue;

            {
                std::lock_guard<std::mutex> lk(clientThreadsMu_);
                for (auto& w : clientThreads_) {
                    if (w.done->load(std::memory_order_acquire) && w.thread.joinable())
                        w.thread.join();
                }
                clientThreads_.erase(
                    std::remove_if(clientThreads_.begin(), clientThreads_.end(),
                                   [](const ClientWorker& w) { return !w.thread.joinable(); }),
                    clientThreads_.end());
            }

            auto self = shared_from_this();
            auto done = std::make_shared<std::atomic<bool>>(false);
            std::lock_guard<std::mutex> lk(clientThreadsMu_);
            clientThreads_.push_back(ClientWorker{
                std::thread([self, client, done] {
                    {
                        sftp::DllExceptionBarrier barrier;
                        sftp::dll_invoke_void(barrier, [self, client] { self->handleClient(client); });
                    }
                    done->store(true, std::memory_order_release);
                }),
                std::move(done)});
        }
    }

    void joinClientThreads() {
        std::lock_guard<std::mutex> lk(clientThreadsMu_);
        for (auto& w : clientThreads_)
            if (w.thread.joinable()) w.thread.join();
        clientThreads_.clear();
    }
};

// ============================================================
// LanFileServer public API
// ============================================================

LanFileServer::LanFileServer()
    : impl_(std::make_shared<Impl>()) {}

LanFileServer::~LanFileServer() { stop(); }

bool LanFileServer::start(uint16_t port, lanpair::PairError* err,
                          const char* bindAddress, const std::string& peerId) noexcept {
    stop();

    if (!impl_->wsa.ok()) {
        if (err) { err->code = WSAGetLastError(); err->message = "WSAStartup failed"; }
        return false;
    }

    impl_->port_ = port;
    char host[256] = {};
    gethostname(host, static_cast<int>(sizeof(host) - 1));
    impl_->serverPeerId_ = !peerId.empty() ? peerId : host[0] ? std::string(host) : Impl::kDefaultPeerId;

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
    if (bindAddress && inet_pton(AF_INET, bindAddress, &bindAddr.sin_addr) != 1) {
        if (err) { err->code = ERROR_INVALID_ADDRESS; err->message = "Invalid bind address"; }
        impl_->closeListen();
        return false;
    }

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
    impl_->acceptThread_ = std::thread([this] {
        sftp::DllExceptionBarrier barrier;
        sftp::dll_invoke_void(barrier, [this] { impl_->runAcceptLoop(); });
    });
    return true;
}

void LanFileServer::stop() noexcept {
    if (!impl_) return;
    impl_->running_ = false;
    impl_->closeListen();
    if (impl_->acceptThread_.joinable())
        impl_->acceptThread_.join();
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

void LanFileServer::setTrustedInstaller(bool enabled) noexcept {
    if (!impl_) return;
    impl_->trustedInstaller_.store(enabled, std::memory_order_relaxed);
}

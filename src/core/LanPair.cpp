#include "LanPair.h"
#include "LanPairInternal.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <wincrypt.h>

#pragma comment(lib, "Iphlpapi.lib")

#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

namespace smb {
namespace {

// Pull in all shared primitives from LanPairInternal.h.
using namespace lanpair_internal;

// ---- helpers local to LanPair.cpp ----

void setErr(PairError* err, int code, std::string message) {
    if (!err) return;
    err->code    = code;
    err->message = std::move(message);
}

std::string unescapeToken(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            const auto decoded = hexDecode(in.substr(i + 1, 2));
            if (decoded && decoded->size() == 1) {
                out.push_back(static_cast<char>((*decoded)[0]));
                i += 2;
                continue;
            }
        }
        out.push_back(in[i]);
    }
    return out;
}

std::string roleToString(PairRole role) {
    switch (role) {
    case PairRole::Donor:    return "donor";
    case PairRole::Receiver: return "receiver";
    case PairRole::Dual:     return "dual";
    }
    return "dual";
}

PairRole roleFromString(const std::string& s) {
    if (s == "donor")    return PairRole::Donor;
    if (s == "receiver") return PairRole::Receiver;
    return PairRole::Dual;
}

std::string getHostNameSafe() {
    char buf[256] = {};
    if (gethostname(buf, static_cast<int>(sizeof(buf) - 1)) == 0)
        return buf;
    return "host";
}

std::filesystem::path secretsDir() {
    const char* appData = std::getenv("APPDATA");
    if (!appData || !*appData)
        return std::filesystem::temp_directory_path() / "sftpplug.secrets";
    return std::filesystem::path(appData) / "GHISLER" / "sftpplug.secrets";
}

std::optional<std::vector<uint8_t>> dpapiProtect(std::span<const uint8_t> plain) {
    DATA_BLOB in{};
    in.pbData = const_cast<BYTE*>(plain.data());
    in.cbData = static_cast<DWORD>(plain.size());

    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"sftpplug-lanpair", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &out))
        return std::nullopt;

    std::vector<uint8_t> enc(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return enc;
}

std::optional<std::vector<uint8_t>> dpapiUnprotect(std::span<const uint8_t> cipher) {
    DATA_BLOB in{};
    in.pbData = const_cast<BYTE*>(cipher.data());
    in.cbData = static_cast<DWORD>(cipher.size());

    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &out))
        return std::nullopt;

    std::vector<uint8_t> plain(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return plain;
}

} // anonymous namespace

struct DiscoveryService::Impl {
    WsaScope wsa;
    DiscoveryConfig cfg;
    std::string peerId;
    std::string displayName;
    PairRole role = PairRole::Dual;
    AnnouncementHandler onPeer;

    std::atomic<bool> stop{false};
    SOCKET txSock = INVALID_SOCKET;
    SOCKET rxSock = INVALID_SOCKET;
    std::thread txThread;
    std::thread rxThread;

    std::mutex peersMu;
    std::unordered_map<std::string, PeerAnnouncement> peers;

    void closeSockets() {
        if (txSock != INVALID_SOCKET) { closesocket(txSock); txSock = INVALID_SOCKET; }
        if (rxSock != INVALID_SOCKET) { closesocket(rxSock); rxSock = INVALID_SOCKET; }
    }

    std::string buildAnnouncement() const {
        std::ostringstream oss;
        oss << cfg.appTag << " ANN "
            << peerId << " "
            << escapeToken(displayName) << " "
            << escapeToken(getHostNameSafe()) << " "
            << roleToString(role) << " "
            << cfg.tcpPort;
        return oss.str();
    }

    void runBroadcast() {
        const std::string msg = buildAnnouncement();

        while (!stop.load(std::memory_order_relaxed)) {
            // Enumerate all up IPv4 adapters and send a directed subnet broadcast
            // on each one so discovery works across multiple NICs, VPNs, and WiFi+Ethernet.
            bool sentAny = false;
            ULONG bufSize = 20000;
            std::vector<uint8_t> adapterBuf;
            PIP_ADAPTER_ADDRESSES addrs = nullptr;
            for (int attempt = 0; attempt < 3; ++attempt) {
                adapterBuf.resize(bufSize);
                addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(adapterBuf.data());
                DWORD rv = GetAdaptersAddresses(
                    AF_INET,
                    GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER |
                    GAA_FLAG_SKIP_FRIENDLY_NAME,
                    nullptr, addrs, &bufSize);
                if (rv == ERROR_SUCCESS) break;
                if (rv == ERROR_BUFFER_OVERFLOW) { adapterBuf.clear(); continue; }
                addrs = nullptr; break;
            }

            if (addrs) {
                for (PIP_ADAPTER_ADDRESSES a = addrs; a; a = a->Next) {
                    if (a->OperStatus != IfOperStatusUp) continue;
                    if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

                    for (PIP_ADAPTER_UNICAST_ADDRESS ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                        if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;

                        auto* sin = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                        DWORD prefixLen = ua->OnLinkPrefixLength;
                        uint32_t ip   = ntohl(sin->sin_addr.s_addr);
                        uint32_t mask = prefixLen ? (~0u << (32 - prefixLen)) : 0u;
                        uint32_t bcast = (ip & mask) | ~mask;

                        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                        if (sock == INVALID_SOCKET) continue;

                        const BOOL yes = TRUE;
                        setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
                                   reinterpret_cast<const char*>(&yes), sizeof(yes));

                        sockaddr_in bindAddr{};
                        bindAddr.sin_family      = AF_INET;
                        bindAddr.sin_port        = 0;
                        bindAddr.sin_addr.s_addr = sin->sin_addr.s_addr;

                        if (bind(sock, reinterpret_cast<const sockaddr*>(&bindAddr),
                                 sizeof(bindAddr)) == 0) {
                            sockaddr_in bcastAddr{};
                            bcastAddr.sin_family      = AF_INET;
                            bcastAddr.sin_port        = htons(cfg.udpPort);
                            bcastAddr.sin_addr.s_addr = htonl(bcast);
                            sendto(sock, msg.c_str(), static_cast<int>(msg.size()), 0,
                                   reinterpret_cast<const sockaddr*>(&bcastAddr),
                                   sizeof(bcastAddr));
                            sentAny = true;
                        }
                        closesocket(sock);
                    }
                }
            }

            // Fallback to global broadcast if adapter enumeration failed.
            if (!sentAny && txSock != INVALID_SOCKET) {
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port   = htons(cfg.udpPort);
                inet_pton(AF_INET, "255.255.255.255", &addr.sin_addr);
                sendto(txSock, msg.c_str(), static_cast<int>(msg.size()), 0,
                       reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
            }

            std::this_thread::sleep_for(cfg.broadcastInterval);
        }
    }

    void runListen() {
        std::array<char, 1024> buf{};
        while (!stop.load(std::memory_order_relaxed)) {
            sockaddr_in from{};
            int fromLen = sizeof(from);
            const int n = recvfrom(rxSock, buf.data(), static_cast<int>(buf.size() - 1), 0,
                                   reinterpret_cast<sockaddr*>(&from), &fromLen);
            if (n <= 0) continue;
            buf[static_cast<size_t>(n)] = 0;

            const std::string line(buf.data());
            const auto parts = splitBySpace(line);
            if (parts.size() != 7) continue;
            if (parts[0] != cfg.appTag || parts[1] != "ANN") continue;
            if (parts[2] == peerId) continue;

            char ip[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));

            PeerAnnouncement ann;
            ann.peerId      = parts[2];
            ann.displayName = unescapeToken(parts[3]); // UTF-8
            ann.hostName    = unescapeToken(parts[4]); // UTF-8
            ann.role        = roleFromString(parts[5]);
            ann.tcpPort     = static_cast<uint16_t>(std::strtoul(parts[6].c_str(), nullptr, 10));
            ann.ip          = ip;
            ann.lastSeen    = std::chrono::steady_clock::now();

            {
                const std::lock_guard<std::mutex> lock(peersMu);
                peers[ann.peerId] = ann;
            }
            if (onPeer) onPeer(ann);
        }
    }
};

DiscoveryService::DiscoveryService() : impl_(std::make_unique<Impl>()) {}
DiscoveryService::~DiscoveryService() { stop(); }

bool DiscoveryService::start(const DiscoveryConfig& cfg,
                             const std::string& peerId,
                             const std::string& displayName,
                             PairRole role,
                             AnnouncementHandler onPeer,
                             PairError* err) {
    stop();

    impl_->cfg         = cfg;
    impl_->peerId      = peerId;
    impl_->displayName = displayName.empty() ? getHostNameSafe() : displayName;
    impl_->role        = role;
    impl_->onPeer      = std::move(onPeer);
    impl_->stop        = false;

    if (!impl_->wsa.ok()) {
        setErr(err, WSAGetLastError(), "WSAStartup failed");
        return false;
    }

    impl_->txSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    impl_->rxSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (impl_->txSock == INVALID_SOCKET || impl_->rxSock == INVALID_SOCKET) {
        setErr(err, WSAGetLastError(), "Cannot create UDP sockets");
        stop();
        return false;
    }

    const BOOL yes = TRUE;
    setsockopt(impl_->txSock, SOL_SOCKET, SO_BROADCAST,
               reinterpret_cast<const char*>(&yes), sizeof(yes));
    setsockopt(impl_->rxSock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port   = htons(cfg.udpPort);
    inet_pton(AF_INET, cfg.bindAddress.c_str(), &bindAddr.sin_addr);

    if (bind(impl_->rxSock,
             reinterpret_cast<const sockaddr*>(&bindAddr), sizeof(bindAddr)) != 0) {
        setErr(err, WSAGetLastError(), "Cannot bind discovery UDP socket");
        stop();
        return false;
    }

    impl_->txThread = std::thread([this] { impl_->runBroadcast(); });
    impl_->rxThread = std::thread([this] { impl_->runListen(); });
    return true;
}

void DiscoveryService::stop() {
    if (!impl_) return;
    impl_->stop = true;
    impl_->closeSockets();
    if (impl_->txThread.joinable()) impl_->txThread.join();
    if (impl_->rxThread.joinable()) impl_->rxThread.join();
}

struct PairServer::Impl {
    WsaScope wsa;
    PairServerConfig cfg;
    AcceptHandler onAccepted;

    std::atomic<bool> stop{false};
    SOCKET listenSock = INVALID_SOCKET;
    std::thread acceptThread;

    void closeListen() {
        if (listenSock != INVALID_SOCKET) {
            closesocket(listenSock);
            listenSock = INVALID_SOCKET;
        }
    }

    bool authenticateClient(SOCKET s, PairSessionInfo* info) {
        std::string line;
        if (!recvLine(s, &line)) return false;

        const auto hello = splitBySpace(line);
        if (hello.size() != 5 || hello[0] != "PAIR1" || hello[1] != "HELLO")
            return false;

        const std::string clientPeerId    = hello[2];
        const PairRole    clientRole      = roleFromString(hello[3]);
        const auto        clientNonceHex  = hello[4];
        const auto        clientNonce     = hexDecode(clientNonceHex);
        if (!clientNonce || clientNonce->size() != kNonceSize) return false;

        std::array<uint8_t, kSaltSize>  salt{};
        std::array<uint8_t, kNonceSize> serverNonce{};
        if (!randomBytes(salt.data(), salt.size()) ||
            !randomBytes(serverNonce.data(), serverNonce.size()))
            return false;

        std::ostringstream ch;
        ch << "PAIR1 CHALLENGE "
           << cfg.peerId << " "
           << escapeToken(cfg.displayName) << " "
           << roleToString(cfg.role) << " "
           << hexEncode(salt.data(), salt.size()) << " "
           << hexEncode(serverNonce.data(), serverNonce.size());

        if (!sendLine(s, ch.str())) return false;
        if (!recvLine(s, &line))    return false;

        const auto auth = splitBySpace(line);
        std::vector<uint8_t> key;
        std::string issuedTrustHex;

        const std::string material = "C|" + clientNonceHex + "|" +
            hexEncode(serverNonce.data(), serverNonce.size()) + "|" +
            clientPeerId + "|" + cfg.peerId;
        const std::string materialSrv = "S|" + clientNonceHex + "|" +
            hexEncode(serverNonce.data(), serverNonce.size()) + "|" +
            clientPeerId + "|" + cfg.peerId;

        if (!cfg.password.empty()) {
            if (auth.size() != 3 || auth[0] != "PAIR1" || auth[1] != "AUTH")
                return false;
            const auto derived = deriveKeyPbkdf2(cfg.password, salt, kDerivedKeySize);
            if (!derived) return false;
            key = *derived;
            const auto expected = hmacSha256(key,
                std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(material.data()), material.size()));
            if (!expected) return false;
            if (hexEncode(expected->data(), expected->size()) != auth[2]) {
                sendLine(s, "PAIR1 FAIL bad-auth");
                return false;
            }
        } else {
            const std::string trustKey = trustKeyForServer(cfg.peerId, clientPeerId);
            std::string storedSecret;
            const bool haveTrust = DpapiSecretStore::loadSecret(trustKey, &storedSecret, nullptr);
            if (haveTrust) {
                if (auth.size() != 3 || auth[0] != "PAIR1" || auth[1] != "AUTH")
                    return false;
                key.assign(storedSecret.begin(), storedSecret.end());
                const auto expected = hmacSha256(key,
                    std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t*>(material.data()), material.size()));
                if (!expected) return false;
                if (hexEncode(expected->data(), expected->size()) != auth[2]) {
                    sendLine(s, "PAIR1 FAIL bad-trust");
                    return false;
                }
            } else {
                if (auth.size() != 2 || auth[0] != "PAIR1" || auth[1] != "TRUSTNEW") {
                    sendLine(s, "PAIR1 FAIL trust-required");
                    return false;
                }
                std::array<uint8_t, kDerivedKeySize> fresh{};
                if (!randomBytes(fresh.data(), fresh.size())) return false;
                key.assign(fresh.begin(), fresh.end());
                issuedTrustHex = hexEncode(fresh.data(), fresh.size());
                std::string secret(reinterpret_cast<const char*>(fresh.data()), fresh.size());
                DpapiSecretStore::saveSecret(trustKey, secret, nullptr);
            }
        }

        const auto serverProof = hmacSha256(key,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(materialSrv.data()), materialSrv.size()));
        if (!serverProof) return false;

        std::ostringstream ok;
        if (!issuedTrustHex.empty()) {
            ok << "PAIR1 OKTRUST " << hexEncode(serverProof->data(), serverProof->size())
               << " " << issuedTrustHex;
        } else {
            ok << "PAIR1 OK " << hexEncode(serverProof->data(), serverProof->size());
        }
        if (!sendLine(s, ok.str())) return false;

        if (info) {
            info->remotePeerId      = clientPeerId;
            info->remoteRole        = clientRole;
            info->remoteDisplayName = clientPeerId;
        }
        return true;
    }

    void runAcceptLoop() {
        while (!stop.load(std::memory_order_relaxed)) {
            sockaddr_in from{};
            int fromLen = sizeof(from);
            SOCKET client = accept(listenSock,
                                   reinterpret_cast<sockaddr*>(&from), &fromLen);
            if (client == INVALID_SOCKET) continue;

            // authTimeout is std::chrono::milliseconds — convert to DWORD for setSocketTimeout.
            setSocketTimeout(client, static_cast<DWORD>(cfg.authTimeout.count()));

            PairSessionInfo info;
            char ip[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
            info.remoteIp = ip;

            const bool ok = authenticateClient(client, &info);
            closesocket(client);

            if (ok && onAccepted) onAccepted(info);
        }
    }
};

PairServer::PairServer() : impl_(std::make_unique<Impl>()) {}
PairServer::~PairServer() { stop(); }

bool PairServer::start(const PairServerConfig& cfg,
                       AcceptHandler onAccepted,
                       PairError* err) {
    stop();

    impl_->cfg        = cfg;
    impl_->onAccepted = std::move(onAccepted);
    impl_->stop       = false;

    if (!impl_->wsa.ok()) {
        setErr(err, WSAGetLastError(), "WSAStartup failed");
        return false;
    }

    impl_->listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (impl_->listenSock == INVALID_SOCKET) {
        setErr(err, WSAGetLastError(), "Cannot create TCP listen socket");
        return false;
    }

    const BOOL yes = TRUE;
    setsockopt(impl_->listenSock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port   = htons(cfg.port);
    inet_pton(AF_INET, cfg.bindAddress.c_str(), &bindAddr.sin_addr);

    if (bind(impl_->listenSock,
             reinterpret_cast<const sockaddr*>(&bindAddr), sizeof(bindAddr)) != 0) {
        setErr(err, WSAGetLastError(), "Cannot bind pairing TCP socket");
        stop();
        return false;
    }

    if (listen(impl_->listenSock, SOMAXCONN) != 0) {
        setErr(err, WSAGetLastError(), "Cannot listen on pairing TCP socket");
        stop();
        return false;
    }

    impl_->acceptThread = std::thread([this] { impl_->runAcceptLoop(); });
    return true;
}

void PairServer::stop() {
    if (!impl_) return;
    impl_->stop = true;
    impl_->closeListen();
    if (impl_->acceptThread.joinable())
        impl_->acceptThread.join();
}

struct PairClient::Impl {
    WsaScope wsa;
};

PairClient::PairClient() : impl_(std::make_unique<Impl>()) {}
PairClient::~PairClient() = default;

bool PairClient::connectAndAuthenticate(const PairClientConfig& cfg,
                                        PairSessionInfo* outInfo,
                                        PairError* err) {
    if (!impl_->wsa.ok()) {
        setErr(err, WSAGetLastError(), "WSAStartup failed");
        return false;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        setErr(err, WSAGetLastError(), "Cannot create TCP socket");
        return false;
    }

    setSocketTimeout(s, static_cast<DWORD>(cfg.timeout.count()));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(cfg.targetPort);
    if (inet_pton(AF_INET, cfg.targetIp.c_str(), &addr.sin_addr) != 1) {
        closesocket(s);
        setErr(err, ERROR_INVALID_ADDRESS, "Invalid target IP");
        return false;
    }

    if (connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        const int code = WSAGetLastError();
        closesocket(s);
        setErr(err, code, "Cannot connect to target peer");
        return false;
    }

    std::array<uint8_t, kNonceSize> clientNonce{};
    if (!randomBytes(clientNonce.data(), clientNonce.size())) {
        closesocket(s);
        setErr(err, GetLastError(), "Cannot generate client nonce");
        return false;
    }
    const std::string clientNonceHex = hexEncode(clientNonce.data(), clientNonce.size());

    std::ostringstream hello;
    hello << "PAIR1 HELLO " << cfg.peerId << " "
          << roleToString(PairRole::Donor) << " " << clientNonceHex;
    if (!sendLine(s, hello.str())) {
        closesocket(s);
        setErr(err, WSAGetLastError(), "Cannot send hello");
        return false;
    }

    std::string line;
    if (!recvLine(s, &line)) {
        closesocket(s);
        setErr(err, WSAGetLastError(), "No challenge received");
        return false;
    }

    const auto ch = splitBySpace(line);
    if (ch.size() != 7 || ch[0] != "PAIR1" || ch[1] != "CHALLENGE") {
        closesocket(s);
        setErr(err, ERROR_INVALID_DATA, "Invalid challenge format");
        return false;
    }

    const std::string serverPeerId      = ch[2];
    const std::string serverDisplayName = unescapeToken(ch[3]);
    const PairRole    serverRole        = roleFromString(ch[4]);
    const auto        salt              = hexDecode(ch[5]);
    const auto        serverNonce       = hexDecode(ch[6]);

    if (!salt || !serverNonce ||
        salt->size() != kSaltSize || serverNonce->size() != kNonceSize) {
        closesocket(s);
        setErr(err, ERROR_INVALID_DATA, "Invalid challenge nonce/salt");
        return false;
    }

    std::vector<uint8_t> key;
    const std::string proofMaterial    = "C|" + clientNonceHex + "|" + ch[6] + "|" + cfg.peerId + "|" + serverPeerId;
    const std::string serverProofMaterial = "S|" + clientNonceHex + "|" + ch[6] + "|" + cfg.peerId + "|" + serverPeerId;

    if (!cfg.password.empty()) {
        const auto derived = deriveKeyPbkdf2(cfg.password, *salt, kDerivedKeySize);
        if (!derived) {
            closesocket(s);
            setErr(err, ERROR_INVALID_DATA, "PBKDF2 failed");
            return false;
        }
        key = *derived;
        const auto proof = hmacSha256(key,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(proofMaterial.data()), proofMaterial.size()));
        if (!proof) {
            closesocket(s);
            setErr(err, ERROR_INVALID_DATA, "Cannot compute client proof");
            return false;
        }
        std::ostringstream auth;
        auth << "PAIR1 AUTH " << hexEncode(proof->data(), proof->size());
        if (!sendLine(s, auth.str())) {
            closesocket(s);
            setErr(err, WSAGetLastError(), "Cannot send auth proof");
            return false;
        }
    } else {
        std::string trustSecret;
        const std::string trustKey = trustKeyForClient(serverPeerId, cfg.peerId);
        const bool haveTrust = DpapiSecretStore::loadSecret(trustKey, &trustSecret, nullptr);
        if (haveTrust) {
            key.assign(trustSecret.begin(), trustSecret.end());
            const auto proof = hmacSha256(key,
                std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(proofMaterial.data()), proofMaterial.size()));
            if (!proof) {
                closesocket(s);
                setErr(err, ERROR_INVALID_DATA, "Cannot compute trust proof");
                return false;
            }
            std::ostringstream auth;
            auth << "PAIR1 AUTH " << hexEncode(proof->data(), proof->size());
            if (!sendLine(s, auth.str())) {
                closesocket(s);
                setErr(err, WSAGetLastError(), "Cannot send trust proof");
                return false;
            }
        } else {
            if (!sendLine(s, "PAIR1 TRUSTNEW")) {
                closesocket(s);
                setErr(err, WSAGetLastError(), "Cannot send trust request");
                return false;
            }
        }
    }

    if (!recvLine(s, &line)) {
        closesocket(s);
        setErr(err, WSAGetLastError(), "No auth response from server");
        return false;
    }

    const auto ok = splitBySpace(line);
    if (ok.size() < 3 || ok[0] != "PAIR1" || (ok[1] != "OK" && ok[1] != "OKTRUST")) {
        closesocket(s);
        setErr(err, ERROR_ACCESS_DENIED, "Authentication failed");
        return false;
    }

    if (ok[1] == "OKTRUST") {
        if (ok.size() != 4) {
            closesocket(s);
            setErr(err, ERROR_INVALID_DATA, "Invalid trust response");
            return false;
        }
        const auto trustBytes = hexDecode(ok[3]);
        if (!trustBytes || trustBytes->empty()) {
            closesocket(s);
            setErr(err, ERROR_INVALID_DATA, "Invalid trust token");
            return false;
        }
        key.assign(trustBytes->begin(), trustBytes->end());
        const std::string trustKey = trustKeyForClient(serverPeerId, cfg.peerId);
        std::string raw(reinterpret_cast<const char*>(trustBytes->data()), trustBytes->size());
        DpapiSecretStore::saveSecret(trustKey, raw, nullptr);
    }

    const auto expectedServerProof = hmacSha256(key,
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(serverProofMaterial.data()), serverProofMaterial.size()));
    if (!expectedServerProof) {
        closesocket(s);
        setErr(err, ERROR_INVALID_DATA, "Cannot verify server proof");
        return false;
    }

    if (hexEncode(expectedServerProof->data(), expectedServerProof->size()) != ok[2]) {
        closesocket(s);
        setErr(err, ERROR_ACCESS_DENIED, "Server proof mismatch");
        return false;
    }

    if (outInfo) {
        outInfo->remotePeerId      = serverPeerId;
        outInfo->remoteDisplayName = serverDisplayName;
        outInfo->remoteRole        = serverRole;
        outInfo->remoteIp          = cfg.targetIp;
    }

    closesocket(s);
    return true;
}

namespace DpapiSecretStore {

bool saveSecret(const std::string& key,
                const std::string& secret,
                PairError* err) {
    const auto encrypted = dpapiProtect(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(secret.data()), secret.size()));
    if (!encrypted) {
        setErr(err, GetLastError(), "CryptProtectData failed");
        return false;
    }

    const auto dir = secretsDir();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        setErr(err, ec.value(), "Cannot create secrets directory");
        return false;
    }

    const auto path = dir / (sanitizeKey(key) + ".bin");
    FILE* f = nullptr;
    if (fopen_s(&f, path.string().c_str(), "wb") != 0 || !f) {
        setErr(err, GetLastError(), "Cannot open secret file for write");
        return false;
    }

    const size_t n = fwrite(encrypted->data(), 1, encrypted->size(), f);
    fclose(f);
    if (n != encrypted->size()) {
        setErr(err, ERROR_WRITE_FAULT, "Cannot write full secret blob");
        return false;
    }
    return true;
}

bool loadSecret(const std::string& key,
                std::string* outSecret,
                PairError* err) {
    if (!outSecret) {
        setErr(err, ERROR_INVALID_PARAMETER, "outSecret is null");
        return false;
    }

    const auto path = secretsDir() / (sanitizeKey(key) + ".bin");
    FILE* f = nullptr;
    if (fopen_s(&f, path.string().c_str(), "rb") != 0 || !f) {
        setErr(err, ERROR_FILE_NOT_FOUND, "Secret file not found");
        return false;
    }

    std::vector<uint8_t> enc;
    std::array<uint8_t, 512> chunk{};
    while (true) {
        const size_t n = fread(chunk.data(), 1, chunk.size(), f);
        if (n > 0) enc.insert(enc.end(), chunk.data(), chunk.data() + n);
        if (n < chunk.size()) break;
    }
    fclose(f);

    if (enc.empty()) {
        setErr(err, ERROR_INVALID_DATA, "Secret file is empty");
        return false;
    }

    const auto plain = dpapiUnprotect(enc);
    if (!plain) {
        setErr(err, GetLastError(), "CryptUnprotectData failed");
        return false;
    }

    outSecret->assign(reinterpret_cast<const char*>(plain->data()), plain->size());
    return true;
}

bool deleteSecret(const std::string& key,
                  PairError* err) {
    const auto path = secretsDir() / (sanitizeKey(key) + ".bin");
    std::error_code ec;
    const bool ok = std::filesystem::remove(path, ec);
    if (!ok && ec) {
        setErr(err, ec.value(), "Cannot delete secret file");
        return false;
    }
    return true;
}

} // namespace DpapiSecretStore

} // namespace smb

// JumpHostConnection.cpp — SSH ProxyJump implementation.
// Connects to a jump host over TCP, authenticates, opens a direct-tcpip channel
// to the target host, and returns an ITransportStream wrapping that channel.
// The target SSH session then performs its own handshake over this stream.

#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <array>
#include <format>
#include <memory>
#include <string>

#include "JumpHostConnection.h"
#include "ITransportStream.h"
#include "ISshBackend.h"
#include "SftpClient.h"
#include "SftpInternal.h"
#include "PluginEntryPoints.h"
#include "CoreUtils.h"
#include "res/resource.h"

#include <libssh2/libssh2.h>
#include <libssh2/libssh2_sftp.h>

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Minimal alloc/free callbacks for the jump session (same as main session).
static LPVOID jmp_alloc(size_t n, LPVOID* /*ab*/)   { return malloc(n); }
static LPVOID jmp_realloc(LPVOID p, size_t n, LPVOID* /*ab*/) { return realloc(p, n); }
static void   jmp_free(LPVOID p, LPVOID* /*ab*/)    { free(p); }

// Context threaded through the jump session abstract pointer for kbd-interactive.
struct JmpKbdCtx {
    const char* password = nullptr;
};

// Keyboard-interactive callback for jump host: just echo the stored password.
extern "C" static void jmp_kbd_callback(
    LPCSTR /*name*/,   int /*name_len*/,
    LPCSTR /*instr*/,  int /*instr_len*/,
    int num_prompts,
    const LIBSSH2_USERAUTH_KBDINT_PROMPT* /*prompts*/,
    LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
    LPVOID* abstract)
{
    auto* ctx = static_cast<JmpKbdCtx*>(*abstract);
    for (int i = 0; i < num_prompts; i++) {
        const char* pw = (ctx && ctx->password) ? ctx->password : "";
        responses[i].text   = _strdup(pw);
        responses[i].length = static_cast<unsigned int>(strlen(pw));
    }
}

// ---------------------------------------------------------------------------
// Libssh2DirectTcpipStream
// ---------------------------------------------------------------------------
// ITransportStream implementation backed by a libssh2 direct-tcpip channel.
// The stream owns the jump ISshSession and ISshChannel.
// It does NOT own cs->sock — the caller (SftpCloseConnection / CleanupFailed)
// closes it via the normal socket teardown path.
// ---------------------------------------------------------------------------
class Libssh2DirectTcpipStream final : public ITransportStream {
public:
    Libssh2DirectTcpipStream(
        std::unique_ptr<ISshSession> session,
        std::unique_ptr<ISshChannel> channel,
        SOCKET                       underlyingSocket)
        : session_(std::move(session))
        , channel_(std::move(channel))
        , sock_(underlyingSocket)
    {}

    ~Libssh2DirectTcpipStream() override { close(); }

    // ------------------------------------------------------------------
    // ITransportStream
    // ------------------------------------------------------------------

    ssize_t read(void* buf, size_t len) override
    {
        if (!channel_)
            return -1;
        ssize_t rc = channel_->read(static_cast<char*>(buf), len);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            return ITRANSPORT_EAGAIN;
        return rc;
    }

    ssize_t write(const void* buf, size_t len) override
    {
        if (!channel_)
            return -1;
        ssize_t rc = channel_->write(static_cast<const char*>(buf), len);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            return ITRANSPORT_EAGAIN;
        return rc;
    }

    bool waitReadable(DWORD timeoutMs) override
    {
        if (sock_ == INVALID_SOCKET)
            return false;
        // The channel data arrives on the jump TCP socket.
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock_, &fds);
        struct timeval tv {};
        tv.tv_sec  = static_cast<long>(timeoutMs / 1000);
        tv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
        return select(0, &fds, nullptr, nullptr, &tv) > 0;
    }

    const char* describe() const override { return desc_.c_str(); }

    void close() override
    {
        if (closed_)
            return;
        closed_ = true;

        // Close the direct-tcpip channel gracefully.
        if (channel_) {
            channel_->sendEof();
            channel_->channelClose();
            channel_->channelFree();
            channel_.reset();
        }

        // Disconnect the jump SSH session.
        if (session_) {
            // Non-blocking disconnect — best effort, ignore EAGAIN.
            for (int i = 0; i < 30; ++i) {
                int r = session_->disconnect("ProxyJump closed");
                if (r != LIBSSH2_ERROR_EAGAIN)
                    break;
                // Give the socket a tick to drain.
                fd_set fds; FD_ZERO(&fds); FD_SET(sock_, &fds);
                struct timeval tv { 0, 50000 };
                select(0, &fds, nullptr, nullptr, &tv);
            }
            session_->free();
            session_.reset();
        }
        // NOTE: sock_ is NOT closed here.
        // The caller (SftpCloseConnection / CleanupFailedConnect) does
        // closesocket(cs->sock) which IS sock_.
    }

    void setDescription(const std::string& d) { desc_ = d; }

private:
    std::unique_ptr<ISshSession> session_;
    std::unique_ptr<ISshChannel> channel_;
    SOCKET                       sock_   { INVALID_SOCKET };
    std::string                  desc_;
    bool                         closed_ { false };
};

// ---------------------------------------------------------------------------
// Internal: verify jump host fingerprint
// ---------------------------------------------------------------------------
// Returns true if fingerprint is accepted (unchanged or user approved).
// Updates jump.fingerprint and writes to INI on first-time / change.
static bool VerifyJumpFingerprint(
    pConnectSettings cs,
    ISshSession*     jmpSession,
    JumpHostSettings& jump)        // in/out: fingerprint field updated
{
    const char* raw = jmpSession->hostkeyHash(LIBSSH2_HOSTKEY_HASH_MD5);
    if (!raw) {
        ShowStatusId(IDS_LOG_JUMP_NO_FP, nullptr, true);
        return false;
    }

    std::string fp;
    fp.reserve(16 * 3);
    for (int i = 0; i < 16; i++) {
        if (i > 0) fp += ' ';
        fp += std::format("{:02X}", static_cast<unsigned char>(raw[i]));
    }
    ShowStatus(("Jump host fingerprint: " + fp).c_str());

    if (jump.fingerprint == fp)
        return true;   // known host, matches

    // First time or changed — ask user.
    const bool firstTime = jump.fingerprint.empty();
    std::string msg = firstTime
        ? "First connection to jump host — fingerprint unknown.\nFingerprint: "
        : "Jump host fingerprint has CHANGED!\nNew fingerprint: ";
    msg += fp;
    msg += "\nAccept?";

    bool accepted = false;
    if (cs->feedback)
        accepted = cs->feedback->AskYesNo(msg.c_str(), "SSH ProxyJump Security Warning");

    if (!accepted)
        return false;

    // Persist to INI.
    WritePrivateProfileString(
        cs->DisplayName.c_str(), "jumpfingerprint",
        fp.c_str(), cs->IniFileName.c_str());
    jump.fingerprint = fp;
    return true;
}

// ---------------------------------------------------------------------------
// Internal: authenticate to jump host
// ---------------------------------------------------------------------------
static bool AuthJumpHost(
    pConnectSettings    cs,
    ISshSession*        jmpSession,
    const JumpHostSettings& jump,
    SOCKET              jmpSock,
    int&                progress,
    int&                loop,
    SYSTICKS&           lasttime)
{
    // Get available auth methods.
    char* authList = jmpSession->userauthList(
        jump.user.c_str(), static_cast<unsigned>(jump.user.size()));

    if (!authList && jmpSession->userauthAuthenticated()) {
        ShowStatusId(IDS_LOG_JUMP_AUTH_NONE, nullptr, true);
        return true;
    }

    const bool canPassword = authList && strstr(authList, "password");
    const bool canPubkey   = authList && strstr(authList, "publickey");
    const bool canKbd      = authList && strstr(authList, "keyboard-interactive");

    ShowStatus(("Jump host auth methods: " + (authList ? std::string(authList) : "(none)")).c_str());

    // --- 1. Agent auth ---
    if (jump.useagent && loadAgent) {
        ShowStatusId(IDS_LOG_JUMP_AGENT_TRY, nullptr, true);
        auto agent = jmpSession->agentInit();
        if (agent && agent->connect() == LIBSSH2_ERROR_NONE) {
            agent->listIdentities();
            struct libssh2_agent_publickey* prev = nullptr;
            struct libssh2_agent_publickey* id   = nullptr;
            while (agent->getIdentity(&id, prev) == 1) {
                int r = LIBSSH2_ERROR_EAGAIN;
                while (r == LIBSSH2_ERROR_EAGAIN) {
                    r = agent->userauth(jump.user.c_str(), id);
                    if (r == LIBSSH2_ERROR_EAGAIN)
                        IsSocketReadable(jmpSock);
                }
                if (r == LIBSSH2_ERROR_NONE) {
                    ShowStatusId(IDS_LOG_JUMP_AGENT_OK, nullptr, true);
                    agent->disconnect();
                    return true;
                }
                prev = id;
            }
            agent->disconnect();
        }
        ShowStatusId(IDS_LOG_JUMP_AGENT_FAIL, nullptr, true);
    }

    // --- 2. Public key auth ---
    if (canPubkey && !jump.privkeyfile.empty()) {
        ShowStatusId(IDS_LOG_JUMP_PUBKEY_TRY, nullptr, true);
        int r = LIBSSH2_ERROR_EAGAIN;
        while (r == LIBSSH2_ERROR_EAGAIN) {
            r = jmpSession->userauthPubkeyFromFile(
                jump.user.c_str(),
                static_cast<unsigned>(jump.user.size()),
                jump.pubkeyfile.empty() ? nullptr : jump.pubkeyfile.c_str(),
                jump.privkeyfile.c_str(),
                jump.password.empty() ? nullptr : jump.password.c_str());
            if (r == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(jmpSock);
            if (ProgressLoop("Jump host: public key auth...", progress, progress + 5, &loop, &lasttime))
                break;
        }
        if (r == LIBSSH2_ERROR_NONE) {
            ShowStatusId(IDS_LOG_JUMP_PUBKEY_OK, nullptr, true);
            return true;
        }
        ShowStatusId(IDS_LOG_JUMP_PUBKEY_FAIL, nullptr, true);
    }

    // --- 3. Password auth ---
    if (canPassword && !jump.password.empty()) {
        ShowStatusId(IDS_LOG_JUMP_PASS_TRY, nullptr, true);
        int r = LIBSSH2_ERROR_EAGAIN;
        while (r == LIBSSH2_ERROR_EAGAIN) {
            r = jmpSession->userauthPassword(
                jump.user.c_str(), static_cast<unsigned>(jump.user.size()),
                jump.password.c_str(), static_cast<unsigned>(jump.password.size()),
                nullptr);
            if (r == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(jmpSock);
            if (ProgressLoop("Jump host: password auth...", progress, progress + 5, &loop, &lasttime))
                break;
        }
        if (r == LIBSSH2_ERROR_NONE) {
            ShowStatusId(IDS_LOG_JUMP_PASS_OK, nullptr, true);
            return true;
        }
        ShowStatusId(IDS_LOG_JUMP_PASS_FAIL, nullptr, true);
    }

    // --- 4. Keyboard-interactive ---
    if (canKbd && !jump.password.empty()) {
        ShowStatusId(IDS_LOG_JUMP_KBD_TRY, nullptr, true);
        int r = LIBSSH2_ERROR_EAGAIN;
        while (r == LIBSSH2_ERROR_EAGAIN) {
            r = jmpSession->userauthKeyboardInteractive(
                jump.user.c_str(), static_cast<unsigned>(jump.user.size()),
                jmp_kbd_callback);
            if (r == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(jmpSock);
            if (ProgressLoop("Jump host: kbd-int auth...", progress, progress + 5, &loop, &lasttime))
                break;
        }
        if (r == LIBSSH2_ERROR_NONE) {
            ShowStatusId(IDS_LOG_JUMP_KBD_OK, nullptr, true);
            return true;
        }
        ShowStatusId(IDS_LOG_JUMP_KBD_FAIL, nullptr, true);
    }

    ShowStatusId(IDS_LOG_JUMP_AUTH_FAIL, nullptr, true);
    return false;
}

// ---------------------------------------------------------------------------
// ConnectViaJumpHost — public API
// ---------------------------------------------------------------------------
std::unique_ptr<ITransportStream> ConnectViaJumpHost(
    pConnectSettings          cs,
    JumpHostSettings&         jump,
    ISshBackend*              backend,
    const std::string&        targetHost,
    unsigned short            targetPort,
    int&                      progress,
    int&                      loop,
    SYSTICKS&                 lasttime)
{
    ShowStatusId(IDS_LOG_PROXYJUMP, nullptr, true);
    ShowStatus(("Jump host: " + jump.host + ":" + std::to_string(jump.port)).c_str());

    // -----------------------------------------------------------------------
    // 1. TCP connect to jump host
    // -----------------------------------------------------------------------
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    const std::string portStr = std::to_string(jump.port);

    struct addrinfo* res = nullptr;
    if (getaddrinfo(jump.host.c_str(), portStr.c_str(), &hints, &res) != 0) {
        ShowStatus(("Jump host: DNS failed for " + jump.host).c_str());
        if (cs->feedback)
            cs->feedback->ShowError(("ProxyJump: cannot resolve jump host: " + jump.host).c_str());
        return nullptr;
    }

    SOCKET jmpSock = INVALID_SOCKET;
    bool connected = false;
    for (struct addrinfo* ai = res; ai && !connected; ai = ai->ai_next) {
        if (jmpSock != INVALID_SOCKET)
            closesocket(jmpSock);
        jmpSock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (jmpSock == INVALID_SOCKET)
            continue;

        SetBlockingSocket(jmpSock, false);
        if (connect(jmpSock, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
            connected = true;
        } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
            SYSTICKS t0 = get_sys_ticks();
            while (get_ticks_between(t0) < 15000) {
                if (IsSocketWritable(jmpSock)) { connected = true; break; }
                if (IsSocketError(jmpSock))    break;
                if (ProgressLoop("Connecting to jump host...", progress, progress + 5, &loop, &lasttime))
                    break;
            }
        }
    }
    freeaddrinfo(res);

    if (!connected) {
        if (jmpSock != INVALID_SOCKET)
            closesocket(jmpSock);
        ShowStatusId(IDS_LOG_JUMP_TCP_FAIL, jump.host.c_str(), true);
        if (cs->feedback)
            cs->feedback->ShowError(("ProxyJump: cannot connect to jump host: " + jump.host).c_str());
        return nullptr;
    }
    ShowStatusId(IDS_LOG_JUMP_TCP_OK, jump.host.c_str(), true);

    // -----------------------------------------------------------------------
    // 2. Create jump SSH session
    // -----------------------------------------------------------------------
    // We store a JmpKbdCtx in the jump session's abstract so kbd-int works.
    JmpKbdCtx kbdCtx{ jump.password.c_str() };

    auto jmpSession = backend->createSession(jmp_alloc, jmp_free, jmp_realloc, &kbdCtx);
    if (!jmpSession) {
        closesocket(jmpSock);
        ShowStatusId(IDS_LOG_JUMP_SSH_FAIL, nullptr, true);
        if (cs->feedback)
            cs->feedback->ShowError("ProxyJump: libssh2 session init failed");
        return nullptr;
    }
    jmpSession->setBlocking(0);

    // SSH handshake with jump host.
    ShowStatusId(IDS_LOG_JUMP_HANDSHAKE, nullptr, true);
    {
        int r = LIBSSH2_ERROR_EAGAIN;
        while (r == LIBSSH2_ERROR_EAGAIN) {
            r = jmpSession->startup(static_cast<int>(jmpSock));
            if (r == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(jmpSock);
            if (ProgressLoop("Jump host: SSH handshake...", progress, progress + 5, &loop, &lasttime))
                break;
        }
        if (r != LIBSSH2_ERROR_NONE) {
            char* msg = nullptr; int mlen = 0;
            jmpSession->lastError(&msg, &mlen, false);
            ShowStatusId(IDS_LOG_JUMP_HANDSHAKE_FAIL, msg ? msg : "unknown", true);
            if (cs->feedback)
                cs->feedback->ShowError(("ProxyJump: jump host SSH handshake failed: " + (msg ? std::string(msg) : "")).c_str());
            jmpSession->free();
            closesocket(jmpSock);
            return nullptr;
        }
    }
    ShowStatusId(IDS_LOG_JUMP_HANDSHAKE_OK, nullptr, true);

    // -----------------------------------------------------------------------
    // 3. Verify jump host fingerprint
    // -----------------------------------------------------------------------
    if (!VerifyJumpFingerprint(cs, jmpSession.get(), jump)) {
        jmpSession->disconnect("fingerprint rejected");
        jmpSession->free();
        closesocket(jmpSock);
        ShowStatusId(IDS_LOG_JUMP_FP_REJECTED, nullptr, true);
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // 4. Authenticate to jump host
    // -----------------------------------------------------------------------
    ShowStatus(("Jump host: authenticating as " + jump.user + "...").c_str());
    if (!AuthJumpHost(cs, jmpSession.get(), jump, jmpSock, progress, loop, lasttime)) {
        jmpSession->disconnect("auth failed");
        jmpSession->free();
        closesocket(jmpSock);
        if (cs->feedback)
            cs->feedback->ShowError(("ProxyJump: authentication to jump host failed.\nUser: " + jump.user).c_str());
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // 5. Open direct-tcpip channel to target
    // -----------------------------------------------------------------------
    ShowStatus(("Jump host: opening tunnel to " + targetHost + ":" + std::to_string(targetPort) + "...").c_str());

    std::unique_ptr<ISshChannel> channel;
    {
        // non-blocking open: retry on EAGAIN
        SYSTICKS t0 = get_sys_ticks();
        while (get_ticks_between(t0) < 15000) {
            channel = jmpSession->directTcpip(
                targetHost.c_str(), static_cast<int>(targetPort),
                "127.0.0.1", 0);
            if (channel)
                break;
            // check if it's EAGAIN
            if (LIBSSH2_ERROR_EAGAIN != jmpSession->lastErrno())
                break;
            IsSocketReadable(jmpSock);
            if (ProgressLoop("Jump host: opening tunnel...", progress, progress + 5, &loop, &lasttime))
                break;
        }
    }

    if (!channel) {
        char* msg = nullptr; int mlen = 0;
        jmpSession->lastError(&msg, &mlen, false);
        ShowStatus(("Jump host: direct-tcpip failed to " + targetHost + ": " + (msg ? msg : "unknown")).c_str());
        if (cs->feedback)
            cs->feedback->ShowError(("ProxyJump: cannot open tunnel to " + targetHost + ":" + std::to_string(targetPort) + "\n" + (msg ? msg : "")).c_str());
        jmpSession->disconnect("direct-tcpip failed");
        jmpSession->free();
        closesocket(jmpSock);
        return nullptr;
    }

    ShowStatus(("Jump host: tunnel open to " + targetHost + ":" + std::to_string(targetPort)).c_str());

    // -----------------------------------------------------------------------
    // 6. Build transport stream
    // -----------------------------------------------------------------------
    // Store jump socket in cs->sock so IsSocketReadable() works for the
    // target SSH session startup loops.
    cs->sock = jmpSock;

    auto stream = std::make_unique<Libssh2DirectTcpipStream>(
        std::move(jmpSession),
        std::move(channel),
        jmpSock);
    stream->setDescription("direct-tcpip:" + targetHost + ":" + std::to_string(targetPort)
                           + "@" + jump.host);

    return stream;
}

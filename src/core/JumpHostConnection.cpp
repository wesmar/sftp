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
#include "ProfileSettings.h"   // LoadServerSettings, for the session-reference case
#include "SshSessionInit.h"    // host key fingerprints
#include "res/resource.h"

#include <libssh2/libssh2.h>
#include <libssh2/libssh2_sftp.h>

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

JumpConfig ResolveJumpConfig(pConnectSettings cs, LPCSTR iniFileName)
{
    JumpConfig out;
    if (!cs || !cs->use_jump_host)
        return out;                      // Disabled

    const bool hasRef    = !cs->jump_session_ref.empty();
    const bool hasManual = !cs->jump_host.empty();

    if (!hasRef && !hasManual) {
        // The profile asks to go through a jump host but names none. This is
        // reachable: picking a session that was later deleted clears the
        // reference and leaves the checkbox on. Refusing is the only safe
        // answer — connecting straight to the target would quietly bypass
        // the bastion the user asked for.
        out.status = JumpConfigStatus::NotConfigured;
        out.error  = LngStrU8(IDS_JUMP_NOT_CONFIGURED,
            "Jump host is enabled for this session but none is configured. "
            "Pick a jump session or fill in the jump host details.");
        return out;
    }

    if (hasRef) {
        tConnectSettings ref{};
        if (!LoadServerSettings(cs->jump_session_ref.c_str(), &ref, iniFileName)) {
            out.status = JumpConfigStatus::RefNotFound;
            out.error  = LngStrU8(IDS_JUMP_SESSION_NOT_FOUND,
                "Jump session '{}' not found in saved sessions");
            const auto p = out.error.find("{}");
            if (p != std::string::npos)
                out.error.replace(p, 2, cs->jump_session_ref);
            return out;
        }

        // Only one hop is supported. Catching this here also covers the
        // A -> B -> A loop.
        if (!ref.jump_session_ref.empty() ||
            (ref.use_jump_host && !ref.jump_host.empty())) {
            out.status = JumpConfigStatus::RefChained;
            out.error  = LngStrU8(IDS_JUMP_SESSION_CHAINED,
                "Jump session '{}' has its own jump-host configuration "
                "— chained or cyclic jump hosts are not supported. "
                "Pick a session that connects directly to the bastion.");
            const auto p = out.error.find("{}");
            if (p != std::string::npos)
                out.error.replace(p, 2, cs->jump_session_ref);
            return out;
        }

        // `server` may carry a ":port" suffix — it is stored raw and split at
        // connect time, so split it the same way here.
        std::array<char, MAX_PATH> hostBuf{};
        strncpy_s(hostBuf.data(), hostBuf.size(), ref.server.c_str(), _TRUNCATE);
        WORD parsedPort = 22;
        ParseAddress(hostBuf.data(), hostBuf.data(), &parsedPort, 22);

        out.endpoint.host        = hostBuf.data();
        out.endpoint.port        = parsedPort;
        out.endpoint.user        = ref.user;
        {
            const StoredSecret secret = SplitStoredSecret(ref.password);
            out.endpoint.password      = secret.accountPassword;
            out.endpoint.keyPassphrase = secret.keyPassphrase;
        }
        out.endpoint.pubkeyfile  = ref.pubkeyfile;
        out.endpoint.privkeyfile = ref.privkeyfile;
        out.endpoint.useagent    = ref.useagent;
        // The fingerprint belongs to the host, which the referenced session
        // describes — so it lives in that session's own key, shared with a
        // direct connection to the same machine.
        out.endpoint.fingerprint        = ref.savedfingerprint;
        out.endpoint.fingerprintSection = cs->jump_session_ref;
        out.endpoint.fingerprintKey     = "fingerprint";
    } else {
        out.endpoint.host        = cs->jump_host;
        out.endpoint.port        = cs->jump_port;
        out.endpoint.user        = cs->jump_user;
        {
            const StoredSecret secret = SplitStoredSecret(cs->jump_password);
            out.endpoint.password      = secret.accountPassword;
            out.endpoint.keyPassphrase = secret.keyPassphrase;
        }
        out.endpoint.pubkeyfile  = cs->jump_pubkeyfile;
        out.endpoint.privkeyfile = cs->jump_privkeyfile;
        out.endpoint.useagent    = cs->jump_useagent;
        // Nothing but this session describes that host.
        out.endpoint.fingerprint        = cs->jump_fingerprint;
        out.endpoint.fingerprintSection = cs->DisplayName;
        out.endpoint.fingerprintKey     = "jumpfingerprint";
    }

    out.status = JumpConfigStatus::Ready;
    return out;
}


// Minimal alloc/free callbacks for the jump session (same as main session).
static LPVOID jmp_alloc(size_t n, LPVOID* /*ab*/)   { return malloc(n); }
static LPVOID jmp_realloc(LPVOID p, size_t n, LPVOID* /*ab*/) { return realloc(p, n); }
static void   jmp_free(LPVOID p, LPVOID* /*ab*/)    { free(p); }

// Context threaded through the jump session abstract pointer for kbd-interactive.
// It points at a string owned further up the stack, so it is only valid while
// authentication runs; ConnectViaJumpHost clears the session's abstract slot
// as soon as that is over.
struct JmpKbdCtx {
    const std::string* password = nullptr;
};

// Keyboard-interactive callback for jump host: echo the stored password only for
// password-looking prompts; send an empty string for OTP/MFA prompts.
extern "C" static void jmp_kbd_callback(
    LPCSTR /*name*/,   int /*name_len*/,
    LPCSTR /*instr*/,  int /*instr_len*/,
    int num_prompts,
    const LIBSSH2_USERAUTH_KBDINT_PROMPT* prompts,
    LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
    LPVOID* abstract)
{
    auto* ctx = static_cast<JmpKbdCtx*>(*abstract);
    for (int i = 0; i < num_prompts; i++) {
        const char* pw = "";
        if (ctx && ctx->password && !ctx->password->empty()) {
            // Copy and lowercase the prompt text to check if it looks like a password prompt.
            std::array<char, 256> lower{};
            const size_t copyLen = min(
                prompts ? static_cast<size_t>(prompts[i].length) : size_t{0},
                lower.size() - 1);
            if (copyLen > 0) memcpy(lower.data(), prompts[i].text, copyLen);
            lower[copyLen] = '\0';
            _strlwr_s(lower.data(), lower.size());
            const bool isPass = strstr(lower.data(), "pass") != nullptr
                             && !strstr(lower.data(), "oath")
                             && !strstr(lower.data(), "one time")
                             && !strstr(lower.data(), "one-time");
            if (isPass || copyLen == 0)
                pw = ctx->password->c_str();
        }
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

    bool waitForSshIo(ISshSession* sess, DWORD timeoutMs) override
    {
        if (sock_ == INVALID_SOCKET)
            return false;
        const int dirs = sess ? sess->blockDirections() : 0;
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        // Always watch read: catches both incoming channel data and SSH
        // control messages (e.g. window-update that unblocks a stalled
        // channel write).
        FD_SET(sock_, &rfds);
        // Inner OUTBOUND-blocked write can also unblock when the jump TCP
        // send buffer drains, so add write-watch only in that case.
        if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND)
            FD_SET(sock_, &wfds);
        struct timeval tv {};
        tv.tv_sec  = static_cast<long>(timeoutMs / 1000);
        tv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
        return select(0, &rfds, &wfds, nullptr, &tv) > 0;
    }

    const char* describe() const override { return desc_.c_str(); }

    void close() override
    {
        if (closed_)
            return;
        closed_ = true;

        // Close the direct-tcpip channel gracefully (sendEof + channel close).
        // ~Libssh2Channel() in channel_.reset() drains the actual free.
        if (channel_) {
            channel_->sendEof();
            channel_->channelClose();
            channel_.reset();
        }

        // Disconnect the jump SSH session — best-effort with brief socket drain.
        // ~Libssh2Session() in session_.reset() handles the free.
        if (session_) {
            for (int i = 0; i < 30; ++i) {
                int r = session_->disconnect("ProxyJump closed");
                if (r != LIBSSH2_ERROR_EAGAIN)
                    break;
                fd_set fds; FD_ZERO(&fds); FD_SET(sock_, &fds);
                struct timeval tv { 0, 50000 };
                select(0, &fds, nullptr, nullptr, &tv);
            }
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
    const HostKeyFingerprint fp = ReadHostKeyFingerprint(jmpSession);
    if (fp.sha256.empty() && fp.md5.empty()) {
        ShowStatusId(IDS_LOG_JUMP_NO_FP, nullptr, true);
        return false;
    }
    ShowStatus(("Jump host fingerprint: " + FingerprintToStore(fp)).c_str());

    // Write it back where the resolver read it from. For a referenced session
    // that is the session's own `fingerprint`, shared with a direct
    // connection to the same machine; for a manual jump host it is this
    // session's `jumpfingerprint`. Writing anywhere else means the value is
    // never found again and the prompt returns on every connect.
    auto store = [&](const std::string& value) {
        if (!jump.fingerprintSection.empty() && !jump.fingerprintKey.empty()) {
            WritePrivateProfileString(
                jump.fingerprintSection.c_str(), jump.fingerprintKey.c_str(),
                value.c_str(), cs->IniFileName.c_str());
        }
        jump.fingerprint = value;
    };

    if (FingerprintMatches(jump.fingerprint, fp)) {
        // An MD5 saved by an earlier version: same key, stored again as SHA256.
        if (!jump.fingerprint.starts_with("SHA256:") && !fp.sha256.empty()) {
            store(fp.sha256);
            SFTP_LOG("JUMP", "Stored MD5 fingerprint matched, rewritten as %s", fp.sha256.c_str());
        }
        return true;
    }

    // First time or changed — ask user.
    const bool firstTime = jump.fingerprint.empty();
    std::string msg = firstTime
        ? "First connection to jump host — fingerprint unknown.\nFingerprint: "
        : "Jump host fingerprint has CHANGED!\nNew fingerprint: ";
    msg += FingerprintForPrompt(fp);
    msg += "\nAccept?";

    bool accepted = false;
    if (cs->feedback)
        accepted = cs->feedback->AskYesNo(msg.c_str(), "SSH ProxyJump Security Warning");

    if (!accepted)
        return false;

    store(FingerprintToStore(fp));
    return true;
}

// ---------------------------------------------------------------------------
// Internal: authenticate to jump host
// ---------------------------------------------------------------------------
static bool AuthJumpHost(
    pConnectSettings    cs,
    ISshSession*        jmpSession,
    JumpHostSettings&   jump,   // non-const: an entered passphrase is kept here
    SOCKET              jmpSock,
    int&                progress,
    int&                loop,
    SYSTICKS&           lasttime)
{
    // Get available auth methods. The jump session is non-blocking, so the
    // first call typically returns NULL with lastErrno() == LIBSSH2_ERROR_EAGAIN
    // until the server's response packet has been received. Without this
    // retry loop the call returns NULL once and we report "(none)" even when
    // the server actually offers publickey/password/keyboard-interactive.
    SFTP_LOG("JUMP", "Querying auth methods for user='%s'", jump.user.c_str());
    char* authList = nullptr;
    SYSTICKS authListStart = get_sys_ticks();
    do {
        authList = jmpSession->userauthList(
            jump.user.c_str(), static_cast<unsigned>(jump.user.size()));
        if (authList)
            break;
        const int err = jmpSession->lastErrno();
        if (err != LIBSSH2_ERROR_EAGAIN) {
            SFTP_LOG("JUMP", "userauthList non-EAGAIN errno=%d", err);
            break;
        }
        if (get_ticks_between(authListStart) > SSH_PROBE_TIMEOUT_MS) {
            SFTP_LOG("JUMP", "userauthList timeout after %d ms", SSH_PROBE_TIMEOUT_MS);
            break;
        }
        if (ProgressLoop("Jump host: querying auth methods...", progress, progress + 2, &loop, &lasttime))
            break;
        IsSocketReadable(jmpSock);
    } while (true);

    if (!authList && jmpSession->userauthAuthenticated()) {
        SFTP_LOG("JUMP", "Server reported already authenticated (no auth list needed)");
        ShowStatusId(IDS_LOG_JUMP_AUTH_NONE, nullptr, true);
        return true;
    }

    const bool canPassword = authList && strstr(authList, "password");
    const bool canPubkey   = authList && strstr(authList, "publickey");
    const bool canKbd      = authList && strstr(authList, "keyboard-interactive");

    SFTP_LOG("JUMP", "Auth methods: '%s' (pw=%d pk=%d kbd=%d)",
             authList ? authList : "(none)", canPassword, canPubkey, canKbd);
    ShowStatus(("Jump host auth methods: " + (authList ? std::string(authList) : "(none)")).c_str());

    // The jump host authenticates through the same code as the target
    // server, so PPK conversion, passphrase prompting, path expansion and
    // the missing-key check apply here too. Failures report through the
    // status line only: this function still has password and
    // keyboard-interactive to fall back on.
    // The passphrase lives on the connection settings, not on `jump`, which
    // ResolveJumpConfig rebuilds for every connect: one entered at a prompt
    // has to outlast this call for the reconnects that run mid-transfer.
    if (cs->jump_key_passphrase.empty())
        cs->jump_key_passphrase = jump.keyPassphrase;

    SshAuthTarget authTarget;
    authTarget.session     = jmpSession;
    authTarget.host        = jump.host;
    authTarget.user        = jump.user;
    authTarget.password      = &jump.password;
    authTarget.keyPassphrase = &cs->jump_key_passphrase;
    authTarget.pubkeyfile  = jump.pubkeyfile;
    authTarget.privkeyfile = jump.privkeyfile;
    authTarget.waitIo      = [jmpSock]() { IsSocketReadable(jmpSock); };

    // --- 1. Agent auth ---
    if (jump.useagent) {
        ShowStatusId(IDS_LOG_JUMP_AGENT_TRY, nullptr, true);
        if (SftpAuthPageantOn(authTarget, "Jump host: agent auth...",
                              progress, &loop, &lasttime) == 0) {
            ShowStatusId(IDS_LOG_JUMP_AGENT_OK, nullptr, true);
            return true;
        }
        ShowStatusId(IDS_LOG_JUMP_AGENT_FAIL, nullptr, true);
    }

    // --- 2. Public key auth ---
    if (canPubkey && !jump.privkeyfile.empty()) {
        ShowStatusId(IDS_LOG_JUMP_PUBKEY_TRY, nullptr, true);
        if (SftpAuthPubKeyOn(authTarget,
                             progress, &loop, &lasttime, nullptr,
                             AuthFailureUi::StatusOnly) == 0) {
            ShowStatusId(IDS_LOG_JUMP_PUBKEY_OK, nullptr, true);
            return true;
        }
        ShowStatusId(IDS_LOG_JUMP_PUBKEY_FAIL, nullptr, true);
    }

    // No stored password, but the server takes one: ask, as for the target.
    // The answer is kept for the reconnects of this connection and never saved.
    if ((canPassword || canKbd) && jump.password.empty()) {
        if (cs->jump_entered_password.empty()) {
            std::array<char, 256> buf{};
            const std::string title = std::format("Jump host password for {}@{}", jump.user, jump.host);
            ShowStatusId(IDS_LOG_REQUEST_PASS, nullptr, true);
            if (RequestInput(RT_Password, title.c_str(), nullptr, buf))
                cs->jump_entered_password = buf.data();
        }
        jump.password = cs->jump_entered_password;
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

        EnableTcpKeepAlive(jmpSock);
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
    JmpKbdCtx kbdCtx{ &jump.password };

    auto jmpSession = backend->createSession(jmp_alloc, jmp_free, jmp_realloc, &kbdCtx);
    if (!jmpSession) {
        ShowStatusId(IDS_LOG_JUMP_SSH_FAIL, nullptr, true);
        if (cs->feedback)
            cs->feedback->ShowError(LngStrU8(IDS_ERR_JUMP_SESSION, "ProxyJump: libssh2 session init failed").c_str());
        return nullptr;
    }
    jmpSession->setBlocking(0);

    // SSH handshake with jump host.
    ShowStatusId(IDS_LOG_JUMP_HANDSHAKE, nullptr, true);
    {
        int r = LIBSSH2_ERROR_EAGAIN;
        while (r == LIBSSH2_ERROR_EAGAIN) {
            r = jmpSession->handshake(jmpSock);
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
            // jmpSession destructor (unique_ptr scope-exit) handles disconnect+free.
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
        // jmpSession destructor (unique_ptr scope-exit) handles disconnect+free.
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
        // jmpSession destructor (unique_ptr scope-exit) handles disconnect+free.
        closesocket(jmpSock);
        if (cs->feedback)
            cs->feedback->ShowError(("ProxyJump: authentication to jump host failed.\nUser: " + jump.user).c_str());
        return nullptr;
    }

    // kbdCtx lives on this frame and the settings it points at one frame up,
    // while the session travels on inside the returned stream. Nothing reads
    // the context once authentication is over, so clear the slot rather than
    // leave the session holding an address that is about to expire.
    if (void** abstractSlot = jmpSession->abstractPtr())
        *abstractSlot = nullptr;

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
        // jmpSession destructor (unique_ptr scope-exit) handles disconnect+free.
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

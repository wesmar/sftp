#pragma once
// Internal declarations shared across SftpClient sub-modules.
// Do NOT include from public headers - this is a build-internal header only.

#include "global.h"
#include "SftpClient.h"
#include "UnicodeHelpers.h"
#include <array>
#include <vector>
#include <string>
#include <chrono>
#include <cstdint>  // for int8_t
#include <functional>

inline bool IsPhpAgentTransport(const pConnectSettings cs) noexcept
{
    if (!cs)
        return false;
    return cs->transfermode == static_cast<int>(sftp::TransferMode::php_agent) ||
           cs->transfermode == static_cast<int>(sftp::TransferMode::php_shell);
}

inline bool IsLanPairTransport(const pConnectSettings cs) noexcept
{
    if (!cs)
        return false;
    return cs->transfermode == static_cast<int>(sftp::TransferMode::smb_lan);
}

// ---------------------------------------------------------------------------
// SCP compile-time feature flags (defined in SftpConnection.cpp)
// ---------------------------------------------------------------------------
extern const bool SSH_ScpNo2GBLimit;
extern const bool SSH_ScpCanSendKeepAlive;
extern const bool SSH_ScpNeedBlockingMode;
extern const bool SSH_ScpNeedQuote;

// ---------------------------------------------------------------------------
// Auth method flags (used in SftpConnection.cpp and SftpAuth.cpp)
// ---------------------------------------------------------------------------
constexpr int SSH_AUTH_PASSWORD         = 0x01;
constexpr int SSH_AUTH_KEYBOARD         = 0x02;
constexpr int SSH_AUTH_PUBKEY           = 0x04;
constexpr int SSH_AUTH_STAGE_TIMEOUT_MS = 10000; // interactive stages (password prompt etc.)
constexpr int SSH_PROBE_TIMEOUT_MS      =  3000; // silent server probe (userauthList)
constexpr int SFTP_INIT_TIMEOUT_MS      = 15000; // SFTP subsystem start; a host without one never answers

// ---------------------------------------------------------------------------
// Shared timing constants (used across SftpConnection.cpp, SftpAuth.cpp, etc.)
// ---------------------------------------------------------------------------
static constexpr DWORD RECONNECT_SLEEP_MS       = 1000;
static constexpr DWORD PAGEANT_WAIT_MS          = 2000;
static constexpr DWORD PAGEANT_TIMEOUT_MS       = 20000;
static constexpr DWORD SOCKET_POLL_MS           = 50;
static constexpr DWORD SOCKET_READ_POLL_MS      = 1000;
static constexpr DWORD PROGRESS_UPDATE_MS       = 100;

// Reconnect timeout, used by ReconnectSFTPChannelIfNeeded. Disconnect needs no
// such budget: SSH_MSG_DISCONNECT is fire-and-forget per RFC 4253 §11.1, so
// SftpCloseConnection only briefly retries on EAGAIN.
static constexpr DWORD RECONNECT_SFTP_TIMEOUT_MS = 2000;

// Tri-state flags for auto-detection fields (utf8names, unixlinebreaks, scpserver64bit).
// AUTODETECT_PENDING means we haven't queried the server yet.
// Using int8_t (guaranteed signed) instead of char (which may be unsigned on some platforms)
inline constexpr int8_t AUTODETECT_OFF     =  0;
inline constexpr int8_t AUTODETECT_ON      =  1;
inline constexpr int8_t AUTODETECT_PENDING = -1;

// ---------------------------------------------------------------------------
// Globals defined in SftpConnection.cpp
// ---------------------------------------------------------------------------
extern pConnectSettings gConnectResults;
extern LPCSTR        gDisplayName;
extern LPCSTR        gIniFileName;
extern LPCSTR        g_pszKey;

// Transfer-mode globals (defined in SftpConnection.cpp, used by Transfer+Shell)
extern char          Global_TransferMode;   // 'I'=Binary, 'A'=Ansi, 'X'=Auto
extern std::array<WCHAR, 1024> Global_TextTypes;
extern char          global_detectcrlf;     // 0=no, 1=yes, -1=detecting

// ---------------------------------------------------------------------------
// Utility functions defined in SftpConnection.cpp
// ---------------------------------------------------------------------------
bool  EscapePressed() noexcept;
void  wcslcpytoutf8(LPSTR utf8str, LPCWSTR utf16str, size_t maxlen);
// Remote names in the session's encoding. W2A writes the whole path or an
// empty string; A2W cuts a name that does not fit (for display). Both return
// whether the text fit; outmax counts the terminator.
bool  CopyStringW2A(pConnectSettings cs, LPCWSTR instr, LPSTR outstr, size_t outmax) noexcept;
bool  CopyStringA2W(pConnectSettings cs, LPCSTR instr, LPWSTR outstr, size_t outmax) noexcept;
bool  ProgressLoop(LPCSTR progresstext, int start, int end, int* loopval, SYSTICKS* lasttime);
void  SftpLogLastError(LPCSTR errtext, int errnr);
void  ShowStatusId(int errorid, LPCSTR suffix, bool silent = true);
void  ShowStatusId(int errorid, bool silent, int value);
inline void ShowStatusId(int errorid, const std::string& suffix, bool silent = true) {
    ShowStatusId(errorid, suffix.c_str(), silent);
}
void  ShowErrorId(int errorid, LPCSTR suffix = nullptr);
void  ShowError(LPCSTR error);

// Socket helpers (defined in SftpConnection.cpp)
void  SetBlockingSocket(SOCKET s, bool blocking);
void  EnableTcpKeepAlive(SOCKET s);
bool  IsSocketError(SOCKET s);
bool  IsSocketWritable(SOCKET s);
bool  IsSocketReadable(SOCKET s);
bool  WaitForTransportReadable(pConnectSettings cs);
bool  WaitForSshIo(pConnectSettings cs, DWORD timeoutMs = SOCKET_READ_POLL_MS);

// Generic EAGAIN-loop wrapper. Retries op() until it returns non-EAGAIN,
// timeout elapses, or Esc is pressed. Between attempts waits on the SSH
// socket in whichever direction libssh2 reports it's blocked on.
// Returns op()'s result on success, LIBSSH2_ERROR_TIMEOUT on timeout,
// LIBSSH2_ERROR_EAGAIN on abort.
template<typename F>
int WaitForOperation(F&& op, DWORD timeoutMs, pConnectSettings cs)
{
    const auto start = std::chrono::steady_clock::now();
    int rc;
    do {
        rc = op();
        if (rc != LIBSSH2_ERROR_EAGAIN)
            return rc;
        if (EscapePressed())
            return LIBSSH2_ERROR_EAGAIN;
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeoutMs)
            return LIBSSH2_ERROR_TIMEOUT;
        if (cs && (cs->sock != INVALID_SOCKET || cs->transport_stream))
            WaitForSshIo(cs, SOCKET_READ_POLL_MS);
        else
            Sleep(25);
    } while (true);
}

// Network helpers (extern "C" so they match libssh2 callback expectations)
extern "C" int mysend(SOCKET s, LPCSTR buf, int len, int flags,
                      LPCSTR progressmessage, int progressstart,
                      int* ploop, SYSTICKS* plasttime);
extern "C" int myrecv(SOCKET s, LPSTR buf, int len, int flags,
                      LPCSTR progressmessage, int progressstart,
                      int* ploop, SYSTICKS* plasttime);

// ---------------------------------------------------------------------------
// Connection functions defined in SftpConnection.cpp, used by other modules
// ---------------------------------------------------------------------------
int  SftpConnect(pConnectSettings ConnectSettings);
bool ReconnectSFTPChannelIfNeeded(pConnectSettings ConnectSettings);

// ---------------------------------------------------------------------------
// Auth functions defined in SftpAuth.cpp, called from SftpConnection.cpp
// ---------------------------------------------------------------------------
extern "C" void kbd_callback(LPCSTR name, int name_len,
                             LPCSTR instruction, int instruction_len,
                             int num_prompts,
                             const LIBSSH2_USERAUTH_KBDINT_PROMPT* prompts,
                             LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
                             LPVOID* abstract);

// A profile stores one secret string, which may pack two:
//     "<account password>","<key passphrase>"
// Both parts quoted, a comma between them; anything else is a plain account
// password. The two are not interchangeable — the account password is offered
// to the server, while the passphrase only ever decrypts a local key file — so
// the split lives here alone and every caller reads the part it names rather
// than deciding for itself what a bare string means.
struct StoredSecret {
    std::string accountPassword;
    std::string keyPassphrase;
    // True when the two-value form stated which secret is which. A plain
    // string is only a guess at the passphrase, so callers can let one
    // entered at a prompt outrank it.
    bool        labelled = false;
};
StoredSecret SplitStoredSecret(const std::string& stored);

// One SSH host to authenticate against. Both the target server and a jump
// host are described by this, so the authentication logic — PPK conversion,
// passphrase prompting, path expansion, missing-file checks — exists once
// instead of once per host kind.
//
// Both secrets point at the settings object that owns them. The password is
// read-only here: writing a key passphrase into it would offer that
// passphrase to the server on a password-auth fallback. The passphrase is
// writable, so one entered at a prompt is remembered for the automatic
// reconnects that run mid-transfer.
//
// `waitIo` differs per host: the target waits through its transport stream
// and a jump host on its own raw socket, because during the jump handshake
// the target's stream does not exist yet.
struct SshAuthTarget {
    ISshSession*          session       = nullptr;
    std::string           host;              // display only: prompts and logs
    std::string           user;
    const std::string*    password      = nullptr;   // offered to the server
    std::string*          keyPassphrase = nullptr;   // decrypts privkeyfile only
    std::string           pubkeyfile;
    std::string           privkeyfile;
    std::function<void()> waitIo;
};

// What a failed attempt should look like to the user. A host with further
// methods left to try reports quietly; a dead end says so with a dialog.
enum class AuthFailureUi { Modal, StatusOnly };

int SftpAuthPageantOn(const SshAuthTarget& target,
                      LPCSTR progressbuf, int progress,
                      int* ploop, SYSTICKS* plasttime);

int SftpAuthPubKeyOn(const SshAuthTarget& target, int progress,
                     int* ploop, SYSTICKS* plasttime, int* auth_pw,
                     AuthFailureUi onFailure);

// Wrappers binding the above to the target server's settings.
int SftpAuthPageant(pConnectSettings ConnectSettings,
                    LPCSTR progressbuf, int progress,
                    int* ploop, SYSTICKS* plasttime);

int SftpAuthPubKey(pConnectSettings ConnectSettings, int progress,
                   int* ploop, SYSTICKS* plasttime, int* auth_pw);

// Whether the file at `path` (expanded the way key paths are at connect)
// holds a private key, judged by its contents rather than by which field
// it was entered in.
bool KeyFileHoldsPrivateKey(const std::string& path, const std::string& user);

// ---------------------------------------------------------------------------
// Shell / channel helpers defined in SftpShell.cpp
// ---------------------------------------------------------------------------
void  StripEscapeSequences(LPSTR msgbuf);
std::unique_ptr<ISshChannel> ConnectChannel(ISshSession* session, SOCKET sock = INVALID_SOCKET);
bool  SendChannelCommand(ISshSession* session, ISshChannel* channel, LPCSTR command, SOCKET sock = INVALID_SOCKET);
bool  SendChannelCommandNoEof(ISshSession* session, ISshChannel* channel, LPCSTR command, SOCKET sock = INVALID_SOCKET);
bool  GetChannelCommandReply(ISshSession* session, ISshChannel* channel, LPCSTR command, SOCKET sock = INVALID_SOCKET);
void  DisconnectShell(ISshChannel* channel);
bool  EnsureScpShell(pConnectSettings cs);
void  CloseScpShell(pConnectSettings cs);
// Reads a shell command's output up to its end marker. `endLineOut`, when
// given, receives the marker line itself: a command that appends its exit
// status there has no other way to report it, since the line is not part of
// the output.
bool  ScpReadCommandOutput(pConnectSettings cs, const char* endMarker, std::vector<std::string>& outLines, DWORD timeoutMs, const char* beginMarker = nullptr, std::string* endLineOut = nullptr);
bool  ReadChannelLine(ISshChannel* channel,
                      char* line, size_t linelen,
                      std::string& msgbuf, std::string& errbuf,
                      SOCKET sock = INVALID_SOCKET,
                      DWORD idleTimeoutMs  = 10000,
                      DWORD totalTimeoutMs = 45000);

int  SftpQuoteCommand2W(pConnectSettings ConnectSettings, LPCWSTR remotedir, LPCWSTR cmd, LPSTR reply, size_t replylen);

// ---------------------------------------------------------------------------
// Transfer helpers defined in SftpTransfer.cpp, used by SftpRemoteOps.cpp
// ---------------------------------------------------------------------------
int CloseRemote(pConnectSettings ConnectSettings,
                ISftpHandle* remotefilesftp,
                ISshChannel* remotefilescp,
                bool timeout, int percent);

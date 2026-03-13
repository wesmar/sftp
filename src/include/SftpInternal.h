#pragma once
// Internal declarations shared across SftpClient sub-modules.
// Do NOT include from public headers - this is a build-internal header only.

#include "global.h"
#include "SftpClient.h"
#include "UnicodeHelpers.h"
#include <array>
#include <vector>
#include <string>
#include <cstdint>  // for int8_t

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
// Dynamic libssh2 function pointers (non-ALLINONE build)
// In SFTP_ALLINONE mode the linker resolves them directly; in dynamic mode
// SftpConnection.cpp holds the pointer variables and every other TU needs
// extern declarations.
// ---------------------------------------------------------------------------
#ifndef SFTP_ALLINONE
#define FUNCDEF(r, f, p)  typedef r (*t##f) p; extern t##f f;
#define FUNCDEF2(r, f, p) typedef r (*t##f) p; extern t##f f;
#include "SshDynFunctions.h"
#undef FUNCDEF2
#undef FUNCDEF
#endif

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

// ---------------------------------------------------------------------------
// Shared timing constants (used across SftpConnection.cpp, SftpAuth.cpp, etc.)
// ---------------------------------------------------------------------------
static constexpr DWORD RECONNECT_SLEEP_MS       = 1000;
static constexpr DWORD PAGEANT_WAIT_MS          = 2000;
static constexpr DWORD PAGEANT_TIMEOUT_MS       = 20000;
static constexpr DWORD SOCKET_POLL_MS           = 50;
static constexpr DWORD SOCKET_READ_POLL_MS      = 1000;
static constexpr DWORD PROGRESS_UPDATE_MS       = 100;

// Disconnect/reconnect loop timeouts (used in SftpCloseConnection and
// ReconnectSFTPChannelIfNeeded to avoid hanging indefinitely).
static constexpr DWORD DISCONNECT_ABORT_MS      = 2000;  // abort if user pressed Escape
static constexpr DWORD DISCONNECT_TIMEOUT_MS    = 5000;  // hard timeout without user input
static constexpr DWORD RECONNECT_SFTP_TIMEOUT_MS = 2000; // partial reconnect timeout

// Tri-state flags for auto-detection fields (utf8names, unixlinebreaks, scpserver64bit).
// AUTODETECT_PENDING means we haven't queried the server yet.
// Using int8_t (guaranteed signed) instead of char (which may be unsigned on some platforms)
inline constexpr int8_t AUTODETECT_OFF     =  0;
inline constexpr int8_t AUTODETECT_ON      =  1;
inline constexpr int8_t AUTODETECT_PENDING = -1;

// ---------------------------------------------------------------------------
// Globals defined in SftpConnection.cpp
// ---------------------------------------------------------------------------
extern bool          loadOK;
extern bool          loadAgent;
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
void  strlcpyansitoutf8(LPSTR utf8str, LPCSTR ansistr, size_t maxlen) noexcept;
void  wcslcpytoutf8(LPSTR utf8str, LPCWSTR utf16str, size_t maxlen);
void  CopyStringW2A(pConnectSettings cs, LPCWSTR instr, LPSTR outstr, size_t outmax) noexcept;
void  CopyStringA2W(pConnectSettings cs, LPCSTR instr, LPWSTR outstr, size_t outmax, bool useCVT = true) noexcept;
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
bool  IsSocketError(SOCKET s);
bool  IsSocketWritable(SOCKET s);
bool  IsSocketReadable(SOCKET s);
bool  WaitForTransportReadable(pConnectSettings cs);

void  EncryptString(LPCTSTR pszPlain,     LPTSTR pszEncrypted, UINT cchEncrypted);
void  DecryptString(LPCTSTR pszEncrypted, LPTSTR pszPlain,     UINT cchPlain);

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

int SftpAuthPageant(pConnectSettings ConnectSettings,
                    LPCSTR progressbuf, int progress,
                    int* ploop, SYSTICKS* plasttime, int* auth_pw);

int SftpAuthPubKey(pConnectSettings ConnectSettings,
                   LPCSTR progressbuf, int progress,
                   int* ploop, SYSTICKS* plasttime, int* auth_pw);

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
bool  ScpReadCommandOutput(pConnectSettings cs, const char* endMarker, std::vector<std::string>& outLines, DWORD timeoutMs, const char* beginMarker = nullptr);
bool  ReadChannelLine(ISshChannel* channel,
                      LPSTR line,   size_t linelen,
                      LPSTR msgbuf, size_t msgbuflen,
                      LPSTR errbuf, size_t errbuflen,
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

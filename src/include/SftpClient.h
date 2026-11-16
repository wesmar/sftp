#pragma once

#include "global.h"

// Modern static linking: include headers from libssh2/ subdirectory in PHP deps.
#include <libssh2/libssh2.h>
#include <libssh2/libssh2_sftp.h>

#include <memory>
#include <string>
#include <unordered_map>
#include "ServerRegistry.h"
#include "CoreUtils.h"
#include "ISshBackend.h"
#include "IUserFeedback.h"

#include "LanPairSession.h"
#include "ITransportStream.h"

enum SftpResult : int
{
    SFTP_OK          = 0,
    SFTP_FAILED      = 1,
    SFTP_EXISTS      = 2,
    SFTP_READFAILED  = 3,
    SFTP_WRITEFAILED = 4,
    SFTP_ABORT       = 5,
    SFTP_PARTIAL     = 6,
};

extern int PluginNumber;
extern char s_quickconnect[64];

namespace sftp {

enum class Proxy : int
{
    notused = 0,
    deflt   = 1,
    http    = 2,
    socks4  = 3,
    socks5  = 4,
};

enum class PassSaveMode : int
{
    empty   = 0,   /* without password */
    crypt   = 1,   /* use TotalCmd as password agent */
    plain   = 2,   /* plaintext */
};

enum class TransferMode : int
{
    ssh_auto   = 0,  // Existing SSH-based transport (SFTP/SCP/shell paths)
    php_agent  = 1,  // Standalone HTTP PHP agent transport
    php_shell  = 2,  // Standalone HTTP PHP shell transport (stage 2)
    smb_lan    = 3,  // Local network pairing transport (future SMB-like mode)
};

}

struct scp_opendir_data {
    int TempPathUniqueValue;
    HANDLE tempfile;
};

// What a listing says about an entry beyond WIN32_FIND_DATA, served to Total
// Commander's custom columns. The mode is kept as a number and formatted on
// request, since a column call gets the path and nothing else.
struct ListingExtra {
    std::wstring owner;
    std::wstring group;
    std::wstring linkTarget;
    DWORD        mode = 0;   // st_mode, 0 when the listing gave none
    uint64_t     size = 0;
    FILETIME     mtime{};    // zero when the listing gave none
};

// Entry name → its extras, for one directory.
using DirectoryExtras = std::unordered_map<std::wstring, ListingExtra>;

struct tConnectSettings {
    std::string DisplayName;
    std::string IniFileName;
    std::string server;
    std::string user;
    std::string password;   // as the profile stores it; may pack both secrets

    // The two secrets `password` resolves to, filled once authentication
    // starts. Runtime only: neither is written to the INI, and the passphrase
    // is never offered to the server. It survives here so an automatic
    // reconnect can reuse the key without prompting again.
    std::string account_password;
    std::string key_passphrase;
    std::string connectsendcommand;
    std::string sftpservercommand;   // empty: request the "sftp" subsystem
    WCHAR lastactivepath[1024];
    std::string savedfingerprint;
    std::string pubkeyfile;
    std::string privkeyfile;
    int sendcommandmode;

    SOCKET sock;
    std::unique_ptr<ISshSession>    session;
    std::unique_ptr<ISftpSession>   sftpsession;
    std::unique_ptr<ISshChannel>    scpShellChannel;

    bool useagent;
    int protocoltype; // 0 = auto,  1 = IPv4,  2 = IPv6
    int servernamelen;
    unsigned short customport;
    int filemod;
    int dirmod;
    int transfermode; // sftp::TransferMode
    bool scponly;
    bool scpfordata;
    bool dialogforconnection;
    bool saveonlyprofile;   // quick dialog: save named profile without immediate connect
    bool compressed;
    bool detailedlog;
    bool neednewchannel;   // kill the sftp channel in case of an error
    SYSTICKS findstarttime; // time findfirstfile started, MUST be int
    char utf8names       = -1;   // 0=no, 1=yes, -1=auto-detect
    int  codepage        = 0;    // only used when utf8names=0 (0 = not set)
    char unixlinebreaks  = -1;   // 0=no, 1=yes, -1=auto-detect
    int proxynr;           // 0=no proxy, >0 use entry  [proxy], [proxy2] etc.
    sftp::Proxy proxytype;
    std::string proxyserver;
    std::string proxyuser;
    std::string proxypassword;
    SYSTICKS lastpercenttime;
    int lastpercent;
    // A copy between two sessions is two transfers, and Total Commander shows
    // one progress bar. Each leg reports its own 0..100, so it is folded into
    // a slice of the whole here, and the names shown are those of the two
    // remote files rather than the temporary one standing between them.
    int  progressFrom = 0;
    int  progressSpan = 100;
    const wchar_t* progressSourceOverride = nullptr;
    const wchar_t* progressTargetOverride = nullptr;
    sftp::PassSaveMode passSaveMode;
    bool InteractivePasswordSent;
    int trycustomlistcommand;  // set to 2 initially, reduce to 1 or 0 if failing
    int  scpserver64bit  = -1;   // 0=no, 1=yes, -1=auto-detect
    bool scpserver64bittemporary;  // true=user allowed transfers>2GB
    std::string scpShellMsgBuf;
    std::string scpShellErrBuf;

    // SCP runtime profile
    bool scp_echo_only_end;
    bool scp_strict_end;
    bool scp_fast_close_required;

    // Shell DD/base64 fallback transfer (for hosts that block both SFTP and SCP)
    bool shell_transfer_dd;    // enabled via INI key "shelltransfer=1"
    bool shell_transfer_force; // INI key "shelltransferforce=1"
    bool shell_dd_b64only;     // cached runtime flag: raw binary failed, use base64 only
    int php_http_mode;         // 0=auto, 1=POST, 2=PUT
    int php_chunk_mib;         // 0=auto, manual: 2/4/8/16/32/64 MiB
    int php_recommended_chunk_mib; // runtime from PROBE (0=unknown), used only when php_chunk_mib=0
    bool php_tar = false;          // TAR streaming for directory downloads (PHP Agent only)
    // Request signing (TCSFTP-HMAC-V2), learnt from the agent's PROBE
    bool php_auth_known = false;    // scheme confirmed and salt read
    std::string php_auth_salt;      // AGENT_PSK_SALT of the agent ("" when none)
    int64_t php_clock_offset = 0;   // agent clock minus ours, in seconds
    int lan_pair_role;         // 0=auto, 1=receiver, 2=donor
    std::string lan_pair_peer; // peerId of the remote machine (set during pairing)
    std::string lan_pair_ip;   // current IP of remote peer (found by discovery)
    uint16_t lan_pair_port = 45846; // TCP port of remote peer's file server
    int lan_pair_timeout_min = 0;         // 0=no limit
    bool lan_pair_trusted_installer = false; // impersonate NT SERVICE\TrustedInstaller on connect
    std::unique_ptr<LanPairSession> lanSession; // active file session (nullptr when disconnected)

    // -----------------------------------------------------------------------
    // SSH ProxyJump / jump host settings
    // Loaded from INI, separate from target host auth.
    // -----------------------------------------------------------------------
    bool           use_jump_host   = false;
    std::string    jump_host;
    unsigned short jump_port       = 22;
    std::string    jump_user;
    std::string    jump_password;
    std::string    jump_pubkeyfile;
    std::string    jump_privkeyfile;
    bool           jump_useagent   = false;
    std::string    jump_fingerprint;   // saved MD5 hex fingerprint
    // Resolved passphrase for the jump host's key. Runtime only, and kept
    // here rather than in JumpHostSettings because that struct is rebuilt on
    // every connect, which would make each reconnect prompt again.
    std::string    jump_key_passphrase;
    // Jump host password typed at the prompt when none is stored. Runtime
    // only, for the same reason as the passphrase above.
    std::string    jump_entered_password;
    // A refused jump host is reported with a dialog once per connection and
    // by status line after that: the reconnects that run mid-transfer would
    // otherwise stack a modal per attempt, on whatever thread they happen on.
    bool           jump_refusal_shown = false;
    // When non-empty, jump host params (host/port/user/password/keys/useagent)
    // are taken from the referenced saved session at connect time, ignoring
    // the manual jump_* fields above. Stored in INI as `jumpsessionref=<name>`.
    std::string    jump_session_ref;

    // Active transport stream. Non-null when ProxyJump is in use.
    // Owned here; must be reset AFTER the target ISshSession is freed,
    // but BEFORE cs->sock is closed.
    std::unique_ptr<ITransportStream> transport_stream;

    WCHAR current_sourceW[wdirtypemax];
    WCHAR current_targetW[wdirtypemax];
    std::unique_ptr<IUserFeedback> feedback;

    // Listing extras per directory, keyed by the directory as Total Commander
    // names it (`\etc`). A new listing replaces that directory's entry only,
    // so the other panel showing another directory keeps its columns.
    std::unordered_map<std::wstring, DirectoryExtras> listingExtras;
};

using pConnectSettings = tConnectSettings*;

// Secrets that live only in memory: entered at a prompt on an earlier connect
// and absent from the stored profile. A background transfer opens its own
// connection to the same session, and without these it prompts for each one.
struct RuntimeSecrets {
    std::string accountPassword;
    std::string keyPassphrase;
    std::string jumpKeyPassphrase;
};

// `loggingAliasName`, when non-null, overrides the name reported to TC via
// LogProc(MSGTYPE_CONNECT). Used for virtual (Imports-cache-backed)
// sessions whose real DisplayName is the internal "__import.<...>" cache
// section — TC needs a clean single-segment path in its toolbar so the
// standard Disconnect button works normally. Non-Import callers pass
// nullptr, which reports the session's own name.
//
// `inherited` carries the runtime secrets above from a connection that
// already prompted for them.
pConnectSettings SftpConnectToServer(LPCSTR DisplayName, LPCSTR inifilename,
                                     LPCSTR overridepass,
                                     LPCSTR loggingAliasName = nullptr,
                                     const RuntimeSecrets* inherited = nullptr);
void SftpGetServerBasePathW(LPCWSTR DisplayName, LPWSTR RelativePath, size_t maxlen, LPCSTR inifilename);
bool SftpConfigureServer(LPCSTR DisplayName, LPCSTR inifilename);
int  SftpCloseConnection(pConnectSettings ConnectSettings);

// Cheap TCP/transport liveness probe on an already-open connection. Answers
// the question "is this session usable RIGHT NOW, without a full round-trip"
// so callers that would otherwise blindly reuse a cached `serverid` can
// detect that the peer (SSH server, LAN pair, PHP agent) died — most often
// via reboot or firewall — and force a fresh implicit connect instead of
// hanging inside SftpFindFirstFileW's openDir retry loop.
//
// Semantics: true = still alive as far as we can tell without generating
// SSH traffic; false = definitely dead (FIN/RST received, transport gone).
// A false positive is safe (the very next libssh2 call will surface the
// real error and reconnect via the existing SftpFindFirstFileW loop); a
// false negative just means we skip the shortcut and pay for the full
// hang detection path, which is the pre-fix behaviour.
bool IsSessionAlive(pConnectSettings ConnectSettings) noexcept;

int  SftpFindFirstFileW(pConnectSettings ConnectSettings, LPCWSTR remotedir, LPVOID * davdataptr);
int  SftpFindNextFileW(pConnectSettings ConnectSettings, LPVOID davdataptr, LPWIN32_FIND_DATAW FindData) noexcept;
int  SftpFindClose(pConnectSettings ConnectSettings, LPVOID davdataptr);

int  SftpCreateDirectoryW(pConnectSettings ConnectSettings, LPCWSTR Path);
int  SftpRenameMoveFileW(pConnectSettings ConnectSettings, LPCWSTR OldName, LPCWSTR NewName, bool Move, bool Overwrite, bool isdir);
int  SftpDownloadFileW(pConnectSettings ConnectSettings, LPCWSTR RemoteName, LPCWSTR LocalName, bool alwaysoverwrite, int64_t filesize, LPFILETIME ft, bool Resume);
int  SftpUploadFileW(pConnectSettings ConnectSettings, LPCWSTR LocalName, LPCWSTR RemoteName, bool Resume, bool setattr);
int  SftpDeleteFileW(pConnectSettings ConnectSettings, LPCWSTR RemoteName, bool isdir);
int  SftpSetAttr(pConnectSettings ConnectSettings, LPCSTR RemoteName, int NewAttr);
int  SftpSetDateTimeW(pConnectSettings ConnectSettings, LPCWSTR RemoteName, LPFILETIME LastWriteTime);
void SftpGetLastActivePathW(pConnectSettings ConnectSettings, LPWSTR RelativePath, size_t maxlen);
bool SftpChmodW(pConnectSettings ConnectSettings, LPCWSTR RemoteName, LPCWSTR chmod);
// Key of a directory in listingExtras: Total Commander's form, no trailing
// separator except for the root.
std::wstring ListingDirKey(std::wstring_view dir);
// Extras the last listing gave for a path relative to the session, or null.
const ListingExtra* FindListingExtra(pConnectSettings cs, std::wstring_view relPath);
// "rwxr-xr-x" with s/S and t/T for the special bits, as `ls` writes it.
std::wstring FormatPermissions(DWORD mode);
bool SftpLinkFolderTargetW(pConnectSettings ConnectSettings, LPWSTR RemoteName, size_t maxlen);
int  SftpQuoteCommand2(pConnectSettings ConnectSettings, LPCSTR remotedir, LPCSTR cmd, LPSTR reply, size_t replylen,
                       DWORD idleTimeoutMs = 10000, DWORD totalTimeoutMs = 45000);
int  SftpQuoteCommand2W(pConnectSettings ConnectSettings, LPCWSTR remotedir, LPCWSTR cmd, LPSTR reply, size_t replylen);
bool SftpQuoteCommand(pConnectSettings ConnectSettings, LPCSTR remotedir, LPCSTR cmd);
void SftpShowPropertiesW(pConnectSettings ConnectSettings, LPCWSTR remotename);
void SftpSetTransferModeW(LPCWSTR mode);
bool SftpDetermineTransferModeW(LPCWSTR RemoteName);
bool SftpSupportsResume(pConnectSettings ConnectSettings);
int  SftpServerSupportsChecksumsW(pConnectSettings ConnectSettings, LPCWSTR RemoteName);
HANDLE SftpStartFileChecksumW(int ChecksumType, pConnectSettings ConnectSettings, LPCWSTR RemoteName);
int SftpGetFileChecksumResultW(bool WantResult, HANDLE ChecksumHandle, pConnectSettings ConnectSettings, LPSTR checksum, size_t maxlen);

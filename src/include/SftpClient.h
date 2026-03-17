#pragma once

#include "global.h"

// Modern static linking: include headers from libssh2/ subdirectory in PHP deps.
#include <libssh2/libssh2.h>
#include <libssh2/libssh2_sftp.h>

#include <memory>
#include <string>
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

struct tConnectSettings {
    std::string DisplayName;
    std::string IniFileName;
    std::string server;
    std::string user;
    std::string password;
    std::string connectsendcommand;
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
    char utf8names;        // 0=no, 1=yes, -1=auto-detect
    int codepage;          // only used when utf8names=0
    char unixlinebreaks;   // 0=no, 1=yes, -1=auto-detect
    int proxynr;           // 0=no proxy, >0 use entry  [proxy], [proxy2] etc.
    sftp::Proxy proxytype;
    std::string proxyserver;
    std::string proxyuser;
    std::string proxypassword;
    SYSTICKS lastpercenttime;
    int lastpercent;
    sftp::PassSaveMode passSaveMode;
    bool InteractivePasswordSent;
    int trycustomlistcommand;  // set to 2 initially, reduce to 1 or 0 if failing
    int scpserver64bit;     // 0=no, 1=yes, -1, auto-detect
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
    int lan_pair_role;         // 0=auto, 1=receiver, 2=donor
    std::string lan_pair_peer; // peerId of the remote machine (set during pairing)
    std::string lan_pair_ip;   // current IP of remote peer (found by discovery)
    uint16_t lan_pair_port = 45846; // TCP port of remote peer's file server
    int lan_pair_timeout_min = 0;   // 0=no limit
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

    // Active transport stream. Non-null when ProxyJump is in use.
    // Owned here; must be reset AFTER the target ISshSession is freed,
    // but BEFORE cs->sock is closed.
    std::unique_ptr<ITransportStream> transport_stream;

    WCHAR current_sourceW[wdirtypemax];
    WCHAR current_targetW[wdirtypemax];
    std::unique_ptr<IUserFeedback> feedback;
};

using pConnectSettings = tConnectSettings*;

pConnectSettings SftpConnectToServer(LPCSTR DisplayName, LPCSTR inifilename, LPCSTR overridepass);
void SftpGetServerBasePathW(LPCWSTR DisplayName, LPWSTR RelativePath, size_t maxlen, LPCSTR inifilename);
bool SftpConfigureServer(LPCSTR DisplayName, LPCSTR inifilename);
int  SftpCloseConnection(pConnectSettings ConnectSettings);
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

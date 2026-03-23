// SFTP transport/session implementation.
// Maintainer: Marek Wesolowski (wesmar)
#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <commdlg.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <fcntl.h>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "UtfConversion.h"
#include "UnicodeHelpers.h"
#include "FtpDirectoryParser.h"

#include "SftpInternal.h"
#include "SshBackendFactory.h"
#include "WindowsUserFeedback.h"
#include <array>
#include <condition_variable>
#include <new>
#include <fstream>
#include <iterator>
#include <vector>
#include "SessionImport.h"
#include "PhpAgentClient.h"
#include "PhpShellConsole.h"
#include "ConnectionDialog.h"
#include "SessionPostAuth.h"
#include "ConnectionLifecycle.h"
#include "ConnectionNetwork.h"
#include "SshSessionInit.h"
#include "ConnectionAuth.h"
#include "SshLibraryLoader.h"
#include "LanPairSession.h"
#include "TrustedInstallerToken.h"
#include "JumpHostConnection.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

// SFTP_ALLINONE: Linker resolves libssh2 functions directly.
// No dynamic LoadLibrary calls needed.

#define CONN_LOG(fmt, ...) SFTP_LOG("CONN", fmt, ##__VA_ARGS__)

// Global SSH backend instance (created once, never changes)
static std::unique_ptr<ISshBackend> g_sshBackend;

// Global LAN Pair file server: started at plugin init, serves all authenticated peers.
// Also the discovery service that announces this machine's presence.
static std::unique_ptr<LanFileServer>    g_lanFileServer;
static std::unique_ptr<lanpair::DiscoveryService> g_lanDiscovery;

// ---------------------------------------------------------------------------
// Connection progress step percentages
// ---------------------------------------------------------------------------
static constexpr int PROG_SOCKET_CONNECT  = 20;
static constexpr int PROG_SESSION_INIT    = 30;
static constexpr int PROG_SESSION_STARTUP = 40;
static constexpr int PROG_AUTH_START      = 60;
static constexpr int PROG_AUTH_DONE       = 70;
static constexpr int PROG_SFTP_INIT       = 80;
static constexpr int PROG_DONE            = 90;

bool serverfieldchangedbyuser = false;
char Global_TransferMode = 'I';  //I=Binary,  A=Ansi,  X=Auto
std::array<WCHAR, 1024> Global_TextTypes{};

char global_detectcrlf = 0;

const bool SSH_ScpNo2GBLimit = true;
const bool SSH_ScpNeedBlockingMode = false;   // Need to use blocking mode for SCP?
const bool SSH_ScpNeedQuote = false;          // Need to use double quotes "" around names with spaces for SCP?
const bool SSH_ScpCanSendKeepAlive = false;   // Declared in SftpInternal.h; keepalive not needed for SCP

void EncryptString(LPCTSTR pszPlain, LPTSTR pszEncrypted, UINT cchEncrypted);


bool EscapePressed() noexcept
{
    // Honor Escape only for the current process.
    if (GetAsyncKeyState(VK_ESCAPE) < 0) {
        DWORD procid1 = 0;
        HWND hwnd = GetActiveWindow();
        if (hwnd) {
            GetWindowThreadProcessId(hwnd, &procid1);
            if (procid1 == GetCurrentProcessId())
                return true;
        }
    }
    return false;
}

void strlcpyansitoutf8(LPSTR utf8str, LPCSTR ansistr, size_t maxlen) noexcept
{
    std::array<WCHAR, 1024> utf16buf{};
    MultiByteToWideChar(CP_ACP, 0, ansistr, -1, utf16buf.data(), static_cast<int>(utf16buf.size()));
    ConvUTF16toUTF8(utf16buf.data(), 0, utf8str, maxlen);
}

void wcslcpytoutf8(LPSTR utf8str, LPCWSTR utf16str, size_t maxlen)
{
    ConvUTF16toUTF8(utf16str, 0, utf8str, maxlen);
}

void CopyStringW2A(pConnectSettings ConnectSettings, LPCWSTR instr, LPSTR outstr, size_t outmax) noexcept
{
    if (ConnectSettings->utf8names > 0) {
        ConvUTF16toUTF8(instr, 0, outstr, outmax);
    } else {
        walcopyCP(ConnectSettings->codepage, outstr, instr, outmax - 1);
    }
}

void CopyStringA2W(pConnectSettings ConnectSettings, LPCSTR instr, LPWSTR outstr, size_t outmax, bool useCVT) noexcept
{
    if (ConnectSettings->utf8names > 0) {
        if (useCVT)
            ConvUTF8toUTF16(instr, 0, outstr, outmax);
        else
            awlcopyCP(CP_UTF8, outstr, instr, outmax - 1);
    } else {
        awlcopyCP(ConnectSettings->codepage, outstr, instr, outmax - 1);
    }
}

extern "C"
LPVOID myalloc(size_t count, LPVOID * abstract)
{
    return malloc(count);
}

extern "C"
LPVOID myrealloc(LPVOID ptr, size_t count, LPVOID * abstract)
{
    return realloc(ptr, count);
}

extern "C"
void myfree(LPVOID ptr, LPVOID * abstract)
{
    free(ptr);
}
bool ProgressLoop(LPCSTR progresstext, int start, int end, int * loopval, SYSTICKS * lasttime)
{
    SYSTICKS time = get_sys_ticks();
    if (time - *lasttime > PROGRESS_UPDATE_MS || *loopval < start) {
        *lasttime = time;
        (*loopval)++;
        if (*loopval < start || *loopval > end)
            *loopval = start;
        return ProgressProc(PluginNumber, progresstext, "-", *loopval) != 0;    // "-" = no target file (TC plugin API convention)
    }
    return false;
}

void SftpLogLastError(LPCSTR errtext, int errnr)
{
    std::array<char, 128> errbuf{};
    if (errnr == 0 || errnr == LIBSSH2_ERROR_EAGAIN)   //no error -> do not log
        return;
    
    // Formatting: "text: error_number"
    snprintf(errbuf.data(), errbuf.size(), "%s %d", errtext ? errtext : "libssh2", errnr);
    LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, errbuf.data());
}

void ShowMessageIdEx(int errorid, LPCSTR p1, int p2, bool silent)
{
    if (errorid < 0)
        return;
    std::array<char, 256> loadedStr{};
    LoadStr(loadedStr, errorid);
    std::string msg = loadedStr.data();
    if (p1) {
        auto pos = msg.find("%s");
        if (pos != std::string::npos)
            msg.replace(pos, 2, p1);
        else if ((pos = msg.find("%d")) != std::string::npos)
            msg.replace(pos, 2, std::to_string(p2));
        else
            msg += p1;
    }
    ShowStatus(msg.c_str());  // log it
    if (!silent)
        RequestProc(PluginNumber, RT_MsgOK, "SFTP Error", msg.c_str(), nullptr, 0);
}

void ShowStatusId(int errorid, bool silent, int value)
{
    ShowMessageIdEx(errorid, "", value, silent);
}

void ShowStatusId(int errorid, LPCSTR suffix, bool silent)
{
    ShowMessageIdEx(errorid, suffix, 0, silent);
}

void ShowErrorId(int errorid, LPCSTR suffix)
{
    ShowMessageIdEx(errorid, suffix, 0, false);
}

void ShowError(LPCSTR error)
{
    ShowStatus(error);  // log it
    RequestProc(PluginNumber, RT_MsgOK, "SFTP Error", error, nullptr, 0);
}


void SetBlockingSocket(SOCKET s, bool blocking)
{
    u_long arg = blocking ? 0 : 1;
    ioctlsocket(s, FIONBIO, &arg);
}

bool IsSocketError(SOCKET s)
{
    fd_set fds;
    timeval timeout = gettimeval(SOCKET_POLL_MS);
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    return 1 == select(0, nullptr, nullptr, &fds, &timeout);
}

bool IsSocketWritable(SOCKET s)
{
    fd_set fds;
    timeval timeout = gettimeval(SOCKET_POLL_MS);
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    return 1 == select(0, nullptr, &fds, nullptr, &timeout);
}

bool IsSocketReadable(SOCKET s)
{
    fd_set fds;
    // Wingate local requires a non-zero timeout in select().
    timeval timeout = gettimeval(SOCKET_READ_POLL_MS);
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    int err = select(0, &fds, nullptr, nullptr, &timeout);
    return (err == 1);
}

bool WaitForTransportReadable(pConnectSettings cs)
{
    if (!cs)
        return false;
    if (cs->transport_stream)
        return cs->transport_stream->waitReadable(SOCKET_READ_POLL_MS);
    return IsSocketReadable(cs->sock);
}

extern "C"
int mysend(SOCKET s, LPCSTR buf, int len, int flags, LPCSTR progressmessage, int progressstart, int * ploop, SYSTICKS * plasttime)
{
    int ret = SOCKET_ERROR;
    while (true) {
        ret = send(s, buf, len, flags);
        if (ret >= 0)
            return ret;
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            if (ProgressLoop(progressmessage, progressstart, progressstart + 10, ploop, plasttime))
                break;
        }
    }
    return ret;
}

extern "C"
int myrecv(SOCKET s, LPSTR buf, int len, int flags, LPCSTR progressmessage, int progressstart, int * ploop, SYSTICKS * plasttime)
{
    int totallen = len;
    int ret = SOCKET_ERROR;
    while (true) {
        if (IsSocketReadable(s)) {
            ret = recv(s, buf, len, flags);
            if (ret == len)
                return totallen;
            if (ret > 0) {
                buf += ret;
                len -= ret;
                continue;
            }
            if (WSAGetLastError() != WSAEWOULDBLOCK)
                return ret;
        }
        if (ProgressLoop(progressmessage, progressstart, progressstart + 10, ploop, plasttime))
            break;   /* User aborted. */
        Sleep(SOCKET_POLL_MS);
    }
    return ret;
}

// ---------------------------------------------------------------------------
// LAN Pair global server management
// ---------------------------------------------------------------------------

// Generate a stable peer ID for this machine/process combination.
static std::string MakeLanPeerId()
{
    char host[256] = {};
    gethostname(host, static_cast<int>(sizeof(host) - 1));
    return std::string(host); // hostname only — stable across TC restarts
}

void StartGlobalLanServices(bool startServer)
{
    if (startServer && (!g_lanFileServer || !g_lanFileServer->isRunning())) {
        g_lanFileServer = std::make_unique<LanFileServer>();
        lanpair::PairError err;
        if (!g_lanFileServer->start(45846, &err)) {
            SFTP_LOG("LAN", "LanFileServer start failed: %s", err.message.c_str());
            g_lanFileServer.reset();
        } else {
            // Restore previously saved server password (set when any LAN Pair profile was connected).
            std::string storedPw;
            if (lanpair::DpapiSecretStore::loadSecret("lanpair-server-pw", &storedPw, nullptr) &&
                !storedPw.empty()) {
                g_lanFileServer->setPassword(storedPw);
            }
        }
    }

    if (!g_lanDiscovery) {
        g_lanDiscovery = std::make_unique<lanpair::DiscoveryService>();
        lanpair::DiscoveryConfig cfg;
        const std::string peerId = MakeLanPeerId();
        char host[256] = {};
        gethostname(host, static_cast<int>(sizeof(host) - 1));
        lanpair::PairError derr;
        if (!g_lanDiscovery->start(cfg, peerId, host, lanpair::PairRole::Dual,
                                   nullptr, &derr)) {
            SFTP_LOG("LAN", "LanDiscovery start failed: %s", derr.message.c_str());
            g_lanDiscovery.reset();
        }
    }
}

void LanFileServerSetPassword(const std::string& pw)
{
    if (g_lanFileServer)
        g_lanFileServer->setPassword(pw);
}

void LanFileServerSetTrustedInstaller(bool enabled)
{
    if (g_lanFileServer)
        g_lanFileServer->setTrustedInstaller(enabled);
}

void StopGlobalLanServices()
{
    if (g_lanDiscovery) { g_lanDiscovery->stop(); g_lanDiscovery.reset(); }
    if (g_lanFileServer) { g_lanFileServer->stop(); g_lanFileServer.reset(); }
}

// Connect a LAN Pair session: run discovery to find the peer's current IP,
// then connect + authenticate with DPAPI trust key.
static int LanPairConnect(pConnectSettings cs)
{
    // lan_pair_role: 0=mutual, 1=receiver (biorca), 2=donor (dawca)
    if (cs->lan_pair_role == 2) {
        StartGlobalLanServices(true);   // ensure our server is running for inbound connections
        if (cs->feedback)
            cs->feedback->ShowError(LngStrU8(IDS_LAN_ERR_DONOR_NO_CONNECT,
                "LAN Pair: this machine is configured as Donor. The remote Receiver must connect here.").c_str());
        return SFTP_FAILED;
    }
    // Receiver (role==1) does not start a local file server; mutual (role==0) starts both.
    StartGlobalLanServices(cs->lan_pair_role == 0);

    // If we already have an active session, nothing to do.
    if (cs->lanSession && cs->lanSession->isConnected())
        return SFTP_OK;
    cs->lanSession.reset();

    ShowStatusId(IDS_LOG_LAN_DISCOVER, nullptr, true);

    // Wait up to 4 seconds for discovery to find the peer.
    const std::string targetPeerId = cs->lan_pair_peer;
    if (targetPeerId.empty()) {
        if (cs->feedback)
            cs->feedback->ShowError(LngStrU8(IDS_LAN_ERR_NO_PEER, "LAN Pair: no peer configured. Open connection settings and pair first.").c_str());
        return SFTP_FAILED;
    }

    std::string foundIp;
    uint16_t foundPort = 45846;

    // Start a short-lived discovery service to look for the peer.
    lanpair::DiscoveryService disco;
    lanpair::DiscoveryConfig dcfg;
    const std::string localId = MakeLanPeerId();
    char host[256] = {};
    gethostname(host, static_cast<int>(sizeof(host) - 1));

    std::mutex mu;
    std::condition_variable cv;
    bool found = false;

    disco.start(dcfg, localId, host, lanpair::PairRole::Dual,
        [&](const lanpair::PeerAnnouncement& ann) {
            if (ann.peerId != targetPeerId) return;
            std::lock_guard<std::mutex> lk(mu);
            foundIp   = ann.ip;
            foundPort = ann.tcpPort ? ann.tcpPort : 45846;
            found     = true;
            cv.notify_one();
        });

    {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait_for(lk, std::chrono::seconds(4), [&] { return found; });
    }
    disco.stop();

    if (!found) {
        if (cs->feedback)
            cs->feedback->ShowError(LngStrU8(IDS_LAN_ERR_PEER_NOT_FOUND, "LAN Pair: peer not found on the network. Make sure the other computer is running.").c_str());
        return SFTP_FAILED;
    }

    cs->lan_pair_ip   = foundIp;
    cs->lan_pair_port = foundPort;

    // Register password with our own server BEFORE connecting —
    // the remote peer may simultaneously try to connect to us using the same password.
    if (!cs->password.empty()) {
        lanpair::DpapiSecretStore::saveSecret("lanpair-server-pw", cs->password, nullptr);
        if (g_lanFileServer)
            g_lanFileServer->setPassword(cs->password);
    }

    {
        std::string s = LngStrU8(IDS_LAN_CONNECTING, "LAN Pair: connecting to {}...");
        const auto p = s.find("{}");
        if (p != std::string::npos) s.replace(p, 2, foundIp);
        ShowStatus(s.c_str());
    }

    lanpair::PairError err;
    auto session = LanPairSession::connect(
        foundIp, foundPort, localId, targetPeerId,
        cs->password,   // empty = use stored trust key
        &err);

    if (!session) {
        std::string msg = LngStrU8(IDS_LAN_ERR_CONN_FAILED, "LAN Pair: connection failed");
        if (!err.message.empty()) msg += " \xe2\x80\x94 " + err.message;
        if (cs->feedback) cs->feedback->ShowError(msg.c_str());
        return SFTP_FAILED;
    }

    session->setTimeoutMin(cs->lan_pair_timeout_min);
    session->setTrustedInstaller(cs->lan_pair_trusted_installer);
    cs->lanSession = std::move(session);

    if (cs->lan_pair_trusted_installer) {
        if (!AcquireTrustedInstallerToken()) {
            if (cs->feedback)
                cs->feedback->ShowError(LngStrU8(IDS_LAN_TI_ERR, "LAN Pair: TrustedInstaller impersonation failed.").c_str());
        }
    }

    ShowStatusId(IDS_LOG_LAN_CONNECTED, nullptr, true);
    return SFTP_OK;
}

int SftpConnect(pConnectSettings ConnectSettings)
{
    int hr = 0;
    if (IsLanPairTransport(ConnectSettings)) {
        return LanPairConnect(ConnectSettings);
    }
    if (IsPhpAgentTransport(ConnectSettings)) {
        ShowStatusId(IDS_LOG_PHP_AGENT_MODE, nullptr, true);
        if (PhpAgentProbe(ConnectSettings) != SFTP_OK) {
            if (ConnectSettings->feedback) {
                std::array<char, 256> msgbuf{};
                const int n = LoadStr(msgbuf, IDS_PHP_PROBE_FAILED);
                ConnectSettings->feedback->ShowError(n > 0 ? msgbuf.data() : "PHP Agent probe failed. Check URL and key.");
            }
            return SFTP_FAILED;
        }
        return SFTP_OK;
    }

    if (!LoadSSHLib())
        return SFTP_FAILED;
    if (!loadAgent && ConnectSettings->useagent) {
        std::array<char, 128> msgTemplate{};
        LoadStr(msgTemplate, IDS_SSH2_TOO_OLD);
        std::string msg = msgTemplate.data();
        auto pos = msg.find("%s");
        if (pos != std::string::npos)
            msg.replace(pos, 2, LIBSSH2_VERSION);
        if (ConnectSettings->feedback) {
            ConnectSettings->feedback->ShowError(msg.c_str());
        }
        return SFTP_FAILED;
    }
    std::array<char, 1024> buf{};
    std::array<char, 250> connecttoserver{};
    std::array<char, 250> progressbuf{};

    int progress = 0;
    unsigned short connecttoport;
    int loop;
    SYSTICKS lasttime = get_sys_ticks();
    auto fail = [&](int code) -> int {
        return CleanupFailedConnect(ConnectSettings, code, &progress, &loop, &lasttime);
    };

    {
        int precheckCode = SFTP_OK;
        if (!ValidateConnectState(ConnectSettings, &precheckCode))
            return precheckCode;
    }

    if (ProgressProc(PluginNumber, "Connecting...", "-", progress))
        return fail(-9);

    if (!ResolveConnectEndpoint(ConnectSettings, connecttoserver.data(), connecttoserver.size(), &connecttoport)) {
        if (ConnectSettings->proxytype == sftp::Proxy::http ||
            ConnectSettings->proxytype == sftp::Proxy::socks4 ||
            ConnectSettings->proxytype == sftp::Proxy::socks5) {
            if (ConnectSettings->feedback)
                ConnectSettings->feedback->ShowError(LngStrU8(IDS_ERR_INVALID_PROXY, "Invalid proxy server address.").c_str());
            return fail(ConnectSettings->proxytype == sftp::Proxy::http ? -11 : -12);
        }
        if (ConnectSettings->feedback) {
            ConnectSettings->feedback->ShowError(LngStrU8(IDS_ERR_NOT_SUPPORTED, "Function not supported yet!").c_str());
        }
        return fail(-13);
    }
    ShowStatus("========================================");
    ShowStatusId(IDS_CONNECT_TO, ConnectSettings->server, true);

    progress = PROG_SOCKET_CONNECT;

    if (ConnectSettings->use_jump_host && !ConnectSettings->jump_host.empty()) {
        // -----------------------------------------------------------------
        // ProxyJump path:
        // 1. TCP + SSH to jump host
        // 2. direct-tcpip channel to target
        // 3. Target SSH session runs over channel (via SEND/RECV callbacks)
        // -----------------------------------------------------------------
        JumpHostSettings jump;
        jump.host        = ConnectSettings->jump_host;
        jump.port        = ConnectSettings->jump_port;
        jump.user        = ConnectSettings->jump_user;
        jump.password    = ConnectSettings->jump_password;
        jump.pubkeyfile  = ConnectSettings->jump_pubkeyfile;
        jump.privkeyfile = ConnectSettings->jump_privkeyfile;
        jump.useagent    = ConnectSettings->jump_useagent;
        jump.fingerprint = ConnectSettings->jump_fingerprint;

        // Target is the server configured in the profile (resolved already
        // in connecttoserver/connecttoport above).
        auto stream = ConnectViaJumpHost(
            ConnectSettings, jump, g_sshBackend.get(),
            ConnectSettings->server, ConnectSettings->customport,
            progress, loop, lasttime);

        if (!stream)
            return fail(-25);

        // Update the in-memory fingerprint copy (may have been set on first connect).
        ConnectSettings->jump_fingerprint = jump.fingerprint;
        ConnectSettings->transport_stream = std::move(stream);
        // cs->sock has been set to the jump socket by ConnectViaJumpHost.

    } else {
        // -----------------------------------------------------------------
        // Direct / proxy path (existing behaviour, unchanged)
        // -----------------------------------------------------------------
        int socketErr = EstablishSocketConnection(ConnectSettings, connecttoserver.data(), connecttoport, progress, loop, lasttime);
        if (socketErr != 0) {
            return fail(socketErr);
        }

        // **********************************************************
        //  Proxy?
        hr = NegotiateProxy(ConnectSettings, connecttoport, progress, loop, lasttime);
        if (hr != 0) return fail(hr);
    }

    hr = InitializeSshSession(ConnectSettings, progress, loop, lasttime, g_sshBackend);
    if (hr != 0) return fail(hr);

    progress = PROG_AUTH_START;
    LoadStr(buf, IDS_SSH_LOGIN);
    if (ProgressProc(PluginNumber, buf.data(), "-", progress))
        return fail(-80);

    hr = VerifyServerFingerprint(ConnectSettings);
    if (hr != 0) return fail(hr);

    // Ask for user name if none was entered
    if (!EnsureUserNameIfMissing(ConnectSettings))
        return fail(-110);

    hr = PerformAuthentication(ConnectSettings, progress, loop, lasttime, progressbuf.data(), loadAgent);
    if (hr != 0) return fail(hr);

    ShowStatusId(IDS_LOG_POST_AUTH_INIT, nullptr, true);
    ShowStatus(ConnectSettings->scponly ? "SCP only mode" : "SFTP mode");
    RunPostAuthAutoDetect(ConnectSettings);

    progress = PROG_SFTP_INIT;

    RunPostAuthUserCommand(ConnectSettings, progressbuf.data(), progress, &loop, &lasttime);

    ResolveScpLargeFileProbe(ConnectSettings);

    progress = PROG_SFTP_INIT;

    if (!InitializeSftpSubsystemIfNeeded(ConnectSettings, progress, &loop, &lasttime))
        return fail(SFTP_FAILED);

    progress = PROG_DONE;

    LoadStr(buf, IDS_GET_DIRECTORY);
    if (ProgressProc(PluginNumber, buf.data(), "-", progress))
        return fail(SFTP_FAILED);

    CONN_LOG("SftpConnect success");
    return SFTP_OK;
}

void SftpGetServerBasePathW(LPCWSTR DisplayName, LPWSTR RelativePath, size_t maxlen, LPCSTR inifilename)
{
    std::array<char, MAX_PATH> displayNameA{};
    std::array<char, MAX_PATH> server{};
    walcopy(displayNameA.data(), DisplayName, displayNameA.size() - 1);
    GetPrivateProfileString(displayNameA.data(), "server", "", server.data(), server.size() - 1, inifilename);
    // LAN Pair: base path is always root.
    if (_strnicmp(server.data(), "lanpair://", 10) == 0) {
        wcslcpy(RelativePath, L"/", maxlen);
        return;
    }
    ReplaceBackslashBySlash(server.data());
    // Remove trailing sftp://
    if (_strnicmp(server.data(), "sftp://", 7) == 0)
        memmove(server.data(), server.data() + 7, strlen(server.data()) - 6);
    ReplaceBackslashBySlash(server.data());
    char* p = strchr(server.data(), '/');
    if (p)
        awlcopy(RelativePath, p, maxlen);
    else
        wcslcpy(RelativePath, L"/", maxlen);
}

int codepagelist[kCodepageListCount] = {-1, -2, 0, 1, 2, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258,
                                        936, 950, 932, 949, 874, 437, 850, 20866, -3, -4};

bool SftpConfigureServer(LPCSTR DisplayName, LPCSTR inifilename)
{
    tConnectSettings ConnectSettings{};
    ConnectSettings.dialogforconnection = false;
    return ShowConnectDialog(&ConnectSettings, DisplayName, inifilename);
}

int SftpCloseConnection(pConnectSettings ConnectSettings)
{
    int rc;
    if (ConnectSettings) {
        // LAN Pair: disconnect file session immediately.
        if (ConnectSettings->lanSession) {
            ConnectSettings->lanSession->disconnect();
            ConnectSettings->lanSession.reset();
        }
        // Fast teardown path: during full disconnect do not perform graceful shell
        // shutdown (can block UI on restrictive SCP servers). Session disconnect
        // below will close remote channels anyway.
        if (ConnectSettings->scpShellChannel) {
            ConnectSettings->scpShellChannel.reset();
            ConnectSettings->scpShellMsgBuf.clear();
            ConnectSettings->scpShellErrBuf.clear();
        }
        if (ConnectSettings->scponly) {
            // Fast close for SCP-only sessions: skip graceful shutdown loops that can block UI.
            ConnectSettings->sftpsession.reset();
            if (ConnectSettings->session) {
                ConnectSettings->session->free();
                ConnectSettings->session.reset();
            }
            if (ConnectSettings->sock != INVALID_SOCKET) {
                closesocket(ConnectSettings->sock);
                ConnectSettings->sock = INVALID_SOCKET;
            }
            ConnectSettings->transport_stream.reset();
            ConnectSettings->feedback.reset();
            return SFTP_FAILED;
        }
        SYSTICKS starttime = get_sys_ticks();
        bool doabort = false;
        if (ConnectSettings->sftpsession) {
            do {
                rc = ConnectSettings->sftpsession->shutdown();
                if (EscapePressed())
                    doabort = true;
                if (doabort && get_ticks_between(starttime) > DISCONNECT_ABORT_MS)
                    break;
                if (get_ticks_between(starttime) > DISCONNECT_TIMEOUT_MS)
                    break;
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    WaitForTransportReadable(ConnectSettings);  // Sleep to avoid 100% CPU usage.
            } while (rc == LIBSSH2_ERROR_EAGAIN);
            ConnectSettings->sftpsession.reset();
        }
        if (ConnectSettings->session) {
            do {
                rc = ConnectSettings->session->disconnect("Disconnect");
                if (EscapePressed())
                    doabort = true;
                if (doabort && get_ticks_between(starttime) > DISCONNECT_ABORT_MS)
                    break;
                if (get_ticks_between(starttime) > DISCONNECT_TIMEOUT_MS)
                    break;
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    WaitForTransportReadable(ConnectSettings);  // Sleep to avoid 100% CPU usage.
            } while (rc == LIBSSH2_ERROR_EAGAIN);
            ConnectSettings->session->free();
            ConnectSettings->session.reset();
        }
        // Release the transport stream (jump channel + jump SSH session) AFTER
        // the target session is freed above and BEFORE the jump socket closes.
        ConnectSettings->transport_stream.reset();
        if (ConnectSettings->sock != INVALID_SOCKET) {
            Sleep(RECONNECT_SLEEP_MS);
            closesocket(ConnectSettings->sock);
            ConnectSettings->sock = INVALID_SOCKET;
        }
        ConnectSettings->feedback.reset();
    }
    return SFTP_FAILED;
}

bool ReconnectSFTPChannelIfNeeded(pConnectSettings ConnectSettings)
{
    if (IsLanPairTransport(ConnectSettings))
        return ConnectSettings->lanSession && ConnectSettings->lanSession->isConnected();
    if (IsPhpAgentTransport(ConnectSettings))
        return true;

    if (ConnectSettings->scponly) {
        // No SFTP subsystem to reconnect, but verify the SSH session and socket are alive.
        // If the socket dropped or the session is gone, do a full reconnect so subsequent
        // ConnectChannel() calls have a live session to work with.
        bool sessionGone = !ConnectSettings->session;
        bool sockLost    = (ConnectSettings->sock == INVALID_SOCKET)
                        || IsSocketError(ConnectSettings->sock);
        if (sessionGone || sockLost) {
            CONN_LOG("ReconnectSFTP(SCP): session/sock lost (gone=%d sockLost=%d), reconnecting",
                     sessionGone ? 1 : 0, sockLost ? 1 : 0);
            ShowStatusId(IDS_LOG_SCP_RECONNECT, nullptr, true);
            SftpCloseConnection(ConnectSettings);
            Sleep(RECONNECT_SLEEP_MS);
            SftpConnect(ConnectSettings);
            CONN_LOG("ReconnectSFTP(SCP): after reconnect session=%s",
                     ConnectSettings->session ? "OK" : "FAILED");
        }
        return ConnectSettings->session != nullptr;
    }
    if (ConnectSettings->neednewchannel || ConnectSettings->sftpsession == nullptr) {
        ConnectSettings->neednewchannel = false;
        SYSTICKS starttime = get_sys_ticks();
        int rc;
        int loop = 0;
        if (ConnectSettings->sftpsession) {
            do {
                rc=ConnectSettings->sftpsession->shutdown();
            } while (rc == LIBSSH2_ERROR_EAGAIN && get_ticks_between(starttime) < RECONNECT_SFTP_TIMEOUT_MS);
            ConnectSettings->sftpsession.reset();
        }

        if (ConnectSettings->session)
            do {
                ConnectSettings->sftpsession = nullptr;
                if (ProgressLoop("Reconnect SFTP channel", 0, 100, &loop, &starttime))
                    break;
                {
                    auto sftpPtr = ConnectSettings->session->sftpInit();
                    if (sftpPtr) {
                        ConnectSettings->sftpsession = std::move(sftpPtr);
                    } else if (ConnectSettings->session->lastErrno() != LIBSSH2_ERROR_EAGAIN) {
                        break;
                    }
                }
            } while (!ConnectSettings->sftpsession);

        // Reconnect the full connection when subsystem recovery fails.
        if (!ConnectSettings->sftpsession) {
            ShowStatusId(IDS_LOG_RECONNECT, nullptr, true);
            SftpCloseConnection(ConnectSettings);
            Sleep(RECONNECT_SLEEP_MS);
            SftpConnect(ConnectSettings);
        }
        ConnectSettings->neednewchannel = ConnectSettings->sftpsession == nullptr;
    }
    return !ConnectSettings->neednewchannel;
}

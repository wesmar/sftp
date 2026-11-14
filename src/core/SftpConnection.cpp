// SFTP transport/session implementation.
// Maintainer: Marek Wesolowski (wesmar)
#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
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
#include "UnicodeHelpers.h"

#include "SftpInternal.h"
#include "SshBackendFactory.h"
#include "WindowsUserFeedback.h"
#include <algorithm>
#include <array>
#include <climits>
#include <condition_variable>
#include <new>
#include <fstream>
#include <iterator>
#include <vector>
#include "PhpAgentClient.h"
#include "PhpShellConsole.h"
#include "ConnectionDialog.h"
#include "SessionPostAuth.h"
#include "ConnectionLifecycle.h"
#include "ConnectionNetwork.h"
#include "SshSessionInit.h"
#include "PluginEntryPointsInternal.h"
#include "ConnectionAuth.h"
#include "LanPairSession.h"
#include "TrustedInstallerToken.h"
#include "JumpHostConnection.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

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

void wcslcpytoutf8(LPSTR utf8str, LPCWSTR utf16str, size_t maxlen)
{
    // All or nothing, as for remote paths below.
    if (ConvUTF16toUTF8(utf16str, 0, utf8str, maxlen) < 0 && utf8str && maxlen > 0)
        utf8str[0] = '\0';
}

namespace {

UINT RemoteCodePage(const tConnectSettings* cs) noexcept
{
    return cs->utf8names > 0 ? CP_UTF8 : static_cast<UINT>(cs->codepage);
}

} // namespace

bool CopyStringW2A(pConnectSettings ConnectSettings, LPCWSTR instr, LPSTR outstr, size_t outmax) noexcept
{
    if (!outstr || outmax == 0)
        return false;
    outstr[0] = '\0';
    if (!instr || !instr[0])
        return true;
    const int capacity = static_cast<int>((std::min)(outmax, static_cast<size_t>(INT_MAX)));
    if (WideCharToMultiByte(RemoteCodePage(ConnectSettings), 0, instr, -1, outstr, capacity, nullptr, nullptr) > 0)
        return true;
    // A path cut short names another file - its parent directory, say - which
    // no command may reach, so nothing is sent rather than a prefix.
    outstr[0] = '\0';
    SFTP_LOG("PATH", "Remote path longer than %zu bytes, not used", outmax - 1);
    return false;
}

bool CopyStringA2W(pConnectSettings ConnectSettings, LPCSTR instr, LPWSTR outstr, size_t outmax) noexcept
{
    if (!outstr || outmax == 0)
        return false;
    outstr[0] = L'\0';
    if (!instr || !instr[0])
        return true;
    const UINT codePage = RemoteCodePage(ConnectSettings);
    const int need = MultiByteToWideChar(codePage, 0, instr, -1, nullptr, 0); // with the terminator
    if (need <= 0)
        return false;
    if (static_cast<size_t>(need) <= outmax)
        return MultiByteToWideChar(codePage, 0, instr, -1, outstr, need) > 0;
    try {
        std::wstring wide(static_cast<size_t>(need), L'\0');
        MultiByteToWideChar(codePage, 0, instr, -1, wide.data(), need);
        size_t n = outmax - 1;
        if (n > 0 && IS_HIGH_SURROGATE(wide[n - 1]))
            --n;
        wmemcpy(outstr, wide.data(), n);
        outstr[n] = L'\0';
    } catch (...) {
        outstr[0] = L'\0';
    }
    return false;
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

// Keeps NAT and firewall mappings alive while a session sits idle: the
// kernel probes after 60 s of silence and every 10 s after that, with no
// SSH traffic and no thread of our own. A dead peer is noticed too.
void EnableTcpKeepAlive(SOCKET s)
{
    tcp_keepalive ka{1, 60000, 10000};
    DWORD bytes = 0;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytes, nullptr, nullptr);
}

bool IsSocketError(SOCKET s)
{
    fd_set fds;
    timeval timeout = gettimeval(SOCKET_POLL_MS);
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    return 1 == select(0, nullptr, nullptr, &fds, &timeout);
}

// True if the raw TCP endpoint has been closed by the peer (server reboot,
// firewall reset, or half-closed FIN). Non-destructive: uses select+recv
// with MSG_PEEK so any bytes in the receive buffer stay there for the next
// legitimate read by libssh2.
static bool IsTcpSocketDead(SOCKET s) noexcept
{
    if (s == INVALID_SOCKET) return true;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    struct timeval tv = { 0, 0 };  // instant, no wait
    const int selRet = select(0, &rfds, nullptr, nullptr, &tv);
    if (selRet < 0)                  return true;   // select failed → treat as dead
    if (selRet == 0)                 return false;  // no data pending, idle-but-alive

    // Socket is readable — could be legit incoming data OR a FIN/RST. Peek
    // one byte non-destructively. recv == 0 is the WinSock signal for a
    // gracefully closed peer; a real error other than WOULDBLOCK is a hard
    // dead connection.
    char peek = 0;
    const int rc = recv(s, &peek, 1, MSG_PEEK);
    if (rc == 0)                     return true;
    if (rc < 0) {
        const int err = WSAGetLastError();
        return err != WSAEWOULDBLOCK;
    }
    return false;  // real data present → alive
}

bool IsSessionAlive(pConnectSettings cs) noexcept
{
    if (!cs) return false;

    // LAN Pair carries its own connected-state accessor.
    if (IsLanPairTransport(cs))
        return cs->lanSession && cs->lanSession->isConnected();

    // PHP Agent uses HTTP-over-transport; no long-lived TCP to probe. If
    // the client object exists we optimistically consider it alive — the
    // next request will error normally and drive a reconnect through the
    // agent's own retry path.
    if (IsPhpAgentTransport(cs))
        return true;

    // Regular SSH / SCP path.
    if (!cs->session)                return false;
    if (cs->sock == INVALID_SOCKET)  return false;
    if (IsTcpSocketDead(cs->sock))   return false;
    return true;
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

// Block_directions-aware wait. Picks read/write/both based on what libssh2
// says it's waiting on; falls back to read when libssh2 has no opinion.
// For ProxyJump the transport stream handles the nested wait — inner
// OUTBOUND can unblock via either incoming window-update (jump read) or
// outbound jump-TCP drain (jump write).
bool WaitForSshIo(pConnectSettings cs, DWORD timeoutMs)
{
    if (!cs)
        return false;

    if (cs->transport_stream)
        return cs->transport_stream->waitForSshIo(cs->session.get(), timeoutMs);

    if (cs->sock == INVALID_SOCKET)
        return false;

    const int dirs = cs->session ? cs->session->blockDirections() : 0;
    fd_set rfds, wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    if (dirs & LIBSSH2_SESSION_BLOCK_INBOUND)
        FD_SET(cs->sock, &rfds);
    if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        FD_SET(cs->sock, &wfds);
    if (!dirs)
        FD_SET(cs->sock, &rfds);

    timeval tv = { static_cast<long>(timeoutMs / 1000),
                   static_cast<long>((timeoutMs % 1000) * 1000) };
    return select(0, &rfds, &wfds, nullptr, &tv) > 0;
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
        // No Sleep here: IsSocketReadable() above already blocked up to
        // SOCKET_READ_POLL_MS waiting for data; extra Sleep would just be
        // dead wait.
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
    LanFileServerSetTrustedInstaller(cs->lan_pair_trusted_installer);

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

    // One resolver decides what this profile's jump host actually is, so the
    // connect path cannot disagree with what the dialog shows. It refuses
    // rather than returning an empty endpoint, which is what keeps a session
    // with a dangling reference from quietly connecting past the bastion.
    const JumpConfig jumpCfg = ResolveJumpConfig(ConnectSettings, inifilename);

    if (jumpCfg.status != JumpConfigStatus::Disabled &&
        jumpCfg.status != JumpConfigStatus::Ready) {
        ShowStatus(jumpCfg.error.c_str());
        if (ConnectSettings->feedback && !ConnectSettings->jump_refusal_shown) {
            ConnectSettings->jump_refusal_shown = true;
            ConnectSettings->feedback->ShowError(jumpCfg.error, "ProxyJump");
        }
        return fail(-25);
    }

    if (jumpCfg.status == JumpConfigStatus::Ready) {
        // -----------------------------------------------------------------
        // ProxyJump path:
        // 1. TCP + SSH to jump host
        // 2. direct-tcpip channel to target
        // 3. Target SSH session runs over channel (via SEND/RECV callbacks)
        // -----------------------------------------------------------------
        // Force-create the SSH backend before ConnectViaJumpHost. The direct
        // path lazily creates it inside InitializeSshSession() which runs
        // AFTER the jump host stage, so on a cold start (first connection of
        // the session is via ProxyJump) g_sshBackend is still null and the
        // jump session creation dereferences nullptr.
        if (!g_sshBackend)
            g_sshBackend = CreateSshBackend();

        JumpHostSettings jump = jumpCfg.endpoint;

        // Target is the server configured in the profile (resolved already
        // in connecttoserver/connecttoport above).
        auto stream = ConnectViaJumpHost(
            ConnectSettings, jump, g_sshBackend.get(),
            ConnectSettings->server, ConnectSettings->customport,
            progress, loop, lasttime);

        if (!stream)
            return fail(-25);

        // Mirror a fingerprint accepted on first connect. Only for a manually
        // configured jump host: this field describes that host, whereas a
        // referenced session keeps its own key under its own section.
        if (ConnectSettings->jump_session_ref.empty())
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

    hr = PerformAuthentication(ConnectSettings, progress, loop, lasttime, progressbuf.data());
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

void SftpGetServerBasePathW(LPCWSTR DisplayName, LPWSTR RelativePath, size_t maxlen, LPCSTR iniFile)
{
    std::array<char, MAX_PATH> displayNameA{};
    std::array<char, MAX_PATH> server{};
    walcopy(displayNameA.data(), DisplayName, displayNameA.size() - 1);
    GetPrivateProfileString(displayNameA.data(), "server", "", server.data(), static_cast<DWORD>(server.size()), iniFile);
    // LAN Pair and PHP Agent: base path is always root. A PHP Agent server is
    // a URL whose path names the script, not a start folder.
    if (_strnicmp(server.data(), "lanpair://", 10) == 0 ||
        _strnicmp(server.data(), "http://", 7) == 0 ||
        _strnicmp(server.data(), "https://", 8) == 0) {
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

bool SftpConfigureServer(LPCSTR DisplayName, LPCSTR iniFile)
{
    tConnectSettings ConnectSettings{};
    ConnectSettings.dialogforconnection = false;
    return ShowConnectDialog(&ConnectSettings, DisplayName, iniFile);
}

int SftpCloseConnection(pConnectSettings ConnectSettings)
{
    if (!ConnectSettings)
        return SFTP_FAILED;

    // 1. LAN Pair (own transport, not SSH) — quick disconnect.
    if (ConnectSettings->lanSession) {
        ConnectSettings->lanSession->disconnect();
        ConnectSettings->lanSession.reset();
    }

    // 2. SCP shell channel (only present in scponly mode). Destructor of
    //    Libssh2Channel sends SSH_MSG_CHANNEL_CLOSE/free with bounded retry.
    if (ConnectSettings->scpShellChannel) {
        ConnectSettings->scpShellChannel.reset();
        ConnectSettings->scpShellMsgBuf.clear();
        ConnectSettings->scpShellErrBuf.clear();
    }

    // 3. SFTP subsystem (only present in SFTP mode). ~Libssh2SftpSession()
    //    sends SFTP_FXP_SHUTDOWN with a bounded retry.
    ConnectSettings->sftpsession.reset();

    // 4. SSH session — send SSH_MSG_DISCONNECT once. RFC 4253 §11.1: server
    //    must not reply, so there is nothing to wait for. EAGAIN here means
    //    the SSH packet did not fit in libssh2's send buffer; retry briefly
    //    just to push it into the OS socket buffer (TCP itself handles wire
    //    delivery from there).
    if (ConnectSettings->session) {
        SYSTICKS t0 = get_sys_ticks();
        int rc;
        do {
            rc = ConnectSettings->session->disconnect("Disconnect");
            if (rc != LIBSSH2_ERROR_EAGAIN)
                break;
            if (get_ticks_between(t0) > 200)
                break;   // 200 ms cap — DISCONNECT is ~50 bytes, must fit by now.
            if (ConnectSettings->sock != INVALID_SOCKET) {
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(ConnectSettings->sock, &wfds);
                timeval tv = { 0, 20000 };  // 20 ms
                select(0, nullptr, &wfds, nullptr, &tv);
            }
        } while (true);
        ConnectSettings->session.reset();   // ~Libssh2Session() frees the struct.
    }

    // 5. ProxyJump transport (jump channel + jump session) — destructors
    //    cascade and tear down the inner session/channel cleanly.
    ConnectSettings->transport_stream.reset();

    // 6. TCP socket — graceful close: the OS flushes any pending DISCONNECT
    //    bytes before sending FIN. No artificial Sleep needed.
    if (ConnectSettings->sock != INVALID_SOCKET) {
        closesocket(ConnectSettings->sock);
        ConnectSettings->sock = INVALID_SOCKET;
    }

    ConnectSettings->feedback.reset();
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
                    auto sftpPtr = ConnectSettings->session->sftpInit(ConnectSettings->sftpservercommand);
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

#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <array>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "UtfConversion.h"
#include "SftpInternal.h"
#include "UnicodeHelpers.h"

namespace {

// Timeout constants (in milliseconds)
constexpr DWORD kShellFlushTimeoutMs      = 1000;
constexpr DWORD kShellEofTimeoutMs        = 3000;
constexpr DWORD kShellCloseTimeoutMs      = 3000;
constexpr DWORD kShellFreeTimeoutMs       = 5000;
constexpr DWORD kScpPtyOpenTimeoutMs      = 10000;
constexpr DWORD kScpShellOpenTimeoutMs    = 15000;
constexpr DWORD kChannelReplyTimeoutMs    = 15000;
constexpr DWORD kChannelExitStatusWaitMs  = 2000;
constexpr DWORD kShellEagainGraceIdleMs   = 1000;
constexpr DWORD kShellEagainGraceTotalMs  = 5000;
constexpr DWORD kQuoteProgressStartMs     = 2000;

// Helper: wait for an operation with timeout, handling EAGAIN
template<typename F>
int WaitForOperation(F&& op, DWORD timeoutMs, pConnectSettings cs, bool forWrite = false)
{
    const auto start = std::chrono::steady_clock::now();
    int rc;
    do {
        rc = op();
        if (rc != LIBSSH2_ERROR_EAGAIN)
            return rc;
        if (EscapePressed())
            return LIBSSH2_ERROR_EAGAIN; // treat as abort
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeoutMs)
            return LIBSSH2_ERROR_TIMEOUT;
        if (cs && cs->sock != INVALID_SOCKET) {
            if (forWrite)
                IsSocketWritable(cs->sock);
            else
                IsSocketReadable(cs->sock);
        } else {
            Sleep(25);
        }
    } while (true);
}

// RAII wrapper for ISshChannel with automatic disconnect
class ScopedChannel {
public:
    explicit ScopedChannel(ISshChannel* ch, pConnectSettings cs) : channel_(ch), cs_(cs) {}
    ~ScopedChannel() { if (channel_) Disconnect(); }

    ScopedChannel(const ScopedChannel&) = delete;
    ScopedChannel& operator=(const ScopedChannel&) = delete;

    ScopedChannel(ScopedChannel&& other) noexcept
        : channel_(std::exchange(other.channel_, nullptr)), cs_(other.cs_) {}

    ISshChannel* get() const noexcept { return channel_; }
    ISshChannel* release() noexcept { return std::exchange(channel_, nullptr); }

private:
    void Disconnect() noexcept
    {
        if (!cs_ || !channel_)
            return;

        WaitForOperation([this] { return channel_->flush(); }, kShellFlushTimeoutMs / 2, cs_, true);
        WaitForOperation([this] { return channel_->sendEof(); }, kShellEofTimeoutMs / 3, cs_, true);
        WaitForOperation([this] { return channel_->waitEof(); }, kShellEofTimeoutMs / 3, cs_, false);
        WaitForOperation([this] { return channel_->channelClose(); }, kShellCloseTimeoutMs / 3, cs_, true);
        WaitForOperation([this] { return channel_->channelFree(); }, kShellFreeTimeoutMs / 5, cs_, true);
        delete channel_;
    }

    ISshChannel* channel_;
    pConnectSettings cs_;
};

// Trim leading whitespace and control characters
std::string_view TrimLeft(std::string_view sv) noexcept
{
    const auto pos = sv.find_first_not_of(" \t\r\n");
    return (pos == std::string_view::npos) ? std::string_view{} : sv.substr(pos);
}

// Check if line looks like an echoed command or prompt
bool IsEchoOrPromptLine(std::string_view line) noexcept
{
    line = TrimLeft(line);
    if (line.empty())
        return false;
    if (line.substr(0, 5) == "echo " || line.find("$ echo ") != std::string_view::npos)
        return true;
    return false;
}

// Decode octal escape sequences in-place (modifies string)
void StripEscapeSequences(std::string& str)
{
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '\x1B') { // ESC
            ++i;
            while (i < str.size() && str[i] != 'm')
                ++i;
            // skip 'm' as well
        } else if (str[i] == '\\' && i + 3 < str.size() &&
                   std::isdigit(static_cast<unsigned char>(str[i+1])) &&
                   std::isdigit(static_cast<unsigned char>(str[i+2])) &&
                   std::isdigit(static_cast<unsigned char>(str[i+3]))) {
            // octal escape: \123
            int value = (str[i+1] - '0') * 64 + (str[i+2] - '0') * 8 + (str[i+3] - '0');
            result.push_back(static_cast<char>(value));
            i += 3;
        } else {
            result.push_back(str[i]);
        }
    }
    str.swap(result);
}

void StripEscapeSequencesLocalA(LPSTR msgbuf)
{
    if (!msgbuf || !msgbuf[0])
        return;
    std::string tmp(msgbuf);
    StripEscapeSequences(tmp);
    strlcpy(msgbuf, tmp.c_str(), tmp.size() + 1);
}

} // anonymous namespace

void StripEscapeSequences(LPSTR msgbuf)
{
    if (!msgbuf)
        return;
    StripEscapeSequencesLocalA(msgbuf);
}

void DisconnectShell(ISshChannel* channel)
{
    if (!channel)
        return;
    // Use WaitForOperation with appropriate timeouts
    WaitForOperation([channel] { return channel->flush(); }, kShellFlushTimeoutMs, nullptr, true);
    WaitForOperation([channel] { return channel->sendEof(); }, kShellEofTimeoutMs, nullptr, true);
    WaitForOperation([channel] { return channel->waitEof(); }, kShellEofTimeoutMs, nullptr, false);
    WaitForOperation([channel] { return channel->channelClose(); }, kShellCloseTimeoutMs, nullptr, true);
    WaitForOperation([channel] { return channel->channelFree(); }, kShellFreeTimeoutMs, nullptr, true);
}

std::unique_ptr<ISshChannel> ConnectChannel(ISshSession* session, SOCKET sock)
{
    if (!session)
        return nullptr;

    session->setBlocking(0);
    if (sock != INVALID_SOCKET)
        SetBlockingSocket(sock, false);

    const auto start = std::chrono::steady_clock::now();
    std::unique_ptr<ISshChannel> channel;

    do {
        channel = session->openChannel();
        if (channel)
            break;

        const int err = session->lastErrno();
        if (err != LIBSSH2_ERROR_EAGAIN)
            break;

        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > 12000) // kOpenChannelTimeoutMs
            break;

        if (sock != INVALID_SOCKET)
            IsSocketReadable(sock);
        else
            Sleep(50);
    } while (!channel);

    if (!channel) {
        std::string errmsg = "Unable to open a session";
        const int err = session->lastErrno();
        switch (err) {
            case LIBSSH2_ERROR_ALLOC:          errmsg += ": internal memory allocation call failed"; break;
            case LIBSSH2_ERROR_SOCKET_SEND:    errmsg += ": Unable to send data on socket"; break;
            case LIBSSH2_ERROR_SOCKET_RECV:    errmsg += ": Unable to receive data on socket"; break;
            case LIBSSH2_ERROR_CHANNEL_FAILURE: errmsg += ": Channel failure"; break;
            default:                            errmsg += ": Error code " + std::to_string(err); break;
        }
        ShowStatus(errmsg.c_str());
        return nullptr;
    }

    channel->setBlocking(0);
    return channel;
}

bool SendChannelCommandNoEof([[maybe_unused]] ISshSession* session, ISshChannel* channel, const char* command, SOCKET sock)
{
    pConnectSettings waitCtx = nullptr;
    tConnectSettings tempCtx{};
    if (sock != INVALID_SOCKET) {
        tempCtx.sock = sock;
        waitCtx = &tempCtx;
    }
    int rc = WaitForOperation([&] { return channel->exec(command); }, SSH_AUTH_STAGE_TIMEOUT_MS, waitCtx, true);
    if (rc < 0)
        return false;

    rc = WaitForOperation([&] { return channel->flush(); }, SSH_AUTH_STAGE_TIMEOUT_MS, waitCtx, true);
    return rc >= 0;
}

bool SendChannelCommand(ISshSession* session, ISshChannel* channel, const char* command, SOCKET sock)
{
    if (!SendChannelCommandNoEof(session, channel, command, sock))
        return false;
    pConnectSettings waitCtx = nullptr;
    tConnectSettings tempCtx{};
    if (sock != INVALID_SOCKET) {
        tempCtx.sock = sock;
        waitCtx = &tempCtx;
    }
    WaitForOperation([&] { return channel->sendEof(); }, SSH_AUTH_STAGE_TIMEOUT_MS, waitCtx, true);
    return true;
}

bool GetChannelCommandReply(ISshSession* session, ISshChannel* channel, const char* command, SOCKET sock)
{
    bool hasStderr = false;
    if (!SendChannelCommand(session, channel, command, sock))
        return false;

    const auto start = std::chrono::steady_clock::now();
    std::array<char, 1024> buf{};
    std::array<char, 1024> errbuf{};

    while (!channel->eof()) {
        const int errRc = channel->readStderr(errbuf.data(), errbuf.size() - 1);
        if (errRc > 0)
            hasStderr = true;

        const int rc = channel->read(buf.data(), buf.size() - 1);
        if (rc == LIBSSH2_ERROR_EAGAIN || errRc == LIBSSH2_ERROR_EAGAIN) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > kChannelReplyTimeoutMs)
                break;
            if (sock != INVALID_SOCKET)
                IsSocketReadable(sock);
            else
                Sleep(50);
        } else if (rc < 0 && errRc < 0 && rc != LIBSSH2_ERROR_EAGAIN && errRc != LIBSSH2_ERROR_EAGAIN) {
            break; // hard error
        }
    }

    // Wait for exit status
    const auto exitStart = std::chrono::steady_clock::now();
    while (channel->getExitStatus() == -1) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - exitStart).count();
        if (elapsed > kChannelExitStatusWaitMs)
            break;
        Sleep(50);
    }

    return (channel->getExitStatus() == 0 && !hasStderr);
}

bool EnsureScpShell(pConnectSettings cs)
{
    if (!cs || !cs->session)
        return false;

    cs->session->setBlocking(0);
    if (cs->sock != INVALID_SOCKET)
        SetBlockingSocket(cs->sock, false);

    if (cs->scpShellChannel) {
        if (cs->sock == INVALID_SOCKET || IsSocketError(cs->sock) || cs->scpShellChannel->eof()) {
            CloseScpShell(cs);
        } else {
            return true;
        }
    }

    auto channel = ConnectChannel(cs->session.get(), cs->sock);
    if (!channel)
        return false;

    // Request PTY
    int ptyRc = WaitForOperation([&] {
        return channel->requestPty("vt102", 5, "", 0, 80, 40, 640, 480);
    }, kScpPtyOpenTimeoutMs, cs, false);

    if (ptyRc < 0 && ptyRc != LIBSSH2_ERROR_EAGAIN) {
        return false;
    }

	// Start shell
    int shellRc = WaitForOperation([&] { return channel->shell(); }, kScpShellOpenTimeoutMs, cs, false);
    if (shellRc < 0) {
        return false;
    }

    // Servers (e.g., home.pl) lose the first login if we send it immediately.
    // We give the shell time to load /etc/profile and the MOTD.
    Sleep(500); 

    cs->scpShellChannel = std::move(channel);
    cs->scpShellMsgBuf[0] = 0;
    cs->scpShellErrBuf[0] = 0;
    return true;
}

void CloseScpShell(pConnectSettings cs)
{
    if (!cs || !cs->scpShellChannel)
        return;

    if (cs->session && cs->sock != INVALID_SOCKET) {
        cs->session->setBlocking(0);
        cs->scpShellChannel->setBlocking(0);

        if (cs->scp_fast_close_required) {
            cs->scpShellChannel->channelClose();
            cs->scpShellChannel->channelFree();
        } else {
            DisconnectShell(cs->scpShellChannel.get());
        }
    }
    cs->scpShellChannel.reset();
    cs->scpShellMsgBuf[0] = 0;
    cs->scpShellErrBuf[0] = 0;
}

bool ScpReadCommandOutput(pConnectSettings cs, const char* endMarker,
                           std::vector<std::string>& outLines,
                           DWORD timeoutMs, const char* beginMarker)
{
    if (!cs || !cs->scpShellChannel || !endMarker)
        return false;

    const std::string endMarkerStr(endMarker);
    const std::string beginMarkerStr(beginMarker ? beginMarker : "");
    const bool hasBegin = !beginMarkerStr.empty();

    std::array<char, 4096> line{};
    const auto start = std::chrono::steady_clock::now();
    bool gotBegin = !hasBegin;
    bool gotEnd = false;

    while (ReadChannelLine(cs->scpShellChannel.get(),
                           line.data(), line.size() - 1,
                           cs->scpShellMsgBuf, sizeof(cs->scpShellMsgBuf) - 1,
                           cs->scpShellErrBuf, sizeof(cs->scpShellErrBuf) - 1))
    {
        std::string lineStr(line.data());
        StripEscapeSequences(lineStr);
        std::string_view trimmed = TrimLeft(lineStr);

        if (trimmed.empty())
            continue;

        if (!gotBegin) {
            if (trimmed.find(beginMarkerStr) != std::string_view::npos) {
                gotBegin = true;
            }
            continue;
        }

        if (!IsEchoOrPromptLine(trimmed) && trimmed.substr(0, endMarkerStr.size()) == endMarkerStr) {
            gotEnd = true;
            break;
        }
        if (trimmed.find(endMarkerStr) != std::string_view::npos) {
            gotEnd = true;
            break;
        }

        outLines.push_back(std::move(lineStr));

        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeoutMs)
            break;
        if (EscapePressed())
            break;
    }

    return gotEnd && gotBegin;
}

bool ReadChannelLine(ISshChannel* channel, char* line, size_t lineLen,
                     char* msgbuf, size_t msgbuflen,
                     char* errbuf, size_t errbuflen, SOCKET sock,
                     DWORD idleTimeoutMs, DWORD totalTimeoutMs)
{
    const auto start = std::chrono::steady_clock::now();
    auto lastData = start;
    bool endReceived = false;
    bool detectingCrLf = true;
    int consecutiveEagain = 0;

    while (true) {
        const auto now = std::chrono::steady_clock::now();
        const auto idle = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastData).count();
        const auto total = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
        if (idle > static_cast<long long>(idleTimeoutMs) || total > static_cast<long long>(totalTimeoutMs))
            return false;

        const size_t prevLen = strlen(msgbuf);
        const size_t remain = msgbuflen - prevLen;
        const size_t remainErr = errbuflen - strlen(errbuf);
        char* p = msgbuf + prevLen;
        char* pErr = errbuf + strlen(errbuf);

        if (channel->eof())
            endReceived = true;

        const int rcerr = static_cast<int>(channel->readStderr(pErr, remainErr));
        const int rc = static_cast<int>(channel->read(p, remain));

        if (rcerr > 0) {
            pErr[rcerr] = '\0';
            lastData = now;
            consecutiveEagain = 0;
        }
        if (rc > 0) {
            p[rc] = '\0';
            lastData = now;
            consecutiveEagain = 0;
        }

        // Check for newline in msgbuf
        char* nl = strchr(msgbuf, '\n');
        if (nl) {
            *nl = '\0';
            // Detect CRLF
            if (nl > msgbuf && *(nl - 1) == '\r') {
                if (detectingCrLf && global_detectcrlf == -1)
                    global_detectcrlf = 1;
                *(nl - 1) = '\0';
            } else if (detectingCrLf && global_detectcrlf == -1) {
                global_detectcrlf = 0;
            }
            strlcpy(line, msgbuf, lineLen);
            StripEscapeSequences(line);
            // Shift buffer
            size_t remaining = strlen(nl + 1) + 1;
            memmove(msgbuf, nl + 1, remaining);
            return true;
        }

        if (rc == LIBSSH2_ERROR_EAGAIN || rc == 0) {
            ++consecutiveEagain;
            if (sock != INVALID_SOCKET)
                IsSocketReadable(sock);
            else
                Sleep(consecutiveEagain > 20 ? 200 : 50);
        }

        if (endReceived && rc <= 0 && rc != LIBSSH2_ERROR_EAGAIN) {
            if (msgbuf[0] && !(msgbuf[0] == '\r' || msgbuf[0] == '\n')) {
                // Flush remaining buffer as line
                strlcpy(line, msgbuf, lineLen);
                StripEscapeSequences(line);
                msgbuf[0] = '\0';
                return true;
            }
            return false;
        }
    }
}

int SftpQuoteCommand2(pConnectSettings cs, const char* remotedir, const char* cmd,
                      char* reply, size_t replylen,
                      DWORD idleTimeoutMs, DWORD totalTimeoutMs)
{
    if (reply && replylen > 0)
        reply[0] = '\0';

    if (!cs)
        return -1;

    std::string dirname, cmdname;
    if (cs->utf8names) {
        if (remotedir) {
            std::wstring wtmp(wdirtypemax, L'\0');
            std::string tmp(wdirtypemax, '\0');
            MultiByteToWideChar(CP_ACP, 0, remotedir, -1, wtmp.data(), static_cast<int>(wtmp.size()));
            wcslcpytoutf8(tmp.data(), wtmp.data(), tmp.size() - 1);
            dirname = tmp.c_str();
        }
        std::wstring wtmp2(wdirtypemax, L'\0');
        std::string tmp2(wdirtypemax, '\0');
        MultiByteToWideChar(CP_ACP, 0, cmd, -1, wtmp2.data(), static_cast<int>(wtmp2.size()));
        wcslcpytoutf8(tmp2.data(), wtmp2.data(), tmp2.size() - 1);
        cmdname = tmp2.c_str();
    } else {
        if (remotedir)
            dirname = remotedir;
        cmdname = cmd;
    }

    // Replace backslashes with slashes
    std::replace(dirname.begin(), dirname.end(), '\\', '/');

    std::string display = "Quote: ";
    display += cmd;
    std::replace(display.begin(), display.end(), '\\', '/');
    ShowStatus(display.c_str());

    auto channel = ConnectChannel(cs->session.get(), cs->sock);
    if (!channel)
        return -1;

    // Build command: cd <dir> && <cmd> (if dir given)
    std::string fullCmd;
    if (remotedir) {
        fullCmd = "cd '";
        fullCmd += string_util::ShellQuoteSingle(dirname) + "' && ";
    }
    fullCmd += cmdname;

    if (!SendChannelCommand(cs->session.get(), channel.get(), fullCmd.c_str(), cs->sock)) {
        return -1;
    }

    std::array<char, 2048> errbuf{};
    std::string msgbuf;
    std::string line;

    while (ReadChannelLine(channel.get(), line.data(), line.size(),
                           msgbuf.data(), msgbuf.size(),
                           errbuf.data(), errbuf.size(), cs->sock,
                           idleTimeoutMs, totalTimeoutMs))
    {
        StripEscapeSequences(line);
        if (!reply) {
            ShowStatus(line.c_str());
        } else {
            if (reply[0])
                strlcat(reply, "\r\n", replylen);
            strlcat(reply, line.c_str(), replylen);
        }
    }

    const int rc = channel->getExitStatus();
    if (rc != 0) {
        char tmp[128];
        snprintf(tmp, sizeof(tmp), "Function return code: %d", rc);
        ShowStatus(tmp);
        if (errbuf[0]) {
            std::string err(errbuf.data());
            StripEscapeSequences(err);
            if (err.substr(0, 19) == "stdin: is not a tty")
                err = err.substr(19);
            ShowStatus(err.c_str());
            if (reply) {
                if (reply[0])
                    strlcat(reply, "\r\n", replylen);
                strlcat(reply, err.c_str(), replylen);
            }
        }
    }

    return rc >= 0 ? rc : 1;
}

int SftpQuoteCommand2W(pConnectSettings cs, LPCWSTR remotedir, LPCWSTR cmd,
                       char* reply, size_t replylen)
{
    if (reply && replylen > 0)
        reply[0] = '\0';

    if (!cs)
        return -1;

    std::string dirname, cmdname;
    if (cs->utf8names) {
        std::string tmp(wdirtypemax, '\0');
        if (remotedir) {
            wcslcpytoutf8(tmp.data(), remotedir, tmp.size() - 1);
            dirname = tmp.c_str();
        }
        std::string tmp2(wdirtypemax, '\0');
        wcslcpytoutf8(tmp2.data(), cmd, tmp2.size() - 1);
        cmdname = tmp2.c_str();
    } else {
        std::string tmp(wdirtypemax, '\0');
        if (remotedir) {
            walcopyCP(cs->codepage, tmp.data(), remotedir, tmp.size() - 1);
            dirname = tmp.c_str();
        }
        std::string tmp2(wdirtypemax, '\0');
        walcopyCP(cs->codepage, tmp2.data(), cmd, tmp2.size() - 1);
        cmdname = tmp2.c_str();
    }

    std::replace(dirname.begin(), dirname.end(), '\\', '/');

    std::wstring display = L"Quote: ";
    display += cmd;
    std::replace(display.begin(), display.end(), L'\\', L'/');
    ShowStatusW(display.c_str());

    auto channel = ConnectChannel(cs->session.get(), cs->sock);
    if (!channel)
        return -1;

    std::string fullCmd;
    if (remotedir) {
        fullCmd = "cd '";
        fullCmd += string_util::ShellQuoteSingle(dirname) + "' && ";
    }
    fullCmd += cmdname;

    if (!SendChannelCommand(cs->session.get(), channel.get(), fullCmd.c_str(), cs->sock)) {
        return -1;
    }

    std::array<char, 2048> errbuf{};
    std::string msgbuf;
    std::string line;
    const auto start = std::chrono::steady_clock::now();
    int loop = 0;
    auto lasttime = get_sys_ticks();

    while (ReadChannelLine(channel.get(), line.data(), line.size() - 1,
                           msgbuf.data(), msgbuf.size() - 1,
                           errbuf.data(), errbuf.size() - 1, cs->sock))
    {
        StripEscapeSequences(line);
        if (!reply) {
            std::wstring wline;
            CopyStringA2W(cs, line.c_str(), wline.data(), wline.size(), false);
            ShowStatusW(wline.c_str());
        } else {
            if (reply[0])
                strlcat(reply, "\r\n", replylen);
            strlcat(reply, line.c_str(), replylen);
        }
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > kQuoteProgressStartMs) {
            if (ProgressLoop("QUOTE", 0, 100, &loop, &lasttime))
                break;
        }
    }

    const int rc = channel->getExitStatus();
    if (rc != 0) {
        char tmp[128];
        snprintf(tmp, sizeof(tmp), "Function return code: %d", rc);
        ShowStatus(tmp);
        if (errbuf[0]) {
            std::string err(errbuf.data());
            StripEscapeSequences(err);
            if (err.substr(0, 19) == "stdin: is not a tty")
                err = err.substr(19);
            ShowStatus(err.c_str());
            if (reply) {
                if (reply[0])
                    strlcat(reply, "\r\n", replylen);
                strlcat(reply, err.c_str(), replylen);
            }
        }
    }

    return rc >= 0 ? rc : 1;
}

bool SftpQuoteCommand(pConnectSettings cs, const char* remotedir, const char* cmd)
{
    return SftpQuoteCommand2(cs, remotedir, cmd, nullptr, 0) >= 0;
}
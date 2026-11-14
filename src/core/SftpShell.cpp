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
#include "SftpInternal.h"
#include "TerminalText.h"
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

        WaitForOperation([this] { return channel_->flush(); }, kShellFlushTimeoutMs / 2, cs_);
        WaitForOperation([this] { return channel_->sendEof(); }, kShellEofTimeoutMs / 3, cs_);
        WaitForOperation([this] { return channel_->waitEof(); }, kShellEofTimeoutMs / 3, cs_);
        WaitForOperation([this] { return channel_->channelClose(); }, kShellCloseTimeoutMs / 3, cs_);
        // Explicit drained channelFree() preferred over destructor's bounded
        // tight-loop because shells on restrictive servers may need socket
        // yielding between EAGAIN retries.
        WaitForOperation([this] { return channel_->channelFree(); }, kShellFreeTimeoutMs / 5, cs_);
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

// Terminal control sequences out, then ls-style \ooo escapes decoded.
void StripEscapeSequences(std::string& str)
{
    str = terminal_text::DecodeOctalEscapes(terminal_text::StripControls(str));
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
    WaitForOperation([channel] { return channel->flush(); }, kShellFlushTimeoutMs, nullptr);
    WaitForOperation([channel] { return channel->sendEof(); }, kShellEofTimeoutMs, nullptr);
    WaitForOperation([channel] { return channel->waitEof(); }, kShellEofTimeoutMs, nullptr);
    WaitForOperation([channel] { return channel->channelClose(); }, kShellCloseTimeoutMs, nullptr);
    // Explicit drained channelFree() — see DisconnectShell rationale.
    WaitForOperation([channel] { return channel->channelFree(); }, kShellFreeTimeoutMs, nullptr);
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
    int rc = WaitForOperation([&] { return channel->exec(command); }, SSH_AUTH_STAGE_TIMEOUT_MS, waitCtx);
    if (rc < 0)
        return false;

    rc = WaitForOperation([&] { return channel->flush(); }, SSH_AUTH_STAGE_TIMEOUT_MS, waitCtx);
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
    WaitForOperation([&] { return channel->sendEof(); }, SSH_AUTH_STAGE_TIMEOUT_MS, waitCtx);
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
        const auto errRc = channel->readStderr(errbuf.data(), errbuf.size());
        if (errRc > 0)
            hasStderr = true;

        const auto rc = channel->read(buf.data(), buf.size());
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
        if (sock != INVALID_SOCKET)
            IsSocketReadable(sock);
        else
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
        // A wide terminal, because the shell echoes back what it is sent and the
        // reader tells output from that echo by the markers wrapped around each
        // command. At 80 columns a command with a full path wraps, the tail
        // carries the end marker, and the reading stops before any output is
        // seen — a listing then looks like an empty directory and a transfer
        // like an empty file.
        return channel->requestPty("vt102", 5, "", 0, 1000, 40, 8000, 480);
    }, kScpPtyOpenTimeoutMs, cs);

    if (ptyRc < 0 && ptyRc != LIBSSH2_ERROR_EAGAIN) {
        return false;
    }

	// Start shell
    int shellRc = WaitForOperation([&] { return channel->shell(); }, kScpShellOpenTimeoutMs, cs);
    if (shellRc < 0) {
        return false;
    }

    // Servers (e.g., home.pl) lose the first login if we send it immediately.
    // We give the shell time to load /etc/profile and the MOTD.
    Sleep(500); 

    cs->scpShellChannel = std::move(channel);
    cs->scpShellMsgBuf.clear();
    cs->scpShellErrBuf.clear();

    // Silence the terminal's echo. Everything sent here comes back otherwise,
    // and the reader tells a command's output from that echo by the markers
    // around it — an echo long enough to be broken up defeats that, and an
    // upload carries its data inside the command line, where no terminal width
    // is enough. A shell without `stty` simply ignores this and behaves as it
    // did before.
    {
        const std::string quiet = "stty -echo 2>/dev/null\n";
        size_t written = 0;
        const auto start = std::chrono::steady_clock::now();
        while (written < quiet.size()) {
            const int rc = static_cast<int>(
                cs->scpShellChannel->write(quiet.data() + written, quiet.size() - written));
            if (rc > 0) {
                written += rc;
                continue;
            }
            if (rc != LIBSSH2_ERROR_EAGAIN)
                break;
            if (std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count() > kScpShellOpenTimeoutMs)
                break;
            IsSocketReadable(cs->sock);
        }
        // Let the command run, then drop whatever it echoed on its way out.
        Sleep(200);
        std::array<char, 1024> drain{};
        while (cs->scpShellChannel->read(drain.data(), drain.size()) > 0) {
        }
        cs->scpShellMsgBuf.clear();
        cs->scpShellErrBuf.clear();
    }
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
            // ~Libssh2Channel() handles channelFree on scope exit.
        } else {
            DisconnectShell(cs->scpShellChannel.get());
        }
    }
    cs->scpShellChannel.reset();
    cs->scpShellMsgBuf.clear();
    cs->scpShellErrBuf.clear();
}

bool ScpReadCommandOutput(pConnectSettings cs, const char* endMarker,
                           std::vector<std::string>& outLines,
                           DWORD timeoutMs, const char* beginMarker,
                           std::string* endLineOut)
{
    if (endLineOut)
        endLineOut->clear();

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
                           cs->scpShellMsgBuf, cs->scpShellErrBuf))
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

        // The shell may still echo what it was sent, and that echo carries
        // every marker the command mentions — including the end one, with a
        // literal "$?" where the status would be. Taken for the real thing it
        // ends the reading at once and reports a status of zero, so it is
        // skipped before either test below.
        if (IsEchoOrPromptLine(trimmed))
            continue;

        // The command ends by echoing the marker, and whatever the command
        // wanted to report rides on that same line. It is handed back rather
        // than dropped, so callers can read an exit status from it.
        if (trimmed.substr(0, endMarkerStr.size()) == endMarkerStr) {
            gotEnd = true;
            if (endLineOut)
                endLineOut->assign(trimmed);
            break;
        }
        if (trimmed.find(endMarkerStr) != std::string_view::npos) {
            gotEnd = true;
            if (endLineOut)
                endLineOut->assign(trimmed);
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
                     std::string& msgbuf, std::string& errbuf, SOCKET sock,
                     DWORD idleTimeoutMs, DWORD totalTimeoutMs)
{
    const auto start = std::chrono::steady_clock::now();
    auto lastData = start;
    bool endReceived = false;
    bool detectingCrLf = true;
    int consecutiveEagain = 0;

    // Stack buffers for raw channel reads — sized to match the old per-call chunk.
    char tmpbuf[4096];
    char tmperr[2048];

    while (true) {
        const auto now = std::chrono::steady_clock::now();
        const auto idle = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastData).count();
        const auto total = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
        if (idle > static_cast<long long>(idleTimeoutMs) || total > static_cast<long long>(totalTimeoutMs))
            return false;

        if (channel->eof())
            endReceived = true;

        const int rcerr = static_cast<int>(channel->readStderr(tmperr, sizeof(tmperr) - 1));
        const int rc    = static_cast<int>(channel->read(tmpbuf, sizeof(tmpbuf) - 1));

        if (rcerr > 0) {
            errbuf.append(tmperr, rcerr);
            lastData = now;
            consecutiveEagain = 0;
        }
        if (rc > 0) {
            msgbuf.append(tmpbuf, rc);
            lastData = now;
            consecutiveEagain = 0;
        }

        // Extract the first complete line from the accumulation buffer.
        const size_t pos = msgbuf.find('\n');
        if (pos != std::string::npos) {
            size_t lineEnd = pos;
            if (pos > 0 && msgbuf[pos - 1] == '\r') {
                if (detectingCrLf && global_detectcrlf == -1)
                    global_detectcrlf = 1;
                lineEnd = pos - 1;
            } else if (detectingCrLf && global_detectcrlf == -1) {
                global_detectcrlf = 0;
            }
            const size_t copyLen = (std::min)(lineEnd, lineLen - 1);
            msgbuf.copy(line, copyLen, 0);
            line[copyLen] = '\0';
            StripEscapeSequences(line);
            msgbuf.erase(0, pos + 1);
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
            if (!msgbuf.empty() && msgbuf[0] != '\r' && msgbuf[0] != '\n') {
                // Flush the remaining partial line (no trailing newline from the server).
                const size_t copyLen = (std::min)(msgbuf.size(), lineLen - 1);
                msgbuf.copy(line, copyLen, 0);
                line[copyLen] = '\0';
                StripEscapeSequences(line);
                msgbuf.clear();
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
    SFTP_LOG("SHELL", "Quote command: %s", cmd);

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

    std::string errbuf;
    std::string msgbuf;
    std::array<char, 4096> linebuf{};

    while (ReadChannelLine(channel.get(), linebuf.data(), linebuf.size() - 1,
                           msgbuf, errbuf, cs->sock,
                           idleTimeoutMs, totalTimeoutMs))
    {
        StripEscapeSequences(linebuf.data());
        if (!reply) {
            ShowStatus(linebuf.data());
        } else {
            if (reply[0])
                strlcat(reply, "\r\n", replylen);
            strlcat(reply, linebuf.data(), replylen);
        }
    }

    // The loop also ends on its timeouts. A command that never finished has
    // no exit status, and the channel reports 0 for one that never came —
    // which would pass a hung `mv` or `cp` for a success.
    if (!channel->eof()) {
        SFTP_LOG("SHELL", "Quote command timed out before it finished");
        return -1;
    }

    const int rc = channel->getExitStatus();
    SFTP_LOG("SHELL", "Quote command done: rc=%d", rc);
    if (rc != 0) {
        char tmp[128];
        snprintf(tmp, sizeof(tmp), "Function return code: %d", rc);
        ShowStatus(tmp);
        if (!errbuf.empty()) {
            std::string err = errbuf;
            StripEscapeSequences(err.data());
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

    std::string errbuf;
    std::string msgbuf;
    std::array<char, 4096> linebuf{};
    const auto start = std::chrono::steady_clock::now();
    int loop = 0;
    auto lasttime = get_sys_ticks();

    while (ReadChannelLine(channel.get(), linebuf.data(), linebuf.size() - 1,
                           msgbuf, errbuf, cs->sock))
    {
        StripEscapeSequences(linebuf.data());
        if (!reply) {
            std::array<wchar_t, 4096> wline{};
            CopyStringA2W(cs, linebuf.data(), wline.data(), wline.size());
            ShowStatusW(wline.data());
        } else {
            if (reply[0])
                strlcat(reply, "\r\n", replylen);
            strlcat(reply, linebuf.data(), replylen);
        }
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > kQuoteProgressStartMs) {
            if (ProgressLoop("QUOTE", 0, 100, &loop, &lasttime))
                break;
        }
    }

    // The loop also ends on its timeouts. A command that never finished has
    // no exit status, and the channel reports 0 for one that never came —
    // which would pass a hung `mv` or `cp` for a success.
    if (!channel->eof()) {
        SFTP_LOG("SHELL", "Quote command timed out before it finished");
        return -1;
    }

    const int rc = channel->getExitStatus();
    SFTP_LOG("SHELL", "Quote command done: rc=%d", rc);
    if (rc != 0) {
        char tmp[128];
        snprintf(tmp, sizeof(tmp), "Function return code: %d", rc);
        ShowStatus(tmp);
        if (!errbuf.empty()) {
            std::string err = errbuf;
            StripEscapeSequences(err.data());
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
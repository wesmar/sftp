#include "global.h"
#include <windows.h>
#include <vector>
#include <array>
#include <memory>
#include <string>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"
#include "TransferUtils.h"
#include "IUserFeedback.h"
#include "ScpTransfer.h"
#include "ScpTransferInternal.h"

namespace {

// SFTP_MAX_READ_SIZE, SFTP_MAX_WRITE_SIZE, SFTP_SCP_BLOCK_SIZE,
// SFTP_SCP_READ_IDLE_TIMEOUT_MS, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS
// are defined in ScpTransferInternal.h
constexpr int SFTP_SCP_CHANNEL_OPEN_TIMEOUT_MS = 20000;
constexpr int64_t SFTP_SPEED_STATS_MIN_BYTES = 300LL * 1000LL * 1000LL;
constexpr int RECV_BLOCK_SIZE = 32768;
constexpr int SCP_IO_POLL_SLEEP_MS = 10;

// Helper: wait for SCP I/O with timeout
template<typename F>
bool ScpWaitFor(pConnectSettings cs, bool forWrite, DWORD timeoutMs, F&& op)
{
    const auto start = std::chrono::steady_clock::now();
    int rc;
    do {
        rc = op();
        if (rc >= 0)
            return true;
        if (rc != LIBSSH2_ERROR_EAGAIN)
            return false;
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeoutMs)
            return false;
        if (forWrite)
            IsSocketWritable(cs->sock);
        else
            IsSocketReadable(cs->sock);
    } while (true);
}

// RAII for SCP channel with automatic cleanup
class ScpChannel {
public:
    ScpChannel(std::unique_ptr<ISshChannel> ch, pConnectSettings cs)
        : channel_(std::move(ch)), cs_(cs) {}

    ~ScpChannel() {
        if (channel_) {
            // Attempt graceful shutdown
            ScpWaitFor(cs_, true, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS,
                       [this] { return channel_->sendEof(); });
            ScpWaitFor(cs_, false, SFTP_SCP_READ_IDLE_TIMEOUT_MS,
                       [this] { return channel_->waitEof(); });
            channel_->channelClose();
            channel_->channelFree();
        }
    }

    ScpChannel(const ScpChannel&) = delete;
    ScpChannel& operator=(const ScpChannel&) = delete;

    ISshChannel* get() const { return channel_.get(); }
    ISshChannel* release() { return channel_.release(); }

    bool WriteAll(const char* data, size_t len, DWORD timeoutMs) {
        size_t sent = 0;
        while (sent < len) {
            if (!ScpWaitFor(cs_, true, timeoutMs, [&] {
                    int w = static_cast<int>(channel_->write(data + sent, len - sent));
                    if (w > 0) sent += w;
                    return w;
                })) {
                return false;
            }
        }
        return true;
    }

    bool ReadByte(char& out, DWORD timeoutMs) {
        return ScpWaitFor(cs_, false, timeoutMs, [&] {
            int r = static_cast<int>(channel_->read(&out, 1));
            return r == 1 ? 1 : r;
        });
    }

    bool ReadLine(std::string& out, DWORD timeoutMs) {
        out.clear();
        const auto start = std::chrono::steady_clock::now();
        while (true) {
            char ch = 0;
            if (!ScpWaitFor(cs_, false, timeoutMs, [&] {
                    int r = static_cast<int>(channel_->read(&ch, 1));
                    return r == 1 ? 1 : r;
                })) {
                return false;
            }
            if (ch == '\n')
                return true;
            if (ch != '\r')
                out.push_back(ch);
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > timeoutMs)
                return false;
        }
    }

    bool SendAck(DWORD timeoutMs) {
        static const char ack = 0;
        return WriteAll(&ack, 1, timeoutMs);
    }

    bool ReadAck(std::string& err, DWORD timeoutMs) {
        char code = 0;
        if (!ReadByte(code, timeoutMs))
            return false;
        if (code == 0)
            return true;
        if (code == 1 || code == 2) {
            std::string line;
            if (ReadLine(line, timeoutMs))
                err = line;
            else
                err = "SCP protocol error.";
            return false;
        }
        err = "SCP protocol error.";
        return false;
    }

private:
    std::unique_ptr<ISshChannel> channel_;
    pConnectSettings cs_;
};

bool ParseScpCLine(const std::string& line, int64_t& outSize, std::string& outName)
{
    if (line.size() < 3 || line[0] != 'C')
        return false;
    const char* p = line.c_str() + 1;
    while (*p == ' ') ++p;
    while (*p >= '0' && *p <= '7') ++p;
    if (*p != ' ') return false;
    ++p;
    char* end = nullptr;
    long long sz = std::strtoll(p, &end, 10);
    if (!end || *end != ' ' || sz < 0) return false;
    ++end;
    outName.assign(end);
    outSize = static_cast<int64_t>(sz);
    return true;
}

} // anonymous namespace

int ConvertCrLfToCr(LPSTR data, size_t len)
{
    if (!data || len == 0)
        return 0;

    size_t out = 0;
    for (size_t i = 0; i < len; ++i) {
        const char ch = data[i];
        if (ch == '\n' && i > 0 && data[i - 1] == '\r') {
            continue;
        }
        data[out++] = ch;
    }
    return static_cast<int>(out);
}

void ShowTransferSpeedIfLarge(LPCSTR prefix, int64_t bytesTransferred, SYSTICKS starttime)
{
    if (bytesTransferred < SFTP_SPEED_STATS_MIN_BYTES)
        return;

    const int elapsedMs = get_ticks_between(starttime);
    if (elapsedMs <= 0)
        return;

    const double seconds = static_cast<double>(elapsedMs) / 1000.0;
    const double mibPerSec = (static_cast<double>(bytesTransferred) / (1024.0 * 1024.0)) / seconds;

    ShowStatus(std::format("{} speed: {:.2f} MiB/s", prefix ? prefix : "Transfer", mibPerSec).c_str());
}

bool ScpWaitIo(pConnectSettings cs, bool forWrite)
{
    if (!cs || cs->sock == INVALID_SOCKET)
        return false;
    return forWrite ? IsSocketWritable(cs->sock) : IsSocketReadable(cs->sock);
}

bool ScpWriteAll(ISshChannel* channel, pConnectSettings cs, const char* data, size_t len, DWORD timeoutMs)
{
    if (!channel || !data || !cs)
        return false;

    size_t sent = 0;
    const auto start = std::chrono::steady_clock::now();
    while (sent < len) {
        const int rc = static_cast<int>(channel->write(data + sent, len - sent));
        if (rc > 0) {
            sent += static_cast<size_t>(rc);
            continue;
        }
        if (rc != LIBSSH2_ERROR_EAGAIN)
            return false;
        if (EscapePressed())
            return false;
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > static_cast<long long>(timeoutMs))
            return false;
        ScpWaitIo(cs, true);
        Sleep(SCP_IO_POLL_SLEEP_MS);
    }
    return true;
}

bool ScpReadByte(ISshChannel* channel, pConnectSettings cs, char* outByte, DWORD timeoutMs)
{
    if (!channel || !cs || !outByte)
        return false;

    const auto start = std::chrono::steady_clock::now();
    while (true) {
        const int rc = static_cast<int>(channel->read(outByte, 1));
        if (rc == 1)
            return true;
        if (rc != LIBSSH2_ERROR_EAGAIN)
            return false;
        if (EscapePressed())
            return false;
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > static_cast<long long>(timeoutMs))
            return false;
        ScpWaitIo(cs, false);
        Sleep(SCP_IO_POLL_SLEEP_MS);
    }
}

bool ScpReadLine(ISshChannel* channel, pConnectSettings cs, std::string& outLine, DWORD timeoutMs)
{
    outLine.clear();
    char ch = 0;
    while (ScpReadByte(channel, cs, &ch, timeoutMs)) {
        if (ch == '\n')
            return true;
        if (ch != '\r')
            outLine.push_back(ch);
    }
    return false;
}

bool ScpSendAck(ISshChannel* channel, pConnectSettings cs)
{
    static const char ack = 0;
    return ScpWriteAll(channel, cs, &ack, 1, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS);
}

bool ScpReadAck(ISshChannel* channel, pConnectSettings cs, std::string& err)
{
    err.clear();
    char code = 0;
    if (!ScpReadByte(channel, cs, &code, SFTP_SCP_READ_IDLE_TIMEOUT_MS))
        return false;
    if (code == 0)
        return true;

    if (code == 1 || code == 2) {
        if (!ScpReadLine(channel, cs, err, SFTP_SCP_READ_IDLE_TIMEOUT_MS))
            err = "SCP protocol error.";
        return false;
    }

    err = "SCP protocol error.";
    return false;
}

bool ContainsNonAscii(LPCWSTR text) noexcept
{
    if (!text) return false;
    for (const WCHAR* p = text; *p; ++p) {
        if (*p > 127)
            return true;
    }
    return false;
}

bool PrepareScpTransferSession(pConnectSettings cs)
{
    if (!cs) return false;
    if (cs->sock == INVALID_SOCKET || IsSocketError(cs->sock) || !cs->session) {
        Sleep(RECONNECT_SLEEP_MS);
        return ReconnectSFTPChannelIfNeeded(cs);
    }
    return true;
}

std::string BuildScpPathArgument(const std::string& path)
{
    if (path.empty()) return {};
    std::string scpTarget = path;
    if (path[0] == '/')
        scpTarget = (path.size() == 1) ? "." : path.substr(1);
    if (SSH_ScpNeedQuote && scpTarget.find(' ') != std::string::npos)
        return "\"" + scpTarget + "\"";
    return scpTarget;
}

bool OpenScpDownloadChannel(pConnectSettings cs, const char* filename,
                            std::unique_ptr<ISshChannel>& outChannel,
                            libssh2_struct_stat* outInfo)
{
    const auto start = std::chrono::steady_clock::now();
    bool didReconnect = false;
    std::unique_ptr<ISshChannel> scpCh;

    do {
        scpCh = cs->session->scpRecv2(filename, outInfo);
        if (EscapePressed()) {
            cs->neednewchannel = true;
            break;
        }
        if (!scpCh) {
            const int err = cs->session->lastErrno();
            if (err == LIBSSH2_ERROR_EAGAIN) {
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed > SFTP_SCP_CHANNEL_OPEN_TIMEOUT_MS) {
                    ShowStatus("SCP download: open channel timeout.");
                    break;
                }
                IsSocketReadable(cs->sock);
            } else if (!didReconnect &&
                       (err == LIBSSH2_ERROR_SOCKET_DISCONNECT ||
                        err == LIBSSH2_ERROR_SOCKET_RECV ||
                        err == LIBSSH2_ERROR_SOCKET_SEND ||
                        err == LIBSSH2_ERROR_CHANNEL_OUTOFORDER)) {
                ShowStatus("SCP: connection dropped, reconnecting...");
                SftpCloseConnection(cs);
                Sleep(RECONNECT_SLEEP_MS);
                if (SftpConnect(cs) == SFTP_OK) {
                    didReconnect = true;
                    continue;
                }
                break;
            } else if (err == LIBSSH2_ERROR_SCP_PROTOCOL) {
                if (cs->feedback) {
                    cs->feedback->ShowError(
                        "Cannot execute SCP to start transfer. Please make sure that SCP is installed on the server and path to it is included in PATH.\n\nYou may also try SFTP instead of SCP (uncheck 'Use SCP for all' in connection settings).",
                        "SCP Protocol Error");
                }
                break;
            } else {
                break;
            }
        }
    } while (!scpCh);

    if (!scpCh)
        return false;
    outChannel = std::move(scpCh);
    return true;
}

int ShellScpDownloadFile(pConnectSettings cs,
                         const std::string& remotePathArg,
                         LPCWSTR remoteNameW,
                         HANDLE localfile,
                         LPCWSTR localNameW,
                         bool textMode,
                         int64_t hintedFileSize,
                         int64_t* outSizeLoaded)
{
    if (!cs || !cs->session || !IsValidFileHandle(localfile) || !outSizeLoaded)
        return SFTP_FAILED;
    *outSizeLoaded = 0;

    auto channel = ConnectChannel(cs->session.get(), cs->sock);
    if (!channel)
        return SFTP_FAILED;

    std::string cmd = "scp -f ";
    cmd += remotePathArg;
    if (!SendChannelCommandNoEof(cs->session.get(), channel.get(), cmd.c_str(), cs->sock)) {
        return SFTP_READFAILED;
    }

    ScpChannel scp(std::move(channel), cs);
    std::string err;
    if (!scp.SendAck(SFTP_SCP_WRITE_IDLE_TIMEOUT_MS) ||
        !scp.ReadAck(err, SFTP_SCP_READ_IDLE_TIMEOUT_MS)) {
        if (!err.empty()) ShowStatus(err.c_str());
        return SFTP_READFAILED;
    }

    int64_t remoteSize = hintedFileSize;
    bool gotDataHeader = false;
    bool lastWasCr = false;
    std::vector<char> dataBuf(SFTP_MAX_READ_SIZE * 2);
    const auto start = std::chrono::steady_clock::now();

    while (true) {
        char type = 0;
        if (!scp.ReadByte(type, SFTP_SCP_READ_IDLE_TIMEOUT_MS)) {
            return SFTP_READFAILED;
        }
        if (type == 'T') {
            std::string tline;
            if (!scp.ReadLine(tline, SFTP_SCP_READ_IDLE_TIMEOUT_MS) ||
                !scp.SendAck(SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)) {
                return SFTP_READFAILED;
            }
            continue;
        }
        if (type == 'E') {
            std::string eline;
            scp.ReadLine(eline, SFTP_SCP_READ_IDLE_TIMEOUT_MS);
            scp.SendAck(SFTP_SCP_WRITE_IDLE_TIMEOUT_MS);
            break;
        }
        if (type == 1 || type == 2) {
            std::string errLine;
            scp.ReadLine(errLine, SFTP_SCP_READ_IDLE_TIMEOUT_MS);
            if (!errLine.empty()) ShowStatus(errLine.c_str());
            return SFTP_READFAILED;
        }
        if (type != 'C') {
            return SFTP_READFAILED;
        }

        std::string cline;
        if (!scp.ReadLine(cline, SFTP_SCP_READ_IDLE_TIMEOUT_MS)) {
            return SFTP_READFAILED;
        }
        cline.insert(cline.begin(), 'C');
        std::string remoteName;
        if (!ParseScpCLine(cline, remoteSize, remoteName) ||
            !scp.SendAck(SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)) {
            return SFTP_READFAILED;
        }
        gotDataHeader = true;

        int64_t remaining = remoteSize;
        while (remaining > 0) {
            const size_t want = std::min<size_t>(static_cast<size_t>(remaining), dataBuf.size());
            int rc = static_cast<int>(scp.get()->read(dataBuf.data(), want));
            if (rc > 0) {
                remaining -= rc;
                int wlen = rc;
                if (textMode)
                    wlen = ConvertCrToCrLf(dataBuf.data(), static_cast<size_t>(rc), &lastWasCr);
                DWORD written = 0;
                if (!WriteFile(localfile, dataBuf.data(), static_cast<DWORD>(wlen), &written, nullptr) ||
                    written != static_cast<DWORD>(wlen)) {
                    return SFTP_WRITEFAILED;
                }
                *outSizeLoaded += rc;
                if (UpdatePercentBar(cs, GetPercent(*outSizeLoaded, remoteSize > 0 ? remoteSize : hintedFileSize),
                                     remoteNameW, localNameW)) {
                    return SFTP_ABORT;
                }
            } else if (rc == LIBSSH2_ERROR_EAGAIN) {
                if (EscapePressed()) return SFTP_ABORT;
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed > SFTP_SCP_READ_IDLE_TIMEOUT_MS) {
                    ShowStatus("SCP download stalled.");
                    return SFTP_READFAILED;
                }
                IsSocketReadable(cs->sock);
            } else {
                return SFTP_READFAILED;
            }
        }

        char endCode = 0;
        if (!scp.ReadByte(endCode, SFTP_SCP_READ_IDLE_TIMEOUT_MS) ||
            endCode != 0 ||
            !scp.SendAck(SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)) {
            return SFTP_READFAILED;
        }
        break;
    }

    return gotDataHeader ? SFTP_OK : SFTP_READFAILED;
}

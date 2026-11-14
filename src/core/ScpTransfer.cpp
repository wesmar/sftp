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
#include "TextConversion.h"
#include "res/resource.h"
#include "LngLoader.h"

extern HINSTANCE hinst;

namespace {

static std::string LngStrA(UINT id, const char* fallback)
{
    const char* s = LngGetString(id);
    if (s) return s;
    std::array<char, 512> buf{};
    const int n = LoadStringA(hinst, id, buf.data(), static_cast<int>(buf.size()) - 1);
    return n > 0 ? std::string(buf.data(), static_cast<size_t>(n)) : (fallback ? fallback : "");
}

// SFTP_MAX_READ_SIZE, SFTP_MAX_WRITE_SIZE, SFTP_SCP_BLOCK_SIZE,
// SFTP_SCP_READ_IDLE_TIMEOUT_MS, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS
// are defined in ScpTransferInternal.h
constexpr int SFTP_SCP_CHANNEL_OPEN_TIMEOUT_MS = 20000;
constexpr int64_t SFTP_SPEED_STATS_MIN_BYTES = 300LL * 1000LL * 1000LL;
constexpr int RECV_BLOCK_SIZE = 32768;

// RAII for SCP channel with automatic cleanup
class ScpChannel {
public:
    ScpChannel(std::unique_ptr<ISshChannel> ch, pConnectSettings cs)
        : channel_(std::move(ch)), cs_(cs) {}

    ~ScpChannel() {
        if (channel_) {
            // Attempt graceful shutdown
            WaitForOperation([this] { return channel_->sendEof(); },
                             SFTP_SCP_WRITE_IDLE_TIMEOUT_MS, cs_);
            WaitForOperation([this] { return channel_->waitEof(); },
                             SFTP_SCP_READ_IDLE_TIMEOUT_MS, cs_);
            channel_->channelClose();
            // ~Libssh2Channel() in unique_ptr scope-exit handles channelFree.
        }
    }

    ScpChannel(const ScpChannel&) = delete;
    ScpChannel& operator=(const ScpChannel&) = delete;

    ISshChannel* get() const { return channel_.get(); }
    ISshChannel* release() { return channel_.release(); }

    bool WriteAll(const char* data, size_t len, DWORD timeoutMs) {
        size_t sent = 0;
        while (sent < len) {
            int rc = WaitForOperation([&] {
                int w = static_cast<int>(channel_->write(data + sent, len - sent));
                if (w > 0) sent += w;
                return w;
            }, timeoutMs, cs_);
            if (rc < 0)
                return false;
        }
        return true;
    }

    bool ReadByte(char& out, DWORD timeoutMs) {
        int rc = WaitForOperation([&] {
            int r = static_cast<int>(channel_->read(&out, 1));
            return r == 1 ? 1 : r;
        }, timeoutMs, cs_);
        return rc >= 0;
    }

    bool ReadLine(std::string& out, DWORD timeoutMs) {
        out.clear();
        const auto start = std::chrono::steady_clock::now();
        while (true) {
            char ch = 0;
            int rc = WaitForOperation([&] {
                int r = static_cast<int>(channel_->read(&ch, 1));
                return r == 1 ? 1 : r;
            }, timeoutMs, cs_);
            if (rc < 0)
                return false;
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
                err = LngStrA(IDS_SCP_PROTOCOL_ERROR, "SCP protocol error.");
            return false;
        }
        err = LngStrA(IDS_SCP_PROTOCOL_ERROR, "SCP protocol error.");
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

bool ScpWriteAll(ISshChannel* channel, pConnectSettings cs, const char* data, size_t len, DWORD timeoutMs)
{
    if (!channel || !data || !cs)
        return false;

    size_t sent = 0;
    while (sent < len) {
        int rc = WaitForOperation([&] {
            int w = static_cast<int>(channel->write(data + sent, len - sent));
            if (w > 0) sent += static_cast<size_t>(w);
            return w;
        }, timeoutMs, cs);
        if (rc < 0)
            return false;
    }
    return true;
}

bool ScpReadByte(ISshChannel* channel, pConnectSettings cs, char* outByte, DWORD timeoutMs)
{
    if (!channel || !cs || !outByte)
        return false;

    int rc = WaitForOperation([&] {
        int r = static_cast<int>(channel->read(outByte, 1));
        return r == 1 ? 1 : r;
    }, timeoutMs, cs);
    return rc == 1;
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
            err = LngStrA(IDS_SCP_PROTOCOL_ERROR, "SCP protocol error.");
        return false;
    }

    err = LngStrA(IDS_SCP_PROTOCOL_ERROR, "SCP protocol error.");
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
    // The path reaches `scp` as it is. Making it relative would tie every
    // transfer to wherever the login left the shell, which is the same reason
    // listing could not leave the home directory.
    if (path.empty()) return {};
    if (SSH_ScpNeedQuote && path.find(' ') != std::string::npos)
        return "\"" + path + "\"";
    return path;
}

// Whether an scp download was refused because the file is not there. Asked
// over SFTP, which "SCP for data" keeps open beside scp; without it there is
// no telling, and the answer is no. `filename` is the scp argument, which
// carries quotes when the path holds a space.
static bool ScpSourceIsMissing(pConnectSettings cs, const char* filename)
{
    if (!cs || !filename)
        return false;
    if (!cs->sftpsession || cs->scponly) {
        SFTP_LOG("SCP", "missing-check: no SFTP session to ask (sftp=%d scponly=%d)",
                 cs->sftpsession ? 1 : 0, cs->scponly ? 1 : 0);
        return false;
    }
    std::string path = filename;
    if (path.size() >= 2 && path.front() == '"' && path.back() == '"')
        path = path.substr(1, path.size() - 2);

    LIBSSH2_SFTP_ATTRIBUTES attr{};
    int rc = 0;
    do {
        rc = cs->sftpsession->lstat(path.c_str(), &attr);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);
    const unsigned long fx = (rc == LIBSSH2_ERROR_SFTP_PROTOCOL) ? cs->sftpsession->lastError() : 0;
    SFTP_LOG("SCP", "missing-check '%s': lstat rc=%d fx=%lu", path.c_str(), rc, fx);
    return fx == LIBSSH2_FX_NO_SUCH_FILE || fx == LIBSSH2_FX_NO_SUCH_PATH;
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
                    ShowStatusId(IDS_LOG_SCP_OPEN_TIMEOUT, nullptr, true);
                    break;
                }
                IsSocketReadable(cs->sock);
            } else if (!didReconnect &&
                       (err == LIBSSH2_ERROR_SOCKET_DISCONNECT ||
                        err == LIBSSH2_ERROR_SOCKET_RECV ||
                        err == LIBSSH2_ERROR_SOCKET_SEND ||
                        err == LIBSSH2_ERROR_CHANNEL_OUTOFORDER)) {
                ShowStatusId(IDS_LOG_SCP_DROPPED, nullptr, true);
                SftpCloseConnection(cs);
                Sleep(RECONNECT_SLEEP_MS);
                if (SftpConnect(cs) == SFTP_OK) {
                    didReconnect = true;
                    continue;
                }
                break;
            } else if (err == LIBSSH2_ERROR_SCP_PROTOCOL) {
                // The commonest refusal is a file that is not there — Shift+F4
                // on a new name asks for one first — which is not scp failing
                // to run. libssh2 reads scp's own message and drops it, so the
                // question goes to SFTP, which this mode keeps open: a missing
                // file gets a status line, anything else the dialog.
                if (ScpSourceIsMissing(cs, filename)) {
                    SFTP_LOG("SCP", "Download refused: '%s' does not exist", filename);
                    ShowStatus("SCP: no such file");
                } else if (cs->feedback) {
                    cs->feedback->ShowError(
                        LngStrA(IDS_SCP_EXEC_FAILED, "Cannot execute SCP to start transfer. Please make sure that SCP is installed on the server and path to it is included in PATH.\n\nYou may also try SFTP instead of SCP (uncheck 'Use SCP for all' in connection settings).").c_str(),
                        LngStrA(IDS_SCP_PROTOCOL_ERROR, "SCP Protocol Error").c_str());
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
    SFTP_LOG("SCP", "download command: %s", cmd.c_str());
    if (!SendChannelCommandNoEof(cs->session.get(), channel.get(), cmd.c_str(), cs->sock)) {
        SFTP_LOG("SCP", "download: sending the command failed");
        return SFTP_READFAILED;
    }

    // `scp -f` sends nothing until it is asked to: the first byte goes out
    // from here, and what comes back is already the file's header, beginning
    // with 'C'. There is no acknowledgement to read in this direction — the
    // loop below reads that header, and handles the 1 and 2 error codes a
    // failing scp would send in its place.
    ScpChannel scp(std::move(channel), cs);
    if (!scp.SendAck(SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)) {
        SFTP_LOG("SCP", "download: could not ask for the file");
        return SFTP_READFAILED;
    }

    int64_t remoteSize = hintedFileSize;
    bool gotDataHeader = false;
    text_conversion::LfToCrLf toCrLf;
    std::vector<char> dataBuf(SFTP_MAX_READ_SIZE * 2);
    std::vector<char> converted;
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
                const char* out = dataBuf.data();
                size_t outLen = static_cast<size_t>(rc);
                if (textMode) {
                    converted.clear();
                    outLen = toCrLf.Convert(dataBuf.data(), outLen, converted);
                    out = converted.data();
                }
                DWORD written = 0;
                if (!WriteFile(localfile, out, static_cast<DWORD>(outLen), &written, nullptr) ||
                    written != static_cast<DWORD>(outLen)) {
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

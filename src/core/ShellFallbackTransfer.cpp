#include "global.h"
#include <windows.h>
#include <array>
#include <memory>
#include <string>
#include <vector>
#include <stdint.h>
#include <stdio.h>
#include <span>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"
#include "TransferUtils.h"
#include "ScpTransfer.h"
#include "ScpTransferInternal.h"
#include "TextConversion.h"
#include "res/resource.h"

// An upload carries its data inside the command line, and the shell reads
// that line through a terminal, which holds at most 4095 bytes of one line.
// A shell that takes base64 spread over lines inside one quoted word gets
// 48 KiB per command in lines of 76 characters; any other gets one line of
// 1 KiB (1368 characters plus the command around them).
static constexpr size_t SHELL_DD_UPLOAD_CHUNK_BYTES  = 1024;
static constexpr size_t SHELL_DD_UPLOAD_LARGE_CHUNK  = 48 * 1024;
static constexpr size_t SHELL_B64_LINE_CHARS         = 76;
static constexpr size_t SHELL_DD_DOWNLOAD_BLOCK      = 65536;

#define SHELL_DD_LOG(fmt, ...) SFTP_LOG("SHELL_DD", fmt, ##__VA_ARGS__)

// ---- minimal base64 helpers (no external dependency) ----
static constexpr std::string_view kB64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string ShellB64Encode(std::span<const uint8_t> data)
{
    std::string out;
    const size_t len = data.size();
    out.reserve(((len + 2) / 3) * 4 + 1);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t b = (uint32_t)data[i] << 16;
        if (i + 1 < len) b |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) b |= (uint32_t)data[i + 2];
        out += kB64Chars[(b >> 18) & 0x3F];
        out += kB64Chars[(b >> 12) & 0x3F];
        out += (i + 1 < len) ? kB64Chars[(b >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? kB64Chars[b & 0x3F]        : '=';
    }
    return out;
}

// Breaks base64 text into lines; `base64 -d` skips the line ends.
static std::string ShellB64WrapLines(const std::string& b64)
{
    std::string out;
    out.reserve(b64.size() + b64.size() / SHELL_B64_LINE_CHARS + 1);
    for (size_t i = 0; i < b64.size(); i += SHELL_B64_LINE_CHARS) {
        if (i)
            out += '\n';
        out.append(b64, i, SHELL_B64_LINE_CHARS);
    }
    return out;
}

static size_t ShellB64Decode(std::string_view in, std::span<uint8_t> out)
{
    // MimeDecode takes (const char*, size_t) and never calls strlen — no copy needed.
    return static_cast<size_t>(MimeDecode(in.data(), in.size(), out.data(), out.size()));
}

// The shell commands address a file by the path they were given. Making it
// relative would send every transfer looking inside the login directory, which
// is where the listing used to be stuck as well.
static std::string ShellNormalizeScpPath(const std::string& path)
{
    return path.empty() ? "." : path;
}

static std::unique_ptr<ISshChannel> OpenShellDdChannel(pConnectSettings cs, const char* where)
{
    if (!cs || !cs->session)
        return {};

    for (int attempt = 0; attempt < 3; ++attempt) {
        auto raw = ConnectChannel(cs->session.get(), cs->sock);
        if (raw)
            return raw;

        SHELL_DD_LOG("%s: ConnectChannel failed (attempt %d/3)", where ? where : "ShellDd", attempt + 1);
        if (attempt == 0) {
            // First retry: give server a small window to close previous channel.
            Sleep(120);
        } else {
            // Next retries: force lightweight reconnect and retry.
            if (!ReconnectSFTPChannelIfNeeded(cs))
                break;
            Sleep(120);
        }
    }
    return {};
}

static bool ShellSendPersistentCommand(pConnectSettings cs, const std::string& command)
{
    if (!cs || !cs->scpShellChannel)
        return false;
    const size_t cmdLen = command.size();
    size_t written = 0;
    const SYSTICKS writeStart = get_sys_ticks();
    while (written < cmdLen) {
        const auto writeRc = cs->scpShellChannel->write(command.c_str() + written, cmdLen - written);
        if (writeRc > 0) {
            written += static_cast<size_t>(writeRc);
            continue;
        }
        if (writeRc != LIBSSH2_ERROR_EAGAIN)
            return false;
        if (get_ticks_between(writeStart) > 15000)
            return false;
        if (cs->sock != INVALID_SOCKET)
            IsSocketReadable(cs->sock);
        else
            Sleep(25);
    }
    return true;
}

static const char* ShellTrimLeft(const char* p) noexcept
{
    while (p && *p && static_cast<unsigned char>(*p) <= 0x20)
        ++p;
    return p ? p : "";
}

static bool ShellIsEchoOrPromptLine(const char* line) noexcept
{
    const char* p = ShellTrimLeft(line);
    if (!p[0])
        return false;
    if (_strnicmp(p, "echo ", 5) == 0)
        return true;
    if (strstr(p, "$ echo ") != nullptr)
        return true;
    return false;
}

template <typename LineHandler>
// `outExitCode`, when given, receives what the command answered: the status is
// appended to the end marker, and the marker line is consumed here rather than
// passed on, so a caller has no other way to learn it. Left at -1 when the
// command did not get that far.
static bool ShellExecPersistentProcessLines(
    pConnectSettings cs,
    const std::string& payload,
    DWORD timeoutMs,
    LineHandler onLine,
    int* outExitCode = nullptr)
{
    if (outExitCode)
        *outExitCode = -1;

    if (!cs)
        return false;
    if (!EnsureScpShell(cs))
        return false;
    if (!cs->scpShellChannel)
        return false;

    cs->scpShellMsgBuf.clear();
    cs->scpShellErrBuf.clear();

    static unsigned shellDdSeq = 1;
    const unsigned seq = shellDdSeq++;
    std::array<char, 128> beginMarker{};
    std::array<char, 128> endMarker{};
    // Use per-command markers to safely parse output when a shared shell channel
    // may contain prompt noise, echoed commands, or delayed lines from previous commands.
    _snprintf_s(beginMarker.data(), beginMarker.size(), _TRUNCATE, "__WFX_DD_BEGIN__%u", seq);
    _snprintf_s(endMarker.data(), endMarker.size(), _TRUNCATE, "__WFX_DD_END__%u", seq);
    const size_t endMarkerLen = strlen(endMarker.data());

    // The end marker goes out split by an empty string, "__WFX_DD_""END__n":
    // the shell joins it when the command runs, but a terminal that still
    // echoes (a host without `stty`) never shows it whole - so the echo of a
    // command's last line cannot pass for the command having finished.
    std::string fullCmd = "echo \"";
    fullCmd += beginMarker.data();
    fullCmd += "\"; ";
    fullCmd += payload;
    fullCmd += "; echo \"__WFX_DD_\"\"";
    fullCmd += endMarker.data() + strlen("__WFX_DD_");
    fullCmd += "\":$?\n";

    if (!ShellSendPersistentCommand(cs, fullCmd)) {
        CloseScpShell(cs);
        return false;
    }

    const SYSTICKS start = get_sys_ticks();
    bool gotBeginMarker = false;
    bool gotEndMarker = false;
    std::array<char, 8192> line{};

    while (ReadChannelLine(cs->scpShellChannel.get(), line.data(), line.size() - 1,
                           cs->scpShellMsgBuf, cs->scpShellErrBuf, cs->sock))
    {
        StripEscapeSequences(line.data());
        const char* p = ShellTrimLeft(line.data());
        if (!p[0])
            continue;

        if (!gotBeginMarker) {
            if (strstr(p, beginMarker.data()) != nullptr) {
                gotBeginMarker = true;
                SFTP_LOG("SCP", "Detected BEGIN marker: %s", beginMarker.data());
            }
            continue;
        }

        // Prefer exact line-start marker matching, but also accept marker anywhere
        // in the line for shells that inject prompt prefixes.
        if (!ShellIsEchoOrPromptLine(p) && strncmp(p, endMarker.data(), endMarkerLen) == 0) {
            gotEndMarker = true;
            if (outExitCode) {
                const char* colon = strrchr(p, ':');
                if (colon)
                    *outExitCode = atoi(colon + 1);
            }
            break;
        }
        if (const char* at = strstr(p, endMarker.data())) {
            gotEndMarker = true;
            if (outExitCode) {
                const char* colon = strchr(at, ':');
                if (colon)
                    *outExitCode = atoi(colon + 1);
            }
            break;
        }

        if (!onLine(p, strlen(p))) {
            CloseScpShell(cs);
            return false;
        }

        if (EscapePressed()) {
            CloseScpShell(cs);
            return false;
        }
        if (get_ticks_between(start) > (int)timeoutMs) {
            CloseScpShell(cs);
            return false;
        }
    }
    if (!gotBeginMarker || !gotEndMarker) {
        CloseScpShell(cs);
        return false;
    }
    return true;
}

static bool ShellExecPersistentCollectLines(
    pConnectSettings cs,
    const std::string& payload,
    std::vector<std::string>& outLines,
    int* outExitCode = nullptr)
{
    outLines.clear();
    return ShellExecPersistentProcessLines(cs, payload, 90000,
        [&](const char* p, size_t len) -> bool {
            outLines.emplace_back(p, len);
            return true;
        }, outExitCode);
}

// ---- helper: get remote file size via "wc -c" ----

static int64_t ShellGetRemoteFileSize(pConnectSettings cs, const std::string& remotePath)
{
    if (!cs || !cs->session)
        return -1;

    const std::string normalizedPath = ShellNormalizeScpPath(remotePath);
    std::string cmd = "wc -c < '" + string_util::ShellQuoteSingle(normalizedPath) + "' 2>/dev/null";

    auto parseOutput = [](const std::vector<std::string>& lines) -> int64_t {
        for (const auto& l : lines) {
            const char* p = l.c_str();
            while (*p == ' ' || *p == '\t') p++;
            if (*p >= '0' && *p <= '9') {
                return _atoi64(p);
            }
        }
        return -1;
    };

    // If shell fallback is forced or base64 fallback is active, use persistent shell
    // to bypass potential blocks on opening new exec channels.
    if (cs->shell_transfer_force || cs->shell_dd_b64only) {
        std::vector<std::string> lines;
        if (ShellExecPersistentCollectLines(cs, cmd, lines)) {
            return parseOutput(lines);
        }
        return -1;
    }

    std::unique_ptr<ISshChannel> ch = OpenShellDdChannel(cs, "ShellGetRemoteFileSize");
    if (!ch) {
        // Fallback to persistent shell if opening an exec channel fails.
        std::vector<std::string> lines;
        if (ShellExecPersistentCollectLines(cs, cmd, lines)) {
            return parseOutput(lines);
        }
        return -1;
    }

    if (!SendChannelCommand(cs->session.get(), ch.get(), cmd.c_str(), cs->sock)) {
        DisconnectShell(ch.get());
        return -1;
    }

    std::string msgbuf, errbuf;
    std::array<char, 256> line{};
    int64_t size = -1;
    while (ReadChannelLine(ch.get(), line.data(), line.size() - 1,
                           msgbuf, errbuf, cs->sock)) {
        StripEscapeSequences(line.data());
        const char* p = line.data();
        while (*p == ' ' || *p == '\t') p++;
        if (*p >= '0' && *p <= '9') {
            size = _atoi64(p);
            break;
        }
    }
    DisconnectShell(ch.get());
    return size;
}

// ---- raw binary download: exec "cat file" / "tail -c +N file" ----

static int ShellDdDownloadRaw(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t hintedSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded)
{
    *outSizeLoaded = resumeFrom;

    // Build remote command. "tail -c +N" skips the first N-1 bytes.
    std::string cmd;
    const std::string normalizedPath = ShellNormalizeScpPath(remotePath);
    const std::string quotedPath = string_util::ShellQuoteSingle(normalizedPath);
    if (resumeFrom > 0) {
        char skipBuf[64];
        _snprintf_s(skipBuf, sizeof(skipBuf), _TRUNCATE, "%lld", (long long)(resumeFrom + 1));
        cmd = "tail -c +" + std::string(skipBuf) + " '" + quotedPath + "' 2>/dev/null";
    } else {
        cmd = "cat '" + quotedPath + "' 2>/dev/null";
    }

    std::unique_ptr<ISshChannel> ch = OpenShellDdChannel(cs, "ShellDdDownloadRaw");
    if (!ch)
        return SFTP_FAILED;

    // SendChannelCommand sends EOF so the remote process gets stdin-EOF.
    // We use SendChannelCommandNoEof here because we need to read stdout.
    if (!SendChannelCommandNoEof(cs->session.get(), ch.get(), cmd.c_str(), cs->sock)) {
        DisconnectShell(ch.get());
        return SFTP_READFAILED;
    }
    // Signal our side is done writing (we never write on a download).
    ch->sendEof();

    std::vector<char> buf(SHELL_DD_DOWNLOAD_BLOCK);
    const SYSTICKS starttime = get_sys_ticks();
    SYSTICKS lastIoTime = get_sys_ticks();

    while (true) {
        int rc = (int)ch->read(buf.data(), buf.size());
        if (rc > 0) {
            DWORD written = 0;
            if (!WriteFile(localfile, buf.data(), (DWORD)rc, &written, nullptr) || written != (DWORD)rc) {
                DisconnectShell(ch.get());
                return SFTP_WRITEFAILED;
            }
            *outSizeLoaded += rc;
            lastIoTime = get_sys_ticks();
            int64_t totalForPct = (hintedSize > 0) ? hintedSize : *outSizeLoaded;
            if (UpdatePercentBar(cs, GetPercent(*outSizeLoaded, totalForPct), remoteNameW, localNameW)) {
                DisconnectShell(ch.get());
                return SFTP_ABORT;
            }
        } else if (rc == LIBSSH2_ERROR_EAGAIN) {
            if (EscapePressed()) {
                DisconnectShell(ch.get());
                return SFTP_ABORT;
            }
            if (get_ticks_between(lastIoTime) > (int)SFTP_SCP_READ_IDLE_TIMEOUT_MS) {
                SHELL_DD_LOG("raw download timeout after %lld bytes", (long long)*outSizeLoaded);
                DisconnectShell(ch.get());
                return SFTP_READFAILED;
            }
            WaitForSshIo(cs);
        } else if (rc == 0 || ch->eof()) {
            break; // clean EOF
        } else {
            SHELL_DD_LOG("raw download read error rc=%d", rc);
            DisconnectShell(ch.get());
            return SFTP_READFAILED;
        }
    }

    DisconnectShell(ch.get());
    ShowTransferSpeedIfLarge("Shell-raw DL", *outSizeLoaded - resumeFrom, starttime);
    return SFTP_OK;
}

// ---- base64 download: exec "base64 -w 0 file" ----

static int ShellDdDownloadBase64(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t hintedSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded)
{
    *outSizeLoaded = resumeFrom;
    SHELL_DD_LOG("b64 DL start: path='%s' hinted=%lld resume=%lld",
                 remotePath.c_str(), (long long)hintedSize, (long long)resumeFrom);

    std::string payload;
    const std::string normalizedPath = ShellNormalizeScpPath(remotePath);
    const std::string quotedPath = string_util::ShellQuoteSingle(normalizedPath);
    if (resumeFrom > 0) {
        char skipBuf[64];
        _snprintf_s(skipBuf, sizeof(skipBuf), _TRUNCATE, "%lld", (long long)(resumeFrom + 1));
        payload = "tail -c +";
        payload += skipBuf;
        payload += " '";
        payload += quotedPath;
        payload += "' 2>/dev/null | base64";
    } else {
        payload = "base64 '";
        payload += quotedPath;
        payload += "' 2>/dev/null";
    }
    SHELL_DD_LOG("b64 DL payload: %s", payload.c_str());

    std::vector<uint8_t> decodeBuf(SHELL_DD_DOWNLOAD_BLOCK);
    const SYSTICKS starttime = get_sys_ticks();
    int lineCount = 0;    
    int64_t decodedTotal = resumeFrom;
    int streamRc = SFTP_OK;
    int exitCode = -1;
    bool ok = ShellExecPersistentProcessLines(cs, payload, 90000,
        [&](const char* p, size_t lineLen) -> bool {
            lineCount++;
            if (lineLen > 0 && (lineCount <= 3 || (lineCount % 100) == 0)) {
                SHELL_DD_LOG("b64 DL line[%d] len=%llu", lineCount, (unsigned long long)lineLen);
            }
            if (lineLen == 0)
                return true;

            size_t decoded = ShellB64Decode(std::string_view(p, lineLen), std::span<uint8_t>(decodeBuf.data(), decodeBuf.size()));
            if (decoded == 0)
                return true;

            DWORD written = 0;
            if (!WriteFile(localfile, decodeBuf.data(), (DWORD)decoded, &written, nullptr) || written != (DWORD)decoded) {
                SHELL_DD_LOG("b64 DL write failed decoded=%llu written=%lu",
                            (unsigned long long)decoded, (unsigned long)written);
                streamRc = SFTP_WRITEFAILED;
                return false;
            }
            *outSizeLoaded += (int64_t)decoded;
            decodedTotal += (int64_t)decoded;

            int64_t totalForPct = (hintedSize > 0) ? hintedSize : *outSizeLoaded;
            if (UpdatePercentBar(cs, GetPercent(*outSizeLoaded, totalForPct), remoteNameW, localNameW)) {
                SHELL_DD_LOG("b64 DL aborted by user/progress");
                streamRc = SFTP_ABORT;
                return false;
            }
            if (EscapePressed()) {
                SHELL_DD_LOG("b64 DL aborted by escape");
                streamRc = SFTP_ABORT;
                return false;
            }
            return true;
        }, &exitCode);
    if (!ok) {
        if (streamRc != SFTP_OK)
            return streamRc;
        SHELL_DD_LOG("b64 DL: persistent shell command failed");
        return SFTP_READFAILED;
    }
    SHELL_DD_LOG("b64 DL end: lines=%d decodedTotal=%lld out=%lld exit=%d",
                 lineCount, (long long)decodedTotal, (long long)*outSizeLoaded, exitCode);

    // A file that could not be read (missing, no permission) gives no output
    // at all - indistinguishable from an empty file except by base64's status.
    // A resumed read is a pipeline whose status is the encoder's; its
    // completeness is checked by size below.
    if (resumeFrom == 0 && exitCode != 0) {
        SHELL_DD_LOG("b64 DL failed: base64 exited with %d", exitCode);
        return SFTP_READFAILED;
    }

    if (lineCount == 0 && hintedSize > resumeFrom) {
        SHELL_DD_LOG("b64 DL failed: no lines returned for non-empty file");
        return SFTP_READFAILED;
    }
    // The stream carries no end-of-file status of its own, so a read that
    // stopped early on the server only shows as a short count.
    if (hintedSize > 0 && *outSizeLoaded != hintedSize) {
        SHELL_DD_LOG("b64 DL size mismatch: got %lld expected %lld",
                     (long long)*outSizeLoaded, (long long)hintedSize);
        return SFTP_READFAILED;
    }

    ShowTransferSpeedIfLarge("Shell-b64 DL", *outSizeLoaded - resumeFrom, starttime);
    return SFTP_OK;
}

// ---- raw binary upload: exec "cat > file" or "cat >> file" ----

static int ShellDdUploadRaw(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded)
{
    *outSizeLoaded = resumeFrom;

    if (resumeFrom > 0) {
        LARGE_INTEGER li;
        li.QuadPart = resumeFrom;
        if (!SetFilePointerEx(localfile, li, nullptr, FILE_BEGIN))
            return SFTP_READFAILED;
    }

    // ">>" appends to existing file (resume); ">" creates/truncates.
    const std::string normalizedPath = ShellNormalizeScpPath(remotePath);
    const std::string quotedPath = string_util::ShellQuoteSingle(normalizedPath);
    std::string cmd = (resumeFrom > 0)
        ? "cat >> '" + quotedPath + "'"
        : "cat > '"  + quotedPath + "'";

    std::unique_ptr<ISshChannel> ch = OpenShellDdChannel(cs, "ShellDdUploadRaw");
    if (!ch)
        return SFTP_FAILED;

    // Do not send EOF yet; data must be written first.
    if (!SendChannelCommandNoEof(cs->session.get(), ch.get(), cmd.c_str(), cs->sock)) {
        DisconnectShell(ch.get());
        return SFTP_WRITEFAILED;
    }

    std::vector<char> buf(SHELL_DD_DOWNLOAD_BLOCK);
    const SYSTICKS starttime = get_sys_ticks();
    DWORD bytesRead = 0;

    while (ReadFile(localfile, buf.data(), (DWORD)buf.size(), &bytesRead, nullptr) && bytesRead > 0) {
        if (!ScpWriteAll(ch.get(), cs, buf.data(), (size_t)bytesRead, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)) {
            DisconnectShell(ch.get());
            return SFTP_WRITEFAILED;
        }
        *outSizeLoaded += bytesRead;
        if (UpdatePercentBar(cs, GetPercent(*outSizeLoaded, fileSize), localNameW, remoteNameW)) {
            DisconnectShell(ch.get());
            return SFTP_ABORT;
        }
        if (EscapePressed()) {
            DisconnectShell(ch.get());
            return SFTP_ABORT;
        }
    }

    // Signal EOF so the remote "cat" process exits and flushes its output.
    const SYSTICKS eofStart = get_sys_ticks();
    while (ch->sendEof() == LIBSSH2_ERROR_EAGAIN) {
        if (get_ticks_between(eofStart) > (int)SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)
            break;
        WaitForSshIo(cs);
    }
    // Wait for remote cat to finish writing.
    const SYSTICKS waitStart = get_sys_ticks();
    while (!ch->eof()) {
        if (get_ticks_between(waitStart) > (int)SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)
            break;
        if (EscapePressed())
            break;
        WaitForSshIo(cs);
    }

    DisconnectShell(ch.get());
    ShowTransferSpeedIfLarge("Shell-raw UL", *outSizeLoaded - resumeFrom, starttime);
    return SFTP_OK;
}

// Whether the shell decodes base64 spread over lines inside one quoted word,
// asked with six bytes before an upload rather than learned from a damaged one.
static bool ShellTakesMultiLineBase64(pConnectSettings cs)
{
    std::vector<std::string> out;
    int status = -1;
    if (!ShellExecPersistentCollectLines(cs, "printf '%s' 'QUJD\nREVG' | base64 -d | wc -c", out, &status) ||
        status != 0)
        return false;
    for (const auto& line : out) {
        const char* p = ShellTrimLeft(line.c_str());
        if (p[0] == '6' && (p[1] == '\0' || static_cast<unsigned char>(p[1]) <= ' '))
            return true;
    }
    return false;
}

// ---- base64 upload: one command per chunk via printf | base64 -d ----

static int ShellDdUploadBase64(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded)
{
    // Every chunk is encoded and decoded on its own, padding included, so a
    // resume may start at any byte; rounding it down to a multiple of three
    // would append bytes the server already holds a second time.
    *outSizeLoaded = resumeFrom;

    if (resumeFrom > 0) {
        LARGE_INTEGER li;
        li.QuadPart = resumeFrom;
        if (!SetFilePointerEx(localfile, li, nullptr, FILE_BEGIN))
            return SFTP_READFAILED;
    }

    bool firstChunk = (resumeFrom == 0);
    const SYSTICKS starttime = get_sys_ticks();
    DWORD bytesRead = 0;

    if (!EnsureScpShell(cs) || !cs->scpShellChannel) {
        SHELL_DD_LOG("b64 UL: no persistent shell");
        return SFTP_FAILED;
    }

    const bool multiLine = fileSize - resumeFrom > static_cast<int64_t>(SHELL_DD_UPLOAD_CHUNK_BYTES) &&
                           ShellTakesMultiLineBase64(cs);
    const size_t chunkBytes = multiLine ? SHELL_DD_UPLOAD_LARGE_CHUNK : SHELL_DD_UPLOAD_CHUNK_BYTES;
    SHELL_DD_LOG("b64 UL: %zu bytes per command", chunkBytes);
    std::vector<uint8_t> readBuf(chunkBytes);

    while (ReadFile(localfile, readBuf.data(), static_cast<DWORD>(chunkBytes), &bytesRead, nullptr) && bytesRead > 0) {
        std::string b64 = ShellB64Encode(std::span<const uint8_t>(readBuf.data(), bytesRead));
        if (multiLine)
            b64 = ShellB64WrapLines(b64);

        // ">" truncates/creates on the first chunk; ">>" appends on all subsequent ones.
        const char* redirect = firstChunk ? ">" : ">>";
        firstChunk = false;

        // printf '%s' avoids echo interpreting backslash escapes or special chars.
        std::string cmd = "printf '%s' '" + b64 + "' | base64 -d ";
        cmd += redirect;
        cmd += " '";
        cmd += string_util::ShellQuoteSingle(ShellNormalizeScpPath(remotePath));
        cmd += "'";

        std::vector<std::string> cmdOut;
        int chunkStatus = -1;
        // A chunk counts as written only when the shell says so. Reading just
        // the markers reports success for a missing `base64`, a read-only
        // destination or a full disk — and an upload that is really a move
        // deletes the local original on the strength of that answer.
        bool cmdOk = ShellExecPersistentCollectLines(cs, cmd, cmdOut, &chunkStatus)
                     && chunkStatus == 0;
        if (!cmdOk) {
            SHELL_DD_LOG("b64 upload chunk: shell answered %d", chunkStatus);
            SHELL_DD_LOG("b64 upload chunk failed at offset %lld", (long long)*outSizeLoaded);
            return SFTP_WRITEFAILED;
        }

        *outSizeLoaded += (int64_t)bytesRead;

        if (UpdatePercentBar(cs, GetPercent(*outSizeLoaded, fileSize), localNameW, remoteNameW)) {
            return SFTP_ABORT;
        }
        if (EscapePressed()) {
            return SFTP_ABORT;
        }
    }

    // The loop above also ends when reading the local file fails, which is
    // not the end of it.
    if (*outSizeLoaded != fileSize) {
        SHELL_DD_LOG("b64 upload: local read stopped at %lld of %lld",
                     (long long)*outSizeLoaded, (long long)fileSize);
        return SFTP_READFAILED;
    }

    // An empty file sends no chunk, so nothing above created it.
    if (firstChunk) {
        const std::string cmd = ": > '" + string_util::ShellQuoteSingle(ShellNormalizeScpPath(remotePath)) + "'";
        std::vector<std::string> cmdOut;
        int status = -1;
        if (!ShellExecPersistentCollectLines(cs, cmd, cmdOut, &status) || status != 0) {
            SHELL_DD_LOG("b64 upload: creating the empty file failed (%d)", status);
            return SFTP_WRITEFAILED;
        }
    }

    // What the server ended up with has the last word. Every chunk answering
    // zero still leaves room for a truncated write, and this upload's caller
    // may delete the local original on the strength of the answer. A server
    // that cannot report the size is taken at the chunks' word, which every
    // one of them gave.
    {
        const int64_t remoteSize = ShellGetRemoteFileSize(cs, remotePath);
        if (remoteSize < 0)
            SHELL_DD_LOG("b64 upload: server did not report the size; chunks all confirmed");
        if (remoteSize >= 0 && remoteSize != fileSize) {
            SHELL_DD_LOG("b64 upload size mismatch: file %lld, server holds %lld",
                         (long long)fileSize, (long long)remoteSize);
            return SFTP_WRITEFAILED;
        }
    }

    ShowTransferSpeedIfLarge("Shell-b64 UL", *outSizeLoaded - resumeFrom, starttime);
    return SFTP_OK;
}

// ---- public entry points (called from SftpDownloadFileW / SftpUploadFileW) ----

int ShellDdDownloadFile(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t hintedSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded)
{
    if (!cs || !cs->session || !IsValidFileHandle(localfile) || !outSizeLoaded)
        return SFTP_FAILED;

    // Forced mode uses the persistent interactive shell channel only.
    if (cs->shell_transfer_force) {
        cs->shell_dd_b64only = true;
        SHELL_DD_LOG("DL forced mode: using persistent shell base64 path");
    } else if (cs->scpShellChannel) {
        // Legacy non-forced mode may use exec channels for raw transfer.
        // Release persistent shell first on hosts with single-channel limits.
        SHELL_DD_LOG("DL closing persistent scpShellChannel before fallback transfer");
        CloseScpShell(cs);
    }

    ShowStatusId(IDS_LOG_SHELL_DL_START, nullptr, true);

    if (!cs->shell_dd_b64only) {
        int rc = ShellDdDownloadRaw(cs, remotePath, remoteNameW,
                                    localfile, localNameW, hintedSize, resumeFrom, outSizeLoaded);
        if (rc == SFTP_OK) {
            // Sanity-check size: if the raw channel mangled bytes the count will
            // mismatch. A resumed file cannot be redone from scratch here, so a
            // mismatch on it is a failure rather than a retry.
            if (hintedSize > 0 && *outSizeLoaded != hintedSize && resumeFrom > 0) {
                SHELL_DD_LOG("raw DL size mismatch after resume: got %lld expected %lld",
                             (long long)*outSizeLoaded, (long long)hintedSize);
                return SFTP_READFAILED;
            }
            if (hintedSize > 0 && *outSizeLoaded != hintedSize && resumeFrom == 0) {
                SHELL_DD_LOG("raw DL size mismatch: got %lld expected %lld, switching to base64",
                             (long long)*outSizeLoaded, (long long)hintedSize);
                cs->shell_dd_b64only = true;
                // Reset local file and retry with base64.
                SetFilePointer(localfile, 0, nullptr, FILE_BEGIN);
                SetEndOfFile(localfile);
                *outSizeLoaded = 0;
                resumeFrom = 0;
                // fall through
            } else {
                return SFTP_OK;
            }
        } else if (rc != SFTP_ABORT) {
            SHELL_DD_LOG("raw DL failed (rc=%d), switching to base64", rc);
            cs->shell_dd_b64only = true;
            SetFilePointer(localfile, 0, nullptr, FILE_BEGIN);
            SetEndOfFile(localfile);
            *outSizeLoaded = 0;
            resumeFrom = 0;
            // fall through
        } else {
            return rc;
        }
    }

    ShowStatusId(IDS_LOG_SHELL_BASE64, nullptr, true);
    return ShellDdDownloadBase64(cs, remotePath, remoteNameW,
                                  localfile, localNameW, hintedSize, resumeFrom, outSizeLoaded);
}

int ShellDdUploadFile(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded)
{
    if (!cs || !cs->session || !IsValidFileHandle(localfile) || !outSizeLoaded)
        return SFTP_FAILED;

    // Forced mode uses the persistent interactive shell channel only.
    if (cs->shell_transfer_force) {
        cs->shell_dd_b64only = true;
        SHELL_DD_LOG("UL forced mode: using persistent shell base64 path");
    } else if (cs->scpShellChannel) {
        // Legacy non-forced mode may use exec channels for raw transfer.
        // Release persistent shell first on hosts with single-channel limits.
        SHELL_DD_LOG("UL closing persistent scpShellChannel before fallback transfer");
        CloseScpShell(cs);
    }

    ShowStatusId(IDS_LOG_SHELL_UL_START, nullptr, true);

    // For resume: query the actual remote byte count so we skip the right amount.
    if (resumeFrom > 0) {
        int64_t remoteSize = ShellGetRemoteFileSize(cs, remotePath);
        if (remoteSize >= 0 && remoteSize <= fileSize)
            resumeFrom = remoteSize;
        else
            resumeFrom = 0;
    }

    if (!cs->shell_dd_b64only) {
        int rc = ShellDdUploadRaw(cs, remotePath, remoteNameW,
                                  localfile, localNameW, fileSize, resumeFrom, outSizeLoaded);
        if (rc == SFTP_OK) {
            // Verify remote size.
            int64_t remoteSize = ShellGetRemoteFileSize(cs, remotePath);
            if (fileSize > 0 && remoteSize != fileSize) {
                SHELL_DD_LOG("raw UL size mismatch: remote=%lld expected=%lld, switching to base64",
                             (long long)remoteSize, (long long)fileSize);
                cs->shell_dd_b64only = true;
                SetFilePointer(localfile, 0, nullptr, FILE_BEGIN);
                *outSizeLoaded = 0;
                resumeFrom = 0;
                // fall through
            } else {
                return SFTP_OK;
            }
        } else if (rc != SFTP_ABORT) {
            SHELL_DD_LOG("raw UL failed (rc=%d), switching to base64", rc);
            cs->shell_dd_b64only = true;
            SetFilePointer(localfile, 0, nullptr, FILE_BEGIN);
            *outSizeLoaded = 0;
            resumeFrom = 0;
            // fall through
        } else {
            return rc;
        }
    }

    ShowStatusId(IDS_LOG_SHELL_BASE64, nullptr, true);
    return ShellDdUploadBase64(cs, remotePath, remoteNameW,
                               localfile, localNameW, fileSize, resumeFrom, outSizeLoaded);
}

static std::string BaseNameFromPath(const std::string& path)
{
    if (path.empty())
        return "upload.bin";
    std::string normalized = path;
    if (normalized.size() >= 2 && normalized.front() == '"' && normalized.back() == '"')
        normalized = normalized.substr(1, normalized.size() - 2);
    size_t pos = normalized.find_last_of('/');
    if (pos == std::string::npos || pos + 1 >= normalized.size())
        return normalized;
    return normalized.substr(pos + 1);
}

int ShellScpUploadFile(
    pConnectSettings cs,
    const std::string& remotePathArg,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    bool textMode,
    int64_t* outSizeLoaded)
{
    if (!cs || !cs->session || !IsValidFileHandle(localfile) || !outSizeLoaded)
        return SFTP_FAILED;

    *outSizeLoaded = 0;

    auto channel = ConnectChannel(cs->session.get(), cs->sock);
    if (!channel)
        return SFTP_FAILED;

    std::string cmd = "scp -t ";
    cmd += remotePathArg;
    SFTP_LOG("SCP", "upload command: %s", cmd.c_str());
    if (!SendChannelCommandNoEof(cs->session.get(), channel.get(), cmd.c_str(), cs->sock)) {
        SFTP_LOG("SCP", "upload: sending the command failed");
        DisconnectShell(channel.get());
        return SFTP_WRITEFAILED;
    }

    std::string ackErr;
    if (!ScpReadAck(channel.get(), cs, ackErr)) {
        SFTP_LOG("SCP", "upload handshake failed: err='%s'", ackErr.c_str());
        if (!ackErr.empty())
            ShowStatus(ackErr.c_str());
        DisconnectShell(channel.get());
        return SFTP_WRITEFAILED;
    }

    const std::string baseName = BaseNameFromPath(remotePathArg);
    std::array<char, 1024> header{};
    _snprintf_s(header.data(), header.size(), _TRUNCATE, "C%04o %lld %s\n", cs->filemod & 0777, (long long)fileSize, baseName.c_str());
    if (!ScpWriteAll(channel.get(), cs, header.data(), strlen(header.data()), SFTP_SCP_WRITE_IDLE_TIMEOUT_MS) ||
        !ScpReadAck(channel.get(), cs, ackErr)) {
        if (!ackErr.empty())
            ShowStatus(ackErr.c_str());
        DisconnectShell(channel.get());
        return SFTP_WRITEFAILED;
    }

    std::vector<char> dataBuf(SFTP_MAX_WRITE_SIZE * 8);
    std::vector<char> converted;
    text_conversion::CrLfToLf toLf;
    int64_t emitted = 0;
    const SYSTICKS starttime = get_sys_ticks();
    for (;;) {
        DWORD len = 0;
        if (!ReadFile(localfile, dataBuf.data(), static_cast<DWORD>(dataBuf.size()), &len, nullptr)) {
            DisconnectShell(channel.get());
            return SFTP_READFAILED;
        }
        const bool atEof = (len == 0);
        const char* out = dataBuf.data();
        size_t outLen = len;
        if (textMode) {
            converted.clear();
            outLen = atEof ? toLf.Finish(converted) : toLf.Convert(dataBuf.data(), len, converted);
            out = converted.data();
        }
        if (outLen > 0 && !ScpWriteAll(channel.get(), cs, out, outLen, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)) {
            DisconnectShell(channel.get());
            return SFTP_WRITEFAILED;
        }
        emitted += static_cast<int64_t>(outLen);
        if (atEof)
            break;
        *outSizeLoaded += len;
        if (UpdatePercentBar(cs, GetPercent(*outSizeLoaded, fileSize), localNameW, remoteNameW)) {
            DisconnectShell(channel.get());
            return SFTP_ABORT;
        }
    }

    // scp -t reads exactly the size the header announced; any other count
    // would leave it waiting for data or read our status byte as content.
    if (emitted != fileSize) {
        SFTP_LOG("SCP", "upload: emitted %lld bytes, header announced %lld",
                 static_cast<long long>(emitted), static_cast<long long>(fileSize));
        DisconnectShell(channel.get());
        return SFTP_READFAILED;
    }

    const char zero = 0;
    if (!ScpWriteAll(channel.get(), cs, &zero, 1, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS) ||
        !ScpReadAck(channel.get(), cs, ackErr)) {
        if (!ackErr.empty())
            ShowStatus(ackErr.c_str());
        DisconnectShell(channel.get());
        return SFTP_WRITEFAILED;
    }

    DisconnectShell(channel.get());
    ShowTransferSpeedIfLarge("Upload speed", *outSizeLoaded, starttime);
    return SFTP_OK;
}
#include "global.h"
#include <windows.h>
#include <vector>
#include <algorithm>
#include <cassert>
#include <memory>
#include <string>
#include <chrono>
#include <array>
#include <ws2tcpip.h>
#include <fcntl.h>
#include <stdio.h>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "UnicodeHelpers.h"
#include "SftpInternal.h"
#include "IUserFeedback.h"
#include "PhpAgentClient.h"
#include "ScpTransfer.h"
#include "ScpTransferInternal.h"
#include "TransferUtils.h"
#include "TextConversion.h"

namespace {

// TU-local derivations from shared constants (defined in ScpTransferInternal.h)
constexpr size_t SFTP_PREFETCH_FACTOR = 64;
constexpr int SFTP_ABORT_GRACE_MS = 2000;
constexpr int SFTP_PROGRESS_ABORT_POLL_MS = 5000;
constexpr int SFTP_PROGRESS_TIMEOUT_MS = 10000;
constexpr int SFTP_SCP_CHANNEL_OPEN_TIMEOUT_MS = 20000;
constexpr int64_t SFTP_SPEED_STATS_MIN_BYTES = 300LL * 1000LL * 1000LL;

// Helper: Open SFTP file with retry loop and timeout
// Extracted to avoid duplication between download and upload paths
std::unique_ptr<ISftpHandle> OpenSftpFileWithRetry(
    pConnectSettings cs,
    const char* path,
    unsigned long flags,
    long mode,
    int timeoutMs = SFTP_SCP_CHANNEL_OPEN_TIMEOUT_MS)
{
    std::unique_ptr<ISftpHandle> handle;
    const SYSTICKS start = get_sys_ticks();
    do {
        handle = cs->sftpsession->open(path, flags, mode);
        if (handle) break;
        const int err = cs->session->lastErrno();
        // In nonblocking mode, some servers/transports can transiently
        // report no concrete errno here. Treat err==0 like EAGAIN and retry.
        if (err != LIBSSH2_ERROR_EAGAIN && err != 0) {
            SftpLogLastError("SFTP open failed: ", err);
            break;
        }
        if (EscapePressed() || get_ticks_between(start) > timeoutMs) {
            ShowStatusId(IDS_LOG_SFTP_OPEN_TIMEOUT, nullptr, true);
            break;
        }
        IsSocketReadable(cs->sock);
    } while (!handle);
    return handle;
}

// RAII wrapper for local file handle
class LocalFile {
public:
    LocalFile() = default;
    explicit LocalFile(HANDLE h) : handle_(h) {}
    ~LocalFile() { if (IsValid()) CloseHandle(handle_); }

    LocalFile(const LocalFile&) = delete;
    LocalFile& operator=(const LocalFile&) = delete;

    LocalFile(LocalFile&& other) noexcept : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)) {}

    bool Open(LPCWSTR path, DWORD access, DWORD share, DWORD creation, DWORD flags) {
        handle_ = CreateFileT(path, access, share, nullptr, creation, flags, nullptr);
        return IsValid();
    }

    bool IsValid() const noexcept { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const noexcept { return handle_; }
    HANDLE release() noexcept { return std::exchange(handle_, INVALID_HANDLE_VALUE); }

    int64_t GetSize() const {
        LARGE_INTEGER li{};
        return GetFileSizeEx(handle_, &li) ? li.QuadPart : -1;
    }

    bool Seek(int64_t offset) {
        LARGE_INTEGER li{};
        li.QuadPart = offset;
        return SetFilePointerEx(handle_, li, nullptr, FILE_BEGIN) != FALSE;
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

// RAII wrapper for remote SFTP handle. ~Libssh2SftpHandle() also drains close
// (bounded tight loop), so this wrapper is functionally optional — kept as a
// readability aid that makes the close point in the upload/download flow
// explicit.
class RemoteSftpFile {
public:
    explicit RemoteSftpFile(std::unique_ptr<ISftpHandle> h) : handle_(std::move(h)) {}
    ~RemoteSftpFile() { if (handle_) Close(); }

    RemoteSftpFile(const RemoteSftpFile&) = delete;
    RemoteSftpFile& operator=(const RemoteSftpFile&) = delete;

    ISftpHandle* get() const { return handle_.get(); }
    std::unique_ptr<ISftpHandle> release() { return std::move(handle_); }

    int Close() {
        if (!handle_) return 0;
        int rc;
        do {
            rc = handle_->close();
        } while (rc == LIBSSH2_ERROR_EAGAIN);
        handle_.reset();
        return rc;
    }

private:
    std::unique_ptr<ISftpHandle> handle_;
};

// RAII wrapper for remote SCP channel. Adds explicit timeout-driven close
// (sendEof / waitEof / channelClose / channelFree) with socket yielding;
// destructor of bare Libssh2Channel performs only a bounded tight-loop free.
// Kept because SCP servers can be timing-sensitive on teardown.
class RemoteScpChannel {
public:
    explicit RemoteScpChannel(std::unique_ptr<ISshChannel> ch, pConnectSettings cs)
        : channel_(std::move(ch)), cs_(cs) {}
    ~RemoteScpChannel() { Close(); }

    RemoteScpChannel(const RemoteScpChannel&) = delete;
    RemoteScpChannel& operator=(const RemoteScpChannel&) = delete;

    ISshChannel* get() const { return channel_.get(); }
    std::unique_ptr<ISshChannel> release() { return std::move(channel_); }

    int Close() {
        if (!channel_ || !cs_) return 0;
        // Attempt graceful shutdown
        WaitForOperation([this] { return channel_->sendEof(); }, 1000, cs_);
        WaitForOperation([this] { return channel_->waitEof(); }, 1000, cs_);
        WaitForOperation([this] { return channel_->channelClose(); }, 1000, cs_);
        // Explicit drained channelFree() — see class header comment.
        WaitForOperation([this] { return channel_->channelFree(); }, 2000, cs_);
        channel_.reset();
        return 0;
    }

private:
    std::unique_ptr<ISshChannel> channel_;
    pConnectSettings cs_;
};

// Helper to display transfer start status
void ShowTransferStart(bool scp, LPCWSTR name, int resId)
{
    std::array<char, MAX_PATH> abuf{};
    std::array<WCHAR, wdirtypemax> wbuf{};
    LoadStr(abuf, resId);
    awlcopy(wbuf.data(), abuf.data(), wdirtypemax - 1);
    if (scp)
        wcslcat(wbuf.data(), L" (SCP)", wdirtypemax);
    wcslcat(wbuf.data(), name, wdirtypemax - 1);
    std::replace(wbuf.begin(), wbuf.end(), L'\\', L'/');
    ShowStatusW(wbuf.data());
}

// Policy decisions for download/upload
bool ResolveScpPolicy(pConnectSettings cs, int64_t filesize, bool resume, bool& useScp)
{
    if (!cs) return false;
    if (useScp && resume && !cs->scponly)
        useScp = false;
    if (!useScp || filesize <= (1LL << 31))
        return true;

    // >2GB handling
    if (!SSH_ScpNo2GBLimit || (cs->scpserver64bit != 1 && !cs->scpserver64bittemporary)) {
        if (!SSH_ScpNo2GBLimit) {
            if (cs->scponly) {
                ShowErrorId(IDS_DLL_VERSION);
                return false;
            }
            useScp = false;
            return true;
        }
        if (cs->scponly) {
            std::array<char, 256> err{};
            LoadStr(err, IDS_NO_2GB_SUPPORT);
            if (!AskUserYesNo(cs, "SFTP Error", err.data()))
                return false;
            cs->scpserver64bittemporary = true;
        }
    }
    return true;
}

// Open local file for download
bool OpenLocalForWrite(LocalFile& file, LPCWSTR path, bool overwrite, bool resume,
                       int64_t& loaded, int64_t filesize)
{
    loaded = 0;
    if (resume) {
        if (!file.Open(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN))
            return false;
        loaded = file.GetSize();
        if (loaded < 0) return false;
        if (filesize <= loaded) {
            // Already complete or larger
            return false;
        }
        if (!file.Seek(loaded))
            return false;
        return true;
    }
    return file.Open(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                     overwrite ? CREATE_ALWAYS : CREATE_NEW,
                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN);
}

// Download data loop (common for SFTP and SCP)
template<typename Handle>
int DownloadLoop(pConnectSettings cs, Handle& remote, LocalFile& local,
                 LPCWSTR remoteName, LPCWSTR localName,
                 bool& textMode, int64_t totalSize, int64_t& loaded,
                 int64_t& scpRemain)
{
    const size_t blockSize = SFTP_MAX_READ_SIZE * SFTP_PREFETCH_FACTOR;
    std::vector<char> buffer(blockSize);
    std::vector<char> converted;
    text_conversion::LfToCrLf toCrLf;
    int ret = SFTP_OK;
    auto lastProgress = std::chrono::steady_clock::now();

    while (true) {
        int len = 0;
        if constexpr (std::is_same_v<Handle, RemoteScpChannel>) {
            if (scpRemain <= 0) break;
            len = static_cast<int>(remote.get()->read(buffer.data(),
                static_cast<size_t>(std::min<int64_t>(scpRemain, static_cast<int64_t>(blockSize)))));
            if (len > 0) scpRemain -= len;
        } else {
            len = static_cast<int>(remote.get()->read(buffer.data(), blockSize));
        }

        if (len > 0) {
            lastProgress = std::chrono::steady_clock::now();
            DWORD written = 0;
            if (textMode && loaded == 0) {
                // Detect binary data
                for (int i = 0; i < len; ++i) {
                    if (buffer[i] == 0) {
                        textMode = false;
                        break;
                    }
                }
            }
            loaded += len;
            const char* out = buffer.data();
            size_t outLen = static_cast<size_t>(len);
            if (textMode) {
                converted.clear();
                outLen = toCrLf.Convert(buffer.data(), outLen, converted);
                out = converted.data();
            }
            if (!WriteFile(local.get(), out, static_cast<DWORD>(outLen), &written, nullptr) ||
                written != static_cast<DWORD>(outLen)) {
                ret = SFTP_WRITEFAILED;
                break;
            }
        } else if (len == LIBSSH2_ERROR_EAGAIN) {
            if constexpr (std::is_same_v<Handle, RemoteScpChannel>) {
                const auto now = std::chrono::steady_clock::now();
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastProgress).count();
                if (elapsed > SFTP_SCP_READ_IDLE_TIMEOUT_MS) {
                    ShowStatusId(IDS_LOG_SCP_DL_TIMEOUT, nullptr, true);
                    ret = SFTP_READFAILED;
                    break;
                }
            }
            IsSocketReadable(cs->sock);
        } else if (len < 0) {
            SftpLogLastError("Download read error: ", len);
            ret = SFTP_READFAILED;
            break;
        } else { // len == 0, EOF
            break;
        }

        if (UpdatePercentBar(cs, GetPercent(loaded, totalSize), remoteName, localName)) {
            ret = SFTP_ABORT;
            break;
        }
    }
    return ret;
}

} // anonymous namespace

int SftpDownloadFileW(pConnectSettings cs, LPCWSTR RemoteName, LPCWSTR LocalName,
                      bool alwaysOverwrite, int64_t filesize, LPFILETIME ft, bool Resume)
{
    if (!cs) return SFTP_FAILED;
    if (IsPhpAgentTransport(cs))
        return PhpAgentDownloadFileW(cs, RemoteName, LocalName, alwaysOverwrite, filesize, Resume);

    const bool forceShellFallback = (cs->scponly && cs->shell_transfer_force && cs->shell_transfer_dd) ||
                                    (cs->scponly && Resume);
    bool useScp = cs->scpfordata;
    if (!ResolveScpPolicy(cs, filesize, Resume, useScp))
        return SFTP_ABORT;

    ShowTransferStart(useScp, RemoteName, IDS_DOWNLOAD);

    std::string remotePath = ToRemotePathA(cs, RemoteName);
    bool textMode = (cs->unixlinebreaks == 1) && SftpDetermineTransferModeW(RemoteName);
    if (textMode && Resume)
        return SFTP_FAILED;

    if (!ReconnectSFTPChannelIfNeeded(cs))
        return SFTP_FAILED;

    if (useScp && !PrepareScpTransferSession(cs))
        return SFTP_FAILED;

    // Open local file
    LocalFile local;
    int64_t loaded = 0;
    if (!OpenLocalForWrite(local, LocalName, alwaysOverwrite, Resume, loaded, filesize)) {
        if (Resume && loaded == filesize)
            return SFTP_OK;
        if (!Resume && GetLastError() == ERROR_FILE_EXISTS)
            return SFTP_EXISTS;
        return SFTP_WRITEFAILED;
    }

    if (forceShellFallback) {
        int64_t shellLoaded = loaded;
        return ShellDdDownloadFile(cs, remotePath, RemoteName,
                                   local.get(), LocalName, filesize, loaded, &shellLoaded);
    }

    // Open remote
    std::unique_ptr<ISftpHandle> sftpHandle;
    std::unique_ptr<ISshChannel> scpHandle;
    libssh2_struct_stat scpInfo{};
    int64_t scpRemain = 0;

    if (useScp) {
        if (cs->scponly) {
            // Shell SCP path
            return ShellScpDownloadFile(cs, BuildShellScpArgument(remotePath), RemoteName,
                                        local.get(), LocalName,
                                        textMode, filesize, &loaded);
        } else {
            if (!OpenScpDownloadChannel(cs, BuildScpPathArgument(remotePath).c_str(), scpHandle, &scpInfo))
                return SFTP_READFAILED;
            scpRemain = scpInfo.st_size;
        }
    } else {
        sftpHandle = OpenSftpFileWithRetry(cs, remotePath.c_str(), LIBSSH2_FXF_READ, 0);
        if (!sftpHandle)
            return SFTP_READFAILED;

        if (Resume && loaded > 0) {
            sftpHandle->seek(static_cast<size_t>(loaded));
            if (static_cast<int64_t>(sftpHandle->tell()) != loaded)
                return SFTP_READFAILED;
        }
    }

    // Download loop
    int ret = SFTP_OK;
    if (useScp) {
        RemoteScpChannel remoteScp(std::move(scpHandle), cs);
        ret = DownloadLoop(cs, remoteScp, local, RemoteName, LocalName,
                           textMode, filesize, loaded, scpRemain);
        // The channel ending before the announced size is a short file, not
        // a finished one. After the data scp sends one status byte: zero for
        // a file read whole, otherwise an error with a message — a server
        // that failed to read pads the rest with zeros, so the size alone
        // does not tell. A server that sends no byte at all is taken at the
        // size it announced.
        if (ret == SFTP_OK && scpRemain > 0) {
            SFTP_LOG("SCP", "Download ended %lld bytes short", static_cast<long long>(scpRemain));
            ret = SFTP_READFAILED;
        } else if (ret == SFTP_OK) {
            char status = 0;
            if (ScpReadByte(remoteScp.get(), cs, &status, SFTP_SCP_READ_IDLE_TIMEOUT_MS) &&
                status != 0)
            {
                std::string err;
                ScpReadLine(remoteScp.get(), cs, err, SFTP_SCP_READ_IDLE_TIMEOUT_MS);
                SFTP_LOG("SCP", "Download status %d: %s", status, err.c_str());
                if (!err.empty())
                    ShowStatus(err.c_str());
                ret = SFTP_READFAILED;
            }
        }
    } else {
        RemoteSftpFile remoteSftp(std::move(sftpHandle));
        int64_t dummyRemain = 0; // not used for SFTP
        ret = DownloadLoop(cs, remoteSftp, local, RemoteName, LocalName,
                           textMode, filesize, loaded, dummyRemain);
    }

    // Close remote (RAII handles will close automatically)
    if (ret == SFTP_OK && ft)
        SetFileTime(local.get(), nullptr, nullptr, ft);

    if (ret == SFTP_READFAILED && loaded > 0 && loaded < filesize && !cs->scponly)
        ret = SFTP_PARTIAL;

    return ret;
}

int SftpUploadFileW(pConnectSettings cs, LPCWSTR LocalName, LPCWSTR RemoteName,
                    bool Resume, bool setattr)
{
    if (!cs) return SFTP_FAILED;
    if (IsPhpAgentTransport(cs))
        return PhpAgentUploadFileW(cs, LocalName, RemoteName, Resume);

    const bool forceShellFallback = (cs->scponly && cs->shell_transfer_force && cs->shell_transfer_dd) ||
                                    (cs->scponly && Resume);
    bool useScp = cs->scpfordata;
    if (useScp && Resume && !cs->scponly)
        useScp = false;

    // Open local file
    LocalFile local;
    if (!local.Open(LocalName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN)) {
        return SFTP_READFAILED;
    }

    int64_t filesize = local.GetSize();
    if (filesize < 0) return SFTP_READFAILED;

    if (!ResolveScpPolicy(cs, filesize, Resume, useScp))
        return SFTP_ABORT;

    ShowTransferStart(useScp, RemoteName, IDS_UPLOAD);

    std::string remotePath = ToRemotePathA(cs, RemoteName);
    bool textMode = (cs->unixlinebreaks == 1) && SftpDetermineTransferModeW(LocalName);
    // Converted text has different offsets on each side, so a resume position
    // taken from the remote size would point into the wrong place locally.
    if (textMode && Resume)
        return SFTP_FAILED;

    if (forceShellFallback) {
        int64_t shellUploaded = 0;
        return ShellDdUploadFile(cs, remotePath, RemoteName,
                                 local.get(), LocalName, filesize, Resume ? 1 : 0, &shellUploaded);
    }

    if (!ReconnectSFTPChannelIfNeeded(cs))
        return SFTP_FAILED;

    if (useScp && !PrepareScpTransferSession(cs))
        return SFTP_FAILED;

    // SCP announces the size before the data, so a text upload is measured
    // with the very converter that will produce it.
    int64_t uploadSize = filesize;
    if (textMode) {
        int64_t converted = 0;
        if (MeasureTextUpload(local.get(), converted))
            uploadSize = converted;
        else
            textMode = false;
    }

    // Open remote
    std::unique_ptr<ISftpHandle> sftpHandle;
    std::unique_ptr<ISshChannel> scpHandle;
    int64_t resumeOffset = 0;

    if (useScp) {
        if (cs->scponly) {
            // Shell SCP upload
            return ShellScpUploadFile(cs, BuildShellScpArgument(remotePath), RemoteName,
                                      local.get(), LocalName, uploadSize, textMode, &filesize);
        } else {
            // Native SCP upload
            FILETIME ft;
            long mtime = 0;
            if (setattr && GetFileTime(local.get(), nullptr, nullptr, &ft))
                mtime = GetUnixTime(&ft);
            // The session is non-blocking, so opening the channel answers
            // EAGAIN until the server has started scp. It is asked again, as
            // the download side does, until it opens or the wait runs out;
            // taking the first EAGAIN for a refusal failed nearly every upload.
            const auto openStart = std::chrono::steady_clock::now();
            int openErr = 0;
            while (true) {
                scpHandle = cs->session->scpSend64(remotePath.c_str(), cs->filemod,
                                                   static_cast<uint64_t>(uploadSize), mtime, 0);
                if (scpHandle)
                    break;
                openErr = cs->session->lastErrno();
                if (openErr != LIBSSH2_ERROR_EAGAIN || EscapePressed())
                    break;
                const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - openStart).count();
                if (waited > SFTP_SCP_CHANNEL_OPEN_TIMEOUT_MS) {
                    ShowStatusId(IDS_LOG_SCP_OPEN_TIMEOUT, nullptr, true);
                    break;
                }
                IsSocketReadable(cs->sock);
            }
            if (!scpHandle) {
                SFTP_LOG("SCP", "Upload: the scp channel did not open (%d)", openErr);
                SftpLogLastError("SCP upload error: ", openErr);
                return SFTP_WRITEFAILED;
            }
        }
    } else {
        unsigned long flags = LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT;
        if (!Resume)
            flags |= LIBSSH2_FXF_TRUNC;

        sftpHandle = OpenSftpFileWithRetry(cs, remotePath.c_str(), flags, 0644);
        if (!sftpHandle)
            return SFTP_WRITEFAILED;

        if (Resume) {
            // Get remote size and seek
            LIBSSH2_SFTP_ATTRIBUTES attr{};
            // Request both permissions AND size from server
            attr.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS | LIBSSH2_SFTP_ATTR_SIZE;
            int rc;
            do {
                rc = sftpHandle->fstat(&attr, 0);
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    IsSocketReadable(cs->sock);
            } while (rc == LIBSSH2_ERROR_EAGAIN);
            // Resuming continues a remote file that is a prefix of this one.
            // A size the server does not report, or one larger than the local
            // file, means it is not: the file is opened without truncation,
            // so writing from the start would leave the old tail behind.
            if (rc != 0 || !(attr.flags & LIBSSH2_SFTP_ATTR_SIZE))
                return SFTP_WRITEFAILED;
            const int64_t remoteSize = static_cast<int64_t>(attr.filesize);
            if (remoteSize > filesize)
                return SFTP_WRITEFAILED;
            if (remoteSize > 0) {
                sftpHandle->seek(static_cast<size_t>(remoteSize));
                if (!local.Seek(remoteSize))
                    return SFTP_READFAILED;
                resumeOffset = remoteSize;
            }
        }
    }

    // Upload loop
    std::vector<char> buffer(SFTP_MAX_WRITE_SIZE * 32);
    std::vector<char> converted;
    text_conversion::CrLfToLf toLf;
    int64_t sent = resumeOffset; // start from resume offset so progress bar is correct
    int64_t emitted = 0;         // bytes handed to the server after conversion
    bool atEof = false;
    auto lastProgress = std::chrono::steady_clock::now();
    int ret = SFTP_OK;

    while (!atEof) {
        DWORD read = 0;
        if (!ReadFile(local.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            SFTP_LOG("SFTP", "Upload: local read failed at %lld (%lu)",
                     static_cast<long long>(sent), GetLastError());
            ret = SFTP_READFAILED;
            break;
        }
        atEof = (read == 0);

        const char* data = buffer.data();
        size_t toWrite = read;
        if (textMode) {
            converted.clear();
            toWrite = atEof ? toLf.Finish(converted) : toLf.Convert(buffer.data(), read, converted);
            data = converted.data();
        }
        // A chunk can convert to nothing (a lone CR held for the next chunk);
        // it is still read input and counts towards progress below.
        size_t written = 0;
        while (written < toWrite) {
            int w = 0;
            if (useScp)
                w = static_cast<int>(scpHandle->write(data + written, toWrite - written));
            else
                w = static_cast<int>(sftpHandle->write(data + written, toWrite - written));

            if (w > 0) {
                written += static_cast<size_t>(w);
                lastProgress = std::chrono::steady_clock::now();
            } else if (w == LIBSSH2_ERROR_EAGAIN) {
                if (useScp) {
                    const auto now = std::chrono::steady_clock::now();
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastProgress).count();
                    if (elapsed > SFTP_SCP_WRITE_IDLE_TIMEOUT_MS) {
                        ShowStatusId(IDS_LOG_SCP_UL_TIMEOUT, nullptr, true);
                        ret = SFTP_WRITEFAILED;
                        break;
                    }
                }
                // libssh2 is often waiting to read here (a window adjust from
                // the server), not to write: wait for whichever it names.
                WaitForSshIo(cs);
            } else {
                SftpLogLastError("Upload write error: ", w);
                ret = SFTP_WRITEFAILED;
                break;
            }
        }

        if (ret != SFTP_OK) break;
        sent += read; // count original bytes for progress
        emitted += static_cast<int64_t>(written);
        if (UpdatePercentBar(cs, GetPercent(sent, filesize), LocalName, RemoteName)) {
            ret = SFTP_ABORT;
            break;
        }
    }

    // End of file is only a success when it falls where the file was measured
    // to end; anything else is a file that changed under the upload. For SCP
    // the converted byte count must also equal the size the header announced.
    if (ret == SFTP_OK && sent != filesize) {
        SFTP_LOG("SFTP", "Upload: sent %lld of %lld bytes",
                 static_cast<long long>(sent), static_cast<long long>(filesize));
        ret = SFTP_READFAILED;
    }
    if (ret == SFTP_OK && useScp && emitted != uploadSize) {
        SFTP_LOG("SCP", "Upload: emitted %lld bytes, header announced %lld",
                 static_cast<long long>(emitted), static_cast<long long>(uploadSize));
        ret = SFTP_READFAILED;
    }

    // scp's receiving side writes the file, then waits for a zero byte from
    // us and answers it; that answer is where a full disk or a quota shows.
    // The shell-driven path returned earlier and does its own handshake.
    if (ret == SFTP_OK && useScp) {
        std::string err;
        if (!ScpSendAck(scpHandle.get(), cs) || !ScpReadAck(scpHandle.get(), cs, err)) {
            SFTP_LOG("SCP", "Upload not acknowledged: %s", err.c_str());
            if (!err.empty())
                ShowStatus(err.c_str());
            ret = SFTP_WRITEFAILED;
        }
    }

    if (ret == SFTP_OK && setattr) {
        // Set timestamps/permissions
        // Only for SFTP transfers (SCP already set timestamps at open)
        // Guard: ensure sftpsession is available (might be null in SCP-only mode)
        if ((!useScp || cs->scponly) && cs->sftpsession != nullptr) {
            // For SFTP, use setstat; for SCP, timestamps were already set at open
            FILETIME ft;
            if (GetFileTime(local.get(), nullptr, nullptr, &ft)) {
                LIBSSH2_SFTP_ATTRIBUTES attr{};
                attr.flags = LIBSSH2_SFTP_ATTR_ACMODTIME | (setattr ? LIBSSH2_SFTP_ATTR_PERMISSIONS : 0);
                attr.mtime = GetUnixTime(&ft);
                attr.atime = attr.mtime;
                if (setattr) attr.permissions = cs->filemod;
                do {
                    int rc = cs->sftpsession->setstat(remotePath.c_str(), &attr);
                    if (rc != LIBSSH2_ERROR_EAGAIN) break;
                    IsSocketReadable(cs->sock);
                } while (true);
            }
        }
    }

    return ret;
}
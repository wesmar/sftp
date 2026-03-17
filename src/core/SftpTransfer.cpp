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
#include "UtfConversion.h"
#include "UnicodeHelpers.h"
#include "FtpDirectoryParser.h"
#include "SftpInternal.h"
#include "IUserFeedback.h"
#include "PhpAgentClient.h"
#include "ScpTransfer.h"
#include "ScpTransferInternal.h"
#include "TransferUtils.h"

namespace {

// TU-local derivations from shared constants (defined in ScpTransferInternal.h)
constexpr size_t SFTP_TEXT_READ_SIZE  = SFTP_MAX_READ_SIZE / 2;
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

// RAII wrapper for remote SFTP handle
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

// RAII wrapper for remote SCP channel
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
        auto wait = [&](auto fn, DWORD timeoutMs) {
            const auto start = std::chrono::steady_clock::now();
            int rc;
            do {
                rc = fn();
                if (rc != LIBSSH2_ERROR_EAGAIN)
                    return rc;
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed > timeoutMs)
                    break;
                IsSocketReadable(cs_->sock);
            } while (true);
            return rc;
        };
        wait([this] { return channel_->sendEof(); }, 1000);
        wait([this] { return channel_->waitEof(); }, 1000);
        wait([this] { return channel_->channelClose(); }, 1000);
        wait([this] { return channel_->channelFree(); }, 2000);
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
bool ResolveScpPolicy(pConnectSettings cs, int64_t filesize, bool resume, bool isDownload, bool& useScp)
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
                 int64_t& scpRemain, bool& lastWasCr)
{
    const size_t maxReadSize = SFTP_MAX_READ_SIZE * SFTP_PREFETCH_FACTOR;
    std::vector<char> buffer(maxReadSize);
    int blockSize = static_cast<int>(textMode ? SFTP_TEXT_READ_SIZE : maxReadSize);
    int ret = SFTP_OK;
    auto lastProgress = std::chrono::steady_clock::now();

    while (true) {
        int len = 0;
        if constexpr (std::is_same_v<Handle, RemoteScpChannel>) {
            if (scpRemain <= 0) break;
            len = static_cast<int>(remote.get()->read(buffer.data(), std::min<int64_t>(scpRemain, blockSize)));
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
            int writeLen = len;
            if (textMode) {
                writeLen = ConvertCrToCrLf(buffer.data(), static_cast<size_t>(len), &lastWasCr);
            }
            if (!WriteFile(local.get(), buffer.data(), static_cast<DWORD>(writeLen), &written, nullptr) ||
                written != static_cast<DWORD>(writeLen)) {
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
    if (!ResolveScpPolicy(cs, filesize, Resume, true, useScp))
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
            return ShellScpDownloadFile(cs, remotePath, RemoteName, local.get(), LocalName,
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
    bool lastWasCr = false;
    int ret = SFTP_OK;
    if (useScp) {
        RemoteScpChannel remoteScp(std::move(scpHandle), cs);
        ret = DownloadLoop(cs, remoteScp, local, RemoteName, LocalName,
                           textMode, filesize, loaded, scpRemain, lastWasCr);
    } else {
        RemoteSftpFile remoteSftp(std::move(sftpHandle));
        int64_t dummyRemain = 0; // not used for SFTP
        ret = DownloadLoop(cs, remoteSftp, local, RemoteName, LocalName,
                           textMode, filesize, loaded, dummyRemain, lastWasCr);
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

    if (!ResolveScpPolicy(cs, filesize, Resume, false, useScp))
        return SFTP_ABORT;

    ShowTransferStart(useScp, RemoteName, IDS_UPLOAD);

    std::string remotePath = ToRemotePathA(cs, RemoteName);
    bool textMode = (cs->unixlinebreaks == 1) && SftpDetermineTransferModeW(LocalName);

    if (forceShellFallback) {
        int64_t shellUploaded = 0;
        return ShellDdUploadFile(cs, remotePath, RemoteName,
                                 local.get(), LocalName, filesize, Resume ? 1 : 0, &shellUploaded);
    }

    if (!ReconnectSFTPChannelIfNeeded(cs))
        return SFTP_FAILED;

    if (useScp && !PrepareScpTransferSession(cs))
        return SFTP_FAILED;

    // For text mode, adjust filesize (approximate)
    int64_t uploadSize = filesize;
    if (textMode) {
        // Simple heuristic: count CRs
        std::array<char, SFTP_SCP_BLOCK_SIZE> buf{};
        DWORD read;
        int64_t crCount = 0;
        if (SetFilePointer(local.get(), 0, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
            while (ReadFile(local.get(), buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr) && read > 0) {
                for (DWORD i = 0; i < read; ++i) {
                    if (buf[i] == '\r')
                        ++crCount;
                    else if (buf[i] == 0) {
                        textMode = false; // binary detected
                        crCount = 0;
                        break;
                    }
                }
                if (!textMode) break;
            }
        }
        if (textMode)
            uploadSize = filesize - crCount;
        SetFilePointer(local.get(), 0, nullptr, FILE_BEGIN);
    }

    // Open remote
    std::unique_ptr<ISftpHandle> sftpHandle;
    std::unique_ptr<ISshChannel> scpHandle;
    int64_t resumeOffset = 0;

    if (useScp) {
        if (cs->scponly) {
            // Shell SCP upload
            return ShellScpUploadFile(cs, BuildScpPathArgument(remotePath), RemoteName,
                                      local.get(), LocalName, uploadSize, textMode, &filesize);
        } else {
            // Native SCP upload
            FILETIME ft;
            long mtime = 0;
            if (setattr && GetFileTime(local.get(), nullptr, nullptr, &ft))
                mtime = GetUnixTime(&ft);
            scpHandle = cs->session->scpSend64(remotePath.c_str(), cs->filemod,
                                               static_cast<uint64_t>(uploadSize), mtime, 0);
            if (!scpHandle) {
                SftpLogLastError("SCP upload error: ", cs->session->lastErrno());
                return SFTP_READFAILED;
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
            // Check if server actually returned size (some servers may not honor the flag)
            if (rc == 0 && (attr.flags & LIBSSH2_SFTP_ATTR_SIZE) && attr.filesize > 0) {
                 int64_t remoteSize = static_cast<int64_t>(attr.filesize);
                if (remoteSize <= filesize) {
                    sftpHandle->seek(static_cast<size_t>(remoteSize));
                    if (!local.Seek(remoteSize))
                        return SFTP_READFAILED;
                    resumeOffset = remoteSize;
                }
            }
        }
    }

    // Upload loop
    std::vector<char> buffer(SFTP_MAX_WRITE_SIZE * 32);
    int64_t sent = resumeOffset; // start from resume offset so progress bar is correct
    auto lastProgress = std::chrono::steady_clock::now();
    int ret = SFTP_OK;

    while (true) {
        DWORD read = 0;
        if (!ReadFile(local.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) || read == 0)
            break;

        int dataLen = static_cast<int>(read);
        char* data = buffer.data();
        if (textMode)
            dataLen = ConvertCrLfToCr(data, read);

        size_t toWrite = static_cast<size_t>(dataLen);
        size_t written = 0;
        while (written < toWrite) {
            int w = 0;
            if (useScp)
                w = static_cast<int>(scpHandle->write(data + written, toWrite - written));
            else
                w = static_cast<int>(sftpHandle->write(data + written, toWrite - written));

            if (w > 0) {
                written += w;
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
                IsSocketWritable(cs->sock);
            } else {
                SftpLogLastError("Upload write error: ", w);
                ret = SFTP_WRITEFAILED;
                break;
            }
        }

        sent += read; // count original bytes for progress
        if (UpdatePercentBar(cs, GetPercent(sent, filesize), LocalName, RemoteName)) {
            ret = SFTP_ABORT;
            break;
        }
        if (ret != SFTP_OK) break;
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
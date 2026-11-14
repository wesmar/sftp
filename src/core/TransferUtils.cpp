#include "global.h"
#include <windows.h>
#include <array>
#include <string>
#include <vector>
#include <algorithm>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"
#include "IUserFeedback.h"
#include "CoreUtils.h"
#include "UnicodeHelpers.h"
#include "TransferUtils.h"
#include "TextConversion.h"
#include "WildcardMatch.h"

namespace {
constexpr int SFTP_PROGRESS_ABORT_POLL_MS = 5000;

// RAII wrapper for SSH channel with explicit timeout-driven close. Provides
// EAGAIN-poll cleanup with cancellation support; destructor of bare
// Libssh2Channel only does a bounded tight-loop free without yielding.
class ScopedChannel {
public:
    explicit ScopedChannel(ISshChannel* channel, pConnectSettings cs) noexcept
        : channel_(channel), cs_(cs) {}

    ~ScopedChannel() {
        if (channel_)
            Close();
    }

    ScopedChannel(const ScopedChannel&) = delete;
    ScopedChannel& operator=(const ScopedChannel&) = delete;

    ScopedChannel(ScopedChannel&& other) noexcept
        : channel_(std::exchange(other.channel_, nullptr)),
          cs_(other.cs_) {}

    ISshChannel* get() const noexcept { return channel_; }
    ISshChannel* release() noexcept { return std::exchange(channel_, nullptr); }

private:
    void Close() noexcept {
        if (!channel_ || !cs_)
            return;

        WaitForOperation([this] { return channel_->sendEof(); }, 1000, cs_);
        WaitForOperation([this] { return channel_->waitEof(); }, 1000, cs_);
        WaitForOperation([this] { return channel_->channelClose(); }, 1000, cs_);
        // Explicit drained channelFree() — see class header comment.
        WaitForOperation([this] { return channel_->channelFree(); }, 2000, cs_);
        delete channel_;
    }

    ISshChannel* channel_;
    pConnectSettings cs_;
};

} // anonymous namespace

int GetPercent(int64_t offset, int64_t filesize)
{
    if (filesize <= 0)
        return 0;
    const int percent = static_cast<int>((offset * 100) / filesize);
    return std::clamp(percent, 0, 100);
}

bool IsValidFileHandle(HANDLE hf) noexcept
{
    return hf != nullptr && hf != INVALID_HANDLE_VALUE;
}

bool AskUserYesNo(pConnectSettings cs, LPCSTR title, LPCSTR message)
{
    if (cs && cs->feedback)
        return cs->feedback->AskYesNo(message ? message : "", title ? title : "SFTP");
    return RequestProc(PluginNumber, RT_MsgYesNo, title ? title : "SFTP", message ? message : "", nullptr, 0) != 0;
}

std::string ToRemotePathA(pConnectSettings cs, LPCWSTR pathW)
{
    std::array<char, wdirtypemax> tmp{};
    CopyStringW2A(cs, pathW, tmp.data(), tmp.size());
    ReplaceBackslashBySlash(tmp.data());
    return std::string(tmp.data());
}

std::string BuildShellScpArgument(const std::string& path)
{
    return "'" + string_util::ShellQuoteSingle(path) + "'";
}

bool SftpDetermineTransferModeW(LPCWSTR RemoteName)
{
    if (Global_TransferMode == 'A')
        return true;
    if (Global_TransferMode == 'I')
        return false;

    // Auto mode: check extension against Global_TextTypes
    std::wstring_view name(RemoteName);
    const auto slash = name.find_last_of(L"/\\");
    if (slash != std::wstring_view::npos)
        name.remove_prefix(slash + 1);

    return MultiFileMatchW(Global_TextTypes.data(), name.data());
}

bool MeasureTextUpload(HANDLE file, int64_t& convertedSize)
{
    convertedSize = 0;
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
        return false;

    text_conversion::CrLfToLf counter;
    std::vector<char> buf(256 * 1024);
    bool isText = true;
    for (;;) {
        DWORD got = 0;
        // A read error is reported by the upload's own read; sending the file
        // unconverted keeps the announced size equal to what is read.
        if (!ReadFile(file, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr)) {
            isText = false;
            break;
        }
        if (got == 0)
            break;
        if (std::find(buf.data(), buf.data() + got, '\0') != buf.data() + got) {
            isText = false;
            break;
        }
        convertedSize += static_cast<int64_t>(counter.Count(buf.data(), got));
    }
    convertedSize += static_cast<int64_t>(counter.FinishCount());
    SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
    return isText;
}

int CloseRemote(pConnectSettings cs, ISftpHandle* remotefilesftp,
                ISshChannel* remotefilescp, bool timeout, int percent)
{
    if (remotefilesftp) {
        // SFTP handle close
        const SYSTICKS start = get_sys_ticks();
        while (LIBSSH2_ERROR_EAGAIN == remotefilesftp->close()) {
            if (timeout && UpdatePercentBar(cs, percent))
                return SFTP_ABORT;
            if (get_ticks_between(start) > SFTP_PROGRESS_ABORT_POLL_MS)
                break;
            IsSocketReadable(cs->sock);
        }
    } else if (remotefilescp) {
        // SCP channel – use ScopedChannel for RAII
        ScopedChannel closer(remotefilescp, cs);
        // Channel will be closed in destructor
    }
    return SFTP_OK;
}

int CheckInputOrTimeout(pConnectSettings ConnectSettings, bool timeout, SYSTICKS starttime, int percent)
{
    if (UpdatePercentBar(ConnectSettings, percent))
        return SFTP_ABORT;
    if (timeout && get_ticks_between(starttime) > SFTP_PROGRESS_ABORT_POLL_MS)
        return SFTP_FAILED;
    return SFTP_OK;
}

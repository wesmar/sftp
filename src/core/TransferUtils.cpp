#include "global.h"
#include <windows.h>
#include <array>
#include <string>
#include <algorithm>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"
#include "IUserFeedback.h"
#include "CoreUtils.h"
#include "UtfConversion.h"
#include "UnicodeHelpers.h"
#include "TransferUtils.h"

namespace {
constexpr int SFTP_PROGRESS_ABORT_POLL_MS = 5000;

// RAII wrapper for SSH channel with automatic timeout handling
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

        auto wait = [&](auto fn, DWORD timeoutMs) {
            const SYSTICKS start = get_sys_ticks();
            int rc;
            do {
                rc = fn();
                if (rc != LIBSSH2_ERROR_EAGAIN)
                    return rc;
                if (EscapePressed() || get_ticks_between(start) > static_cast<int>(timeoutMs))
                    break;
                Sleep(25);
            } while (true);
            return rc;
        };

        wait([&] { return channel_->sendEof(); }, 1000);
        wait([&] { return channel_->waitEof(); }, 1000);
        wait([&] { return channel_->channelClose(); }, 1000);
        wait([&] { return channel_->channelFree(); }, 2000);
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

int ConvertCrToCrLf(LPSTR data, size_t len, bool* pLastWasCr)
{
    if (!data || !pLastWasCr)
        return 0;

    bool lastWasCr = *pLastWasCr;
    std::string result;
    result.reserve(len + len / 2); // worst case expansion

    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        if (c == '\r') {
            lastWasCr = true;
            result.push_back('\r');
        } else if (c == '\n') {
            if (!lastWasCr)
                result.push_back('\r');
            result.push_back('\n');
            lastWasCr = false;
        } else {
            lastWasCr = false;
            result.push_back(c);
        }
    }

    *pLastWasCr = lastWasCr;
    memcpy(data, result.data(), result.size());
    return static_cast<int>(result.size());
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

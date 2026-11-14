#include "global.h"
#include <windows.h>
#include <array>
#include <string>
#include <string_view>
#include <cctype>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"
#include "res/resource.h"

static void ToUpperInPlace(char* s) noexcept
{
    for (; *s; ++s)
        *s = (char)std::toupper((unsigned char)*s);
}

static void SaveAutoDetectResult(pConnectSettings cs, const char* key, int value)
{
    if (cs->DisplayName != s_quickconnect)
        WritePrivateProfileString(cs->DisplayName.c_str(), key, value ? "1" : "0", cs->IniFileName.c_str());
}

int SftpSessionDetectUtf8(pConnectSettings ConnectSettings)
{
    std::array<char, 8192> reply{};
    int hr = 0;

    reply[0] = 0;
    if (SftpQuoteCommand2(ConnectSettings, nullptr, "echo $LC_ALL $LC_CTYPE $LANG", reply.data(), reply.size()-1, 3000, 8000) == 0) {
        ToUpperInPlace(reply.data());
        const bool noLocaleVars = reply.data()[strspn(reply.data(), " \t\r\n")] == 0;
        if (strstr(reply.data(), "UTF-8")) {
            hr = AUTODETECT_ON;
        } else {
            reply[0] = 0;
            const int localeRc = SftpQuoteCommand2(ConnectSettings, nullptr, "locale", reply.data(), reply.size()-1, 3000, 8000);
            if (localeRc == 0) {
                ToUpperInPlace(reply.data());
                if (strstr(reply.data(), "UTF-8"))
                    hr = AUTODETECT_ON;
            } else if (noLocaleVars) {
                // No locale variable and no `locale` command — busybox on a
                // camera or a router. Such a system names files in bytes and
                // has no codepage of its own to suggest; UTF-8 is what its
                // other clients write, where the Windows codepage would leave
                // names nothing on the device can read.
                hr = AUTODETECT_ON;
            }
        }
    }
    SaveAutoDetectResult(ConnectSettings, "utf8", hr);
    return hr;
}

int SftpSessionDetectLineBreaks(pConnectSettings ConnectSettings)
{
    std::array<char, 8192> reply{};
    int hr = 0;

    reply[0] = 0;
    if (SftpQuoteCommand2(ConnectSettings, nullptr, "echo $OSTYPE", reply.data(), reply.size()-1, 3000, 8000) == 0) {
        ToUpperInPlace(reply.data());
        if (strstr(reply.data(), "LINUX") || strstr(reply.data(), "UNIX") || strstr(reply.data(), "AIX")) {
            hr = AUTODETECT_ON;
        } else {
            global_detectcrlf = -1;
            reply[0] = 0;
            if (SftpQuoteCommand2(ConnectSettings, nullptr, "ls -l", reply.data(), reply.size()-1, 3000, 8000) == 0) {
                if (global_detectcrlf == 0)
                    hr = 1;
            }
        }
    }
    SaveAutoDetectResult(ConnectSettings, "unixlinebreaks", hr);
    return hr;
}

namespace {

// Shows one chunk of the command's output as a status line, without the
// surrounding whitespace. Bytes above 0x7F belong to UTF-8 text and stay.
void ShowCommandOutput(std::string_view text)
{
    const auto isSpace = [](char c) { return static_cast<unsigned char>(c) <= ' '; };
    while (!text.empty() && isSpace(text.front()))
        text.remove_prefix(1);
    while (!text.empty() && isSpace(text.back()))
        text.remove_suffix(1);
    if (!text.empty())
        ShowStatus(std::string(text).c_str());
}

// Runs the profile's post-login command: in a shell whose output is shown
// until it ends (modes 0 and 1; mode 0 also closes the shell), or as an exec
// request that is not waited for (mode 2).
void SendUserCommand(pConnectSettings ConnectSettings, LPCSTR progressText, int progress, int* ploop, SYSTICKS* plasttime)
{
    auto channel = ConnectChannel(ConnectSettings->session.get(), ConnectSettings->sock);
    SftpLogLastError("ConnectChannel: ", ConnectSettings->session->lastErrno());
    if (!channel)
        return;

    if (ConnectSettings->sendcommandmode <= 1) {
        if (SendChannelCommand(ConnectSettings->session.get(), channel.get(),
                               ConnectSettings->connectsendcommand.c_str(), ConnectSettings->sock)) {
            std::array<char, 1024> chunk{};
            while (!channel->eof()) {
                if (ProgressLoop(progressText, progress, progress + 10, ploop, plasttime))
                    break;
                const auto errLen = channel->readStderr(chunk.data(), chunk.size());
                if (errLen > 0)
                    ShowCommandOutput({ chunk.data(), static_cast<size_t>(errLen) });
                if (channel->eof())
                    break;
                const auto outLen = channel->read(chunk.data(), chunk.size());
                if (outLen > 0)
                    ShowCommandOutput({ chunk.data(), static_cast<size_t>(outLen) });
            }
        }
        if (ConnectSettings->sendcommandmode == 0)
            DisconnectShell(channel.get());
        return;
    }

    for (;;) {
        int rc = channel->exec(ConnectSettings->connectsendcommand.c_str());
        if (rc >= 0)
            break;
        if (rc == -1)
            rc = ConnectSettings->session->lastErrno();
        if (rc != LIBSSH2_ERROR_EAGAIN || EscapePressed())
            break;
    }
}

} // namespace
void RunPostAuthAutoDetect(pConnectSettings ConnectSettings)
{
    SFTP_LOG("CONN", "Post-auth init start: scponly=%d scpfordata=%d utf8=%d unixlinebreaks=%d large=%d",
             ConnectSettings->scponly ? 1 : 0,
             ConnectSettings->scpfordata ? 1 : 0,
             ConnectSettings->utf8names,
             ConnectSettings->unixlinebreaks,
             ConnectSettings->scpserver64bit);

    // Shell-only sessions skip the other probes, but not this one: every
    // file name they send goes through the shell in this encoding, and
    // leaving it undecided meant the Windows codepage, unreadable on the
    // server.
    if (ConnectSettings->utf8names == AUTODETECT_PENDING) {
        ShowStatusId(IDS_LOG_DETECT_UTF8, nullptr, true);
        ConnectSettings->codepage = 0;
        ConnectSettings->utf8names = AUTODETECT_OFF;
        int rc = SftpSessionDetectUtf8(ConnectSettings);
        ConnectSettings->utf8names = (rc == AUTODETECT_ON) ? AUTODETECT_ON : AUTODETECT_OFF;
    }
    if (ConnectSettings->scponly)
        return;
    if (ConnectSettings->unixlinebreaks == AUTODETECT_PENDING) {
        ShowStatusId(IDS_LOG_DETECT_LINEBREAK, nullptr, true);
        ConnectSettings->unixlinebreaks = AUTODETECT_OFF;
        int rc = SftpSessionDetectLineBreaks(ConnectSettings);
        ConnectSettings->unixlinebreaks = (rc == AUTODETECT_ON) ? AUTODETECT_ON : AUTODETECT_OFF;
    }
}

void RunPostAuthUserCommand(pConnectSettings ConnectSettings, LPCSTR progressText, int progress, int* loop, SYSTICKS* lasttime)
{
    if (ConnectSettings->scponly || ConnectSettings->connectsendcommand.empty())
        return;

    ShowStatusId(IDS_LOG_USER_COMMAND, nullptr, true);
    ShowStatus(ConnectSettings->connectsendcommand.c_str());
    SendUserCommand(ConnectSettings, progressText, progress, loop, lasttime);

    static constexpr int kPostCommandPollIterations = 10;
    static constexpr int kPostCommandPollSleepMs = 100;
    for (int wait = 0; wait < kPostCommandPollIterations && !EscapePressed(); wait++) {
        ProgressLoop(progressText, progress, progress + 5, loop, lasttime);
        Sleep(kPostCommandPollSleepMs);
    }
}

void ResolveScpLargeFileProbe(pConnectSettings ConnectSettings)
{
    if (ConnectSettings->scponly && ConnectSettings->scpserver64bit == AUTODETECT_PENDING) {
        ConnectSettings->scpserver64bit = AUTODETECT_OFF;
        SFTP_LOG("CONN", "SCP-only: forcing largefilesupport=0, skipping 'which scp' probe");
        if (ConnectSettings->DisplayName != s_quickconnect)
            WritePrivateProfileString(ConnectSettings->DisplayName.c_str(), "largefilesupport", "0", ConnectSettings->IniFileName.c_str());
        return;
    }

    if (!(ConnectSettings->scpfordata && ConnectSettings->scpserver64bit == AUTODETECT_PENDING))
        return;

    ConnectSettings->scpserver64bit = AUTODETECT_OFF;
    SFTP_LOG("CONN", "SCP data mode: probing scp binary architecture");
    std::array<char, 8192> reply{};
    reply[0] = 0;
    if (SftpQuoteCommand2(ConnectSettings, nullptr, "file `which scp`", reply.data(), reply.size()-1) == 0) {
        ToUpperInPlace(reply.data());
        if (strstr(reply.data(), "64-BIT")) {
            ShowStatusId(IDS_LOG_SCP64, nullptr, true);
            ConnectSettings->scpserver64bit = 1;
        }
    }
    if (ConnectSettings->DisplayName != s_quickconnect)
        WritePrivateProfileString(ConnectSettings->DisplayName.c_str(), "largefilesupport",
                                  ConnectSettings->scpserver64bit ? "1" : "0",
                                  ConnectSettings->IniFileName.c_str());
}

#include "global.h"
#include <windows.h>
#include <array>
#include <string>
#include <cctype>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"

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
    if (SftpQuoteCommand2(ConnectSettings, nullptr, "echo $LC_ALL $LC_CTYPE $LANG", reply.data(), reply.size()-1) == 0) {
        ToUpperInPlace(reply.data());
        if (strstr(reply.data(), "UTF-8")) {
            hr = AUTODETECT_ON;
        } else {
            reply[0] = 0;
            if (SftpQuoteCommand2(ConnectSettings, nullptr, "locale", reply.data(), reply.size()-1) == 0) {
                ToUpperInPlace(reply.data());
                if (strstr(reply.data(), "UTF-8"))
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
    if (SftpQuoteCommand2(ConnectSettings, nullptr, "echo $OSTYPE", reply.data(), reply.size()-1) == 0) {
        ToUpperInPlace(reply.data());
        if (strstr(reply.data(), "LINUX") || strstr(reply.data(), "UNIX") || strstr(reply.data(), "AIX")) {
            hr = AUTODETECT_ON;
        } else {
            global_detectcrlf = -1;
            reply[0] = 0;
            if (SftpQuoteCommand2(ConnectSettings, nullptr, "ls -l", reply.data(), reply.size()-1) == 0) {
                if (global_detectcrlf == 0)
                    hr = 1;
            }
        }
    }
    SaveAutoDetectResult(ConnectSettings, "unixlinebreaks", hr);
    return hr;
}

int SftpSessionSendCommand(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int* ploop, SYSTICKS* plasttime)
{
    std::array<char, 1024> buf{};
    auto channel = ConnectChannel(ConnectSettings->session.get(), ConnectSettings->sock);
    SftpLogLastError("ConnectChannel: ", ConnectSettings->session->lastErrno());
    if (!channel)
        return -1;
    if (ConnectSettings->sendcommandmode <= 1) {
        if (SendChannelCommand(ConnectSettings->session.get(), channel.get(), ConnectSettings->connectsendcommand.c_str(), ConnectSettings->sock)) {
            while (!channel->eof()) {
                if (ProgressLoop(buf.data(), progress, progress + 10, ploop, plasttime))
                    break;
                std::array<char, 1024> databuf{};
                char* p = nullptr;
                char* p2 = nullptr;
                databuf[0] = 0;
                if (0 < channel->readStderr(databuf.data(), databuf.size()-1)) {
                    p = databuf.data();
                    while (p[0] > 0 && p[0] <= ' ')
                        p++;
                    if (p[0]) {
                        p2 = p + strlen(p) - 1;
                        while (p2[0] <= ' ' && p2 >= p) {
                            p2[0] = 0;
                            p2--;
                        }
                    }
                    if (p[0])
                        ShowStatus(databuf.data());
                }
                databuf[0] = 0;
                if (channel->eof())
                    break;
                if (0 < channel->read(databuf.data(), databuf.size()-1)) {
                    p = databuf.data();
                    while (p[0] > 0 && p[0] <= ' ')
                        p++;
                    if (p[0]) {
                        p2 = p + strlen(p) - 1;
                        while (p2[0] <= ' ' && p2 >= p) {
                            p2[0] = 0;
                            p2--;
                        }
                    }
                    if (p[0])
                        ShowStatus(databuf.data());
                }
            }
        }
        if (ConnectSettings->sendcommandmode == 0)
            DisconnectShell(channel.get());
        return 0;
    }
    int rc = -1;
    do {
        rc = channel->exec(ConnectSettings->connectsendcommand.c_str());
        if (rc < 0) {
            if (rc == -1)
                rc = ConnectSettings->session->lastErrno();
            if (rc != LIBSSH2_ERROR_EAGAIN)
                break;
        }
        if (EscapePressed())
            break;
    } while (rc < 0);

    return 0;
}

void RunPostAuthAutoDetect(pConnectSettings ConnectSettings)
{
    if (ConnectSettings->scponly && ConnectSettings->utf8names < 0)
        ConnectSettings->utf8names = AUTODETECT_OFF;

    SFTP_LOG("CONN", "Post-auth init start: scponly=%d scpfordata=%d utf8=%d unixlinebreaks=%d large=%d",
             ConnectSettings->scponly ? 1 : 0,
             ConnectSettings->scpfordata ? 1 : 0,
             ConnectSettings->utf8names,
             ConnectSettings->unixlinebreaks,
             ConnectSettings->scpserver64bit);

    if (ConnectSettings->scponly)
        return;

    if (ConnectSettings->utf8names == AUTODETECT_PENDING) {
        ShowStatus("Auto-detecting UTF-8 support...");
        ConnectSettings->codepage = 0;
        ConnectSettings->utf8names = AUTODETECT_OFF;
        int rc = SftpSessionDetectUtf8(ConnectSettings);
        ConnectSettings->utf8names = (rc == AUTODETECT_ON) ? AUTODETECT_ON : AUTODETECT_OFF;
    }
    if (ConnectSettings->unixlinebreaks == AUTODETECT_PENDING) {
        ShowStatus("Auto-detecting line break mode...");
        ConnectSettings->unixlinebreaks = AUTODETECT_OFF;
        int rc = SftpSessionDetectLineBreaks(ConnectSettings);
        ConnectSettings->unixlinebreaks = (rc == AUTODETECT_ON) ? AUTODETECT_ON : AUTODETECT_OFF;
    }
}

void RunPostAuthUserCommand(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int* loop, SYSTICKS* lasttime)
{
    if (ConnectSettings->scponly || ConnectSettings->connectsendcommand.empty())
        return;

    ShowStatus("Sending user-defined command:");
    ShowStatus(ConnectSettings->connectsendcommand.c_str());
    SftpSessionSendCommand(ConnectSettings, progressbuf, progress, loop, lasttime);

    static constexpr int kPostCommandPollIterations = 10;
    static constexpr int kPostCommandPollSleepMs = 100;
    for (int wait = 0; wait < kPostCommandPollIterations && !EscapePressed(); wait++) {
        ProgressLoop(progressbuf, progress, progress + 5, loop, lasttime);
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
            ShowStatus("64-bit scp detected!");
            ConnectSettings->scpserver64bit = 1;
        }
    }
    if (ConnectSettings->DisplayName != s_quickconnect)
        WritePrivateProfileString(ConnectSettings->DisplayName.c_str(), "largefilesupport",
                                  ConnectSettings->scpserver64bit ? "1" : "0",
                                  ConnectSettings->IniFileName.c_str());
}

#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <chrono>
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
#include "PhpAgentClient.h"

namespace {

constexpr const char* kScpListBeginMarker = "__WFX_LIST_BEGIN__";
constexpr const char* kScpListEndMarker = "__WFX_LIST_END__";
constexpr uint32_t kScpDataMagic = 0x53435044u; // 'SCPD'
constexpr int kScpWriteTimeoutMs = 15000;
constexpr int kScpReadTimeoutMs = 30000;
constexpr int kScpDeleteReadTimeoutMs = 15000;
constexpr int kSftpProgressStartMs = 2000;
constexpr int kSftpAbortGraceMs = 2000;
constexpr int kSftpProgressDivMs = 200;

struct ScpListState {
    std::vector<WIN32_FIND_DATAW> entries;
    size_t nextIndex = 0;
};

struct ScpData {
    uint32_t magic;
    std::unique_ptr<ISshChannel> channel;
    std::array<char, 2048> msgbuf;
    std::array<char, 2048> errbuf;
    std::unique_ptr<ScpListState> listingState;
};

ScpData* AsScpData(LPVOID data) noexcept
{
    if (!data) return nullptr;
    ScpData* scpd = static_cast<ScpData*>(data);
    return (scpd->magic == kScpDataMagic) ? scpd : nullptr;
}

// Parse SCP listing line into WIN32_FIND_DATAW
bool ParseScpListingLine(pConnectSettings cs, const char* line, WIN32_FIND_DATAW& outData)
{
    if (!cs || !line || !line[0])
        return false;

    // Work on a copy
    std::string lineStr(line);
    // Trim leading spaces
    size_t start = lineStr.find_first_not_of(" \t");
    if (start == std::string::npos)
        return false;
    lineStr = lineStr.substr(start);
    if (lineStr.empty())
        return false;

    const char c0 = lineStr[0];
    if (!(c0 == '-' || c0 == 'd' || c0 == 'l' || c0 == 'b' || c0 == 'c' || c0 == 'p' || c0 == 's'))
        return false;

    // Tokenize by spaces
    std::vector<std::string> tokens;
    size_t pos = 0;
    while (pos < lineStr.size()) {
        while (pos < lineStr.size() && (lineStr[pos] == ' ' || lineStr[pos] == '\t'))
            ++pos;
        if (pos >= lineStr.size())
            break;
        size_t tokStart = pos;
        while (pos < lineStr.size() && lineStr[pos] != ' ' && lineStr[pos] != '\t')
            ++pos;
        tokens.push_back(lineStr.substr(tokStart, pos - tokStart));
    }

    if (tokens.size() < 9)
        return false;

    // Find name start: after 8 tokens
    size_t namePos = 0;
    int tokCount = 0;
    pos = 0;
    while (tokCount < 8 && pos < lineStr.size()) {
        while (pos < lineStr.size() && (lineStr[pos] == ' ' || lineStr[pos] == '\t'))
            ++pos;
        if (pos >= lineStr.size())
            break;
        while (pos < lineStr.size() && lineStr[pos] != ' ' && lineStr[pos] != '\t')
            ++pos;
        ++tokCount;
    }
    while (pos < lineStr.size() && (lineStr[pos] == ' ' || lineStr[pos] == '\t'))
        ++pos;
    if (pos >= lineStr.size())
        return false;
    std::string name = lineStr.substr(pos);
    // Trim trailing whitespace
    while (!name.empty() && (name.back() == ' ' || name.back() == '\t' || name.back() == '\r' || name.back() == '\n'))
        name.pop_back();
    // Remove symlink arrow
    size_t arrow = name.find(" -> ");
    if (arrow != std::string::npos)
        name.resize(arrow);
    if (name.empty())
        return false;

    WIN32_FIND_DATAW fd{};
    CopyStringA2W(cs, name.c_str(), fd.cFileName, _countof(fd.cFileName));
    if (!fd.cFileName[0])
        return false;

    fd.dwFileAttributes = (c0 == 'd') ? FILE_ATTRIBUTE_DIRECTORY : 0;
    if (c0 == 'l') {
        fd.dwFileAttributes |= FS_ATTR_UNIXMODE;
        fd.dwReserved0 = LIBSSH2_SFTP_S_IFLNK | 0555;
    }

    if (fd.dwFileAttributes == 0 && tokens.size() > 4) {
        unsigned long long sz = _strtoui64(tokens[4].c_str(), nullptr, 10);
        fd.nFileSizeHigh = static_cast<DWORD>(sz >> 32);
        fd.nFileSizeLow = static_cast<DWORD>(sz & 0xFFFFFFFFULL);
    }

    outData = fd;
    return true;
}

} // anonymous namespace

int SftpFindFirstFileW(pConnectSettings cs, LPCWSTR remotedir, LPVOID* davdataptr)
{
    {
        std::array<char, wdirtypemax> statusBuf{};
        LoadStr(statusBuf, IDS_GET_DIR);
        size_t len = strlen(statusBuf.data());
        if (len < statusBuf.size() - 1)
            walcopy(statusBuf.data() + len, remotedir, static_cast<int>(statusBuf.size() - len - 1));
        ShowStatus(statusBuf.data());
    }

    for (int i = 0; i < 10; ++i) {
        if (EscapePressed())
            Sleep(100);
    }

    std::string dirStr(wdirtypemax, '\0');
    CopyStringW2A(cs, remotedir, dirStr.data(), dirStr.size());
    dirStr.resize(strlen(dirStr.c_str()));
    std::replace(dirStr.begin(), dirStr.end(), '\\', '/');
    if (dirStr.size() > 1 && dirStr.back() != '/')
        dirStr += '/';

    if (IsPhpAgentTransport(cs)) {
        std::vector<WIN32_FIND_DATAW> entries;
        int rc = PhpAgentListDirectoryW(cs, remotedir, entries);
        if (rc != SFTP_OK)
            return rc;

        auto scpd = std::make_unique<ScpData>();
        scpd->magic = kScpDataMagic;
        auto state = std::make_unique<ScpListState>();
        state->entries = std::move(entries);
        scpd->listingState = std::move(state);
        *davdataptr = scpd.release();
        wcslcpy(cs->lastactivepath, remotedir, _countof(cs->lastactivepath) - 1);
        return SFTP_OK;
    }

if (cs->scponly) {
        // Retry loop in case of silent TCP disconnections (e.g., home.pl)
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (!EnsureScpShell(cs)) {
                bool sockLost = (cs->sock == INVALID_SOCKET) || IsSocketError(cs->sock);
                int sessErr = cs->session ? cs->session->lastErrno() : -1;
                if (sockLost || sessErr == LIBSSH2_ERROR_SOCKET_DISCONNECT ||
                    sessErr == LIBSSH2_ERROR_SOCKET_SEND || sessErr == LIBSSH2_ERROR_SOCKET_RECV) {
                    ShowStatus("SCP: session lost, reconnecting...");
                    SftpCloseConnection(cs);
                    Sleep(RECONNECT_SLEEP_MS);
                    if (SftpConnect(cs) != SFTP_OK || !EnsureScpShell(cs)) {
                        if (attempt == 1) { // If this is your second attempt, give up
                            ShowStatus("SCP listing: no shell");
                            return SFTP_FAILED;
                        }
                        continue; // Try again
                    }
                } else {
                    ShowStatus("SCP listing: no shell");
                    return SFTP_FAILED;
                }
            }

            ISshChannel* channel = cs->scpShellChannel.get();
            if (!channel) {
                ShowStatus("SCP listing: no shell");
                return SFTP_FAILED;
            }

            cs->scpShellMsgBuf[0] = 0;
            cs->scpShellErrBuf[0] = 0;

            std::string listTarget = dirStr;
            if (!listTarget.empty() && listTarget[0] == '/')
                listTarget = (listTarget.size() == 1) ? "." : listTarget.substr(1);

            static unsigned scpListSeq = 1;
            const unsigned markerSeq = scpListSeq++;
            std::string beginMarker = std::string(kScpListBeginMarker) + "_" + std::to_string(markerSeq);
            std::string endMarker   = std::string(kScpListEndMarker)   + "_" + std::to_string(markerSeq);

            std::string command = "echo \"" + beginMarker + "\"; ls -la '" + string_util::ShellQuoteSingle(listTarget) +
                                  "'; echo \"" + endMarker + "\":$?\n";

            // Write command
            bool writeFailed = false;
            {
                const auto writeStart = std::chrono::steady_clock::now();
                size_t written = 0;
                while (written < command.size()) {
                    int rc = static_cast<int>(channel->write(command.data() + written, command.size() - written));
                    if (rc > 0) {
                        written += rc;
                        continue;
                    }
                    if (rc != LIBSSH2_ERROR_EAGAIN) {
                        writeFailed = true;
                        break;
                    }
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - writeStart).count();
                    if (elapsed > kScpWriteTimeoutMs) {
                        writeFailed = true;
                        break;
                    }
                    IsSocketReadable(cs->sock);
                }
            }

            // Instead of immediately throwing an error, we force a restart on the next iteration.
            if (writeFailed) {
                CloseScpShell(cs);
                if (attempt == 0) {
                    cs->sock = INVALID_SOCKET; // Simulate socket loss
                    continue;
                }
                return SFTP_FAILED;
            }

            std::vector<std::string> lines;
            bool gotEnd = ScpReadCommandOutput(cs, endMarker.c_str(), lines, kScpReadTimeoutMs, beginMarker.c_str());

            std::vector<WIN32_FIND_DATAW> entries;
            for (const auto& line : lines) {
                if (line.empty() || _strnicmp(line.c_str(), "total ", 6) == 0)
                    continue;
                WIN32_FIND_DATAW fd{};
                if (ParseScpListingLine(cs, line.c_str(), fd)) {
                    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                        continue;
                    entries.push_back(fd);
                }
            }

            if (!gotEnd && entries.empty()) {
                if (cs->scpShellErrBuf[0]) {
                    std::array<char, sizeof(cs->scpShellErrBuf)> err{};
                    strlcpy(err.data(), cs->scpShellErrBuf, err.size() - 1);
                    StripEscapeSequences(err.data());
                    ShowStatus(err.data());
                } else {
                    ShowStatus("SCP listing failed: no output or timeout.");
                }
                CloseScpShell(cs);

                // Instead of immediately throwing an error, try reconnecting.
                if (attempt == 0) {
                    cs->sock = INVALID_SOCKET;
                    continue;
                }
                return SFTP_FAILED;
            }

            auto scpd = std::make_unique<ScpData>();
            scpd->magic = kScpDataMagic;
            auto state = std::make_unique<ScpListState>();
            state->entries = std::move(entries);
            scpd->listingState = std::move(state);
            *davdataptr = scpd.release();
            wcslcpy(cs->lastactivepath, remotedir, _countof(cs->lastactivepath) - 1);
            
            return SFTP_OK;
        }
    }

    if (!ReconnectSFTPChannelIfNeeded(cs))
        return SFTP_FAILED;

    cs->findstarttime = get_sys_ticks();
    SYSTICKS aborttime = -1;
    int retrycount = 3;
    std::unique_ptr<ISftpHandle> dirhandle;

    do {
        dirhandle = cs->sftpsession->openDir(dirStr.c_str());
        if (dirhandle)
            break;

        int err = cs->session->lastErrno();
        if (err != LIBSSH2_ERROR_EAGAIN) {
            if (err == LIBSSH2_FX_EOF || err == LIBSSH2_FX_FAILURE ||
                err == LIBSSH2_FX_BAD_MESSAGE || err == LIBSSH2_FX_NO_CONNECTION ||
                err == LIBSSH2_FX_CONNECTION_LOST || err < 0) {
                --retrycount;
                if (retrycount <= 0)
                    break;
                cs->neednewchannel = true;
                if (!ReconnectSFTPChannelIfNeeded(cs))
                    return SFTP_FAILED;
            }
        } else {
            IsSocketReadable(cs->sock);
        }

        Sleep(50);
        int delta = get_ticks_between(cs->findstarttime);
        if (delta > kSftpProgressStartMs && aborttime == -1) {
            if (ProgressProc(PluginNumber, dirStr.c_str(), "temp", (delta / kSftpProgressDivMs) % 100))
                aborttime = get_sys_ticks() + kSftpAbortGraceMs;
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            cs->neednewchannel = true;
            break;
        }
    } while (!dirhandle);

    if (!dirhandle) {
        char* errmsg = nullptr;
        int errmsg_len = 0;
        cs->session->lastError(&errmsg, &errmsg_len, false);
        std::string msg = "Directory not opened: ";
        if (errmsg) msg += errmsg;
        ShowStatus(msg.c_str());
        return SFTP_FAILED;
    }

    *davdataptr = dirhandle.release();
    wcslcpy(cs->lastactivepath, remotedir, _countof(cs->lastactivepath) - 1);
    return SFTP_OK;
}

int SftpFindNextFileW(pConnectSettings cs, LPVOID davdataptr, LPWIN32_FIND_DATAW FindData) noexcept
{
    ScpData* scpd = AsScpData(davdataptr);
    if (scpd && scpd->listingState) {
        if (scpd->listingState->nextIndex >= scpd->listingState->entries.size())
            return SFTP_FAILED;
        *FindData = scpd->listingState->entries[scpd->listingState->nextIndex++];
        return SFTP_OK;
    }

    ISftpHandle* dirhandle = static_cast<ISftpHandle*>(davdataptr);
    if (!dirhandle)
        return SFTP_FAILED;

    std::array<char, 512> name{};
    std::array<char, 2048> longentry{};
    LIBSSH2_SFTP_ATTRIBUTES file{};
    SYSTICKS aborttime = -1;

    int rc;
    while ((rc = dirhandle->readdir(name.data(), name.size(),
                                     longentry.data(), longentry.size(), &file)) == LIBSSH2_ERROR_EAGAIN) {
        int delta = get_ticks_between(cs->findstarttime);
        if (delta > kSftpProgressStartMs && aborttime == -1) {
            if (ProgressProc(PluginNumber, "dir", "temp", (delta / kSftpProgressDivMs) % 100))
                aborttime = get_sys_ticks() + kSftpAbortGraceMs;
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            cs->neednewchannel = true;
            break;
        }
        IsSocketReadable(cs->sock);
    }

    if (rc > 0) {
        if (cs->detailedlog && longentry[0])
            ShowStatus(longentry.data());

        FindData->dwFileAttributes = 0;
        CopyStringA2W(cs, name.data(), FindData->cFileName, _countof(FindData->cFileName));
        if (file.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
            if ((file.permissions & S_IFMT) == S_IFDIR)
                FindData->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        } else if (longentry[0] == 'd') {
            FindData->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        }

        FindData->cAlternateFileName[0] = 0;
        FindData->ftCreationTime.dwHighDateTime = 0;
        FindData->ftCreationTime.dwLowDateTime = 0;
        FindData->ftLastAccessTime.dwHighDateTime = 0;
        FindData->ftLastAccessTime.dwLowDateTime = 0;

        if (file.flags & LIBSSH2_SFTP_ATTR_SIZE && FindData->dwFileAttributes == 0) {
            FindData->nFileSizeHigh = static_cast<DWORD>(file.filesize >> 32);
            FindData->nFileSizeLow = static_cast<DWORD>(file.filesize);
        } else {
            FindData->nFileSizeHigh = 0;
            FindData->nFileSizeLow = 0;
        }

        if (file.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
            ConvUnixTimeToFileTime(&FindData->ftLastWriteTime, file.mtime);
        }

        if (file.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
            FindData->dwFileAttributes |= 0x80000000;
            FindData->dwReserved0 = file.permissions & 0xFFFF;
        }
        return SFTP_OK;
    }
    return SFTP_FAILED;
}

int SftpFindClose(pConnectSettings cs, LPVOID davdataptr)
{
    ScpData* scpd = AsScpData(davdataptr);
    if (scpd) {
        delete scpd;
        return SFTP_OK;
    }

    ISftpHandle* dirhandle = static_cast<ISftpHandle*>(davdataptr);
    if (!dirhandle)
        return SFTP_FAILED;

    if (!cs) {
        delete dirhandle;
        return SFTP_OK;
    }

    SYSTICKS aborttime = -1;
    while (dirhandle->close() == LIBSSH2_ERROR_EAGAIN) {
        int delta = get_ticks_between(cs->findstarttime);
        if (delta > kSftpProgressStartMs && aborttime == -1) {
            if (ProgressProc(PluginNumber, "close dir", "temp", (delta / kSftpProgressDivMs) % 100))
                aborttime = get_sys_ticks() + kSftpAbortGraceMs;
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            cs->neednewchannel = true;
            break;
        }
        IsSocketReadable(cs->sock);
    }
    delete dirhandle;
    return SFTP_OK;
}

int SftpCreateDirectoryW(pConnectSettings cs, LPCWSTR Path)
{
    std::array<char, MAX_PATH> msgBuf{};
    LoadStr(msgBuf, IDS_MK_DIR);
    std::wstring display(wdirtypemax, L'\0');
    awlcopy(display.data(), msgBuf.data(), wdirtypemax - 1);
    display.resize(wcslen(display.c_str()));
    display += Path;
    ShowStatusW(display.c_str());

    std::string dirStr(wdirtypemax, '\0');
    CopyStringW2A(cs, Path, dirStr.data(), dirStr.size());
    dirStr.resize(strlen(dirStr.c_str()));
    std::replace(dirStr.begin(), dirStr.end(), '\\', '/');

    if (IsPhpAgentTransport(cs))
        return PhpAgentCreateDirectoryW(cs, Path);

    if (cs->scponly) {
        auto channel = ConnectChannel(cs->session.get(), cs->sock);
        if (!channel) {
            ShowStatus("SCP Mkdir: channel creation failed");
            return SFTP_FAILED;
        }

        std::string target = dirStr;
        if (!target.empty() && target[0] == '/')
            target = (target.size() == 1) ? "." : target.substr(1);
        
        std::string cmd = "mkdir '" + string_util::ShellQuoteSingle(target) + "'";
        bool ok = GetChannelCommandReply(cs->session.get(), channel.get(), cmd.c_str(), cs->sock);
        return ok ? SFTP_OK : SFTP_FAILED;
    }

    const SYSTICKS start = get_sys_ticks();
    SYSTICKS aborttime = -1;
    int rc;
    do {
        rc = cs->sftpsession->mkdir(dirStr.c_str(), cs->dirmod);
        if (rc == 0)
            break;
        Sleep(50);
        int delta = get_ticks_between(cs->findstarttime);
        if (delta > kSftpProgressStartMs && aborttime == -1) {
            if (EscapePressed())
                aborttime = get_sys_ticks() + kSftpAbortGraceMs;
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            cs->neednewchannel = true;
            break;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    if (rc == 0) {
        if (cs->dirmod != 0755) {
            LIBSSH2_SFTP_ATTRIBUTES attr{};
            attr.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;
            attr.permissions = cs->dirmod;
            do {
                rc = cs->sftpsession->setstat(dirStr.c_str(), &attr);
                if (EscapePressed()) {
                    cs->neednewchannel = true;
                    break;
                }
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    IsSocketReadable(cs->sock);
            } while (rc == LIBSSH2_ERROR_EAGAIN);
        }
        return SFTP_OK;
    } else {
        char* errmsg = nullptr;
        int errmsg_len = 0;
        cs->session->lastError(&errmsg, &errmsg_len, false);
        std::string msg = "Directory not created: ";
        if (errmsg) msg += errmsg;
        ShowStatus(msg.c_str());
        return SFTP_FAILED;
    }
}

int SftpDeleteFileW(pConnectSettings cs, LPCWSTR RemoteName, bool isdir)
{
    std::array<char, MAX_PATH> msgBuf{};
    LoadStr(msgBuf, IDS_DELETE);
    std::wstring display(wdirtypemax, L'\0');
    awlcopy(display.data(), msgBuf.data(), wdirtypemax - 1);
    display.resize(wcslen(display.c_str()));
    display += RemoteName;
    ShowStatusW(display.c_str());

    std::string nameStr(wdirtypemax, '\0');
    CopyStringW2A(cs, RemoteName, nameStr.data(), nameStr.size());
    nameStr.resize(strlen(nameStr.c_str()));
    std::replace(nameStr.begin(), nameStr.end(), '\\', '/');

    if (IsPhpAgentTransport(cs))
        return PhpAgentDeleteFileW(cs, RemoteName, isdir);

    if (nameStr == "/~")
        return SFTP_FAILED;

    if (cs->scponly) {
        std::string target = nameStr;
        if (!target.empty() && target[0] == '/')
            target = (target.size() == 1) ? "." : target.substr(1);

        std::string cmd = isdir ? "rm -rf '" : "rm -f '";
        cmd += string_util::ShellQuoteSingle(target) + "'";

        if (!EnsureScpShell(cs))
            return SFTP_FAILED;

        std::string fullCmd = cmd + "; echo \"" + kScpListEndMarker + "\":$?\n";
        ISshChannel* channel = cs->scpShellChannel.get();
        const auto writeStart = std::chrono::steady_clock::now();
        size_t written = 0;
        while (written < fullCmd.size()) {
            int rc = static_cast<int>(channel->write(fullCmd.data() + written, fullCmd.size() - written));
            if (rc > 0) {
                written += rc;
                continue;
            }
            if (rc != LIBSSH2_ERROR_EAGAIN)
                return SFTP_FAILED;
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - writeStart).count();
            if (elapsed > kScpWriteTimeoutMs)
                return SFTP_FAILED;
            IsSocketReadable(cs->sock);
        }

        std::vector<std::string> lines;
        bool gotEnd = ScpReadCommandOutput(cs, kScpListEndMarker, lines, kScpDeleteReadTimeoutMs);
        int exitCode = 0;
        for (const auto& l : lines) {
            size_t p = l.find(kScpListEndMarker);
            if (p != std::string::npos && p + strlen(kScpListEndMarker) < l.size() && l[p + strlen(kScpListEndMarker)] == ':')
                exitCode = atoi(l.c_str() + p + strlen(kScpListEndMarker) + 1);
        }
        return (gotEnd && exitCode == 0) ? SFTP_OK : SFTP_FAILED;
    }

    const SYSTICKS start = get_sys_ticks();
    SYSTICKS aborttime = -1;
    int rc;
    do {
        rc = isdir ? cs->sftpsession->rmdir(nameStr.c_str())
                   : cs->sftpsession->unlink(nameStr.c_str());
        int delta = get_ticks_between(start);
        if (delta > kSftpProgressStartMs && aborttime == -1) {
            if (ProgressProcT(PluginNumber, display.data(), L"delete", (delta / kSftpProgressDivMs) % 100))
                aborttime = get_sys_ticks() + kSftpAbortGraceMs;
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            cs->neednewchannel = true;
            break;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    if (rc == 0)
        return SFTP_OK;

    char* errmsg = nullptr;
    int errmsg_len = 0;
    cs->session->lastError(&errmsg, &errmsg_len, false);
    std::string err = "Delete FAILED: ";
    if (errmsg) err += errmsg;
    ShowStatus(err.c_str());
    return SFTP_FAILED;
}

int SftpRenameMoveFileW(pConnectSettings cs, LPCWSTR OldName, LPCWSTR NewName, bool Move, bool Overwrite, [[maybe_unused]] bool isdir)
{
    if (!cs)
        return SFTP_FAILED;

    if (IsPhpAgentTransport(cs))
        return PhpAgentRenameMoveFileW(cs, OldName, NewName, Overwrite);

    std::string oldNameA(wdirtypemax, '\0');
    std::string newNameA(wdirtypemax, '\0');
    CopyStringW2A(cs, OldName, oldNameA.data(), oldNameA.size());
    CopyStringW2A(cs, NewName, newNameA.data(), newNameA.size());
    ReplaceBackslashBySlash(oldNameA.data());
    ReplaceBackslashBySlash(newNameA.data());

    if (cs->scponly) {
        std::wstring cmdW = Move ? L"mv '" : L"cp '";
        cmdW += string_util::ShellQuoteSingleW(OldName) + L"' '";
        cmdW += string_util::ShellQuoteSingleW(NewName) + L"'";
        const int rc = SftpQuoteCommand2W(cs, nullptr, cmdW.c_str(), nullptr, 0);
        return (rc >= 0) ? SFTP_OK : SFTP_FAILED;
    }

    if (!Overwrite) {
        LIBSSH2_SFTP_ATTRIBUTES attr{};
        int lrc = 0;
        do {
            lrc = cs->sftpsession->lstat(newNameA.data(), &attr);
            if (lrc == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(cs->sock);
        } while (lrc == LIBSSH2_ERROR_EAGAIN);
        if (lrc >= 0)
            return SFTP_EXISTS;
    }

    int rc = 0;
    do {
        rc = cs->sftpsession->rename(oldNameA.data(), newNameA.data());
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);
    return (rc == 0) ? SFTP_OK : SFTP_FAILED;
}

int SftpSetAttr(pConnectSettings cs, LPCSTR RemoteName, int NewAttr)
{
    if (!cs || !RemoteName || !RemoteName[0])
        return SFTP_FAILED;
    if (cs->scponly || IsPhpAgentTransport(cs))
        return SFTP_OK;  // no SFTP channel available; silently skip
    if (!cs->sftpsession)
        return SFTP_FAILED;

    std::string nameStr(RemoteName);
    std::replace(nameStr.begin(), nameStr.end(), '\\', '/');

    // Fetch current permissions via lstat so we can do a RMW on the mode bits.
    LIBSSH2_SFTP_ATTRIBUTES attrs{};
    int rc = 0;
    do {
        rc = cs->sftpsession->lstat(nameStr.c_str(), &attrs);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    if (rc != 0 || !(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS))
        return SFTP_FAILED;

    // Map Windows FILE_ATTRIBUTE_READONLY (0x01) onto Unix write-bit mask.
    // Preserve all other bits; only toggle write bits (0222).
    const bool makeReadOnly = (NewAttr & 0x01) != 0;
    if (makeReadOnly)
        attrs.permissions &= ~(unsigned long)0222;   // remove all write bits
    else
        attrs.permissions |=  (unsigned long)0200;   // restore at least owner write

    attrs.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;
    do {
        rc = cs->sftpsession->setstat(nameStr.c_str(), &attrs);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    return (rc == 0) ? SFTP_OK : SFTP_FAILED;
}

int SftpSetDateTimeW(pConnectSettings cs, LPCWSTR RemoteName, LPFILETIME LastWriteTime)
{
    if (!cs || !RemoteName || !LastWriteTime || cs->scponly || IsPhpAgentTransport(cs))
        return SFTP_FAILED;

    std::string nameA(wdirtypemax, '\0');
    CopyStringW2A(cs, RemoteName, nameA.data(), nameA.size());
    ReplaceBackslashBySlash(nameA.data());

    LIBSSH2_SFTP_ATTRIBUTES attr{};
    attr.flags = LIBSSH2_SFTP_ATTR_ACMODTIME;
    attr.mtime = GetUnixTime(LastWriteTime);
    attr.atime = attr.mtime;
    int rc = 0;
    do {
        rc = cs->sftpsession->setstat(nameA.data(), &attr);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);
    return (rc == 0) ? SFTP_OK : SFTP_FAILED;
}

void SftpGetLastActivePathW(pConnectSettings cs, LPWSTR RelativePath, size_t maxlen)
{
    if (!RelativePath || maxlen == 0)
        return;
    RelativePath[0] = 0;
    if (!cs)
        return;
    wcslcpy(RelativePath, cs->lastactivepath, maxlen - 1);
}

bool SftpChmodW(pConnectSettings cs, LPCWSTR RemoteName, LPCWSTR chmod)
{
    if (!cs || !RemoteName || !chmod || !chmod[0])
        return false;

    std::wstring cmd = L"chmod ";
    cmd += chmod;
    cmd += L" '";
    cmd += string_util::ShellQuoteSingleW(RemoteName);
    cmd += L"'";
    return SftpQuoteCommand2W(cs, nullptr, cmd.c_str(), nullptr, 0) >= 0;
}

bool SftpLinkFolderTargetW(pConnectSettings cs, LPWSTR RemoteName, size_t maxlen)
{
    if (!cs || !RemoteName || maxlen < 2)
        return false;

    // Only handle the virtual ~ home-directory symlink injected by FsFindFirstW.
    // Real SFTP symlinks would need lstat + readlink, which is a separate feature.
    const std::wstring_view remoteView(RemoteName);
    const bool isTildeHome = (remoteView == L"\\~" || remoteView == L"/~" || remoteView == L"~");
    if (!isTildeHome)
        return false;

    // --- PHP agent transport: no realpath API available, fall back to server root ---
    if (IsPhpAgentTransport(cs)) {
        wcslcpy(RemoteName, L"/", maxlen - 1);
        return true;
    }

    // --- SCP-only mode: resolve home dir via persistent shell using `echo ~` ---
    if (cs->scponly) {
        if (!EnsureScpShell(cs))
            return false;
        ISshChannel* channel = cs->scpShellChannel.get();
        if (!channel)
            return false;

        static unsigned homeSeq = 1;
        const unsigned seq = homeSeq++;
        std::string endMarker = std::string(kScpListEndMarker) + "_H_" + std::to_string(seq);
        std::string cmd = "echo ~; echo \"" + endMarker + "\"\n";

        size_t written = 0;
        const auto t0 = std::chrono::steady_clock::now();
        while (written < cmd.size()) {
            int n = static_cast<int>(channel->write(cmd.data() + written, cmd.size() - written));
            if (n > 0) {
                written += n;
                continue;
            }
            if (n != LIBSSH2_ERROR_EAGAIN)
                return false;
            if (std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count() > kScpWriteTimeoutMs)
                return false;
            IsSocketReadable(cs->sock);
        }

        std::vector<std::string> lines;
        ScpReadCommandOutput(cs, endMarker.c_str(), lines, kScpReadTimeoutMs);

        for (const auto& line : lines) {
            if (line.find(kScpListEndMarker) != std::string::npos)
                continue;
            std::string home = line;
            // Strip trailing whitespace / CR / LF
            while (!home.empty() && (home.back() == '\r' || home.back() == '\n' || home.back() == ' '))
                home.pop_back();
            if (home.empty() || home[0] != '/')
                continue;
            CopyStringA2W(cs, home.c_str(), RemoteName, maxlen);
            ReplaceSlashByBackslashW(RemoteName);
            return true;
        }
        return false;
    }

    // --- Standard SFTP: use realpath(".") to resolve the server-side home directory ---
    if (!cs->sftpsession)
        return false;

    std::string realBuf(wdirtypemax, '\0');
    int rc = 0;
    const SYSTICKS start = get_sys_ticks();
    do {
        rc = cs->sftpsession->realpath(".", realBuf.data(),
                                         static_cast<int>(realBuf.size()) - 1);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN && get_ticks_between(start) < 5000);

    if (rc > 0) {
        realBuf[static_cast<size_t>(rc)] = '\0';
        CopyStringA2W(cs, realBuf.data(), RemoteName, maxlen);
        ReplaceSlashByBackslashW(RemoteName);
        return true;
    }

    return false;
}

void SftpShowPropertiesW(pConnectSettings cs, LPCWSTR remotename)
{
    (void)cs;
    (void)remotename;
}

void SftpSetTransferModeW(LPCWSTR mode)
{
    if (!mode || !mode[0])
        return;
    WCHAR ch = mode[0];
    if (ch >= L'a' && ch <= L'z')
        ch = static_cast<WCHAR>(ch - (L'a' - L'A'));
    Global_TransferMode = static_cast<char>(ch & 0xFF);
    if (Global_TransferMode == 'X') {
        wcslcpy(Global_TextTypes.data(), mode + 1, Global_TextTypes.size() - 1);
    }
}

bool SftpSupportsResume(pConnectSettings ConnectSettings)
{
    return ConnectSettings != nullptr;
}

int SftpServerSupportsChecksumsW(pConnectSettings ConnectSettings, LPCWSTR RemoteName)
{
    (void)ConnectSettings;
    (void)RemoteName;
    return 0;
}

HANDLE SftpStartFileChecksumW(int ChecksumType, pConnectSettings ConnectSettings, LPCWSTR RemoteName)
{
    (void)ChecksumType;
    (void)ConnectSettings;
    (void)RemoteName;
    return nullptr;
}

int SftpGetFileChecksumResultW(bool WantResult, HANDLE ChecksumHandle, pConnectSettings ConnectSettings, LPSTR checksum, size_t maxlen)
{
    (void)WantResult;
    (void)ChecksumHandle;
    (void)ConnectSettings;
    if (checksum && maxlen > 0)
        checksum[0] = 0;
    return FS_CHK_ERR_FAIL;
}
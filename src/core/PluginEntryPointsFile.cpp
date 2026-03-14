#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <algorithm>
#include "fsplugin.h"
#include "CoreUtils.h"
#include "res/resource.h"
#include "SftpClient.h"
#include "SftpInternal.h"
#include "ServerRegistry.h"
#include "UnicodeHelpers.h"
#include "PluginEntryPoints.h"
#include "DllExceptionBarrier.h"
#include "LanPairSession.h"
#include "PluginEntryPointsInternal.h"

int WINAPI FsExecuteFileW(HWND MainWin, LPWSTR RemoteName, LPCWSTR Verb)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_EXEC_ERROR, [&]() -> int {
        std::array<char, wdirtypemax> remoteserver{};
        std::array<WCHAR, wdirtypemax> remotedir{};
        if (_wcsicmp(Verb, L"open") == 0) {   // follow symlink
            if (is_full_name(RemoteName)) {
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
                if (!serverid)
                    return FS_EXEC_YOURSELF;
            
                if (!SftpLinkFolderTargetW(serverid, remotedir.data(), wdirtypemax - 1)) {
                    // Check if this is a tilde home shortcut — never let TC download it.
                    std::wstring_view rv(remotedir.data());
                    while (!rv.empty() && (rv.front() == L'\\' || rv.front() == L'/'))
                        rv.remove_prefix(1);
                    if (rv == L"~") {
                        // Shell was stale (e.g. after PHP→SCP session switch). Reconnect once and retry.
                        SftpCloseConnection(serverid);
                        Sleep(500);
                        if (SftpConnect(serverid) == SFTP_OK &&
                            SftpLinkFolderTargetW(serverid, remotedir.data(), wdirtypemax - 1)) {
                            // fall through to success path below
                        } else {
                            return FS_EXEC_ERROR;  // fail hard — never download "~" as a file
                        }
                    } else {
                        return FS_EXEC_YOURSELF;
                    }
                }
            
                // now build the target name: server name followed by new path
                LPWSTR p = cut_srv_name(RemoteName);
                if (!p)
                    return FS_EXEC_ERROR;
                // Ensure the target path is reachable.
                wcslcat(RemoteName, remotedir.data(), wdirtypemax-1);
                ReplaceSlashByBackslashW(RemoteName);
                return FS_EXEC_SYMLINK;
            }
            if (_wcsicmp(RemoteName + 1, s_f7newconnectionW.data()) != 0) {
                LPWSTR p = RemoteName + wcslen(RemoteName);
                int pmaxlen = wdirtypemax - (size_t)(p - RemoteName) - 1;
                walcopy(remoteserver.data(), RemoteName + 1, remoteserver.size() - 1);
                pConnectSettings serverid = static_cast<pConnectSettings>(GetServerIdFromName(remoteserver.data(), GetCurrentThreadId()));
                if (serverid) {
                    SftpGetLastActivePathW(serverid, p, pmaxlen);
                } else {
                    // Quick connect: connect here, otherwise the selected subpath cannot be applied.
                    walcopy(remoteserver.data(), RemoteName + 1, remoteserver.size() - 1);
                    if (_stricmp(remoteserver.data(), s_quickconnect) == 0) {
                        serverid = SftpConnectToServer(remoteserver.data(), inifilename, nullptr);
                        if (!serverid)
                            return FS_EXEC_OK; // cancelled or save-only from quick dialog
                        SetServerIdForName(remoteserver.data(), static_cast<SERVERID>(serverid));
                        SftpGetLastActivePathW(serverid, p, pmaxlen);
                    } else {
                        SftpGetServerBasePathW(RemoteName + 1, p, pmaxlen, inifilename);
                    }
                }
                if (p[0] == 0)
                    wcslcat(RemoteName, L"/", wdirtypemax-1);
                ReplaceSlashByBackslashW(RemoteName);
                return FS_EXEC_SYMLINK;
            }
            // Open quick/new-connection dialog directly from the helper entry.
            pConnectSettings serveridQuick = SftpConnectToServer(s_quickconnect, inifilename, nullptr);
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            return serveridQuick ? FS_EXEC_OK : FS_EXEC_YOURSELF;
        }
        if (_wcsicmp(Verb, L"properties") == 0) {
            if (RemoteName[1] && wcschr(RemoteName+1, L'\\') == 0) {
                walcopy(remoteserver.data(), RemoteName+1, remoteserver.size() - 1);
                if (_stricmp(remoteserver.data(), s_f7newconnection) != 0 && _stricmp(remoteserver.data(), s_quickconnect) != 0) {
                    if (SftpConfigureServer(remoteserver.data(), inifilename)) {
                        LoadServersFromIniW(inifilenameW, s_quickconnect);
                    
                        // ZERWANIE "ZATRUTEJ SESJI": 
                        // Total Commander nie rozłącza aktywnej sesji przy edycji jej właściwości (Alt+Enter).
                        // Wymuszamy rozłączenie, aby wtyczka natychmiast zbudowała nowe połączenie
                        // z nowymi ustawieniami (np. przełączając między SFTP a PHP Agentem).
                        std::array<char, wdirtypemax> disconnPath{};
                        strlcpy(disconnPath.data(), "\\", disconnPath.size() - 1);
                        strlcat(disconnPath.data(), remoteserver.data(), disconnPath.size() - 1);
                        FsDisconnect(disconnPath.data());
                    }
                }
            } else {
                std::array<WCHAR, wdirtypemax> remotenameW{};
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotenameW.data(), remotenameW.size() - 1);
                if (serverid)
                    SftpShowPropertiesW(serverid, remotenameW.data());
                else
                    return FS_EXEC_ERROR;
            }
            return FS_EXEC_OK;
        }
        if (_wcsnicmp(Verb, L"chmod ", 6) == 0) {
            if (RemoteName[1] && wcschr(RemoteName+1, '\\') != 0) {
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
                if (serverid && SftpChmodW(serverid, remotedir.data(), Verb+6))
                    return FS_EXEC_OK;
            }
            return FS_EXEC_ERROR;
        }
        if (_wcsnicmp(Verb, L"quote ", 6) == 0) {
            if (wcsncmp(Verb+6, L"cd ", 3) == 0) {
                // first get the start path within the plugin
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
                if (!serverid)
                    return FS_EXEC_ERROR;
                if (Verb[9] != '\\' && Verb[9] != '/') {     // relative path?
                    wcslcatbackslash(remotedir.data(), remotedir.size() - 1);
                    wcslcat(remotedir.data(), Verb+9, remotedir.size() - 1);
                } else
                    wcslcpy(remotedir.data(), Verb+9, remotedir.size() - 1);
                ReplaceSlashByBackslashW(remotedir.data());

                LPWSTR p = cut_srv_name(RemoteName);
                if (!p)
                    return FS_EXEC_ERROR;
                // Ensure the target path is reachable.
                wcslcat(RemoteName, remotedir.data(), wdirtypemax-1);
                ReplaceSlashByBackslashW(RemoteName);
                return FS_EXEC_SYMLINK;
            } else {
                if (is_full_name(RemoteName)) {
                    std::array<WCHAR, wdirtypemax> quoteRemotedir{};
                    pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, quoteRemotedir.data(), quoteRemotedir.size() - 1);
                    if (serverid && SftpQuoteCommand2W(serverid, quoteRemotedir.data(), Verb+6, nullptr, 0) != 0)
                        return FS_EXEC_OK;
                }
            }
            return FS_EXEC_ERROR;
        }
        if (_wcsnicmp(Verb, L"mode ", 5) == 0) {   // Binary/Text/Auto
            SftpSetTransferModeW(Verb+5);
            return FS_EXEC_OK;
        }
        return FS_EXEC_ERROR;
    });
}

int WINAPI FsExecuteFile(HWND MainWin, LPSTR RemoteName, LPCSTR Verb)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_EXEC_ERROR, [&]() -> int {
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        std::array<WCHAR, wdirtypemax> verbW{};
        int ret = FsExecuteFileW(MainWin, awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), awlcopy(verbW.data(), Verb, verbW.size() - 1));
        if (ret == FS_EXEC_SYMLINK)
            walcopy(RemoteName, remoteNameW.data(), MAX_PATH-1);
        return ret;
    });
}

static bool CopyMoveEncryptedPassword(LPCSTR OldName, LPSTR NewName, bool Move)
{
    if (!CryptProc)
        return false;
    int mode = Move ? FS_CRYPT_MOVE_PASSWORD : FS_CRYPT_COPY_PASSWORD;
    int rc = CryptProc(PluginNumber, CryptoNumber, mode, OldName, NewName, 0);
    return (rc == FS_FILE_OK) ? true : false;
}

int WINAPI FsRenMovFileW(LPCWSTR OldName, LPCWSTR NewName, BOOL Move, BOOL OverWrite, RemoteInfoStruct * ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        // Use std::wstring instead of std::array<WCHAR, wdirtypemax>
        std::wstring olddir(wdirtypemax, L'\0');
        std::wstring newdir(wdirtypemax, L'\0');

        // Rename or copy a server?
        LPCWSTR p1 = wcschr(OldName + 1, L'\\');
        LPCWSTR p2 = wcschr(NewName + 1, L'\\');
        if (p1 == nullptr && p2 == nullptr) {
            // Use std::string instead of std::array<char, MAX_PATH>
            std::string oldNameA(MAX_PATH, '\0');
            std::string newNameA(MAX_PATH, '\0');
            walcopy(oldNameA.data(), OldName + 1, oldNameA.size() - 1);
            walcopy(newNameA.data(), NewName + 1, newNameA.size() - 1);
            oldNameA.resize(strlen(oldNameA.data()));
            newNameA.resize(strlen(newNameA.data()));
            int rc = CopyMoveServerInIniW(oldNameA.data(), newNameA.data(), !!Move, !!OverWrite, inifilenameW);
            if (rc == FS_FILE_OK) {
                CopyMoveEncryptedPassword(oldNameA.data(), newNameA.data(), !!Move);
                return FS_FILE_OK;
            }
            if (rc == FS_FILE_EXISTS)
                return FS_FILE_EXISTS;
            return FS_FILE_NOTFOUND;
        }

        pConnectSettings serverid1 = GetServerIdAndRelativePathFromPathW(OldName, olddir.data(), olddir.size() - 1);
        pConnectSettings serverid2 = GetServerIdAndRelativePathFromPathW(NewName, newdir.data(), newdir.size() - 1);
        olddir.resize(wcslen(olddir.data()));
        newdir.resize(wcslen(newdir.data()));

        // Source and destination must be on the same server.
        if (serverid1 != serverid2 || serverid1 == nullptr)
            return FS_FILE_NOTFOUND;

        ResetLastPercent(serverid1);

        bool isdir = (ri->Attr & FILE_ATTRIBUTE_DIRECTORY) ? true : false;

        // LAN Pair rename.
        if (IsLanPairTransport(serverid1)) {
            if (!serverid1->lanSession || !serverid1->lanSession->isConnected()) return FS_FILE_WRITEERROR;
            const std::string oldUtf8 = LanRemotePathToUtf8(olddir.data());
            const std::string newUtf8 = LanRemotePathToUtf8(newdir.data());
            return serverid1->lanSession->rename(oldUtf8, newUtf8) ? FS_FILE_OK : FS_FILE_WRITEERROR;
        }

        int rc = SftpRenameMoveFileW(serverid1, olddir.data(), newdir.data(), !!Move, !!OverWrite, isdir);
        switch (rc) {
        case SFTP_OK:
            return FS_FILE_OK;
        case SFTP_EXISTS:
            return FS_FILE_EXISTS;
        default:
            return FS_FILE_WRITEERROR;
        }
    });
}

int WINAPI FsRenMovFile(LPCSTR OldName, LPCSTR NewName, BOOL Move, BOOL OverWrite, RemoteInfoStruct * ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        std::array<WCHAR, wdirtypemax> oldNameW{};
        std::array<WCHAR, wdirtypemax> newNameW{};
        return FsRenMovFileW(awlcopy(oldNameW.data(), OldName, oldNameW.size() - 1), awlcopy(newNameW.data(), NewName, newNameW.size() - 1), Move, OverWrite, ri);
    });
}

static bool FileExistsT(LPCWSTR LocalName)
{
    WIN32_FIND_DATAW s;
    HANDLE findhandle = FindFirstFileT(LocalName, &s);
    if (!findhandle || findhandle == INVALID_HANDLE_VALUE)
        return false;
    FindClose(findhandle);
    return true;
}

static void SanitizeLocalFileNameW(LPWSTR localPath) noexcept
{
    if (!localPath || !localPath[0])
        return;
    const std::wstring_view pathView(localPath);
    const size_t slashPos = pathView.find_last_of(L"\\/");
    if (slashPos == std::wstring_view::npos || slashPos + 1 >= pathView.size())
        return;
    wchar_t* filePart = localPath + slashPos + 1;
    while (*filePart) {
        if (static_cast<unsigned>(*filePart) < 32u) {
            *filePart = L' ';
        } else if (*filePart == L':' || *filePart == L'|' || *filePart == L'*' || *filePart == L'?' ||
                   *filePart == L'\\' || *filePart == L'/' || *filePart == L'"') {
            *filePart = L'_';
        }
        ++filePart;
    }
}

static int CreateHelpFileLocalW(LPCWSTR localName, bool overwrite)
{
    const DWORD disposition = overwrite ? CREATE_ALWAYS : CREATE_NEW;
    handle_util::FileHandle outFile(CreateFileT(
        localName,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        disposition,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr));

    if (!outFile) {
        const DWORD gle = GetLastError();
        if (gle == ERROR_ALREADY_EXISTS || gle == ERROR_FILE_EXISTS)
            return FS_FILE_EXISTS;
        return FS_FILE_WRITEERROR;
    }

    std::array<char, 256> helpText{};
    LoadString(hinst, IDS_HELPTEXT, helpText.data(), static_cast<int>(helpText.size()));
    DWORD written = 0;
    const BOOL ok = WriteFile(outFile.get(), helpText.data(),
                              static_cast<DWORD>(strlen(helpText.data())), &written, nullptr);
    return ok ? FS_FILE_OK : FS_FILE_WRITEERROR;
}

int WINAPI FsGetFileW(LPCWSTR RemoteName, LPWSTR LocalName, int CopyFlags, RemoteInfoStruct * ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_READERROR, [&]() -> int {
        const bool OverWrite = !!(CopyFlags & FS_COPYFLAGS_OVERWRITE);
        bool Resume = !!(CopyFlags & FS_COPYFLAGS_RESUME);
        const bool Move = !!(CopyFlags & FS_COPYFLAGS_MOVE);
        SFTP_LOG("ENTRY", "FsGetFileW start flags=0x%x overwrite=%d resume=%d move=%d shift=%d",
                 CopyFlags, OverWrite ? 1 : 0, Resume ? 1 : 0, Move ? 1 : 0,
                 (GetAsyncKeyState(VK_SHIFT) & 0x8000) ? 1 : 0);

        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};
        if (remoteView.size() < 3 || !LocalName || !ri)
            return FS_FILE_NOTFOUND;

        if (remoteView.substr(1) == std::wstring_view(s_f7newconnectionW.data())) {
            return CreateHelpFileLocalW(LocalName, OverWrite);
        }

        SanitizeLocalFileNameW(LocalName);

        std::wstring remotedir(wdirtypemax, L'\0');
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return FS_FILE_READERROR;

        int startPct = 0;
        if (Resume && ri && ri->Size64 > 0) {
            HANDLE h = CreateFileW(LocalName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER li{};
                if (GetFileSizeEx(h, &li) && li.QuadPart > 0)
                    startPct = (int)std::clamp((li.QuadPart * 100LL) / ri->Size64, 0LL, 100LL);
                CloseHandle(h);
            }
        }

        serverid->lastpercent = startPct;

        int err = ProgressProcT(PluginNumber, RemoteName, LocalName, startPct);
        if (err)
            return FS_FILE_USERABORT;
        if (!OverWrite && !Resume && FileExistsT(LocalName)) {
            bool TextMode = (serverid->unixlinebreaks == 1) && SftpDetermineTransferModeW(RemoteName);
            if (TextMode)
                return FS_FILE_NOTSUPPORTED;
            return FS_FILE_EXISTSRESUMEALLOWED;
        }
        if (OverWrite) {
            DeleteFileT(LocalName);
        }

        // LAN Pair download.
        if (IsLanPairTransport(serverid)) {
            if (!serverid->lanSession || !serverid->lanSession->isConnected())
                return FS_FILE_READERROR;
            const std::string remoteUtf8 = LanRemotePathToUtf8(remotedir.data());
            int fsResult = FS_FILE_READERROR;
            serverid->lanSession->getFile(remoteUtf8, LocalName,
                                          ri ? ri->Size64 : 0,
                                          ri ? &ri->LastWriteTime : nullptr,
                                          OverWrite, Resume, &fsResult);
            return fsResult;
        }

        while (true) {  // auto-resume loop
            int rc = SftpDownloadFileW(serverid, remotedir.data(), LocalName, true, ri->Size64, &ri->LastWriteTime, Resume);
            SFTP_LOG("ENTRY", "FsGetFileW SftpDownloadFileW rc=%d", rc);
            switch (rc) {
                case SFTP_OK:          return FS_FILE_OK;
                case SFTP_EXISTS:      return FS_FILE_EXISTS;
                case SFTP_READFAILED:  return FS_FILE_READERROR;
                case SFTP_WRITEFAILED: return FS_FILE_WRITEERROR;
                case SFTP_ABORT:       return FS_FILE_USERABORT;
                case SFTP_PARTIAL:     Resume = true; break;
                default:               return FS_FILE_READERROR;
            }
        }
        return FS_FILE_OK;
    });
}

int WINAPI FsGetFile(LPCSTR RemoteName, LPSTR LocalName, int CopyFlags, RemoteInfoStruct* ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_READERROR, [&]() -> int {
        if (!RemoteName || !LocalName || !ri)
            return FS_FILE_NOTFOUND;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        std::array<WCHAR, wdirtypemax> localNameW{};
        return FsGetFileW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), awlcopy(localNameW.data(), LocalName, localNameW.size() - 1), CopyFlags, ri);
    });
}

int WINAPI FsPutFileW(LPCWSTR LocalName, LPCWSTR RemoteName, int CopyFlags)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        const bool OverWrite = !!(CopyFlags & FS_COPYFLAGS_OVERWRITE);
        const bool Resume = !!(CopyFlags & FS_COPYFLAGS_RESUME);
        const bool Move = !!(CopyFlags & FS_COPYFLAGS_MOVE);
        SFTP_LOG("ENTRY", "FsPutFileW start flags=0x%x overwrite=%d resume=%d move=%d shift=%d",
                 CopyFlags, OverWrite ? 1 : 0, Resume ? 1 : 0, Move ? 1 : 0,
                 (GetAsyncKeyState(VK_SHIFT) & 0x8000) ? 1 : 0);

        const std::wstring_view localView = LocalName ? std::wstring_view(LocalName) : std::wstring_view{};
        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};

        // Auto-overwrites files -> return error if file exists
        if ((CopyFlags & (FS_COPYFLAGS_EXISTS_SAMECASE | FS_COPYFLAGS_EXISTS_DIFFERENTCASE)) != 0) {
            if (!OverWrite && !Resume) {
                return FS_FILE_EXISTSRESUMEALLOWED;
            }
        }

        if (remoteView.size() < 3 || localView.empty())
            return FS_FILE_WRITEERROR;

        int err = ProgressProcT(PluginNumber, LocalName, RemoteName, 0);
        if (err)
            return FS_FILE_USERABORT;

        std::array<WCHAR, wdirtypemax> remotedir{};
    
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return FS_FILE_READERROR;
        ResetLastPercent(serverid);

        // LAN Pair upload.
        if (IsLanPairTransport(serverid)) {
            if (!serverid->lanSession || !serverid->lanSession->isConnected())
                return FS_FILE_WRITEERROR;
            const std::string remoteUtf8 = LanRemotePathToUtf8(remotedir.data());
            int fsResult = FS_FILE_WRITEERROR;
            serverid->lanSession->putFile(LocalName, remoteUtf8, OverWrite, Resume, &fsResult);
            return fsResult;
        }

        const bool setattr = !!(CopyFlags & FS_COPYFLAGS_EXISTS_SAMECASE);
        int rc = SftpUploadFileW(serverid, LocalName, remotedir.data(), Resume, setattr);
        SFTP_LOG("ENTRY", "FsPutFileW SftpUploadFileW rc=%d", rc);
        switch (rc) {
            case SFTP_OK:          return FS_FILE_OK;
            case SFTP_EXISTS:      return SftpSupportsResume(serverid) ? FS_FILE_EXISTSRESUMEALLOWED : FS_FILE_EXISTS;
            case SFTP_READFAILED:  return FS_FILE_READERROR;
            case SFTP_WRITEFAILED: return FS_FILE_WRITEERROR;
            case SFTP_ABORT:       return FS_FILE_USERABORT;
            default:               return FS_FILE_WRITEERROR;
        }
        return FS_FILE_WRITEERROR;
    });
}

int WINAPI FsPutFile(LPCSTR LocalName, LPCSTR RemoteName, int CopyFlags)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        if (!LocalName || !RemoteName)
            return FS_FILE_WRITEERROR;
        std::array<WCHAR, wdirtypemax> localNameW{};
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsPutFileW(awlcopy(localNameW.data(), LocalName, localNameW.size() - 1), awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), CopyFlags);
    });
}

BOOL WINAPI FsDeleteFileW(LPCWSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};
        if (remoteView.size() < 2)
            return false;

        const bool hasRemoteSubPath = remoteView.find(L'\\', 1) != std::wstring_view::npos;
        if (hasRemoteSubPath) {
            // Use std::wstring instead of std::array<WCHAR, wdirtypemax>
            std::wstring remotedir(wdirtypemax, L'\0');
            pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
            remotedir.resize(wcslen(remotedir.data()));
            if (serverid == nullptr)
                return false;
            ResetLastPercent(serverid);
            if (IsLanPairTransport(serverid)) {
                if (!serverid->lanSession || !serverid->lanSession->isConnected()) return false;
                return serverid->lanSession->remove(LanRemotePathToUtf8(remotedir.data()));
            }
            int rc = SftpDeleteFileW(serverid, remotedir.data(), false);
            return (rc == SFTP_OK) ? true : false;
        }
        // delete server
        const std::wstring_view serverNameW = remoteView.substr(1);
        const std::wstring serverName(serverNameW);
        if (_wcsicmp(serverName.c_str(), s_f7newconnectionW.data()) != 0 &&
            _wcsicmp(serverName.c_str(), s_quickconnectW.data()) != 0) {
            // Use std::string instead of std::array<char, wdirtypemax>
            std::string remotedirA(wdirtypemax, '\0');
            walcopy(remotedirA.data(), serverName.c_str(), remotedirA.size() - 1);
            remotedirA.resize(strlen(remotedirA.data()));
            if (DeleteServerFromIniW(remotedirA.data(), inifilenameW)) {
                if (CryptProc)
                    CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_DELETE_PASSWORD, remotedirA.data(), nullptr, 0);
                return true;
            }
        }
        return false;
    });
}

BOOL WINAPI FsDeleteFile(LPCSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsDeleteFileW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1));
    });
}

BOOL WINAPI FsRemoveDirW(LPCWSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (is_full_name(RemoteName)) {
            // Use std::wstring instead of std::array<WCHAR, wdirtypemax>
            std::wstring remotedir(wdirtypemax, L'\0');
            pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
            remotedir.resize(wcslen(remotedir.data()));
            if (serverid == nullptr)
                return false;
            ResetLastPercent(serverid);
            if (IsLanPairTransport(serverid)) {
                if (!serverid->lanSession || !serverid->lanSession->isConnected()) return false;
                return serverid->lanSession->remove(LanRemotePathToUtf8(remotedir.data()));
            }
            int rc = SftpDeleteFileW(serverid, remotedir.data(), true);
            return (rc == SFTP_OK) ? true : false;
        }
        return false;
    });
}

BOOL WINAPI FsRemoveDir(LPCSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsRemoveDirW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1));
    });
}

// ANSI attribute API used by TC in this plugin ABI.

BOOL WINAPI FsSetAttrW(LPCWSTR RemoteName, int NewAttr)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        // Use std::wstring instead of std::array<WCHAR, wdirtypemax>
        std::wstring remotedirW(wdirtypemax, L'\0');
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedirW.data(), remotedirW.size() - 1);
        remotedirW.resize(wcslen(remotedirW.data()));
        if (serverid == nullptr)
            return false;
        ResetLastPercent(serverid);
        // Use std::string instead of std::array<char, wdirtypemax>
        std::string remotedirA(wdirtypemax, '\0');
        walcopy(remotedirA.data(), remotedirW.data(), remotedirA.size() - 1);
        remotedirA.resize(strlen(remotedirA.data()));
        int rc = SftpSetAttr(serverid, remotedirA.data(), NewAttr);
        return (rc == SFTP_OK) ? true : false;
    });
}

BOOL WINAPI FsSetAttr(LPCSTR RemoteName, int NewAttr)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<char, wdirtypemax> remotedir{};
        pConnectSettings serverid = GetServerIdAndRelativePathFromPath(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return false;
        ResetLastPercent(serverid);
        int rc = SftpSetAttr(serverid, remotedir.data(), NewAttr);
        return (rc == SFTP_OK) ? true : false;
    });
}

BOOL WINAPI FsSetTimeW(LPCWSTR RemoteName, LPFILETIME CreationTime, LPFILETIME LastAccessTime, LPFILETIME LastWriteTime)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};
        if (remoteView.size() < 3 || !LastWriteTime)
            return false;

        // Use std::wstring instead of std::array<WCHAR, wdirtypemax>
        std::wstring remotedir(wdirtypemax, L'\0');
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        remotedir.resize(wcslen(remotedir.data()));
        if (serverid == nullptr)
            return false;
        ResetLastPercent(serverid);
        int rc = SftpSetDateTimeW(serverid, remotedir.data(), LastWriteTime);
        return (rc == SFTP_OK) ? true : false;
    });
}

BOOL WINAPI FsSetTime(LPCSTR RemoteName, LPFILETIME CreationTime, LPFILETIME LastAccessTime, LPFILETIME LastWriteTime)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsSetTimeW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), CreationTime, LastAccessTime, LastWriteTime);
    });
}

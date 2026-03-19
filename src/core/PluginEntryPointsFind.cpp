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
#include "PhpAgentClient.h"

// RAII guard for a freshly-established server connection.
// Prevents connection leaks on error paths without manual cleanup pairing.
//
// Registered variant (name non-empty): on rollback, calls SetServerIdForName(nullptr)
//   which closes the session and deletes the settings object via the registry.
// Unregistered variant (name empty): directly calls SftpCloseConnection + delete.
// commit() disarms the guard — ownership is transferred permanently to the registry.
class ConnectionGuard {
public:
    ConnectionGuard(pConnectSettings cs, LPCSTR registeredName) noexcept
        : cs_(cs), name_(registeredName ? registeredName : "") {}

    void commit() noexcept { cs_ = nullptr; }

    ~ConnectionGuard() noexcept {
        if (!cs_) return;
        if (!name_.empty())
            SetServerIdForName(name_.c_str(), nullptr);
        else {
            SftpCloseConnection(cs_);
            delete cs_;
        }
    }

    ConnectionGuard(const ConnectionGuard&) = delete;
    ConnectionGuard& operator=(const ConnectionGuard&) = delete;

private:
    pConnectSettings cs_;
    std::string name_;
};

// ---------------------------------------------------------------------------
// Find handle state types
// ---------------------------------------------------------------------------

struct LanPairFindState {
    std::vector<LanPairSession::DirEntry> entries;
    size_t index = 0;
};

typedef struct {
    LPVOID           sftpdataptr;    /* LIBSSH2_SFTP_HANDLE, SCP_DATA, or LanPairFindState* */
    pConnectSettings serverid;
    SERVERHANDLE     rootfindhandle;
    bool             rootfindfirst;
    bool             isLanPair;  /* if true, sftpdataptr is LanPairFindState* */
} tLastFindStuct, *pLastFindStuct;

static HANDLE CreateLastFindHandle(LPVOID sftpdataptr, pConnectSettings serverid, bool rootfindfirst) noexcept
{
    auto lfMem = std::make_unique<tLastFindStuct>();
    lfMem->sftpdataptr = sftpdataptr;
    lfMem->serverid = serverid;
    lfMem->rootfindhandle = nullptr;
    lfMem->rootfindfirst = rootfindfirst;
    lfMem->isLanPair = false;
    return static_cast<HANDLE>(lfMem.release());
}

// ---------------------------------------------------------------------------
// LAN Pair helpers for directory enumeration
// ---------------------------------------------------------------------------

// Convert a wide TC remote path to a UTF-8 Windows path for the LAN protocol.
// TC uses backslash separators; the remote side expects Windows paths directly.
std::string LanRemotePathToUtf8(LPCWSTR remotedir)
{
    if (!remotedir || !remotedir[0])
        return "\\";
    int needed = WideCharToMultiByte(CP_UTF8, 0, remotedir, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return "\\";
    std::string s(needed - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, remotedir, -1, s.data(), needed, nullptr, nullptr);
    return s;
}

// Fill a WIN32_FIND_DATAW from a LAN Pair DirEntry.
static void LanFillFindData(WIN32_FIND_DATAW* fd, const LanPairSession::DirEntry& e)
{
    *fd = {};
    MultiByteToWideChar(CP_UTF8, 0, e.name.c_str(), -1,
                        fd->cFileName, static_cast<int>(MAX_PATH - 1));
    fd->ftLastWriteTime = e.lastWrite;
    fd->dwFileAttributes = e.isDir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    if (e.winAttrs)
        fd->dwFileAttributes = e.winAttrs;
    if (!e.isDir) {
        fd->nFileSizeLow  = static_cast<DWORD>(e.size & 0xFFFFFFFF);
        fd->nFileSizeHigh = static_cast<DWORD>((e.size >> 32) & 0xFFFFFFFF);
    }
}

// Create a find handle for a LAN Pair directory result.
static HANDLE LanCreateFindHandle(std::vector<LanPairSession::DirEntry> entries,
                                  WIN32_FIND_DATAW* FindData,
                                  pConnectSettings serverid)
{
    auto state = std::make_unique<LanPairFindState>();
    state->entries = std::move(entries);
    state->index   = 0;

    auto lf = std::make_unique<tLastFindStuct>();
    lf->serverid      = serverid;
    lf->rootfindhandle = nullptr;
    lf->rootfindfirst  = false;
    lf->isLanPair      = true;

    if (state->entries.empty()) {
        lf->sftpdataptr = state.release();
        SetLastError(ERROR_NO_MORE_FILES);
        // Return a valid handle so TC calls FindClose — even if no files.
        return static_cast<HANDLE>(lf.release());
    }

    LanFillFindData(FindData, state->entries[0]);
    state->index = 1;
    lf->sftpdataptr = state.release();
    return static_cast<HANDLE>(lf.release());
}

HANDLE WINAPI FsFindFirstW(LPCWSTR Path, LPWIN32_FIND_DATAW FindData)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, INVALID_HANDLE_VALUE, [&]() -> HANDLE {
        int hr = ERROR_SUCCESS;
        std::array<WCHAR, wdirtypemax> remotedir{};
        std::array<char, wdirtypemax> displayName{};
        std::array<char, wdirtypemax> pathA{};

        if (wcscmp(Path, L"\\") == 0) {  // in the root.
            ApplyTcLanguageToPluginResources(g_wincmdIniPath);
            std::array<char, 256> s_helptext{};
            LoadString(hinst, IDS_HELPTEXT, s_helptext.data(), static_cast<int>(s_helptext.size()));
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            *FindData = {};

            awlcopy(FindData->cFileName, s_f7newconnection, countof(FindData->cFileName)-1);
            FindData->dwFileAttributes = 0;
            SetInt64ToFileTime(&FindData->ftLastWriteTime, FS_TIME_UNKNOWN);
            FindData->nFileSizeLow = static_cast<DWORD>(strlen(s_helptext.data()));
            return CreateLastFindHandle(nullptr, nullptr, true);
        }

        pConnectSettings serverid = nullptr;
        pConnectSettings new_serverid = nullptr;
        LPVOID sftpdataptr = nullptr;

        // load server list if user connects directly via URL
        LoadServersFromIniW(inifilenameW, s_quickconnect);
        // Disable reading only within an active server context.
        if (disablereading && IsMainThread()) {
            SetLastError(ERROR_NO_MORE_FILES);
            return INVALID_HANDLE_VALUE;
        }
        walcopy(pathA.data(), Path, pathA.size() - 1);
        GetDisplayNameFromPath(pathA.data(), displayName.data(), displayName.size() - 1);
        serverid = static_cast<pConnectSettings>(GetServerIdFromName(displayName.data(), GetCurrentThreadId()));
        bool wasconnected = serverid != nullptr;
        if (!wasconnected) {
            new_serverid = SftpConnectToServer(displayName.data(), inifilename, nullptr);
            if (!new_serverid) {
                SetLastError(ERROR_PATH_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
            serverid = new_serverid;
            SetServerIdForName(displayName.data(), static_cast<SERVERID>(serverid));
        }
        // Connection to the selected server is now established.

        // Guard rolls back a fresh connection on any error path below.
        // No-op when wasconnected (existing connection must not be torn down on listing failure).
        ConnectionGuard newConnGuard(wasconnected ? nullptr : serverid,
                                     wasconnected ? nullptr : displayName.data());

        *FindData = {};

        GetServerIdAndRelativePathFromPathW(Path, remotedir.data(), remotedir.size() - 1);

        // LAN Pair: use our own directory enumeration.
        if (IsLanPairTransport(serverid)) {
            SFTP_LOG("LAN", "FsFindFirstW LAN path='%S'", Path);
            if (!serverid->lanSession || !serverid->lanSession->isConnected()) {
                SFTP_LOG("LAN", "FsFindFirstW: no active lanSession");
                SetLastError(ERROR_CONNECTION_REFUSED);
                return INVALID_HANDLE_VALUE;
            }
            const std::string remotePathUtf8 = LanRemotePathToUtf8(remotedir.data());
            SFTP_LOG("LAN", "FsFindFirstW remotePathUtf8='%s'", remotePathUtf8.c_str());
            // Root (empty or single backslash) → list available drives.
            if (remotePathUtf8.empty() || remotePathUtf8 == "\\" || remotePathUtf8 == "/") {
                std::vector<std::string> roots;
                if (!serverid->lanSession->listRoots(roots) || roots.empty()) {
                    SFTP_LOG("LAN", "FsFindFirstW: listRoots failed or empty");
                    SetLastError(ERROR_NO_MORE_FILES);
                    return INVALID_HANDLE_VALUE;
                }
                std::vector<LanPairSession::DirEntry> driveEntries;
                driveEntries.reserve(roots.size());
                for (const auto& r : roots) {
                    LanPairSession::DirEntry e;
                    e.isDir = true;
                    e.name  = r;  // e.g. "C:\\"
                    // Remove trailing backslash for display: show "C:" etc.
                    if (!e.name.empty() && e.name.back() == '\\')
                        e.name.pop_back();
                    driveEntries.push_back(std::move(e));
                }
                newConnGuard.commit();
                HANDLE hdl = LanCreateFindHandle(std::move(driveEntries), FindData, serverid);
                return hdl;
            }
            // Regular directory listing.
            std::vector<LanPairSession::DirEntry> entries;
            if (!serverid->lanSession->listDirectory(remotePathUtf8, entries)) {
                SetLastError(ERROR_PATH_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
            newConnGuard.commit();
            return LanCreateFindHandle(std::move(entries), FindData, serverid);
        }

        // Retrieve the directory
        bool ok = (SFTP_OK == SftpFindFirstFileW(serverid, remotedir.data(), &sftpdataptr));

        if (wcslen(remotedir.data()) <= 1 || wcscmp(remotedir.data() + 1, L"home") == 0) {    // root -> add ~ link to home dir
            SYSTEMTIME st;
            wcslcpy(FindData->cFileName, L"~", countof(FindData->cFileName)-1);
            GetSystemTime(&st);
            SystemTimeToFileTime(&st, &FindData->ftLastWriteTime);
            FindData->dwFileAttributes = FS_ATTR_UNIXMODE;
            FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK | kHomeSymlinkMode;

            newConnGuard.commit();  // root listing: connection is permanent
            return CreateLastFindHandle(ok ? sftpdataptr : nullptr, serverid, false);
        }
        if (!ok) {
            if (!wasconnected) freportconnect = false;
            // newConnGuard destructor fires: SetServerIdForName(name, nullptr) → close + delete
            SetLastError(ERROR_PATH_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }

        newConnGuard.commit();  // directory listing succeeded: connection is permanent
        if (SFTP_OK == SftpFindNextFileW(serverid, sftpdataptr, FindData)) {
            return CreateLastFindHandle(sftpdataptr, serverid, false);
        }
        SftpFindClose(serverid, sftpdataptr);
        SetLastError(ERROR_NO_MORE_FILES);
        return INVALID_HANDLE_VALUE;
    });
}

HANDLE WINAPI FsFindFirst(LPCSTR Path, LPWIN32_FIND_DATA FindData)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, INVALID_HANDLE_VALUE, [&]() -> HANDLE {
        WIN32_FIND_DATAW FindDataW;
        std::array<WCHAR, wdirtypemax> pathW{};
        HANDLE retval = FsFindFirstW(awlcopy(pathW.data(), Path, pathW.size() - 1), &FindDataW);
        if (retval != INVALID_HANDLE_VALUE)
            copyfinddatawa(FindData, &FindDataW);
        return retval;
    });
}

BOOL WINAPI FsFindNextW(HANDLE Hdl, LPWIN32_FIND_DATAW FindData)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        pLastFindStuct lf;
        std::array<char, wdirtypemax> name{};

        // Root enumeration sentinel used by FsFindFirstW for helper pseudo-entry.
        if (Hdl == kFsFindRootSentinel)
            return false;

        lf = (pLastFindStuct)Hdl;
        if (!lf || lf == INVALID_HANDLE_VALUE)
            return false;

        if (lf->rootfindfirst) {
            name[0] = 0;
            SERVERHANDLE hdl = FindFirstServer(name.data(), name.size() - 1);
            if (!hdl)
                return false;
            awlcopy(FindData->cFileName, name.data(), countof(FindData->cFileName)-1);
            lf->rootfindhandle = hdl;
            lf->rootfindfirst = false;
            SetInt64ToFileTime(&FindData->ftLastWriteTime, FS_TIME_UNKNOWN);
            FindData->dwFileAttributes = FS_ATTR_UNIXMODE;
            FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK; // Link entry.
            FindData->nFileSizeLow = 0;
            return true;
        }
        if (lf->rootfindhandle) {
            name[0] = 0;
            lf->rootfindhandle = FindNextServer(lf->rootfindhandle, name.data(), name.size() - 1);
            if (!lf->rootfindhandle)
                return false;
            awlcopy(FindData->cFileName, name.data(), countof(FindData->cFileName)-1);
            FindData->dwFileAttributes = FS_ATTR_UNIXMODE;
            FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK; // Link entry.
            return true;
        }
        if (lf->isLanPair) {
            auto* state = static_cast<LanPairFindState*>(lf->sftpdataptr);
            if (!state || state->index >= state->entries.size())
                return false;
            LanFillFindData(FindData, state->entries[state->index++]);
            return true;
        }
        if (lf->sftpdataptr) {
            int rc = SftpFindNextFileW(lf->serverid, lf->sftpdataptr, FindData);
            return (rc == SFTP_OK) ? true : false;
        }
        return false;
    });
}

BOOL WINAPI FsFindNext(HANDLE Hdl, LPWIN32_FIND_DATA FindData)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        WIN32_FIND_DATAW FindDataW;
        copyfinddataaw(&FindDataW, FindData);
        BOOL retval = FsFindNextW(Hdl, &FindDataW);
        if (retval)
            copyfinddatawa(FindData, &FindDataW);
        return retval;
    });
}

int WINAPI FsFindClose(HANDLE Hdl)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        if (!Hdl || Hdl == INVALID_HANDLE_VALUE)
            return 0;
        pLastFindStuct lf = (pLastFindStuct)Hdl;
        if (lf->isLanPair) {
            delete static_cast<LanPairFindState*>(lf->sftpdataptr);
            lf->sftpdataptr = nullptr;
        } else if (lf->sftpdataptr) {
            SftpFindClose(lf->serverid, lf->sftpdataptr);
            lf->sftpdataptr = nullptr;
        }
        if (lf->rootfindhandle) {
            FindCloseServer(lf->rootfindhandle);
            lf->rootfindhandle = nullptr;
        }
        delete lf;
        return 0;
    });
}

BOOL WINAPI FsMkDirW(LPCWSTR Path)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        const std::wstring_view pathView = Path ? std::wstring_view(Path) : std::wstring_view{};
        if (pathView.size() < 2)
            return false;

        const bool hasRemoteSubPath = pathView.find(L'\\', 1) != std::wstring_view::npos;
        if (hasRemoteSubPath) {
            // Use std::wstring instead of std::array<WCHAR, wdirtypemax>
            std::wstring remotedir(wdirtypemax, L'\0');
            pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(Path, remotedir.data(), remotedir.size() - 1);
            remotedir.resize(wcslen(remotedir.data()));
            if (!serverid)
                return false;
            if (IsLanPairTransport(serverid)) {
                if (!serverid->lanSession || !serverid->lanSession->isConnected()) return false;
                return serverid->lanSession->mkdir(LanRemotePathToUtf8(remotedir.data()));
            }
            // PHP Agent TAR mode: skip remote mkdir; directories are created by TAR extraction.
            // Also start TAR session here if not already active (e.g. single-directory copy).
            if (IsPhpAgentTransport(serverid) && serverid->php_tar) {
                SFTP_LOG("TAR", "FsMkDirW TAR: dir='%S' tarWasActive=%d",
                         remotedir.data(), TarUploadSessionIsActive(serverid) ? 1 : 0);
                if (!TarUploadSessionIsActive(serverid))
                    TarUploadSessionBegin(serverid);
                return true;
            }
            int rc = SftpCreateDirectoryW(serverid, remotedir.data());
            return (rc == SFTP_OK) ? true : false;
        }
        // new connection
        // Use std::string instead of std::array<char, wdirtypemax>
        std::string remotedirA(wdirtypemax, '\0');
        walcopy(remotedirA.data(), Path + 1, remotedirA.size() - 1);
        remotedirA.resize(strlen(remotedirA.data()));

        // Capture TC main window before opening any modal dialog (GetActiveWindow is valid here)
        HWND hTcPanel = GetActiveWindow();
        HWND hTcMain  = hTcPanel ? GetAncestor(hTcPanel, GA_ROOTOWNER) : nullptr;
        if (!hTcMain)
            hTcMain = FindWindowA("TTOTAL_CMD", nullptr);

        // Handling cases where user presses F7 on virtual items and accepts the autofilled name
        if (strcmp(remotedirA.data(), s_quickconnect) == 0 || strcmp(remotedirA.data(), s_f7newconnection) == 0) {
            SftpConnectToServer(s_quickconnect, inifilename, nullptr);
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
            return true;
        }

        // Normal new named connection
        if (SftpConfigureServer(remotedirA.data(), inifilename)) {
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
            return true;
        }
        return false;
    });
}

BOOL WINAPI FsMkDir(LPCSTR Path)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!Path || !Path[0])
            return false;
        std::array<WCHAR, wdirtypemax> wbuf{};
        return FsMkDirW(awlcopy(wbuf.data(), Path, wbuf.size() - 1));
    });
}

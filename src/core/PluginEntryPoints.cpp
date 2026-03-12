// sertransplg.cpp : Defines the entry point for the DLL application.
// Total Commander SFTP filesystem plugin entry points.
// Maintainer: Marek Wesolowski (wesmar)

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

// Declared in SftpConnection.cpp
void StartGlobalLanServices();
void StopGlobalLanServices();

HINSTANCE hinst = nullptr;
HWND hWndMain = nullptr;

#define defininame  "sftpplug.ini"
#define defininamew L"sftpplug.ini"
#define templatefile "sftpplug.tpl"
char    inifilename[MAX_PATH]  = defininame;   // ANSI path (legacy / read-only)
wchar_t inifilenameW[MAX_PATH] = defininamew;  // Unicode path (preferred for all ini calls)
char pluginname[] = "SFTP";
char defrootname[] = "Secure FTP";

char s_f7newconnection[32];
char s_quickconnect[32];
std::array<WCHAR, 32> s_f7newconnectionW{};
std::array<WCHAR, 32> s_quickconnectW{};

bool disablereading = false;   // disable reading of subdirs to delete whole drives
bool freportconnect = true;    // report connect to caller only on first connect
bool CryptCheckPass = false;   // check 'store password encrypted' by default

int PluginNumber = 0;
int CryptoNumber = 0;
DWORD mainthreadid = 0;
tProgressProc  ProgressProc = nullptr;
tProgressProcW ProgressProcW = nullptr;
tLogProc       LogProc = nullptr;
tLogProcW      LogProcW = nullptr;
tRequestProc   RequestProc = nullptr;
tRequestProcW  RequestProcW = nullptr;
tCryptProc     CryptProc = nullptr;
static bool g_winsockInitialized = false;
static constexpr DWORD kHomeSymlinkMode = 0555;
static const HANDLE kFsFindRootSentinel = (HANDLE)1;
static LANGID g_configuredUiLangId = 0;

static LANGID DetectTcUiLangIdFromIni(const char* tcIniPath) noexcept
{
    if (!tcIniPath || !tcIniPath[0]) {
        return 0;
    }

    std::array<char, MAX_PATH> expandedIniPath{};
    const DWORD expanded = ExpandEnvironmentStringsA(tcIniPath, expandedIniPath.data(),
                                                     static_cast<DWORD>(expandedIniPath.size()));
    const char* iniPath = tcIniPath;
    if (expanded > 0 && expanded < expandedIniPath.size()) {
        iniPath = expandedIniPath.data();
    }

    std::array<char, MAX_PATH> languageIni{};
    GetPrivateProfileStringA("Configuration", "LanguageIni", "", languageIni.data(),
                             static_cast<DWORD>(languageIni.size()), iniPath);
    if (!languageIni[0]) {
        return 0;
    }

    // Normalize to uppercase to make matching robust across naming conventions.
    CharUpperBuffA(languageIni.data(), static_cast<DWORD>(strlen(languageIni.data())));
    std::string normalized(languageIni.data());

    auto has = [&normalized](const char* token) noexcept -> bool {
        return normalized.find(token) != std::string::npos;
    };

    // Common TC naming patterns:
    // - WCMD_PL.LNG / WCMD_POL.LNG
    // - WCMD_DE.LNG / WCMD_DEU.LNG
    // - WCMD_FR.LNG / WCMD_FRA.LNG
    // - WCMD_ES.LNG / WCMD_ESP.LNG
    if (has("_PL") || has(".PL") || has("POL")) {
        return MAKELANGID(LANG_POLISH, SUBLANG_DEFAULT);
    }
    if (has("_DE") || has(".DE") || has("DEU") || has("GER")) {
        return MAKELANGID(LANG_GERMAN, SUBLANG_GERMAN);
    }
    if (has("_FR") || has(".FR") || has("FRA") || has("FRE")) {
        return MAKELANGID(LANG_FRENCH, SUBLANG_FRENCH);
    }
    if (has("_ES") || has(".ES") || has("ESP") || has("SPA")) {
        return MAKELANGID(LANG_SPANISH, SUBLANG_SPANISH_MODERN);
    }
    if (has("_EN") || has(".EN") || has("ENU") || has("ENG")) {
        return MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
    }

    return 0;
}

static void ApplyTcLanguageToPluginResources(const char* tcIniPath) noexcept
{
    const LANGID langId = DetectTcUiLangIdFromIni(tcIniPath);
    if (langId == 0) {
        return;
    }

    g_configuredUiLangId = langId;

    // Make Win32 resource lookup prefer the language configured in Total Commander.
    SetThreadUILanguage(langId);
    SetThreadLocale(MAKELCID(langId, SORT_DEFAULT));

    // Refresh cached strings that were initially loaded in DllMain.
    LoadStringW(hinst, IDS_F7NEW, s_f7newconnectionW.data(), static_cast<int>(s_f7newconnectionW.size()) - 1);
    walcopy(s_f7newconnection, s_f7newconnectionW.data(), countof(s_f7newconnection) - 1);
    LoadStringW(hinst, IDS_QUICKCONNECT, s_quickconnectW.data(), static_cast<int>(s_quickconnectW.size()) - 1);
    walcopy(s_quickconnect, s_quickconnectW.data(), countof(s_quickconnect) - 1);
}

void ApplyConfiguredUiLanguageForCurrentThread() noexcept
{
    if (g_configuredUiLangId == 0) {
        return;
    }
    SetThreadUILanguage(g_configuredUiLangId);
    SetThreadLocale(MAKELCID(g_configuredUiLangId, SORT_DEFAULT));
}

LANGID GetConfiguredUiLanguageId() noexcept
{
    return g_configuredUiLangId;
}


BOOL APIENTRY DllMain( HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        hinst = (HINSTANCE)hModule;
        LoadStringW(hinst, IDS_F7NEW, s_f7newconnectionW.data(), static_cast<int>(s_f7newconnectionW.size()) - 1);
        walcopy(s_f7newconnection, s_f7newconnectionW.data(), countof(s_f7newconnection) - 1);
        LoadStringW(hinst, IDS_QUICKCONNECT, s_quickconnectW.data(), static_cast<int>(s_quickconnectW.size()) - 1);
        walcopy(s_quickconnect, s_quickconnectW.data(), countof(s_quickconnect) - 1);
    }
    if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        // Stop LAN services before CRT destroys global objects
        StopGlobalLanServices();
        ShutdownMultiServer();
        if (g_winsockInitialized) {
            WSACleanup();
            g_winsockInitialized = false;
        }
        // Release DbgHelp symbol tables — required for clean reload
        sftp::ShutdownSymbols();
    }
    return true;
}

// Returns true when operation should be aborted by user/progress callback.
static bool MessageLoop(pConnectSettings ConnectSettings) noexcept
{
    bool aborted = false;
    if (ConnectSettings && get_ticks_between(ConnectSettings->lastpercenttime) > PROGRESS_UPDATE_MS) {
        // Keep this call after soft_aborted is set.
        // Prefer the Unicode variant (set by FsInitW); fall back to ANSI (set by FsInit).
        WCHAR* src = ConnectSettings->current_sourceW[0] ? ConnectSettings->current_sourceW : nullptr;
        WCHAR* dst = ConnectSettings->current_targetW[0] ? ConnectSettings->current_targetW : nullptr;

        if (ProgressProcW)
            aborted = (0 != ProgressProcW(PluginNumber, src, dst, ConnectSettings->lastpercent));
        else if (ProgressProc) {
            std::array<char, wdirtypemax> srcA{}, dstA{};
            if (src) walcopyCP(ConnectSettings->codepage, srcA.data(), src, srcA.size()-1);
            if (dst) walcopyCP(ConnectSettings->codepage, dstA.data(), dst, dstA.size()-1);
            aborted = (0 != ProgressProc(PluginNumber, src ? srcA.data() : nullptr, dst ? dstA.data() : nullptr, ConnectSettings->lastpercent));
        }
        // Allow cancellation with Escape when no progress dialog is shown.
        ConnectSettings->lastpercenttime = get_sys_ticks();
    }
    return aborted;
}

void LogMsg(LPCSTR fmt, ...) noexcept
{
    std::array<char, 512> buf{};
    va_list argptr;
    va_start(argptr, fmt);
    int len = _vsnprintf(buf.data(), buf.size() - 2, fmt, argptr);
    va_end(argptr);
    if (len < 0) {
        strcpy_s(buf.data(), buf.size(), "<INCORRECT-INPUT-DATA> ");
        strcat_s(buf.data(), buf.size(), fmt);
    } else {
        buf[static_cast<size_t>(len)] = 0;
    }
    LogProc(PluginNumber, MSGTYPE_DETAILS, buf.data());
}

void ShowStatus(LPCSTR status) noexcept
{
    if (LogProc)
        LogProc(PluginNumber, MSGTYPE_DETAILS, status);
}

void ShowStatusW(LPCWSTR status) noexcept
{
    LogProcT(PluginNumber, MSGTYPE_DETAILS, status);
}

// Returns true when operation should be aborted by user/progress callback.
bool UpdatePercentBar(pConnectSettings ConnectSettings, int percent, LPCWSTR source, LPCWSTR target) noexcept
{
    if (ConnectSettings) {
        ConnectSettings->lastpercent = percent;  // used for MessageLoop below
        if (source)
            wcslcpy(ConnectSettings->current_sourceW, source, countof(ConnectSettings->current_sourceW) - 1);

        if (target)
            wcslcpy(ConnectSettings->current_targetW, target, countof(ConnectSettings->current_targetW) - 1);
    }

    return MessageLoop(ConnectSettings);  // Updates the percent bar.
}

static pConnectSettings GetServerIdAndRelativePathFromPath(LPCSTR Path, LPSTR RelativePath, size_t maxlen)
{
    if (!Path || !RelativePath || maxlen == 0)
        return nullptr;

    auto extractRelative = [](std::string_view path) -> std::string_view {
        const size_t firstNonSlash = path.find_first_not_of("\\/");
        if (firstNonSlash == std::string_view::npos)
            return std::string_view{};
        const size_t sep = path.find_first_of("\\/", firstNonSlash);
        if (sep == std::string_view::npos)
            return std::string_view{};
        return path.substr(sep);
    };

    std::array<char, wdirtypemax> displayName{};
    GetDisplayNameFromPath(Path, displayName.data(), displayName.size() - 1);
    pConnectSettings serverid = static_cast<pConnectSettings>(GetServerIdFromName(displayName.data(), GetCurrentThreadId()));
    if (serverid) {
        const std::string_view rel = extractRelative(Path);
        if (!rel.empty()) {
            const size_t copyLen = (std::min)(rel.size(), maxlen - 1);
            memcpy(RelativePath, rel.data(), copyLen);
            RelativePath[copyLen] = '\0';
        } else {
            strlcpy(RelativePath, "\\", maxlen - 1);
        }
    } else {
        strlcpy(RelativePath, "\\", maxlen - 1);
    }
    return serverid;
}

static pConnectSettings GetServerIdAndRelativePathFromPathW(LPCWSTR Path, LPWSTR RelativePath, size_t maxlen)
{
    if (!Path || !RelativePath || maxlen == 0)
        return nullptr;

    auto extractRelativeW = [](std::wstring_view path) -> std::wstring_view {
        const size_t firstNonSlash = path.find_first_not_of(L"\\/");
        if (firstNonSlash == std::wstring_view::npos)
            return std::wstring_view{};
        const size_t sep = path.find_first_of(L"\\/", firstNonSlash);
        if (sep == std::wstring_view::npos)
            return std::wstring_view{};
        return path.substr(sep);
    };

    std::array<char, wdirtypemax> displayName{};
    const std::wstring_view pathView(Path);
    const size_t firstNonSlash = pathView.find_first_not_of(L"\\/");
    if (firstNonSlash == std::wstring_view::npos)
        return nullptr;
    const size_t sep = pathView.find_first_of(L"\\/", firstNonSlash);
    const std::wstring_view displayW = (sep == std::wstring_view::npos)
        ? pathView.substr(firstNonSlash)
        : pathView.substr(firstNonSlash, sep - firstNonSlash);
    walcopy(displayName.data(), std::wstring(displayW).c_str(), displayName.size() - 1);

    pConnectSettings serverid = static_cast<pConnectSettings>(GetServerIdFromName(displayName.data(), GetCurrentThreadId()));
    if (serverid) {
        const std::wstring_view rel = extractRelativeW(pathView);
        if (!rel.empty()) {
            const size_t copyLen = (std::min)(rel.size(), maxlen - 1);
            wmemcpy(RelativePath, rel.data(), copyLen);
            RelativePath[copyLen] = L'\0';
        } else {
            wcslcpy(RelativePath, L"\\", maxlen - 1);
        }
    } else {
        wcslcpy(RelativePath, L"\\", maxlen - 1);
    }
    return serverid;
}

__forceinline
static void ResetLastPercent(pConnectSettings ConnectSettings)
{
    if (ConnectSettings)
        ConnectSettings->lastpercent = 0;
}

static bool is_full_name(LPCSTR path)
{
    return path && path[0] && path[1] && strchr(path + 1, '\\');
}

static bool is_full_name(LPCWSTR path)
{
    return path && path[0] && path[1] && wcschr(path + 1, L'\\');
}

static bool is_full_name(LPWSTR path)
{
    return path && path[0] && path[1] && wcschr(path + 1, L'\\');
}

static LPWSTR cut_srv_name(LPWSTR path)
{
    if (path && path[0] && path[1]) {
        LPWSTR p = wcschr(path + 1, L'\\');
        if (p) {
            p[0] = 0;
            return path + 1;
        }
    }
    return nullptr;
}


static int _FsInit(int PluginNr)
{
    if (!g_winsockInitialized) {
        WSADATA wsaData{};
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return 1;
        }
        g_winsockInitialized = true;
    }
    PluginNumber = PluginNr;
    mainthreadid = GetCurrentThreadId();
    InitMultiServer();
    StartGlobalLanServices();  // Start LAN Pair file server + discovery in background
    return 0;
}

int WINAPI FsInit(int PluginNr, tProgressProc pProgressProc, tLogProc pLogProc, tRequestProc pRequestProc)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 1, [&]() -> int {
        ProgressProc = pProgressProc;
        LogProc = pLogProc;
        RequestProc = pRequestProc;
        return _FsInit(PluginNr);
    });
}

int WINAPI FsInitW(int PluginNr, tProgressProcW pProgressProcW, tLogProcW pLogProcW, tRequestProcW pRequestProcW)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 1, [&]() -> int {
        ProgressProcW = pProgressProcW;
        LogProcW = pLogProcW;
        RequestProcW = pRequestProcW;
        return _FsInit(PluginNr);
    });
}

void WINAPI FsSetCryptCallback(tCryptProc pCryptProc, int CryptoNr, int Flags)
{
    sftp::DllExceptionBarrier _barrier;
    sftp::dll_invoke_void(_barrier, [&] {
        CryptProc = pCryptProc;
        CryptCheckPass = (Flags & FS_CRYPTOPT_MASTERPASS_SET) != 0;
        CryptoNumber = CryptoNr;
    });
}

// LAN Pair directory enumeration state.
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

BOOL WINAPI FsDisconnect(LPCSTR DisconnectRoot)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        // Use std::string instead of std::array<char, wdirtypemax>
        std::string displayName;
        displayName.resize(wdirtypemax);
        GetDisplayNameFromPath(DisconnectRoot, displayName.data(), displayName.size() - 1);
        displayName.resize(strlen(displayName.data()));
    
        pConnectSettings serverid = static_cast<pConnectSettings>(GetServerIdFromName(displayName.data(), GetCurrentThreadId()));
        if (serverid) {
            // Build disconnect log message using std::string
            std::string connBuf = "DISCONNECT \\";
            connBuf += displayName;
            LogProc(PluginNumber, MSGTYPE_DISCONNECT, connBuf.c_str());
            SftpCloseConnection(serverid);
            SetServerIdForName(displayName.data(), nullptr); // this also frees the entry.
        }
        return true;
    });
}
 
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
// LAN Pair helpers for directory enumeration
// ---------------------------------------------------------------------------

// Convert a wide TC remote path to a UTF-8 Windows path for the LAN protocol.
// TC uses backslash separators; the remote side expects Windows paths directly.
static std::string LanRemotePathToUtf8(LPCWSTR remotedir)
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
            int rc = SftpCreateDirectoryW(serverid, remotedir.data());
            return (rc == SFTP_OK) ? true : false;
        }
        // new connection
        // Use std::string instead of std::array<char, wdirtypemax>
        std::string remotedirA(wdirtypemax, '\0');
        walcopy(remotedirA.data(), Path + 1, remotedirA.size() - 1);
        remotedirA.resize(strlen(remotedirA.data()));

        // Handling cases where user presses F7 on virtual items and accepts the autofilled name
        if (strcmp(remotedirA.data(), s_quickconnect) == 0 || strcmp(remotedirA.data(), s_f7newconnection) == 0) {
            // Pop the Quick Connect dialog
            SftpConnectToServer(s_quickconnect, inifilename, nullptr);
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            return true;
        }

        // Normal new named connection
        if (SftpConfigureServer(remotedirA.data(), inifilename)) {
            LoadServersFromIniW(inifilenameW, s_quickconnect);
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
        if (remoteView.size() < 3)
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

// Status callbacks are handled through ANSI entry in current plugin ABI.
void WINAPI FsStatusInfo(LPCSTR RemoteDir, int InfoStartEnd, int InfoOperation)
{
    sftp::DllExceptionBarrier _barrier;
    sftp::dll_invoke_void(_barrier, [&] {
        if (strlen(RemoteDir) < 2)
            if (InfoOperation == FS_STATUS_OP_DELETE || InfoOperation == FS_STATUS_OP_RENMOV_MULTI)
                disablereading = (InfoStartEnd == FS_STATUS_START) ? true : false;

        if (InfoOperation == FS_STATUS_OP_GET_MULTI_THREAD || InfoOperation == FS_STATUS_OP_PUT_MULTI_THREAD) {
            if (InfoStartEnd != FS_STATUS_START) {
                FsDisconnect(RemoteDir);
                return;
            }
            std::array<char, MAX_PATH> displayName{};
            const char* oldpass = nullptr;
            GetDisplayNameFromPath(RemoteDir, displayName.data(), displayName.size() - 1);
            // get password from main thread
            pConnectSettings oldserverid = static_cast<pConnectSettings>(GetServerIdFromName(displayName.data(), mainthreadid));
            if (oldserverid) {
                oldpass = oldserverid->password.c_str();
                if (!oldpass[0])
                    oldpass = nullptr;
            }
            pConnectSettings serverid = SftpConnectToServer(displayName.data(), inifilename, oldpass);
            if (serverid)
                SetServerIdForName(displayName.data(), static_cast<SERVERID>(serverid));
        }
    });
}

void WINAPI FsGetDefRootName(LPSTR DefRootName, int maxlen)
{
    sftp::DllExceptionBarrier _barrier;
    sftp::dll_invoke_void(_barrier, [&] {
        if (!DefRootName || maxlen <= 0)
            return;
        strlcpy(DefRootName, defrootname, maxlen);
    });
}

// Use the default location but keep the plugin-specific INI file name.
void WINAPI FsSetDefaultParams(FsDefaultParamStruct * dps)
{
    sftp::DllExceptionBarrier _barrier;
    sftp::dll_invoke_void(_barrier, [&] {
        std::array<char, MAX_PATH> tcIniPath{};
        strlcpy(tcIniPath.data(), dps->DefaultIniName, tcIniPath.size() - 1);
        char* slash = strrchr(tcIniPath.data(), '\\');
        if (slash) {
            slash[1] = '\0';
            strlcat(tcIniPath.data(), "wincmd.ini", tcIniPath.size() - 1);
        }

        // Align plugin resource language with Total Commander language setting.
        ApplyTcLanguageToPluginResources(tcIniPath.data());

        strlcpy(inifilename, dps->DefaultIniName, MAX_PATH-1);
        LPSTR p = strrchr(inifilename, '\\');
        if (p)
            p[1] = 0;
        else
            inifilename[0] = 0;
        strlcat(inifilename, defininame, countof(inifilename)-1);

        // Build the Unicode version of the ini path so that ini access works
        // correctly even when the user profile directory contains non-ANSI characters.
        MultiByteToWideChar(CP_ACP, 0, inifilename, -1, inifilenameW, MAX_PATH);

        // Copy INI template from plugin directory if present.
        std::array<char, MAX_PATH> templateName{};
        DWORD len = GetModuleFileName(hinst, templateName.data(), templateName.size() - 1);
        if (len > 0) {
            LPSTR p = strrchr(templateName.data(), '\\');
            if (p) {
                p[1] = 0;
                strlcat(templateName.data(), templatefile, templateName.size() - 1);
            }
            CopyFileA(templateName.data(), inifilename, true);  // only copy if target doesn't exist
        }
    });
}

int WINAPI FsExtractCustomIcon(LPCSTR RemoteName, int ExtractFlags, HICON * TheIcon)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_ICON_USEDEFAULT, [&]() -> int {
        if (strlen(RemoteName) > 1) {
            if (!is_full_name(RemoteName)) {   // a server.
                if (_stricmp(RemoteName + 1, s_f7newconnection) != 0) {
                    std::array<char, wdirtypemax> remotedir{};
                    pConnectSettings serverid = GetServerIdAndRelativePathFromPath(RemoteName, remotedir.data(), remotedir.size() - 1);
                    bool sm = (ExtractFlags & FS_ICONFLAG_SMALL) != 0;
                    // Show a different icon when connected.
                    LPCSTR lpIconName = serverid
                        ? MAKEINTRESOURCEA(sm ? IDI_ICON2SMALL : IDI_ICON2)
                        : MAKEINTRESOURCEA(sm ? IDI_ICON1SMALL : IDI_ICON1);
                    *TheIcon = LoadIconA(hinst, lpIconName);
                    return FS_ICON_EXTRACTED;
                }
            }
        } 
        return FS_ICON_USEDEFAULT;
    });
}

int WINAPI FsGetBackgroundFlags(void)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        return BG_DOWNLOAD | BG_UPLOAD | BG_ASK_USER;
    });
}

int WINAPI FsServerSupportsChecksumsW(LPCWSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        std::array<WCHAR, wdirtypemax> remotedir{};
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return 0;
        ResetLastPercent(serverid);
        return SftpServerSupportsChecksumsW(serverid, remotedir.data());
    });
}

int WINAPI FsServerSupportsChecksums(LPCSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsServerSupportsChecksumsW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1));
    });
}

HANDLE WINAPI FsStartFileChecksumW(int ChecksumType, LPCWSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, nullptr, [&]() -> HANDLE {
        std::array<WCHAR, wdirtypemax> remotedir{};
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return nullptr;
        ResetLastPercent(serverid);
        return SftpStartFileChecksumW(ChecksumType, serverid, remotedir.data());
    });
}

HANDLE WINAPI FsStartFileChecksum(int ChecksumType, LPCSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, nullptr, [&]() -> HANDLE {
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsStartFileChecksumW(ChecksumType, awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1));
    });
}


int WINAPI FsGetFileChecksumResultW(BOOL WantResult, HANDLE ChecksumHandle, LPCWSTR RemoteName, LPSTR checksum, int maxlen)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        std::array<WCHAR, wdirtypemax> remotedir{};
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return 0;
        ResetLastPercent(serverid);
        return SftpGetFileChecksumResultW(!!WantResult, ChecksumHandle, serverid, checksum, maxlen);
    });
}

int WINAPI FsGetFileChecksumResult(BOOL WantResult, HANDLE ChecksumHandle, LPCSTR RemoteName, LPSTR checksum, int maxlen)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsGetFileChecksumResultW(!!WantResult, ChecksumHandle, awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), checksum, maxlen);
    });
}
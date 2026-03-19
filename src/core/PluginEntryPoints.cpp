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
#include "LngLoader.h"
#include "PhpAgentClient.h"

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
char g_wincmdIniPath[MAX_PATH] = {};    // path to wincmd.ini, used for live language detection
char pluginname[] = "SFTP";
char defrootname[] = "Secure FTP";

char s_f7newconnection[32];
char s_quickconnect[64];
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
    // - WCMD_IT.LNG / WCMD_ITA.LNG
    // - WCMD_RU.LNG  / WCMD_RUS.LNG
    // - WCMD_CZ.LNG / WCMD_CSY.LNG
    // - WCMD_HU.LNG / WCMD_HUN.LNG
    // - WCMD_JP.LNG / WCMD_JPN.LNG
    // - WCMD_NL.LNG / WCMD_NLD.LNG
    // - WCMD_BR.LNG / WCMD_PTB.LNG
    // - WCMD_RO.LNG / WCMD_ROM.LNG
    // - WCMD_SK.LNG / WCMD_SKY.LNG
    // - WCMD_UA.LNG / WCMD_UKR.LNG
    // - WCMD_SC.LNG / WCMD_CHS.LNG
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
    if (has("_IT") || has(".IT") || has("ITA")) {
        return MAKELANGID(LANG_ITALIAN, SUBLANG_ITALIAN);
    }
    if (has("_RU") || has(".RU") || has("RUS")) {
        return MAKELANGID(LANG_RUSSIAN, SUBLANG_DEFAULT);
    }
    if (has("_CZ") || has(".CZ") || has("CSY") || has("_CS")) {
        return MAKELANGID(LANG_CZECH, SUBLANG_DEFAULT);
    }
    if (has("_HU") || has(".HU") || has("HUN")) {
        return MAKELANGID(LANG_HUNGARIAN, SUBLANG_DEFAULT);
    }
    if (has("_JP") || has(".JP") || has("JPN")) {
        return MAKELANGID(LANG_JAPANESE, SUBLANG_DEFAULT);
    }
    if (has("_NL") || has(".NL") || has("NLD") || has("HOL")) {
        return MAKELANGID(LANG_DUTCH, SUBLANG_DUTCH);
    }
    if (has("_BR") || has("PTB") || has("PT-B")) {
        return MAKELANGID(LANG_PORTUGUESE, SUBLANG_PORTUGUESE_BRAZILIAN);
    }
    if (has("_RO") || has(".RO") || has("ROM") || has("RUM")) {
        return MAKELANGID(LANG_ROMANIAN, SUBLANG_DEFAULT);
    }
    if (has("_SK") || has(".SK") || has("SKY")) {
        return MAKELANGID(LANG_SLOVAK, SUBLANG_DEFAULT);
    }
    if (has("_UA") || has(".UA") || has("UKR") || has("_UK")) {
        return MAKELANGID(LANG_UKRAINIAN, SUBLANG_DEFAULT);
    }
    if (has("_SC") || has("_CN") || has("CHS") || has("CHI") || has("CHN")) {
        return MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED);
    }
    if (has("_EN") || has(".EN") || has("ENU") || has("ENG")) {
        return MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
    }

    return 0;
}

void ApplyTcLanguageToPluginResources(const char* tcIniPath) noexcept
{
    const LANGID langId = DetectTcUiLangIdFromIni(tcIniPath);
    if (langId == 0) {
        return;
    }

    g_configuredUiLangId = langId;

    // Load external .lng file for non-English languages; clears any previous load.
    LngLoadForLanguage(langId, hinst);

    // Make Win32 resource lookup prefer the language configured in Total Commander.
    SetThreadUILanguage(langId);
    SetThreadLocale(MAKELCID(langId, SORT_DEFAULT));

    // Refresh cached strings: prefer .lng translation, fall back to compiled RC resource.
    const char* f7Str = LngGetString(IDS_F7NEW);
    if (f7Str) {
        std::wstring wF7 = unicode_util::utf8_to_wstring(f7Str);
        wcsncpy_s(s_f7newconnectionW.data(), s_f7newconnectionW.size(), wF7.c_str(), _TRUNCATE);
    } else {
        LoadStringW(hinst, IDS_F7NEW, s_f7newconnectionW.data(), static_cast<int>(s_f7newconnectionW.size()) - 1);
    }
    walcopy(s_f7newconnection, s_f7newconnectionW.data(), countof(s_f7newconnection) - 1);

    const char* qcStr = LngGetString(IDS_QUICKCONNECT);
    if (qcStr) {
        std::wstring wQc = unicode_util::utf8_to_wstring(qcStr);
        wcsncpy_s(s_quickconnectW.data(), s_quickconnectW.size(), wQc.c_str(), _TRUNCATE);
    } else {
        LoadStringW(hinst, IDS_QUICKCONNECT, s_quickconnectW.data(), static_cast<int>(s_quickconnectW.size()) - 1);
    }
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

pConnectSettings GetServerIdAndRelativePathFromPath(LPCSTR Path, LPSTR RelativePath, size_t maxlen)
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

pConnectSettings GetServerIdAndRelativePathFromPathW(LPCWSTR Path, LPWSTR RelativePath, size_t maxlen)
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
void ResetLastPercent(pConnectSettings ConnectSettings)
{
    if (ConnectSettings)
        ConnectSettings->lastpercent = 0;
}

bool is_full_name(LPCSTR path)
{
    return path && path[0] && path[1] && strchr(path + 1, '\\');
}

bool is_full_name(LPCWSTR path)
{
    return path && path[0] && path[1] && wcschr(path + 1, L'\\');
}

bool is_full_name(LPWSTR path)
{
    return path && path[0] && path[1] && wcschr(path + 1, L'\\');
}

LPWSTR cut_srv_name(LPWSTR path)
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


// Detects and applies TC language if not already loaded.
// Called from both FsSetDefaultParams and _FsInit to cover all load orders.
static void DetectAndApplyLanguage(const char* fallbackIniPath) noexcept
{
    if (g_wincmdIniPath[0])
        return;  // Already loaded by a prior call.

    std::array<char, MAX_PATH> tcIniPath{};

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Ghisler\\Total Commander",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type = 0;
        DWORD bytes = static_cast<DWORD>(tcIniPath.size()) - 1;
        if (RegQueryValueExA(hKey, "IniFileName", nullptr, &type,
                             reinterpret_cast<LPBYTE>(tcIniPath.data()), &bytes) == ERROR_SUCCESS
            && (type == REG_SZ || type == REG_EXPAND_SZ)) {
            // Path retrieved from registry (may contain %APPDATA% etc.)
        } else {
            tcIniPath[0] = '\0';
        }
        RegCloseKey(hKey);
    }

    if (!tcIniPath[0] && fallbackIniPath && fallbackIniPath[0]) {
        strlcpy(tcIniPath.data(), fallbackIniPath, tcIniPath.size() - 1);
        char* slash = strrchr(tcIniPath.data(), '\\');
        if (slash) {
            slash[1] = '\0';
            strlcat(tcIniPath.data(), "wincmd.ini", tcIniPath.size() - 1);
        }
    }

    if (tcIniPath[0]) {
        strlcpy(g_wincmdIniPath, tcIniPath.data(), MAX_PATH - 1);
        ApplyTcLanguageToPluginResources(g_wincmdIniPath);
    }
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

    // Load language now in case FsSetDefaultParams was not called yet or registry lookup failed.
    DetectAndApplyLanguage(nullptr);

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
// Status callbacks are handled through ANSI entry in current plugin ABI.
void WINAPI FsStatusInfo(LPCSTR RemoteDir, int InfoStartEnd, int InfoOperation)
{
    sftp::DllExceptionBarrier _barrier;
    sftp::dll_invoke_void(_barrier, [&] {
        SFTP_LOG("STATUS", "FsStatusInfo op=%d %s dir='%s'",
                 InfoOperation,
                 InfoStartEnd == FS_STATUS_START ? "START" : "END",
                 RemoteDir ? RemoteDir : "");

        if (strlen(RemoteDir) < 2)
            if (InfoOperation == FS_STATUS_OP_DELETE || InfoOperation == FS_STATUS_OP_RENMOV_MULTI)
                disablereading = (InfoStartEnd == FS_STATUS_START) ? true : false;

        if (InfoOperation == FS_STATUS_OP_PUT_MULTI ||
            InfoOperation == FS_STATUS_OP_PUT_SINGLE) {
            std::array<char, wdirtypemax> remotedir{};
            pConnectSettings cs = GetServerIdAndRelativePathFromPath(RemoteDir, remotedir.data(), remotedir.size() - 1);
            if (InfoStartEnd == FS_STATUS_START) {
                SFTP_LOG("STATUS", "PUT START: php_tar=%d isPhpAgent=%d tarActive=%d",
                         cs ? cs->php_tar : -1,
                         cs ? IsPhpAgentTransport(cs) : -1,
                         TarUploadSessionIsActive() ? 1 : 0);
                if (cs && IsPhpAgentTransport(cs) && cs->php_tar)
                    TarUploadSessionBegin(cs);
            } else {
                SFTP_LOG("STATUS", "PUT END: tarActive=%d", TarUploadSessionIsActive() ? 1 : 0);
                if (TarUploadSessionIsActive()) {
                    const int rc = TarUploadSessionExecuteAndClear();
                    SFTP_LOG("STATUS", "PUT END: TarExecute rc=%d", rc);
                    if (rc != SFTP_OK && rc != SFTP_ABORT)
                        ShowStatusId(IDS_LOG_TAR_UPLOAD_FAIL, nullptr, false);
                }
            }
        }

        if (InfoOperation == FS_STATUS_OP_GET_MULTI_THREAD || InfoOperation == FS_STATUS_OP_PUT_MULTI_THREAD) {
            if (InfoStartEnd != FS_STATUS_START) {
                if (InfoOperation == FS_STATUS_OP_PUT_MULTI_THREAD && TarUploadSessionIsActive()) {
                    const int rc = TarUploadSessionExecuteAndClear();
                    if (rc != SFTP_OK && rc != SFTP_ABORT)
                        ShowStatusId(IDS_LOG_TAR_UPLOAD_FAIL, nullptr, false);
                }
                FsDisconnect(RemoteDir);
                return;
            }
            std::array<char, MAX_PATH> displayName{};
            const char* oldpass = nullptr;
            GetDisplayNameFromPath(RemoteDir, displayName.data(), displayName.size() - 1);
            // get password from main thread
            pConnectSettings oldserverid = static_cast<pConnectSettings>(GetServerIdFromName(displayName.data(), mainthreadid));
            if (oldserverid) {
                if (InfoOperation == FS_STATUS_OP_PUT_MULTI_THREAD
                    && IsPhpAgentTransport(oldserverid) && oldserverid->php_tar)
                    TarUploadSessionBegin(nullptr);  // cs filled in by first FsPutFileW
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
        if (dps) {
            // Detect wincmd.ini from registry, falling back to the path derived from dps->DefaultIniName.
            DetectAndApplyLanguage(dps->DefaultIniName);
        }

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

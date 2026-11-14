#pragma once

#include <array>
#include <string>
#include <windows.h>
#include "SftpClient.h"
#include "SftpInternal.h"

// Constants shared across all entry-point TUs.
static constexpr DWORD kHomeSymlinkMode = 0555;
static const HANDLE kFsFindRootSentinel = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(1));

// Globals defined in PluginEntryPoints.cpp, used across all entry-point TUs.
extern char    inifilename[MAX_PATH];
extern wchar_t inifilenameW[MAX_PATH];
extern char    g_wincmdIniPath[MAX_PATH];
extern char    s_f7newconnection[32];
extern std::array<WCHAR, 32> s_f7newconnectionW;
extern std::array<WCHAR, 32> s_quickconnectW;
extern bool    disablereading;
extern bool    freportconnect;
// True while TC is running a multi-step transfer through our plugin
// (RENMOV_MULTI: bulk copy/move). FsMkDir checks this to tell apart
// "user pressed F7 to create a new session" from "TC is auto-creating a
// destination folder mid-transfer" — the latter must not pop the Edit
// Session dialog.
extern bool    g_inMultiOpTransfer;

// Path helpers — defined in PluginEntryPoints.cpp, used across all entry-point TUs.
pConnectSettings GetServerIdAndRelativePathFromPath(LPCSTR Path, LPSTR RelativePath, size_t maxlen);
pConnectSettings GetServerIdAndRelativePathFromPathW(LPCWSTR Path, LPWSTR RelativePath, size_t maxlen);

// Re-scans every channel of one import source into the cache, as
// [Refresh] does (PluginEntryPointsFile.cpp).
void RefreshImportSource(const std::string& sourceId);
void  ResetLastPercent(pConnectSettings ConnectSettings);
void  ApplyTcLanguageToPluginResources(const char* tcIniPath) noexcept;

// Show a message the way Total Commander shows its own: through RequestProcW,
// falling back to MessageBoxW only where that callback is missing. Both ids
// carry a fallback string for the case where no .lng is loaded. `icon` reaches
// the fallback path only — TC picks its own for RT_MsgOK.
void  ShowPluginMessage(UINT messageId, const char* messageFallback,
                        UINT titleId,   const char* titleFallback,
                        UINT icon = MB_ICONWARNING);

// LAN path conversion — defined in PluginEntryPointsFind.cpp, also used by PluginEntryPointsFile.cpp.
std::string LanRemotePathToUtf8(LPCWSTR remotedir);

// Magic virtual-folder name shown in the plugin root only while at least one
// session is connected. Entering it lists every active session; F8 on a row
// disconnects that session; F8 on `kDisconnectAllEntry` disconnects all.
inline constexpr const char*    kActiveSessionsFolder  = "[Active Sessions]";
inline constexpr const wchar_t* kActiveSessionsFolderW = L"[Active Sessions]";
inline constexpr const char*    kDisconnectAllEntry    = "[Disconnect All]";

// Path classifier for the [Active Sessions] magic folder. Returns true if
// `path` points at the folder itself (e.g. "\\[Active Sessions]") or at any
// entry inside it; on inside-entry matches the leaf name is converted to a
// narrow ANSI string with backslashes normalised to forward slashes (so
// folder-nested DisplayNames like "home/raspi" round-trip cleanly) and
// written into `outEntry`. On folder-itself matches `outEntry` is cleared.
// Implementation in PluginEntryPointsFind.cpp.
bool IsActiveSessionsPath(LPCWSTR path, std::string* outEntry = nullptr);

// Magic virtual-folder listing the proxy records every session can point at.
// Always present: it is where a first record is created, with F7. A row is
// one record, named by the same description the connection dialog shows in
// its dropdown, which begins with the record's number. Enter edits a record,
// F8 deletes one.
inline constexpr const char*    kProxiesFolder  = "[Proxies]";
inline constexpr const wchar_t* kProxiesFolderW = L"[Proxies]";

// Path classifier for [Proxies], shaped like IsActiveSessionsPath: true for
// the folder itself, with `outEntry` cleared, or for a row inside it, with the
// row's name written to `outEntry`.
bool IsProxiesPath(LPCWSTR path, std::string* outEntry = nullptr);

// The record number a [Proxies] row name begins with, or 0 when the name does
// not start with one. Row names are built by DescribeProxyRecordW, so the
// number is always the leading digits before ':'.
int ProxyNrFromRowName(const std::string& rowName);

// Umbrella folder in the plugin root that groups every known import source
// under a single entry, avoiding one-folder-per-source clutter in the root.
// Its children are the registered adapters' FolderName() values (always all
// of them, detection state only affects the display suffix). Content of
// [Imports]\<Source>\ is served from ImportCache (persistent snapshot) plus
// adapter-driven pseudo entries.
inline constexpr const char*    kImportsFolder      = "[Imports]";
inline constexpr const wchar_t* kImportsFolderW     = L"[Imports]";
inline constexpr const char*    kRefreshEntry       = "[Refresh]";
inline constexpr const char*    kAddCustomEntry     = "[Add custom location...]";
inline constexpr const char*    kManageCustomFolder = "[Manage custom locations]";

// Path classifier for the [Imports] magic folder tree. Each variant tells
// callers unambiguously what part of the tree `path` addresses; the boolean
// combinations that used to be re-derived from (outSourceId.empty(),
// outSubPath.empty()) at every call site now correspond to a single enum
// value each.
enum class ImportsPathKind {
    NotImports,     // path is not under \[Imports]
    Umbrella,       // path is \[Imports] itself (no source segment)
    UnknownSource,  // path is under \[Imports] but the source segment does
                    // not match any registered adapter — callers refuse it
    SourceRoot,     // \[Imports]\<Source> or \[Imports]\<Source>\ (no subpath)
    SourceSubPath,  // \[Imports]\<Source>\<something-after>
};

// Classify `path` against the [Imports] tree. For every non-NotImports
// result:
//   outSourceId is the lowercase adapter SourceId() when the source
//               segment matched a registered adapter (SourceRoot,
//               SourceSubPath); empty for Umbrella / UnknownSource.
//   outSubPath  is what comes after \[Imports]\<Source>\, with backslashes
//               normalised to forward slashes (mirrors IsActiveSessionsPath);
//               non-empty only for SourceSubPath. For UnknownSource it holds
//               the unrecognised segment plus any trailing path so a caller
//               can log or display it.
// Implementation in PluginEntryPointsFind.cpp.
ImportsPathKind ClassifyImportsPath(LPCWSTR path,
                                    std::string* outSourceId = nullptr,
                                    std::string* outSubPath  = nullptr);

// Boolean convenience: is `path` under \[Imports] at all? Callers that only
// need "yes/no" (e.g. FsFindFirstW dispatch, FsPutFile no-op guard) use this
// wrapper; callers that need to distinguish umbrella from source-level or
// SourceRoot from SourceSubPath call ClassifyImportsPath directly.
inline bool IsImportsPath(LPCWSTR path,
                          std::string* outSourceId = nullptr,
                          std::string* outSubPath  = nullptr)
{
    return ClassifyImportsPath(path, outSourceId, outSubPath) !=
           ImportsPathKind::NotImports;
}

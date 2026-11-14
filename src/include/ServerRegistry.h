#pragma once

#include <string>

typedef LPVOID  SERVERID;
typedef LPVOID  SERVERHANDLE;

// Lifecycle
void InitMultiServer() noexcept;
void ShutdownMultiServer() noexcept;   // DeleteCriticalSection + FreeServerList
void FreeServerList() noexcept;

// Ini access — Unicode (W) variants accept a pre-computed wide path so that
// the ini file may live under a Unicode directory. The ANSI shims convert
// and delegate to the W variants; prefer the W forms in new code.
int  LoadServersFromIniW(LPCWSTR inifilename, LPCSTR quickconnectname) noexcept;
bool DeleteServerFromIniW(LPCSTR servername, LPCWSTR inifilename) noexcept;
int  CopyMoveServerInIniW(LPCSTR oldservername, LPCSTR newservername, bool Move, bool OverWrite, LPCWSTR inifilename) noexcept;

int  LoadServersFromIni(LPCSTR inifilename, LPCSTR quickconnectname) noexcept;
bool DeleteServerFromIni(LPCSTR servername, LPCSTR inifilename) noexcept;
int  CopyMoveServerInIni(LPCSTR oldservername, LPCSTR newservername, bool Move, bool OverWrite, LPCSTR inifilename) noexcept;

// Server id lookup / registration
SERVERID GetServerIdFromName(LPCSTR servername, DWORD threadid) noexcept;
bool SetServerIdForName(LPCSTR displayname, SERVERID newid) noexcept;

// Thread-agnostic full disconnect: find every registry entry with `name`
// across ALL threads (main + any background), close the underlying SSH
// session exactly once (via the first non-null serverid), free the
// tConnectSettings memory once, and drop every entry. Returns the number
// of entries removed. Zero means the name was not registered anywhere.
//
// Used by FsDisconnect — TC can call the WFX disconnect entry from a
// non-main thread, and the per-thread lookup pattern
// `GetServerIdFromName(name, GetCurrentThreadId())` returns null in that
// case even when the main-thread entry exists, so the connection would
// otherwise be leaked.
size_t DisconnectServerByName(LPCSTR name) noexcept;

// Path helpers
void GetDisplayNameFromPath(LPCSTR Path, LPSTR DisplayName, size_t maxlen) noexcept;

// Folder-aware path resolution. Consults the loaded session registry
// (g_servers) and decides what a TC-style path refers to. Used by every
// entry point that must distinguish "session vs folder vs remote sub-path".
//
// Algorithm: normalise leading slashes off and convert '\' to '/', then
// longest-prefix-match against saved session names. If a prefix is a real
// session and equals the full path → SessionLeaf. If a prefix is a real
// session and the path has more segments after it → SessionWithSubpath
// (those segments become `relative`, restored to backslash form). If no
// prefix matches but at least one session starts with `path/` → Folder.
// Otherwise → Invalid.
enum class PathKind {
    SessionLeaf,         // path resolves to a saved session; nothing after
    SessionWithSubpath,  // path enters a saved session and has remote sub-path
    Folder,              // path is a folder prefix containing at least one session
    Invalid,             // path matches nothing in the registry
};

struct PathResolution {
    PathKind     kind = PathKind::Invalid;
    std::string  displayName;  // session name (Session*) or folder prefix (Folder); empty for Invalid / root
    std::string  relative;     // server sub-path after the session prefix, '\\'-separated; empty unless SessionWithSubpath
    // The same sub-path taken from the caller's Unicode path (ResolvePathKindW
    // only). `relative` went through the ANSI code page and loses every
    // character outside it; remote paths must be built from this one.
    std::wstring relativeW;
};

PathResolution ResolvePathKind(LPCSTR path) noexcept;
PathResolution ResolvePathKindW(LPCWSTR path) noexcept;

// Convert a TC-style path to a canonical session DisplayName form:
// strips leading slashes and converts '\\' separators to '/'. Used when
// constructing the *target* name for create/rename operations where the
// resolver can't yet find the session in the registry (because it doesn't
// exist there until after this call commits).
std::string PathToDisplayName(LPCSTR path) noexcept;
std::string PathToDisplayNameW(LPCWSTR path) noexcept;

SERVERHANDLE FindFirstServer(LPSTR displayname, size_t maxlen) noexcept;
SERVERHANDLE FindNextServer(SERVERHANDLE searchhandle, LPSTR displayname, size_t maxlen) noexcept;
void FindCloseServer(SERVERHANDLE searchhandle) noexcept;

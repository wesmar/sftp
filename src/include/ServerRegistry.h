#pragma once

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

// Path helpers
void GetDisplayNameFromPath(LPCSTR Path, LPSTR DisplayName, size_t maxlen) noexcept;

SERVERHANDLE FindFirstServer(LPSTR displayname, size_t maxlen) noexcept;
SERVERHANDLE FindNextServer(SERVERHANDLE searchhandle, LPSTR displayname, size_t maxlen) noexcept;
void FindCloseServer(SERVERHANDLE searchhandle) noexcept;

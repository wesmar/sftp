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

// Path helpers — defined in PluginEntryPoints.cpp, used across all entry-point TUs.
pConnectSettings GetServerIdAndRelativePathFromPath(LPCSTR Path, LPSTR RelativePath, size_t maxlen);
pConnectSettings GetServerIdAndRelativePathFromPathW(LPCWSTR Path, LPWSTR RelativePath, size_t maxlen);
void  ResetLastPercent(pConnectSettings ConnectSettings);
bool  is_full_name(LPCSTR  path);
bool  is_full_name(LPCWSTR path);
bool  is_full_name(LPWSTR  path);
LPWSTR cut_srv_name(LPWSTR path);
void  ApplyTcLanguageToPluginResources(const char* tcIniPath) noexcept;

// LAN path conversion — defined in PluginEntryPointsFind.cpp, also used by PluginEntryPointsFile.cpp.
std::string LanRemotePathToUtf8(LPCWSTR remotedir);

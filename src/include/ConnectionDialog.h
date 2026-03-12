#pragma once

#include <windows.h>
#include <string>
#include "SftpClient.h"

INT_PTR WINAPI ProxyDlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam);
INT_PTR WINAPI ConnectDlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam);
bool ShowConnectDialog(pConnectSettings ConnectSettings, LPCSTR DisplayName, LPCSTR inifilename);
void fillProxyCombobox(HWND hWnd, int defproxynr, LPCSTR iniFileName);

// Helpers implemented in SftpConnection.cpp and used by dialog module.
bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName);
bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults, LPCSTR iniFileName);
void EnableControlsPageant(HWND hWnd, bool enable);
void UpdateKeyControlsForPrivateKey(HWND hWnd);
void UpdateScpOnlyDependentControls(HWND hWnd);
bool UpdateLocalPhpAgentScriptWithPassword(LPCSTR plainPassword);
bool GetPluginDirectoryA(std::string& outDir);
void OpenPluginHelp(HWND hWnd);

constexpr int kCodepageListCount = 24;
extern int codepagelist[kCodepageListCount];

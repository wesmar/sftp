#pragma once

#include "CoreUtils.h"
#include "fsplugin.h"
#include "SftpClient.h"

extern HINSTANCE hinst;
extern int PluginNumber;
extern int CryptoNumber;
extern DWORD mainthreadid;

extern tProgressProc  ProgressProc;
extern tProgressProcW ProgressProcW;
extern tLogProc       LogProc;
extern tLogProcW      LogProcW;
extern tRequestProc   RequestProc;
extern tRequestProcW  RequestProcW;
extern tCryptProc     CryptProc;

extern bool CryptCheckPass;

extern char pluginname[];

__forceinline
bool IsMainThread() noexcept
{
    return GetCurrentThreadId() == mainthreadid;
}

void LogMsg(LPCSTR fmt, ...) noexcept;
void ShowStatus(LPCSTR status) noexcept;
void ShowStatusW(LPCWSTR status) noexcept;
bool UpdatePercentBar(pConnectSettings ConnectSettings, int percent, LPCWSTR source = nullptr, LPCWSTR target = nullptr) noexcept;
void ApplyConfiguredUiLanguageForCurrentThread() noexcept;
LANGID GetConfiguredUiLanguageId() noexcept;



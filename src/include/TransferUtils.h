#pragma once

#include <windows.h>
#include <string>
#include "SftpClient.h"

int GetPercent(int64_t offset, int64_t filesize);
bool IsValidFileHandle(HANDLE hf) noexcept;
bool AskUserYesNo(pConnectSettings ConnectSettings, LPCSTR title, LPCSTR message);
std::string ToRemotePathA(pConnectSettings cs, LPCWSTR pathW);
int CheckInputOrTimeout(pConnectSettings ConnectSettings, bool timeout, SYSTICKS starttime, int percent);
int CloseRemote(pConnectSettings ConnectSettings, ISftpHandle* remotefilesftp, ISshChannel* remotefilescp, bool timeout, int percent);
int ConvertCrToCrLf(LPSTR data, size_t len, bool* pLastWasCr);
bool SftpDetermineTransferModeW(LPCWSTR RemoteName);

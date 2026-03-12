#pragma once

#include <windows.h>
#include <string>
#include "SftpClient.h"

int ConvertCrLfToCr(LPSTR data, size_t len);
void ShowTransferSpeedIfLarge(LPCSTR prefix, int64_t bytesTransferred, SYSTICKS starttime);
bool ScpWaitIo(pConnectSettings cs, bool forWrite);
bool ScpWriteAll(ISshChannel* channel, pConnectSettings cs, const char* data, size_t len, DWORD timeoutMs);
bool ScpReadByte(ISshChannel* channel, pConnectSettings cs, char* outByte, DWORD timeoutMs);
bool ScpReadLine(ISshChannel* channel, pConnectSettings cs, std::string& outLine, DWORD timeoutMs);
bool ScpSendAck(ISshChannel* channel, pConnectSettings cs);
bool ScpReadAck(ISshChannel* channel, pConnectSettings cs, std::string& err);

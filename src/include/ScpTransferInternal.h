#pragma once

#include <windows.h>
#include <string>
#include "SftpClient.h"

// ---------------------------------------------------------------------------
// Shared transfer buffer / block size constants.
// Defined here so SftpTransfer.cpp and ShellFallbackTransfer.cpp stay in sync.
// ---------------------------------------------------------------------------
inline constexpr size_t SFTP_MAX_READ_SIZE  = 30'000;
inline constexpr size_t SFTP_MAX_WRITE_SIZE = 30'000;
inline constexpr size_t SFTP_SCP_BLOCK_SIZE = 16'384;

inline constexpr int SFTP_SCP_READ_IDLE_TIMEOUT_MS  = 20'000;
inline constexpr int SFTP_SCP_WRITE_IDLE_TIMEOUT_MS = 20'000;

int ConvertCrLfToCr(LPSTR data, size_t len);
void ShowTransferSpeedIfLarge(LPCSTR prefix, int64_t bytesTransferred, SYSTICKS starttime);
bool ScpWaitIo(pConnectSettings cs, bool forWrite);
bool ScpWriteAll(ISshChannel* channel, pConnectSettings cs, const char* data, size_t len, DWORD timeoutMs);
bool ScpReadByte(ISshChannel* channel, pConnectSettings cs, char* outByte, DWORD timeoutMs);
bool ScpReadLine(ISshChannel* channel, pConnectSettings cs, std::string& outLine, DWORD timeoutMs);
bool ScpSendAck(ISshChannel* channel, pConnectSettings cs);
bool ScpReadAck(ISshChannel* channel, pConnectSettings cs, std::string& err);

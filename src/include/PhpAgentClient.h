#pragma once

#include "global.h"
#include "SftpClient.h"
#include <string>
#include <vector>

// PHP Agent transport operations.
// All functions return SFTP_OK / SFTP_* error codes used by the plugin.

int PhpAgentProbe(pConnectSettings cs);
int PhpAgentValidateAuth(pConnectSettings cs, std::string& outErrorText);
int PhpAgentListDirectoryW(pConnectSettings cs, LPCWSTR remoteDir, std::vector<WIN32_FIND_DATAW>& outEntries);
int PhpAgentDownloadFileW(pConnectSettings cs,
                          LPCWSTR remoteNameW, LPCWSTR localNameW,
                          bool alwaysOverwrite, int64_t hintedSize, bool resume);
int PhpAgentUploadFileW(pConnectSettings cs,
                        LPCWSTR localNameW, LPCWSTR remoteNameW, bool resume);
int PhpAgentCreateDirectoryW(pConnectSettings cs, LPCWSTR remoteDirW);
int PhpAgentRenameMoveFileW(pConnectSettings cs, LPCWSTR oldNameW, LPCWSTR newNameW, bool overwrite);
int PhpAgentDeleteFileW(pConnectSettings cs, LPCWSTR remoteNameW, bool isdir);
int PhpShellExecuteCommand(pConnectSettings cs,
                           const char* command,
                           std::string& outText,
                           std::string* outCwdAbs = nullptr,
                           const std::string* inCwdAbs = nullptr);

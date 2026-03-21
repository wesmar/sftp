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
int PhpAgentDownloadDirAsTar(pConnectSettings cs, LPCWSTR remoteDirW, LPCWSTR localDirW, bool overwrite);

struct TarUploadEntry {
    std::wstring localPath;
    std::string  tarName;    // relative path in archive (UTF-8, '/' separators)
    int64_t      fileSize = 0;
    time_t       mtime    = 0;
    bool         isDir    = false;
};

int  PhpAgentUploadDirAsTar(pConnectSettings cs, LPCWSTR remoteDirW,
                             const std::vector<TarUploadEntry>& entries);

// TAR upload session — manages deferred batch uploads triggered via FsStatusInfo.
void TarUploadSessionBegin(pConnectSettings cs);
void TarUploadSessionClear();
bool TarUploadSessionIsActive(pConnectSettings cs = nullptr);
bool TarUploadSessionQueue(pConnectSettings cs, LPCWSTR localPath, const char* remotePath);
int  TarUploadSessionExecuteAndClear();

struct TarDownloadEntry {
    std::string  remotePath;   // UTF-8, relative to agent root (e.g. "dir/file.txt")
    std::wstring localPath;    // local destination full path
};

int  PhpAgentDownloadFilesAsTar(pConnectSettings cs,
                                 const std::vector<TarDownloadEntry>& entries);

// TAR download session — batches FsGetFileW calls into a single TAR_PACK request.
void TarDownloadSessionBegin(pConnectSettings cs);
void TarDownloadSessionClear();
bool TarDownloadSessionIsActive(pConnectSettings cs = nullptr);
bool TarDownloadSessionQueue(pConnectSettings cs, LPCWSTR localPath, LPCWSTR remotePath);
int  TarDownloadSessionExecuteAndClear();

int PhpShellExecuteCommand(pConnectSettings cs,
                           const char* command,
                           std::string& outText,
                           std::string* outCwdAbs = nullptr,
                           const std::string* inCwdAbs = nullptr);

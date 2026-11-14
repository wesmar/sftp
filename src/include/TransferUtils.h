#pragma once

#include <windows.h>
#include <string>
#include "SftpClient.h"

int GetPercent(int64_t offset, int64_t filesize);
bool IsValidFileHandle(HANDLE hf) noexcept;
bool AskUserYesNo(pConnectSettings ConnectSettings, LPCSTR title, LPCSTR message);
std::string ToRemotePathA(pConnectSettings cs, LPCWSTR pathW);

// The same remote path, ready to be pasted into a command line the plugin
// builds itself. libssh2 quotes what it is given; a command assembled here
// does not, and an unquoted name carrying a space, a semicolon or a backtick
// would be read by the remote shell as syntax instead of as a file name.
std::string BuildShellScpArgument(const std::string& path);
int CheckInputOrTimeout(pConnectSettings ConnectSettings, bool timeout, SYSTICKS starttime, int percent);
int CloseRemote(pConnectSettings ConnectSettings, ISftpHandle* remotefilesftp, ISshChannel* remotefilescp, bool timeout, int percent);
bool SftpDetermineTransferModeW(LPCWSTR RemoteName);

// Exact size of a local file after CRLF -> LF conversion, measured with the
// converter the upload itself uses so an SCP header can announce it.
// Returns false when the file holds a NUL byte (binary: send it unconverted).
// The file pointer is restored to the start either way.
bool MeasureTextUpload(HANDLE file, int64_t& convertedSize);

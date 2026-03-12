#pragma once

#include <windows.h>
#include "SftpClient.h"

namespace sftp {

int ShowExternalSessionImportMenu(HWND owner,
                                  LPCSTR iniFileName,
                                  pConnectSettings applyTo,
                                  LPSTR importedSessionName = nullptr,
                                  size_t importedSessionNameSize = 0) noexcept;

}

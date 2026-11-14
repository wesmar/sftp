#pragma once

#include "global.h"
#include "SftpClient.h"

// Opens an interactive pseudo-terminal window for PHP shell mode. The window
// is a top-level one of its own and outlives the dialog that opened it.
void ShowPhpShellConsole(tConnectSettings settings);


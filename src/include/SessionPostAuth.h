#pragma once

#include <windows.h>
#include "SftpClient.h"

int SftpSessionDetectUtf8(pConnectSettings ConnectSettings);
int SftpSessionDetectLineBreaks(pConnectSettings ConnectSettings);
void RunPostAuthAutoDetect(pConnectSettings ConnectSettings);
void RunPostAuthUserCommand(pConnectSettings ConnectSettings, LPCSTR progressText, int progress, int* loop, SYSTICKS* lasttime);
void ResolveScpLargeFileProbe(pConnectSettings ConnectSettings);

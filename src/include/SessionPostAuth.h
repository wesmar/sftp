#pragma once

#include <windows.h>
#include "SftpClient.h"

int SftpSessionDetectUtf8(pConnectSettings ConnectSettings);
int SftpSessionDetectLineBreaks(pConnectSettings ConnectSettings);
int SftpSessionSendCommand(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int* ploop, SYSTICKS* plasttime);
void RunPostAuthAutoDetect(pConnectSettings ConnectSettings);
void RunPostAuthUserCommand(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int* loop, SYSTICKS* lasttime);
void ResolveScpLargeFileProbe(pConnectSettings ConnectSettings);

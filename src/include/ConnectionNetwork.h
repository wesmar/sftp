#pragma once

#include "SftpClient.h"

int EstablishSocketConnection(pConnectSettings ConnectSettings, LPCSTR connecttoserver, unsigned short connecttoport, int& progress, int& loop, SYSTICKS& lasttime);
bool InitializeSftpSubsystemIfNeeded(pConnectSettings ConnectSettings, int progress, int* loop, SYSTICKS* lasttime);

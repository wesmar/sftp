#pragma once

#include <windows.h>
#include "SftpClient.h"

int SftpConnectProxyHttp(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int* ploop, SYSTICKS* plasttime);
int SftpConnectProxySocks4(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int* ploop, SYSTICKS* plasttime);
int SftpConnectProxySocks5(pConnectSettings ConnectSettings, int connecttoport, LPCSTR progressbuf, int progress, int* ploop, SYSTICKS* plasttime);


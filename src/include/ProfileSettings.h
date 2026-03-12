#pragma once
#include "SftpClient.h"

bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName);
bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults, LPCSTR iniFileName);

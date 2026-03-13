#pragma once

#include "SftpClient.h"

bool ValidateConnectState(pConnectSettings cs, int* outErrorCode);
bool ResolveConnectEndpoint(pConnectSettings cs, char* outHost, size_t outHostLen, unsigned short* outPort);
bool EnsureUserNameIfMissing(pConnectSettings cs);
int CleanupFailedConnect(
    pConnectSettings cs,
    int code,
    int* ioProgress,
    int* ioLoop,
    SYSTICKS* ioLastTime);

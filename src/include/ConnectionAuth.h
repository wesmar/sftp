#pragma once

#include "SftpClient.h"

int NegotiateProxy(
    pConnectSettings ConnectSettings,
    unsigned short connecttoport,
    int& progress,
    int& loop,
    SYSTICKS& lasttime);

int PerformAuthentication(
    pConnectSettings ConnectSettings,
    int& progress,
    int& loop,
    SYSTICKS& lasttime,
    char* progressbuf,
    bool agentAvailable);

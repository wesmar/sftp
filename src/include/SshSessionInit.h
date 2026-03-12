#pragma once

#include <memory>
#include "SftpClient.h"

struct ISshBackend;

int InitializeSshSession(
    pConnectSettings ConnectSettings,
    int& progress,
    int& loop,
    SYSTICKS& lasttime,
    std::unique_ptr<ISshBackend>& backend);

int VerifyServerFingerprint(pConnectSettings ConnectSettings);

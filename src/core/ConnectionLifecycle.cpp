#include "global.h"
#include <windows.h>
#include <array>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"
#include "fsplugin.h"
#include "res/resource.h"
#include "ConnectionLifecycle.h"

bool ValidateConnectState(pConnectSettings cs, int* outErrorCode)
{
    if (!cs || !outErrorCode)
        return false;
    *outErrorCode = SFTP_OK;

    if (cs->session) {
        *outErrorCode = SFTP_OK;
        return false;
    }
    if (cs->sftpsession) {
        *outErrorCode = -1;
        return false;
    }
    if (cs->sock != 0 && cs->sock != INVALID_SOCKET) {
        *outErrorCode = -2;
        return false;
    }
    return true;
}

bool ResolveConnectEndpoint(pConnectSettings cs, char* outHost, size_t outHostLen, unsigned short* outPort)
{
    if (!cs || !outHost || outHostLen == 0 || !outPort)
        return false;

    outHost[0] = 0;
    *outPort = 0;

    switch (cs->proxytype) {
    case sftp::Proxy::notused:
        strlcpy(outHost, cs->server.c_str(), outHostLen - 1);
        *outPort = cs->customport;
        return true;
    case sftp::Proxy::http:
        return ParseAddress(cs->proxyserver.c_str(), outHost, outPort, 8080);
    case sftp::Proxy::socks4:
    case sftp::Proxy::socks5:
        return ParseAddress(cs->proxyserver.c_str(), outHost, outPort, 1080);
    default:
        return false;
    }
}

bool EnsureUserNameIfMissing(pConnectSettings cs)
{
    if (!cs)
        return false;
    if (!cs->user.empty())
        return true;

    std::array<char, 250> titleLoaded{};
    LoadStr(titleLoaded.data(), IDS_USERNAME_FOR);
    const std::string title = std::string(titleLoaded.data()) + cs->server;
    std::array<char, MAX_PATH> userBuf{};
    if (!RequestProc(PluginNumber, RT_UserName, title.c_str(), nullptr, userBuf.data(), static_cast<int>(userBuf.size() - 1)))
        return false;
    cs->user = userBuf.data();
    return true;
}

int CleanupFailedConnect(
    pConnectSettings cs,
    int code,
    char* progressTextBuf,
    int* ioProgress,
    int* ioLoop,
    SYSTICKS* ioLastTime)
{
    if (!code || !cs || !progressTextBuf || !ioProgress || !ioLoop || !ioLastTime)
        return code;

    LoadStr(progressTextBuf, IDS_DISCONNECTING);
    int rc = 0;
    if (cs->sftpsession) {
        do {
            rc = cs->sftpsession->shutdown();
            if (ProgressLoop(progressTextBuf, *ioProgress, 90, ioLoop, ioLastTime))
                break;
            WaitForTransportReadable(cs);
        } while (rc == LIBSSH2_ERROR_EAGAIN);
        cs->sftpsession.reset();
        *ioProgress = 90;
    }
    if (cs->session) {
        int rc2 = 0;
        do {
            rc2 = cs->session->disconnect("Shutdown");
            if (ProgressLoop(progressTextBuf, *ioProgress, 100, ioLoop, ioLastTime))
                break;
            WaitForTransportReadable(cs);
        } while (rc2 == LIBSSH2_ERROR_EAGAIN);
        cs->session->free();
        cs->session.reset();
    }
    // Release transport stream AFTER the target session is already freed
    // (above) but BEFORE the jump socket closes.
    cs->transport_stream.reset();
    Sleep(RECONNECT_SLEEP_MS);
    if (cs->sock) {
        closesocket(cs->sock);
        cs->sock = 0;
    }
    return code;
}

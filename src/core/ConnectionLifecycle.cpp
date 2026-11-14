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
    LoadStr(titleLoaded, IDS_USERNAME_FOR);
    const std::string title = std::string(titleLoaded.data()) + cs->server;
    std::array<char, MAX_PATH> userBuf{};
    if (!RequestInput(RT_UserName, title.c_str(), nullptr, userBuf))
        return false;
    cs->user = userBuf.data();
    return true;
}

int CleanupFailedConnect(
    pConnectSettings cs,
    int code,
    int* ioProgress,
    int* ioLoop,
    SYSTICKS* ioLastTime)
{
    if (!code || !cs || !ioProgress || !ioLoop || !ioLastTime)
        return code;

    std::array<char, 512> progressTextBuf{};
    LoadStr(progressTextBuf, IDS_DISCONNECTING);

    // SFTP subsystem — destructor sends FXP_SHUTDOWN with bounded retry.
    cs->sftpsession.reset();
    *ioProgress = 90;

    // SSH session — fire-and-forget DISCONNECT (no ack expected per RFC 4253);
    // brief EAGAIN retry only to push the packet into the OS send buffer.
    if (cs->session) {
        SYSTICKS t0 = get_sys_ticks();
        int rc;
        do {
            rc = cs->session->disconnect("Shutdown");
            if (rc != LIBSSH2_ERROR_EAGAIN)
                break;
            if (get_ticks_between(t0) > 200)
                break;
            if (cs->sock != INVALID_SOCKET) {
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(cs->sock, &wfds);
                timeval tv = { 0, 20000 };  // 20 ms
                select(0, nullptr, &wfds, nullptr, &tv);
            }
        } while (true);
        cs->session.reset();   // ~Libssh2Session() frees the struct.
    }
    *ioProgress = 100;
    ProgressLoop(progressTextBuf.data(), *ioProgress, 100, ioLoop, ioLastTime);

    // Release transport stream (jump channel + jump session) before socket close.
    cs->transport_stream.reset();
    if (cs->sock != INVALID_SOCKET) {
        closesocket(cs->sock);
        cs->sock = INVALID_SOCKET;
    }
    return code;
}

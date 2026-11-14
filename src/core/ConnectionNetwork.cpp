#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <array>
#include <format>
#include "SftpClient.h"
#include "SftpInternal.h"
#include "PluginEntryPoints.h"
#include "CoreUtils.h"
#include "res/resource.h"
#include "ConnectionNetwork.h"

int EstablishSocketConnection(pConnectSettings ConnectSettings, LPCSTR connecttoserver, unsigned short connecttoport, int& progress, int& loop, SYSTICKS& lasttime)
{
    struct addrinfo hints{};
    bool connected = false;
    switch (ConnectSettings->protocoltype) {
    case 1:
        hints.ai_family = AF_INET;
        break;
    case 2:
        hints.ai_family = AF_INET6;
        break;
    default:
        hints.ai_family = AF_UNSPEC;
        break;
    }
    hints.ai_socktype = SOCK_STREAM;
    const std::string portStr = std::format("{}", connecttoport);
    std::array<char, 256> progressBuf{};
    struct addrinfo* res = nullptr;
    if (getaddrinfo(connecttoserver, portStr.c_str(), &hints, &res) != 0) {
        ShowErrorId(IDS_ERR_GETADDRINFO);
        if (LogProc) {
            const std::string msg = std::format("SFTP: DNS lookup failed for '{}' (WSA error {})", connecttoserver, WSAGetLastError());
            LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, msg.c_str());
        }
        return -20;
    }
    ConnectSettings->sock = INVALID_SOCKET;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        closesocket(ConnectSettings->sock);
        ConnectSettings->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (ConnectSettings->sock == INVALID_SOCKET)
            continue;
        std::array<char, NI_MAXHOST> host{};
        std::array<char, NI_MAXSERV> port{};
        if (getnameinfo(ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen), host.data(), static_cast<DWORD>(host.size()),
                        port.data(), static_cast<DWORD>(port.size()), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
            const bool v6 = ai->ai_family == AF_INET6;
            ShowStatus(std::format("IP address: {}{}{}:{}", v6 ? "[" : "", host.data(), v6 ? "]" : "", port.data()).c_str());
        }

        int nodelay = 1;
        setsockopt(ConnectSettings->sock, IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
        EnableTcpKeepAlive(ConnectSettings->sock);
        SetBlockingSocket(ConnectSettings->sock, false);
        connected = connect(ConnectSettings->sock, ai->ai_addr, (int)ai->ai_addrlen) == 0;
        if (!connected && WSAGetLastError() == WSAEWOULDBLOCK) {
            while (true) {
                if (IsSocketWritable(ConnectSettings->sock)) {
                    connected = true;
                    break;
                }
                if (IsSocketError(ConnectSettings->sock))
                    break;
                if (ProgressLoop(progressBuf.data(), 0, progress, &loop, &lasttime))
                    break;
            }
        }
        if (connected)
            break;
    }
    freeaddrinfo(res);

    if (!connected) {
        if (ConnectSettings->proxytype != sftp::Proxy::notused)
            ShowErrorId(IDS_ERR_PROXYCONNECT);
        else
            ShowErrorId(IDS_ERR_SERVERCONNECT);
        if (LogProc) {
            const std::string msg = std::format("SFTP: TCP connect failed to '{}:{}' (WSA error {})", connecttoserver, connecttoport, WSAGetLastError());
            LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, msg.c_str());
        }
        return -30;
    }
    return 0;
}

bool InitializeSftpSubsystemIfNeeded(pConnectSettings ConnectSettings, int progress, int* loop, SYSTICKS* lasttime)
{
    if (ConnectSettings->scponly)
        return true;

    std::array<char, 1024> buf{};
    char* errmsg = nullptr;
    int errmsg_len = 0;
    const std::string& serverCommand = ConnectSettings->sftpservercommand;
    ShowStatusId(IDS_LOG_SFTP_INIT, nullptr, true);
    if (serverCommand.empty())
        SFTP_LOG("CONN", "Initializing SFTP subsystem");
    else
        SFTP_LOG("CONN", "Initializing SFTP via server command: %s", serverCommand.c_str());
    ShowStatusId(IDS_SESSION_STARTUP, " (SFTP)", true);
    // A host with no SFTP subsystem — dropbear on a camera or a router —
    // may never answer the request, and the call keeps saying "not yet".
    // The wait is bounded so such a host fails instead of hanging.
    const SYSTICKS sftpInitStart = get_sys_ticks();
    bool sftpInitTimedOut = false;
    do {
        ConnectSettings->sftpsession = nullptr;
        if (ProgressLoop(buf.data(), progress, progress + 10, loop, lasttime))
            break;
        auto sftpPtr = ConnectSettings->session->sftpInit(serverCommand);
        if (sftpPtr) {
            ConnectSettings->sftpsession = std::move(sftpPtr);
        } else if (ConnectSettings->session->lastErrno() != LIBSSH2_ERROR_EAGAIN) {
            break;
        } else if (get_ticks_between(sftpInitStart) > SFTP_INIT_TIMEOUT_MS) {
            sftpInitTimedOut = true;
            break;
        }
        IsSocketReadable(ConnectSettings->sock);
    } while (!ConnectSettings->sftpsession);

    if (!ConnectSettings->sftpsession) {
        ConnectSettings->session->lastError(&errmsg, &errmsg_len, false);
        ShowStatusId(IDS_ERR_INIT_SFTP, errmsg, true);
        SFTP_LOG("CONN", "SFTP init failed%s: %s", sftpInitTimedOut ? " (no answer)" : "",
                 errmsg ? errmsg : "(null)");
        // The likeliest reason is a host that offers only a shell, and the
        // session has a mode for exactly that; say so rather than leave a
        // bare "could not initialise".
        ShowErrorId(IDS_ERR_NO_SFTP_HINT);
        if (LogProc) {
            const std::string msg = std::format("SFTP: SFTP subsystem init failed: {}", errmsg ? errmsg : "(no details)");
            LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, msg.c_str());
        }
        return false;
    }

    ConnectSettings->session->setBlocking(0);
    return true;
}

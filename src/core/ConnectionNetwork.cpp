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
        return -20;
    }
    ConnectSettings->sock = INVALID_SOCKET;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        closesocket(ConnectSettings->sock);
        ConnectSettings->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (ConnectSettings->sock == INVALID_SOCKET)
            continue;
        std::array<char, 256> addrBuf{};
        DWORD addrLen = static_cast<DWORD>(addrBuf.size());
        WSAAddressToString(ai->ai_addr, ai->ai_addrlen, nullptr, addrBuf.data(), &addrLen);
        ShowStatus(("IP address: " + std::string(addrBuf.data())).c_str());

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
    ShowStatus("Initializing SFTP subsystem...");
    SFTP_LOG("CONN", "Initializing SFTP subsystem");
    ShowStatusId(IDS_SESSION_STARTUP, " (SFTP)", true);
    do {
        ConnectSettings->sftpsession = nullptr;
        if (ProgressLoop(buf.data(), progress, progress + 10, loop, lasttime))
            break;
        auto sftpPtr = ConnectSettings->session->sftpInit();
        if (sftpPtr) {
            ConnectSettings->sftpsession = std::move(sftpPtr);
        } else if (ConnectSettings->session->lastErrno() != LIBSSH2_ERROR_EAGAIN) {
            break;
        }
        IsSocketReadable(ConnectSettings->sock);
    } while (!ConnectSettings->sftpsession);

    if (!ConnectSettings->sftpsession) {
        ConnectSettings->session->lastError(&errmsg, &errmsg_len, false);
        ShowStatusId(IDS_ERR_INIT_SFTP, errmsg, true);
        SFTP_LOG("CONN", "SFTP init failed: %s", errmsg ? errmsg : "(null)");
        return false;
    }

    ConnectSettings->session->setBlocking(0);
    return true;
}

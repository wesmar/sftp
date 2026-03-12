#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <array>
#include <stdio.h>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "SftpInternal.h"
#include "ProxyNegotiator.h"

// Helpers implemented in SftpConnection.cpp
void ShowErrorId(int errorid, LPCSTR suffix);
void ShowError(LPCSTR error);

static constexpr BYTE SOCKS4_VERSION = 4;
static constexpr BYTE SOCKS4_CMD_TCP = 1;
static constexpr BYTE SOCKS5_VERSION = 5;
static constexpr BYTE SOCKS5_CMD_TCP = 1;
static constexpr BYTE SOCKS5_ADDR_IPV4 = 1;
static constexpr BYTE SOCKS5_ADDR_DOMAIN = 3;
static constexpr BYTE SOCKS5_ADDR_IPV6 = 4;
static constexpr BYTE SOCKS5_AUTH_NONE = 0;
static constexpr BYTE SOCKS5_AUTH_USERPASS = 2;
static constexpr BYTE SOCKS5_AUTH_REJECT = 0xFF;

int SftpConnectProxyHttp(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime)
{
    std::array<char, 1024> buf{};
    const char* server = ConnectSettings->server.c_str();
    const char* proxyUser = ConnectSettings->proxyuser.c_str();
    const char* proxyServer = ConnectSettings->proxyserver.c_str();
    const char* proxyPass = ConnectSettings->proxypassword.c_str();
    // Send "CONNECT hostname:port HTTP/1.1"<CRLF>"Host: hostname:port"<2xCRLF> to the proxy
    LPCSTR txt;
    if (IsNumericIPv6(server))
        txt = "CONNECT [%s]:%d HTTP/1.1\r\nHost: [%s]:%d\r\n";
    else
        txt = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n";
    sprintf_s(buf.data(), buf.size(), txt, server, ConnectSettings->customport, server, ConnectSettings->customport);
    if (!ConnectSettings->proxyuser.empty()) {
        std::array<char, 250> buf1{};
        std::array<char, 500> buf2{};
        std::array<char, 250> title{};
        std::array<char, 256> passphrase{};
        strlcpy(passphrase.data(), proxyPass, passphrase.size()-1);

        LoadStr(buf1.data(), IDS_PROXY_PASSWORD_FOR);
        strlcpy(title.data(), buf1.data(), title.size()-1);
        strlcat(title.data(), proxyUser, title.size()-1);
        strlcat(title.data(), "@", title.size()-1);
        strlcat(title.data(), proxyServer, title.size()-1);
        LoadStr(buf1.data(), IDS_PROXY_PASSWORD);
        if (passphrase[0] == 0)
            RequestProc(PluginNumber, RT_Password, title.data(), buf1.data(), passphrase.data(), passphrase.size()-1);

        strlcpy(buf1.data(), proxyUser, buf1.size()-1);
        strlcat(buf1.data(), ":", buf1.size()-1);
        strlcat(buf1.data(), passphrase.data(), buf1.size()-1);
        strlcat(buf.data(), "Proxy-Authorization: Basic ", buf.size()-1);
        MimeEncode(buf1.data(), buf2.data(), buf2.size()-1);
        strlcat(buf.data(), buf2.data(), buf.size()-1);
        strlcat(buf.data(), "\r\n", buf.size()-1);
    }
    strlcat(buf.data(), "\r\n", buf.size()-1);
    mysend(ConnectSettings->sock, buf.data(), (int)strlen(buf.data()), 0, progressbuf, progress, ploop, plasttime);
    // Response;
    // HTTP/1.0 200 Connection established
    // Proxy-agent: WinProxy/1.5.3<2xCRLF>
    bool lastcrlfcrlf = false;
    int nrbytes = myrecv(ConnectSettings->sock, buf.data(), 12, 0, progressbuf, progress, ploop, plasttime);
    if (nrbytes == 12 && buf[9] == '2') {    // Proxy signaled success.
                                             // read data until we get 2xCRLF
        bool lastcrlf = false;
        bool lastcr = false;
        while (1) {
            nrbytes = myrecv(ConnectSettings->sock, buf.data(), 1, 0, progressbuf, progress, ploop, plasttime);
            if (nrbytes <= 0)
                break;
            if (buf[0] == '\r') {
                lastcr = true;
                continue;
            }
            if (buf[0] != '\n') {
                lastcr = false;
                lastcrlf = false;
                continue;
            }
            if (!lastcr) {
                lastcrlf = false;
                continue;
            }
            if (!lastcrlf) {
                lastcrlf = true;
                continue;
            }
            lastcrlfcrlf = true;
            break;
        }
    }
    if (!lastcrlfcrlf) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -1;
    }
    return SFTP_OK;
}

int SftpConnectProxySocks4(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime)
{
    std::array<char, 1024> buf{};
    const char* server = ConnectSettings->server.c_str();
    const char* proxyUser = ConnectSettings->proxyuser.c_str();
    ZeroMemory(buf.data(), buf.size());
    buf[0] = SOCKS4_VERSION;
    buf[1] = SOCKS4_CMD_TCP;
    *((PWORD)&buf[2]) = htons(ConnectSettings->customport);

    // numerical IPv4 given?
    ULONG hostaddr = inet_addr(server);
    // SOCKS4A uses 0.0.0.1 as the placeholder IP when hostname resolution is delegated to the proxy
    static constexpr ULONG SOCKS4A_PLACEHOLDER_IP = 0x00000001;
    // SOCKS4 fixed header size: VER(1)+CMD(1)+PORT(2)+ADDR(4) = 8 bytes
    static constexpr size_t SOCKS4_HEADER_SIZE = 8;
    if (hostaddr == INADDR_NONE)
        *((PLONG)&buf[4]) = htonl(SOCKS4A_PLACEHOLDER_IP);
    else
        *((PLONG)&buf[4]) = hostaddr;  // Already in network byte order.
    size_t nrbytes = SOCKS4_HEADER_SIZE;
    strlcpy(&buf[nrbytes], proxyUser, buf.size() - nrbytes - 1);
    nrbytes += strlen(proxyUser) + 1;
    if (hostaddr == INADDR_NONE) {  // SOCKS4A
        strlcpy(&buf[nrbytes], server, buf.size() - nrbytes - 1);
        nrbytes += strlen(server) + 1;
    }
    //
    mysend(ConnectSettings->sock, buf.data(), nrbytes, 0, progressbuf, progress, ploop, plasttime);
    int rc = myrecv(ConnectSettings->sock, buf.data(), 8, 0, progressbuf, progress, ploop, plasttime);
    if (rc != 8 || buf[0] != 0 || buf[1] != 0x5a) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -1;
    }
    return SFTP_OK;
}

int SftpConnectProxySocks5(pConnectSettings ConnectSettings, int connecttoport, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime)
{
    std::array<char, 1024> buf{};
    const char* server = ConnectSettings->server.c_str();
    const char* proxyUser = ConnectSettings->proxyuser.c_str();
    const char* proxyPass = ConnectSettings->proxypassword.c_str();
    ZeroMemory(buf.data(), buf.size());
    buf[0] = SOCKS5_VERSION;
    buf[2] = SOCKS5_AUTH_NONE;
    int nrbytes = 3;
    if (!ConnectSettings->proxyuser.empty()) {
        buf[3] = SOCKS5_AUTH_USERPASS;
        nrbytes++;
    }
    buf[1] = nrbytes - 2; // nr. of methods

    mysend(ConnectSettings->sock, buf.data(), nrbytes, 0, progressbuf, progress, ploop, plasttime);
    nrbytes = myrecv(ConnectSettings->sock, buf.data(), 2, 0, progressbuf, progress, ploop, plasttime);
    if (ConnectSettings->proxyuser.empty() && buf[1] != 0) {
        *((PBYTE)&buf[1]) = SOCKS5_AUTH_REJECT;
    }
    if (nrbytes != 2 || buf[0] != SOCKS5_VERSION || buf[1] == SOCKS5_AUTH_REJECT) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -1;
    }
    if (buf[1] == 2) { // user/pass auth
        size_t len;
        ZeroMemory(buf.data(), buf.size());
        buf[0] = 1; // version
        len = strlen(proxyUser);
        buf[1] = len;
        strlcpy(&buf[2], proxyUser, buf.size() - 3);
        nrbytes = len + 2;
        len = strlen(proxyPass);
        buf[nrbytes] = len;
        strlcpy(&buf[nrbytes+1], proxyPass, buf.size() - nrbytes - 1);
        nrbytes += len + 1;

        mysend(ConnectSettings->sock, buf.data(), nrbytes, 0, progressbuf, progress, ploop, plasttime);
        nrbytes = myrecv(ConnectSettings->sock, buf.data(), 2, 0, progressbuf, progress, ploop, plasttime);
        if (nrbytes != 2 || buf[1] != 0) {
            LoadStr(buf.data(), IDS_SOCKS5PROXYERR);
            ShowError(buf.data());
            return -2;
        }
    }

    ZeroMemory(buf.data(),  buf.size());
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_TCP;
    buf[2] = 0; // reserved

    ULONG hostaddr = inet_addr(server);
    if (hostaddr != INADDR_NONE) {
        buf[3] = SOCKS5_ADDR_IPV4;
        *((PLONG)&buf[4]) = hostaddr;  // Already in network byte order.
        nrbytes = 4 + 4;
    } else {
        bool numipv6 = false;  // is it an IPv6 numeric address?
        if (IsNumericIPv6(server)) {
            struct addrinfo hints{};
            hints.ai_family = AF_INET6;
            hints.ai_socktype = SOCK_STREAM;
            sprintf_s(buf.data(), buf.size(), "%d", connecttoport);
            struct addrinfo* res = nullptr;
            if (getaddrinfo(server, buf.data(), &hints, &res) == 0) {
                if (res->ai_addrlen >= sizeof(sockaddr_in6)) {
                    numipv6 = true;
                    buf[3] = SOCKS5_ADDR_IPV6;
                    const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(res->ai_addr);
                    memcpy(&buf[4], &addr6->sin6_addr, 16);
                    nrbytes = 4 + 16;
                }
                freeaddrinfo(res);
            }
        }
        if (!numipv6) {
            buf[3] = SOCKS5_ADDR_DOMAIN;
            // BUG-04: SOCKS5 length field is a single byte; clamp and use unsigned
            const size_t hostlen = strlen(server);
            buf[4] = static_cast<char>(hostlen > 255 ? 255 : hostlen);
            strlcpy(&buf[5], server, buf.size() - 6);
            nrbytes = static_cast<unsigned char>(buf[4]) + 5;
        }
    }
    *((PWORD)&buf[nrbytes]) = htons(ConnectSettings->customport);
    nrbytes += 2;

    mysend(ConnectSettings->sock, buf.data(), nrbytes, 0, progressbuf, progress, ploop, plasttime);
    nrbytes = myrecv(ConnectSettings->sock, buf.data(), 4, 0, progressbuf, progress, ploop, plasttime);
    if (nrbytes != 4 || buf[0] != SOCKS5_VERSION || buf[1] != 0) {
        //ShowErrorId(IDS_VIA_PROXY_CONNECT);
        switch(buf[1]) {
            case 1: LoadStr(buf.data(), IDS_GENERALSOCKSFAILURE); break;
            case 2: LoadStr(buf.data(), IDS_CONNNOTALLOWED); break;
            case 3: LoadStr(buf.data(), IDS_NETUNREACHABLE); break;
            case 4: LoadStr(buf.data(), IDS_HOSTUNREACHABLE); break;
            case 5: LoadStr(buf.data(), IDS_CONNREFUSED); break;
            case 6: LoadStr(buf.data(), IDS_TTLEXPIRED); break;
            case 7: LoadStr(buf.data(), IDS_CMDNOTSUPPORTED); break;
            case 8: LoadStr(buf.data(), IDS_ADDRTYPENOTSUPPORTED); break;
            default:
            {
                std::array<char, MAX_PATH> buf2{};
                LoadStr(buf2.data(), IDS_UNKNOWNSOCKERR);
                sprintf_s(buf.data(), buf.size(), buf2.data(), buf[1]);
            }
        }
        ShowError(buf.data());
        return -3;
    }
    int needread = 0;
    switch(buf[3]) {
        case 1: 
            needread = 6;   // IPv4+port
            break;
        case 3:
            nrbytes = myrecv(ConnectSettings->sock, buf.data(), 1, 0, progressbuf, progress, ploop, plasttime);
            if (nrbytes == 1)
                needread = buf[0] + 2;
            break;    // Domain Name+port
        case 4:
            needread = 18;   // IPv6+port
            break;
    }
    nrbytes = myrecv(ConnectSettings->sock, buf.data(), needread, 0, progressbuf, progress, ploop, plasttime);
    if (nrbytes != needread) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -4;
    }
    return SFTP_OK;
}



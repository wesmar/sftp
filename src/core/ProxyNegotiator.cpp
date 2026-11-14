#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <array>
#include <cstdint>
#include <format>
#include <string>
#include <vector>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "SftpInternal.h"
#include "ProxyNegotiator.h"

namespace {

constexpr uint8_t SOCKS4_VERSION       = 4;
constexpr uint8_t SOCKS4_CMD_TCP       = 1;
constexpr uint8_t SOCKS4_GRANTED       = 0x5A;
constexpr uint8_t SOCKS5_VERSION       = 5;
constexpr uint8_t SOCKS5_CMD_TCP       = 1;
constexpr uint8_t SOCKS5_ADDR_IPV4     = 1;
constexpr uint8_t SOCKS5_ADDR_DOMAIN   = 3;
constexpr uint8_t SOCKS5_ADDR_IPV6     = 4;
constexpr uint8_t SOCKS5_AUTH_NONE     = 0;
constexpr uint8_t SOCKS5_AUTH_USERPASS = 2;
constexpr uint8_t RFC1929_VERSION      = 1;

// The proxy conversations read and write bytes; char is signed here, so
// every byte that is compared goes through this.
constexpr uint8_t Byte(char c) noexcept
{
    return static_cast<uint8_t>(c);
}

void PutPort(char* at, unsigned short port) noexcept
{
    const u_short network = htons(port);
    memcpy(at, &network, sizeof(network));
}

} // namespace

int SftpConnectProxyHttp(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int* ploop, SYSTICKS* plasttime)
{
    const std::string& server = ConnectSettings->server;
    const std::string host = IsNumericIPv6(server) ? "[" + server + "]" : server;
    std::string request = std::format("CONNECT {0}:{1} HTTP/1.1\r\nHost: {0}:{1}\r\n",
                                      host, ConnectSettings->customport);

    if (!ConnectSettings->proxyuser.empty()) {
        std::string password = ConnectSettings->proxypassword;
        if (password.empty()) {
            std::array<char, 250> label{};
            LoadStr(label, IDS_PROXY_PASSWORD_FOR);
            const std::string title = std::format("{}{}@{}", label.data(),
                                                  ConnectSettings->proxyuser, ConnectSettings->proxyserver);
            LoadStr(label, IDS_PROXY_PASSWORD);
            std::array<char, 256> entered{};
            if (RequestInput(RT_Password, title.c_str(), label.data(), entered))
                password = entered.data();
            SecureZeroMemory(entered.data(), entered.size());
        }
        std::string credentials = ConnectSettings->proxyuser + ":" + password;
        std::vector<char> encoded(4 * ((credentials.size() + 2) / 3) + 1);
        MimeEncodeData(credentials.data(), credentials.size(), encoded.data(), encoded.size());
        request += "Proxy-Authorization: Basic ";
        request += encoded.data();
        request += "\r\n";
        SecureZeroMemory(credentials.data(), credentials.size());
        SecureZeroMemory(password.data(), password.size());
        SecureZeroMemory(encoded.data(), encoded.size());
    }
    request += "\r\n";
    mysend(ConnectSettings->sock, request.data(), static_cast<int>(request.size()), 0, progressbuf, progress, ploop, plasttime);
    SecureZeroMemory(request.data(), request.size());

    // "HTTP/1.x 2xx ...", header lines, then an empty line.
    std::array<char, 16> buf{};
    bool headerEnd = false;
    if (myrecv(ConnectSettings->sock, buf.data(), 12, 0, progressbuf, progress, ploop, plasttime) == 12 &&
        buf[9] == '2') {
        bool lastCr = false;
        bool lastCrLf = false;
        while (myrecv(ConnectSettings->sock, buf.data(), 1, 0, progressbuf, progress, ploop, plasttime) == 1) {
            if (buf[0] == '\r') {
                lastCr = true;
                continue;
            }
            if (buf[0] == '\n' && lastCr) {
                if (lastCrLf) {
                    headerEnd = true;
                    break;
                }
                lastCrLf = true;
            } else {
                lastCrLf = false;
            }
            lastCr = false;
        }
    }
    if (!headerEnd) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -1;
    }
    return SFTP_OK;
}

int SftpConnectProxySocks4(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int* ploop, SYSTICKS* plasttime)
{
    const std::string& server = ConnectSettings->server;
    const std::string& user = ConnectSettings->proxyuser;

    // VER, CMD, PORT(2), ADDR(4), user id, NUL - and for SOCKS4A, where the
    // address 0.0.0.1 hands name resolution to the proxy, the name and a NUL.
    constexpr size_t kHeaderSize = 8;
    IN_ADDR address{};
    const bool numeric = inet_pton(AF_INET, server.c_str(), &address) == 1;
    if (!numeric)
        address.s_addr = htonl(0x00000001);

    std::array<char, 1024> buf{};
    const size_t length = kHeaderSize + user.size() + 1 + (numeric ? 0 : server.size() + 1);
    if (length > buf.size()) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -1;
    }
    buf[0] = static_cast<char>(SOCKS4_VERSION);
    buf[1] = static_cast<char>(SOCKS4_CMD_TCP);
    PutPort(&buf[2], ConnectSettings->customport);
    memcpy(&buf[4], &address, sizeof(address));
    memcpy(&buf[kHeaderSize], user.c_str(), user.size() + 1);
    if (!numeric)
        memcpy(&buf[kHeaderSize + user.size() + 1], server.c_str(), server.size() + 1);

    mysend(ConnectSettings->sock, buf.data(), static_cast<int>(length), 0, progressbuf, progress, ploop, plasttime);
    const int got = myrecv(ConnectSettings->sock, buf.data(), 8, 0, progressbuf, progress, ploop, plasttime);
    if (got != 8 || buf[0] != 0 || Byte(buf[1]) != SOCKS4_GRANTED) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -1;
    }
    return SFTP_OK;
}

int SftpConnectProxySocks5(pConnectSettings ConnectSettings, int connecttoport, LPCSTR progressbuf, int progress, int* ploop, SYSTICKS* plasttime)
{
    const std::string& server = ConnectSettings->server;
    const std::string& user = ConnectSettings->proxyuser;
    const std::string& password = ConnectSettings->proxypassword;
    std::array<char, 1024> buf{};

    // Greeting: the methods offered, user/password only with a user set.
    buf[0] = static_cast<char>(SOCKS5_VERSION);
    buf[1] = static_cast<char>(user.empty() ? 1 : 2);
    buf[2] = static_cast<char>(SOCKS5_AUTH_NONE);
    buf[3] = static_cast<char>(SOCKS5_AUTH_USERPASS);
    mysend(ConnectSettings->sock, buf.data(), user.empty() ? 3 : 4, 0, progressbuf, progress, ploop, plasttime);
    int got = myrecv(ConnectSettings->sock, buf.data(), 2, 0, progressbuf, progress, ploop, plasttime);
    const uint8_t method = Byte(buf[1]);
    const bool offered = method == SOCKS5_AUTH_NONE || (method == SOCKS5_AUTH_USERPASS && !user.empty());
    if (got != 2 || Byte(buf[0]) != SOCKS5_VERSION || !offered) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -1;
    }

    if (method == SOCKS5_AUTH_USERPASS) {
        // RFC 1929: VER, ULEN, UNAME, PLEN, PASSWD - each length one byte.
        if (user.size() > 255 || password.size() > 255) {
            LoadStr(buf, IDS_SOCKS5PROXYERR);
            ShowError(buf.data());
            return -2;
        }
        buf[0] = static_cast<char>(RFC1929_VERSION);
        buf[1] = static_cast<char>(user.size());
        memcpy(&buf[2], user.data(), user.size());
        buf[2 + user.size()] = static_cast<char>(password.size());
        memcpy(&buf[3 + user.size()], password.data(), password.size());
        const int length = static_cast<int>(3 + user.size() + password.size());
        mysend(ConnectSettings->sock, buf.data(), length, 0, progressbuf, progress, ploop, plasttime);
        SecureZeroMemory(buf.data(), buf.size());
        got = myrecv(ConnectSettings->sock, buf.data(), 2, 0, progressbuf, progress, ploop, plasttime);
        if (got != 2 || buf[1] != 0) {
            LoadStr(buf, IDS_SOCKS5PROXYERR);
            ShowError(buf.data());
            return -2;
        }
    }

    // Request: VER, CMD, RSV, ATYP, address, PORT(2).
    buf.fill(0);
    buf[0] = static_cast<char>(SOCKS5_VERSION);
    buf[1] = static_cast<char>(SOCKS5_CMD_TCP);
    size_t length = 0;
    IN_ADDR ipv4{};
    if (inet_pton(AF_INET, server.c_str(), &ipv4) == 1) {
        buf[3] = static_cast<char>(SOCKS5_ADDR_IPV4);
        memcpy(&buf[4], &ipv4, sizeof(ipv4));
        length = 4 + sizeof(ipv4);
    } else if (IsNumericIPv6(server)) {
        addrinfo hints{};
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICHOST;
        addrinfo* res = nullptr;
        if (getaddrinfo(server.c_str(), std::to_string(connecttoport).c_str(), &hints, &res) == 0) {
            if (res->ai_addrlen >= sizeof(sockaddr_in6)) {
                const auto* addr6 = reinterpret_cast<const sockaddr_in6*>(res->ai_addr);
                buf[3] = static_cast<char>(SOCKS5_ADDR_IPV6);
                memcpy(&buf[4], &addr6->sin6_addr, sizeof(addr6->sin6_addr));
                length = 4 + sizeof(addr6->sin6_addr);
            }
            freeaddrinfo(res);
        }
    }
    if (length == 0) {
        // The length field is one byte. A longer name is refused rather
        // than cut, which would name a different host.
        if (server.empty() || server.size() > 255) {
            ShowErrorId(IDS_VIA_PROXY_CONNECT);
            return -1;
        }
        buf[3] = static_cast<char>(SOCKS5_ADDR_DOMAIN);
        buf[4] = static_cast<char>(server.size());
        memcpy(&buf[5], server.data(), server.size());
        length = 5 + server.size();
    }
    PutPort(&buf[length], ConnectSettings->customport);
    length += 2;

    mysend(ConnectSettings->sock, buf.data(), static_cast<int>(length), 0, progressbuf, progress, ploop, plasttime);
    got = myrecv(ConnectSettings->sock, buf.data(), 4, 0, progressbuf, progress, ploop, plasttime);
    if (got != 4 || Byte(buf[0]) != SOCKS5_VERSION || buf[1] != 0) {
        const int reply = got >= 2 ? Byte(buf[1]) : -1;
        switch (reply) {
            case 1: LoadStr(buf, IDS_GENERALSOCKSFAILURE); break;
            case 2: LoadStr(buf, IDS_CONNNOTALLOWED); break;
            case 3: LoadStr(buf, IDS_NETUNREACHABLE); break;
            case 4: LoadStr(buf, IDS_HOSTUNREACHABLE); break;
            case 5: LoadStr(buf, IDS_CONNREFUSED); break;
            case 6: LoadStr(buf, IDS_TTLEXPIRED); break;
            case 7: LoadStr(buf, IDS_CMDNOTSUPPORTED); break;
            case 8: LoadStr(buf, IDS_ADDRTYPENOTSUPPORTED); break;
            default: {
                std::array<char, MAX_PATH> format{};
                LoadStr(format, IDS_UNKNOWNSOCKERR);
                sprintf_s(buf.data(), buf.size(), format.data(), reply);
                break;
            }
        }
        ShowError(buf.data());
        return -3;
    }

    // The reply ends with the address the proxy bound and its port.
    int remaining = 0;
    switch (Byte(buf[3])) {
        case SOCKS5_ADDR_IPV4:
            remaining = 4 + 2;
            break;
        case SOCKS5_ADDR_DOMAIN:
            if (myrecv(ConnectSettings->sock, buf.data(), 1, 0, progressbuf, progress, ploop, plasttime) == 1)
                remaining = Byte(buf[0]) + 2;
            break;
        case SOCKS5_ADDR_IPV6:
            remaining = 16 + 2;
            break;
        default:
            break;
    }
    if (remaining == 0 ||
        myrecv(ConnectSettings->sock, buf.data(), remaining, 0, progressbuf, progress, ploop, plasttime) != remaining) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -4;
    }
    return SFTP_OK;
}

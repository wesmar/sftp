#include "global.h"
#include "PhpAgentClient.h"
#include <winhttp.h>
#include <array>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <format>
#include <cctype>
#include <cstdlib>
#include <regex>
#include "CoreUtils.h"
#include "UtfConversion.h"
#include "UnicodeHelpers.h"
#include "SftpInternal.h"
#include "PluginEntryPoints.h"

#pragma comment(lib, "winhttp.lib")

#define PHP_LOG(fmt, ...) SFTP_LOG("PHP", fmt, ##__VA_ARGS__)

namespace {

struct AgentUrl {
    bool secure = false;
    INTERNET_PORT port = 0;
    std::wstring host;
    std::wstring object;
};

struct HttpHandles {
    HINTERNET session = nullptr;
    HINTERNET connect = nullptr;
    HINTERNET request = nullptr;
    ~HttpHandles() {
        if (request) WinHttpCloseHandle(request);
        if (connect) WinHttpCloseHandle(connect);
        if (session) WinHttpCloseHandle(session);
    }
};

static bool ParseAgentUrl(pConnectSettings cs, AgentUrl* out);
static bool QueryStatus(HINTERNET request, DWORD* outStatus);
static bool QueryHeaderInt64(HINTERNET request, const wchar_t* headerName, int64_t* outValue);
static int ReadAllResponse(HINTERNET request, std::string& outBody);

struct AutoFileHandle {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit AutoFileHandle(HANDLE in = INVALID_HANDLE_VALUE) : h(in) {}
    ~AutoFileHandle() {
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
    HANDLE get() const noexcept { return h; }
};

// Utf8ToWide removed - use unicode_util::utf8_to_wstring() instead
// WideToUtf8 removed - use unicode_util::wide_to_narrow() instead

static bool StartsWithIcase(const std::string& s, const std::string& prefix)
{
    if (prefix.size() > s.size())
        return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        const unsigned char a = static_cast<unsigned char>(s[i]);
        const unsigned char b = static_cast<unsigned char>(prefix[i]);
        if (std::tolower(a) != std::tolower(b))
            return false;
    }
    return true;
}

static std::string NormalizePhpRemotePath(pConnectSettings cs, LPCWSTR pathW)
{
    std::string p = unicode_util::wide_to_narrow(pathW ? pathW : L".");
    if (p.empty())
        return ".";
    ReplaceBackslashBySlash(p.data());

    // Collapse duplicate slashes.
    std::string collapsed;
    collapsed.reserve(p.size());
    bool lastSlash = false;
    for (char c : p) {
        if (c == '/') {
            if (!lastSlash)
                collapsed.push_back(c);
            lastSlash = true;
        } else {
            collapsed.push_back(c);
            lastSlash = false;
        }
    }
    p.swap(collapsed);
    while (!p.empty() && p.front() == '/')
        p.erase(p.begin());

    AgentUrl url;
    if (ParseAgentUrl(cs, &url)) {
        std::string host = unicode_util::wide_to_narrow(url.host.c_str());
        if (!host.empty()) {
            if (StartsWithIcase(p, host + "/"))
                p.erase(0, host.size() + 1);
            else if (StartsWithIcase(p, host))
                p.erase(0, host.size());
        }

        std::string object = unicode_util::wide_to_narrow(url.object.c_str());
        size_t q = object.find('?');
        if (q != std::string::npos)
            object = object.substr(0, q);
        while (!object.empty() && object.front() == '/')
            object.erase(object.begin());

        if (!object.empty()) {
            if (StartsWithIcase(p, object + "/"))
                p.erase(0, object.size() + 1);
            else if (StartsWithIcase(p, object))
                p.erase(0, object.size());

            size_t slash = object.find_last_of('/');
            std::string base = (slash == std::string::npos) ? object : object.substr(slash + 1);
            if (!base.empty()) {
                if (StartsWithIcase(p, base + "/"))
                    p.erase(0, base.size() + 1);
                else if (StartsWithIcase(p, base))
                    p.erase(0, base.size());
            }
        }
    }

    while (!p.empty() && (p.front() == '/' || p.front() == '\\'))
        p.erase(p.begin());
    return p.empty() ? "." : p;
}

static std::wstring UrlEncodeUtf8(const std::string& v)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(v.size() * 3);
    for (unsigned char c : v) {
        const bool safe = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || c == '/';
        if (safe) {
            out.push_back((char)c);
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return unicode_util::utf8_to_wstring(out);
}

static bool ParseAgentUrl(pConnectSettings cs, AgentUrl* out)
{
    if (!cs || !out || cs->server.empty())
        return false;
    std::wstring url = unicode_util::utf8_to_wstring(cs->server);
    if (url.empty())
        return false;

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    std::array<wchar_t, 512> host{};
    std::array<wchar_t, 2048> path{};
    std::array<wchar_t, 2048> extra{};
    uc.lpszHostName = host.data();
    uc.dwHostNameLength = (DWORD)host.size();
    uc.lpszUrlPath = path.data();
    uc.dwUrlPathLength = (DWORD)path.size();
    uc.lpszExtraInfo = extra.data();
    uc.dwExtraInfoLength = (DWORD)extra.size();
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc))
        return false;

    out->secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    out->port = uc.nPort;
    out->host.assign(host.data(), uc.dwHostNameLength);
    out->object.assign(path.data(), uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength > 0)
        out->object.append(extra.data(), uc.dwExtraInfoLength);
    if (out->object.empty())
        out->object = L"/";
    return true;
}

static std::wstring BuildObjectPath(const std::wstring& baseObject, const std::wstring& query)
{
    if (query.empty())
        return baseObject;
    std::wstring out = baseObject;
    out += (baseObject.find(L'?') == std::wstring::npos) ? L'?' : L'&';
    out += query;
    return out;
}

static std::string Base64DecodeString(const std::string& b64)
{
    if (b64.empty())
        return {};
    std::vector<char> out((b64.size() * 3) / 4 + 8);
    int n = MimeDecode(b64.c_str(), b64.size(), out.data(), out.size());
    if (n <= 0)
        return {};
    return std::string(out.data(), (size_t)n);
}

static bool ExtractJsonStringField(const std::string& body, const char* field, std::string* out)
{
    if (!field || !out)
        return false;
    std::string pattern = "\"";
    pattern += field;
    pattern += "\"\\s*:\\s*\"([^\"]*)\"";
    std::smatch m;
    if (!std::regex_search(body, m, std::regex(pattern)) || m.size() < 2)
        return false;
    *out = m[1].str();
    return true;
}

static bool ExtractJsonIntField(const std::string& body, const char* field, int* out)
{
    if (!field || !out)
        return false;
    std::string pattern = "\"";
    pattern += field;
    pattern += "\"\\s*:\\s*(-?[0-9]+)";
    std::smatch m;
    if (!std::regex_search(body, m, std::regex(pattern)) || m.size() < 2)
        return false;
    *out = atoi(m[1].str().c_str());
    return true;
}

static bool ExtractJsonInt64Field(const std::string& body, const char* field, int64_t* out)
{
    if (!field || !out)
        return false;
    std::string pattern = "\"";
    pattern += field;
    pattern += "\"\\s*:\\s*(-?[0-9]+)";
    std::smatch m;
    if (!std::regex_search(body, m, std::regex(pattern)) || m.size() < 2)
        return false;
    *out = std::strtoll(m[1].str().c_str(), nullptr, 10);
    return true;
}

static bool ExtractJsonBoolField(const std::string& body, const char* field, bool* out)
{
    if (!field || !out)
        return false;
    std::string pattern = "\"";
    pattern += field;
    pattern += "\"\\s*:\\s*(true|false|1|0)";
    std::smatch m;
    if (!std::regex_search(body, m, std::regex(pattern, std::regex::icase)) || m.size() < 2)
        return false;
    std::string v = m[1].str();
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    *out = (v == "true" || v == "1");
    return true;
}

static bool ExtractErrorMessage(const std::string& body, std::string* out)
{
    if (!out)
        return false;
    std::string msg;
    if (ExtractJsonStringField(body, "message", &msg)) {
        *out = msg;
        return true;
    }
    return false;
}

static bool QueryStatus(HINTERNET request, DWORD* outStatus)
{
    DWORD code = 0;
    DWORD sz = sizeof(code);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX))
        return false;
    *outStatus = code;
    return true;
}

static bool QueryHeaderInt64(HINTERNET request, const wchar_t* headerName, int64_t* outValue)
{
    if (!request || !headerName || !outValue)
        return false;
    std::array<wchar_t, 64> value{};
    DWORD sizeBytes = (DWORD)(value.size() * sizeof(wchar_t));
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, headerName, value.data(), &sizeBytes, WINHTTP_NO_HEADER_INDEX))
        return false;
    const wchar_t* p = value.data();
    while (*p == L' ' || *p == L'\t')
        ++p;
    if (*p == 0)
        return false;
    wchar_t* endPtr = nullptr;
    long long v = std::wcstoll(p, &endPtr, 10);
    if (endPtr == p)
        return false;
    *outValue = (int64_t)v;
    return true;
}

static int ReadAllResponse(HINTERNET request, std::string& outBody)
{
    outBody.clear();
    std::array<char, 8192> buf{};
    while (true) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(request, &avail))
            return SFTP_READFAILED;
        if (avail == 0)
            break;
        DWORD got = 0;
        if (!WinHttpReadData(request, buf.data(), (DWORD)std::min<size_t>(buf.size(), avail), &got))
            return SFTP_READFAILED;
        if (got == 0)
            break;
        outBody.append(buf.data(), got);
    }
    return SFTP_OK;
}

static int SendSimpleRequest(
    pConnectSettings cs,
    const wchar_t* method,
    const wchar_t* op,
    const std::wstring& query,
    const char* body,
    DWORD bodyLen,
    DWORD* outStatus,
    std::string* outBody)
{
    PHP_LOG("HTTP %ls op=%ls query_len=%u", method ? method : L"", op ? op : L"", (unsigned)query.size());
    AgentUrl url;
    if (!ParseAgentUrl(cs, &url))
        return SFTP_FAILED;

    HttpHandles h;
    h.session = WinHttpOpen(L"TC-SFTP-PHP-Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h.session)
        return SFTP_FAILED;
    WinHttpSetTimeouts(h.session, 15000, 15000, 60000, 60000);

    h.connect = WinHttpConnect(h.session, url.host.c_str(), url.port, 0);
    if (!h.connect)
        return SFTP_FAILED;

    std::wstring object = BuildObjectPath(url.object, query);
    h.request = WinHttpOpenRequest(h.connect, method, object.c_str(), nullptr, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, url.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!h.request)
        return SFTP_FAILED;

    std::wstring headers = L"X-SFTP-OP: ";
    headers += op;
    headers += L"\r\nX-SFTP-AUTH: ";
    headers += unicode_util::utf8_to_wstring(cs->password);
    headers += L"\r\n";

    BOOL ok = WinHttpSendRequest(h.request, headers.c_str(), (DWORD)-1L,
                                 (LPVOID)body, bodyLen, bodyLen, 0);
    if (!ok)
        return SFTP_FAILED;
    if (!WinHttpReceiveResponse(h.request, nullptr))
        return SFTP_FAILED;

    DWORD status = 0;
    if (!QueryStatus(h.request, &status))
        return SFTP_FAILED;
    PHP_LOG("HTTP status=%lu op=%ls", (unsigned long)status, op ? op : L"");
    if (outStatus)
        *outStatus = status;
    if (outBody) {
        int rr = ReadAllResponse(h.request, *outBody);
        if (rr != SFTP_OK)
            return rr;
    }
    return SFTP_OK;
}

static bool IsHttpSuccess(DWORD code) noexcept
{
    return code >= 200 && code < 300;
}

static void ReportPhpAgentHttpError(pConnectSettings cs, DWORD code, const char* op)
{
    if (!cs || !cs->feedback)
        return;
    if (code == 401 || code == 403) {
        cs->feedback->ShowError(std::format("Wrong credentials for PHP Agent (HTTP {}).", static_cast<unsigned long>(code)), "PHP Agent");
        return;
    }
    if (code >= 400) {
        cs->feedback->ShowError(std::format("PHP Agent request failed for {} (HTTP {}).", op ? op : "operation", static_cast<unsigned long>(code)), "PHP Agent");
    }
}

static bool ParseListLine(const std::string& line, WIN32_FIND_DATAW* outFd)
{
    // Format: TYPE \t SIZE \t MTIME \t BASE64_NAME
    if (!outFd || line.empty())
        return false;
    size_t p1 = line.find('\t');
    if (p1 == std::string::npos) return false;
    size_t p2 = line.find('\t', p1 + 1);
    if (p2 == std::string::npos) return false;
    size_t p3 = line.find('\t', p2 + 1);
    if (p3 == std::string::npos) return false;

    const std::string type = line.substr(0, p1);
    const std::string sizeS = line.substr(p1 + 1, p2 - p1 - 1);
    const std::string mtimeS = line.substr(p2 + 1, p3 - p2 - 1);
    const std::string b64 = line.substr(p3 + 1);
    if (b64.empty())
        return false;

    // Minimal base64 decoder for item names.
    static const int8_t dec[128] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    std::string nameUtf8;
    nameUtf8.reserve(b64.size());
    uint32_t buf = 0;
    int bits = 0;
    for (unsigned char c : b64) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ')
            continue;
        if (c > 127)
            continue;
        int8_t v = dec[c];
        if (v < 0)
            continue;
        buf = (buf << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            nameUtf8.push_back((char)((buf >> bits) & 0xFF));
        }
    }

    WIN32_FIND_DATAW fd{};
    fd.dwFileAttributes = (type == "D") ? FILE_ATTRIBUTE_DIRECTORY : 0;
    unsigned long long sz = _strtoui64(sizeS.c_str(), nullptr, 10);
    fd.nFileSizeHigh = (DWORD)(sz >> 32);
    fd.nFileSizeLow = (DWORD)(sz & 0xFFFFFFFFULL);
    long long mt = std::strtoll(mtimeS.c_str(), nullptr, 10);
    ConvUnixTimeToFileTime(&fd.ftLastWriteTime, mt);
    ConvUTF8toUTF16(nameUtf8.c_str(), 0, fd.cFileName, countof(fd.cFileName) - 1);
    if (!fd.cFileName[0])
        return false;
    *outFd = fd;
    return true;
}

static std::wstring BuildQueryPathOnly(const wchar_t* op, const std::string& pathUtf8)
{
    std::wstring q = L"op=";
    q += op;
    q += L"&path=";
    q += UrlEncodeUtf8(pathUtf8);
    return q;
}

static int StreamDownloadToFile(
    pConnectSettings cs,
    const std::wstring& query,
    HANDLE hLocal,
    LPCWSTR remoteName,
    LPCWSTR localName)
{
    AgentUrl url;
    if (!ParseAgentUrl(cs, &url))
        return SFTP_FAILED;

    HttpHandles h;
    h.session = WinHttpOpen(L"TC-SFTP-PHP-Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h.session)
        return SFTP_FAILED;
    WinHttpSetTimeouts(h.session, 15000, 15000, 60000, 60000);
    h.connect = WinHttpConnect(h.session, url.host.c_str(), url.port, 0);
    if (!h.connect)
        return SFTP_FAILED;
    const std::wstring object = BuildObjectPath(url.object, query);
    h.request = WinHttpOpenRequest(h.connect, L"GET", object.c_str(), nullptr, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, url.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!h.request)
        return SFTP_FAILED;

    std::wstring headers = L"X-SFTP-OP: GET\r\nX-SFTP-AUTH: ";
    headers += unicode_util::utf8_to_wstring(cs->password);
    headers += L"\r\n";
    if (!WinHttpSendRequest(h.request, headers.c_str(), (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        return SFTP_FAILED;
    if (!WinHttpReceiveResponse(h.request, nullptr))
        return SFTP_FAILED;

    DWORD code = 0;
    if (!QueryStatus(h.request, &code) || !IsHttpSuccess(code)) {
        ReportPhpAgentHttpError(cs, code, "GET");
        return SFTP_READFAILED;
    }

    int64_t loaded = 0;
    int64_t responseLength = -1;
    int64_t responseFileSize = -1;
    int64_t responseOffset = 0;
    QueryHeaderInt64(h.request, L"Content-Length", &responseLength);
    QueryHeaderInt64(h.request, L"X-SFTP-File-Size", &responseFileSize);
    QueryHeaderInt64(h.request, L"X-SFTP-Offset", &responseOffset);
    if (responseOffset < 0)
        responseOffset = 0;
    int64_t totalForPercent = responseFileSize > 0 ? responseFileSize : (responseLength > 0 ? (responseOffset + responseLength) : 0);

    std::vector<uint8_t> buf(32768);
    while (true) {
        DWORD got = 0;
        if (!WinHttpReadData(h.request, buf.data(), (DWORD)buf.size(), &got))
            return SFTP_READFAILED;
        if (got == 0)
            break;
        DWORD wr = 0;
        if (!WriteFile(hLocal, buf.data(), got, &wr, nullptr) || wr != got)
            return SFTP_WRITEFAILED;
        loaded += got;
        int percent = 0;
        if (totalForPercent > 0) {
            const int64_t done = responseOffset + loaded;
            percent = (int)((done * 100) / totalForPercent);
            if (percent < 0)
                percent = 0;
            if (percent > 100)
                percent = 100;
        }
        if (UpdatePercentBar(cs, percent, remoteName, localName))
            return SFTP_ABORT;
    }
    if (totalForPercent > 0)
        UpdatePercentBar(cs, 100, remoteName, localName);
    return SFTP_OK;
}

static int StreamUploadFromFile(
    pConnectSettings cs,
    const std::wstring& query,
    const wchar_t* method,
    bool reportHttpError,
    HANDLE hLocal,
    int64_t startOffset,
    int64_t chunkLength,
    int64_t totalFileSize,
    LPCWSTR localName,
    LPCWSTR remoteName)
{
    LARGE_INTEGER li{};
    li.QuadPart = startOffset;
    if (!SetFilePointerEx(hLocal, li, nullptr, FILE_BEGIN))
        return SFTP_READFAILED;

    AgentUrl url;
    if (!ParseAgentUrl(cs, &url))
        return SFTP_FAILED;

    HttpHandles h;
    h.session = WinHttpOpen(L"TC-SFTP-PHP-Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h.session)
        return SFTP_FAILED;
    WinHttpSetTimeouts(h.session, 15000, 15000, 60000, 60000);
    h.connect = WinHttpConnect(h.session, url.host.c_str(), url.port, 0);
    if (!h.connect)
        return SFTP_FAILED;
    const std::wstring object = BuildObjectPath(url.object, query);
    h.request = WinHttpOpenRequest(h.connect, method ? method : L"POST", object.c_str(), nullptr, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, url.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!h.request)
        return SFTP_FAILED;

    std::wstring headers = L"X-SFTP-OP: PUT\r\nX-SFTP-AUTH: ";
    headers += unicode_util::utf8_to_wstring(cs->password);
    headers += L"\r\nContent-Type: application/octet-stream\r\n";

    const DWORD bodyLen = (DWORD)chunkLength;
    if (!WinHttpSendRequest(h.request, headers.c_str(), (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, bodyLen, 0))
        return SFTP_FAILED;

    INT64 sent = 0;
    const INT64 totalForPercent = totalFileSize > 0 ? totalFileSize : 0;
    std::vector<uint8_t> buf(32768);
    while (sent < chunkLength) {
        DWORD toRead = (DWORD)std::min<INT64>(buf.size(), chunkLength - sent);
        DWORD rd = 0;
        if (!ReadFile(hLocal, buf.data(), toRead, &rd, nullptr))
            return SFTP_READFAILED;
        if (rd == 0)
            break;
        DWORD wr = 0;
        if (!WinHttpWriteData(h.request, buf.data(), rd, &wr) || wr != rd)
            return SFTP_WRITEFAILED;
        sent += wr;
        int percent = 0;
        if (totalForPercent > 0) {
            const int64_t done = startOffset + sent;
            percent = (int)((done * 100) / totalForPercent);
            if (percent < 0)
                percent = 0;
            if (percent > 100)
                percent = 100;
        }
        if (UpdatePercentBar(cs, percent, localName, remoteName))
            return SFTP_ABORT;
    }

    if (!WinHttpReceiveResponse(h.request, nullptr))
        return SFTP_FAILED;
    DWORD code = 0;
    if (!QueryStatus(h.request, &code) || !IsHttpSuccess(code)) {
        if (reportHttpError)
            ReportPhpAgentHttpError(cs, code, method ? (wcscmp(method, L"PUT") == 0 ? "PUT" : "POST") : "POST");
        return SFTP_WRITEFAILED;
    }
    return SFTP_OK;
}

} // namespace

int PhpAgentProbe(pConnectSettings cs)
{
    PHP_LOG("Probe start url='%s'", (cs && !cs->server.empty()) ? cs->server.c_str() : "");
    DWORD code = 0;
    std::string body;
    int rc = SendSimpleRequest(cs, L"GET", L"PROBE", L"op=PROBE", nullptr, 0, &code, &body);
    if (rc != SFTP_OK)
        return rc;
    if (cs) {
        cs->php_recommended_chunk_mib = 0;
        int recBytes = 0;
        if (ExtractJsonIntField(body, "recommended_chunk_size", &recBytes) && recBytes > 0) {
            int recMiB = recBytes / (1024 * 1024);
            if (recMiB <= 0)
                recMiB = 1;
            recMiB = std::clamp(recMiB, 1, 64);
            cs->php_recommended_chunk_mib = recMiB;
            PHP_LOG("Probe recommended chunk parsed=%d MiB", recMiB);
        }
    }
    PHP_LOG("Probe done status=%lu body_len=%u", (unsigned long)code, (unsigned)body.size());
    return IsHttpSuccess(code) ? SFTP_OK : SFTP_FAILED;
}

int PhpAgentValidateAuth(pConnectSettings cs, std::string& outErrorText)
{
    outErrorText.clear();
    DWORD code = 0;
    std::string body;
    const int rc = SendSimpleRequest(cs, L"GET", L"LIST", L"op=LIST&path=.&format=plain", nullptr, 0, &code, &body);
    if (rc != SFTP_OK) {
        outErrorText = "Cannot reach PHP agent endpoint.";
        return rc;
    }
    if (IsHttpSuccess(code))
        return SFTP_OK;

    std::string serverMsg;
    ExtractErrorMessage(body, &serverMsg);
    if (code == 401 || code == 403) {
        outErrorText = "Wrong credentials for PHP Agent (HTTP " + std::to_string(static_cast<unsigned long>(code)) + ").";
    } else if (code == 404) {
        outErrorText = "PHP agent endpoint not found (HTTP 404).\n"
                       "Check URL path/filename and upload sftp.php to that location.";
    } else if (code == 503) {
        outErrorText = "PHP agent is not configured on server (HTTP 503).\n"
                       "Set AGENT_PSK / AGENT_PSK_SHA256 in sftp.php and upload again.";
    } else if (!serverMsg.empty()) {
        outErrorText = "PHP Agent rejected request: " + serverMsg;
    } else {
        outErrorText = "PHP Agent validation failed (HTTP " + std::to_string(static_cast<unsigned long>(code)) + ").";
    }
    return SFTP_FAILED;
}

int PhpAgentListDirectoryW(pConnectSettings cs, LPCWSTR remoteDir, std::vector<WIN32_FIND_DATAW>& outEntries)
{
    outEntries.clear();
    std::string pathUtf8 = NormalizePhpRemotePath(cs, remoteDir ? remoteDir : L".");
    DWORD code = 0;
    std::string body;
    auto doList = [&](const std::string& p) -> int {
        std::wstring query = BuildQueryPathOnly(L"LIST", p);
        query += L"&format=plain";
        return SendSimpleRequest(cs, L"GET", L"LIST", query, nullptr, 0, &code, &body);
    };

    int rc = doList(pathUtf8);
    if (rc != SFTP_OK)
        return rc;
    if (!IsHttpSuccess(code)) {
        // Some sessions start in virtual/home path from SSH mode.
        // PHP agent has its own root jail, so fallback to agent root listing.
        if (code == 404 && pathUtf8 != "." && pathUtf8 != "/") {
            PHP_LOG("LIST 404 for path='%s', retrying with root", pathUtf8.c_str());
            rc = doList(".");
            if (rc != SFTP_OK)
                return rc;
        }
    }
    if (!IsHttpSuccess(code)) {
        ReportPhpAgentHttpError(cs, code, "LIST");
        return SFTP_FAILED;
    }

    size_t pos = 0;
    while (pos < body.size()) {
        size_t eol = body.find('\n', pos);
        if (eol == std::string::npos)
            eol = body.size();
        std::string line = body.substr(pos, eol - pos);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        WIN32_FIND_DATAW fd{};
        if (ParseListLine(line, &fd)) {
            if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0)
                outEntries.push_back(fd);
        }
        pos = eol + 1;
    }
    return SFTP_OK;
}

int PhpAgentDownloadFileW(pConnectSettings cs,
                          LPCWSTR remoteNameW, LPCWSTR localNameW,
                          bool alwaysOverwrite, int64_t hintedSize, bool resume)
{
    DWORD createDisposition = alwaysOverwrite ? CREATE_ALWAYS : CREATE_NEW;
    if (resume)
        createDisposition = OPEN_ALWAYS;
    HANDLE hLocal = CreateFileT(localNameW, GENERIC_WRITE, FILE_SHARE_READ, nullptr, createDisposition,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hLocal == INVALID_HANDLE_VALUE)
        return SFTP_WRITEFAILED;
    AutoFileHandle local(hLocal);

    int64_t offset = 0;
    if (resume) {
        LARGE_INTEGER li{};
        if (!GetFileSizeEx(local.get(), &li))
            return SFTP_READFAILED;
        offset = li.QuadPart;
        if (offset > 0) {
            LARGE_INTEGER seek{};
            seek.QuadPart = offset;
            SetFilePointerEx(local.get(), seek, nullptr, FILE_BEGIN);
        }
    }

    std::string pathUtf8 = NormalizePhpRemotePath(cs, remoteNameW);
    PHP_LOG("GET normalized path='%s'", pathUtf8.c_str());
    std::wstring query = BuildQueryPathOnly(L"GET", pathUtf8);
    if (offset > 0) {
        std::array<wchar_t, 64> off{};
        _snwprintf_s(off.data(), off.size(), _TRUNCATE, L"%lld", (long long)offset);
        query += L"&offset=";
        query += off.data();
    }

    int rc = StreamDownloadToFile(cs, query, local.get(), remoteNameW, localNameW);
    if (rc != SFTP_OK)
        return rc;

    if (hintedSize > 0) {
        LARGE_INTEGER li{};
        if (GetFileSizeEx(local.get(), &li) && li.QuadPart < hintedSize)
            return SFTP_PARTIAL;
    }
    return SFTP_OK;
}

int PhpAgentUploadFileW(pConnectSettings cs,
                        LPCWSTR localNameW, LPCWSTR remoteNameW, bool resume)
{
    HANDLE hLocal = CreateFileT(localNameW, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hLocal == INVALID_HANDLE_VALUE)
        return SFTP_READFAILED;
    AutoFileHandle local(hLocal);

    LARGE_INTEGER li{};
    if (!GetFileSizeEx(local.get(), &li))
        return SFTP_READFAILED;
    int64_t localSize = li.QuadPart;

    std::string pathUtf8 = NormalizePhpRemotePath(cs, remoteNameW);
    // Resume may be invoked against an already-visible "*.part" entry.
    // Canonicalize to the final target name to avoid creating "*.part.part".
    if (resume && pathUtf8.size() > 5 && _stricmp(pathUtf8.c_str() + pathUtf8.size() - 5, ".part") == 0) {
        pathUtf8.resize(pathUtf8.size() - 5);
    }
    PHP_LOG("PUT normalized path='%s'", pathUtf8.c_str());

    int64_t offset = 0;
    // Auto-resume from "<path>.part" even when host did not request Resume via TC prompt.
    // This makes interrupted PHP uploads continue seamlessly on restrictive hosts.
    {
        std::wstring statQuery = BuildQueryPathOnly(L"STAT", pathUtf8 + ".part");
        DWORD statCode = 0;
        std::string statBody;
        const int statRc = SendSimpleRequest(cs, L"GET", L"STAT", statQuery, nullptr, 0, &statCode, &statBody);
        if (statRc == SFTP_OK && IsHttpSuccess(statCode)) {
            bool isFile = false;
            int64_t partSize = 0;
            ExtractJsonBoolField(statBody, "is_file", &isFile);
            if (isFile && ExtractJsonInt64Field(statBody, "size", &partSize) && partSize > 0) {
                offset = partSize;
                if (offset > localSize)
                    offset = 0;
                PHP_LOG("PUT %sresume found .part size=%lld local=%lld",
                        resume ? "" : "auto-",
                        (long long)partSize,
                        (long long)localSize);
            }
        }
    }

    if (offset == localSize) {
        // Upload data already present in .part, finalize only.
        DWORD code = 0;
        std::wstring finOnly = BuildQueryPathOnly(L"FINALIZE", pathUtf8);
        int rc = SendSimpleRequest(cs, L"POST", L"FINALIZE", finOnly, nullptr, 0, &code, nullptr);
        if (rc != SFTP_OK)
            return rc;
        if (!IsHttpSuccess(code)) {
            ReportPhpAgentHttpError(cs, code, "FINALIZE");
            return SFTP_WRITEFAILED;
        }
        if (localSize > 0)
            UpdatePercentBar(cs, 100, localNameW, remoteNameW);
        return SFTP_OK;
    }

    int chunkMiB = cs->php_chunk_mib;
    if (chunkMiB == 0) {
        // Auto mode: prefer probe recommendation, fallback to 1 MiB.
        chunkMiB = cs->php_recommended_chunk_mib > 0 ? cs->php_recommended_chunk_mib : 1;
    }
    chunkMiB = std::clamp(chunkMiB, 1, 64);
    const int64_t chunkSize = static_cast<int64_t>(chunkMiB) * 1024 * 1024;

    auto sendChunk = [&](const std::wstring& query, int64_t start, int64_t len) -> int {
        // 0=auto, 1=POST, 2=PUT
        if (cs->php_http_mode == 1)
            return StreamUploadFromFile(cs, query, L"POST", true, local.get(), start, len, localSize, localNameW, remoteNameW);
        if (cs->php_http_mode == 2)
            return StreamUploadFromFile(cs, query, L"PUT", true, local.get(), start, len, localSize, localNameW, remoteNameW);

        int rc = StreamUploadFromFile(cs, query, L"POST", false, local.get(), start, len, localSize, localNameW, remoteNameW);
        if (rc == SFTP_OK)
            return rc;
        return StreamUploadFromFile(cs, query, L"PUT", true, local.get(), start, len, localSize, localNameW, remoteNameW);
    };

    while (offset < localSize || (localSize == 0 && offset == 0)) {
        int64_t currentChunk = std::min<int64_t>(chunkSize, localSize - offset);

        std::wstring query = BuildQueryPathOnly(L"PUT", pathUtf8);
        query += L"&part=1";
        
        std::array<wchar_t, 64> offStr{};
        _snwprintf_s(offStr.data(), offStr.size(), _TRUNCATE, L"&offset=%lld", (long long)offset);
        query += offStr.data();

        int rc = sendChunk(query, offset, currentChunk);
        if (rc != SFTP_OK)
            return rc;
            
        offset += currentChunk;
        if (localSize == 0) break; // empty file
    }

    DWORD code = 0;
    std::wstring fin = BuildQueryPathOnly(L"FINALIZE", pathUtf8);
    int rc = SendSimpleRequest(cs, L"POST", L"FINALIZE", fin, nullptr, 0, &code, nullptr);
    if (rc != SFTP_OK)
        return rc;
    if (!IsHttpSuccess(code)) {
        ReportPhpAgentHttpError(cs, code, "FINALIZE");
        return SFTP_WRITEFAILED;
    }
    if (localSize > 0)
        UpdatePercentBar(cs, 100, localNameW, remoteNameW);
    return SFTP_OK;
}

int PhpAgentCreateDirectoryW(pConnectSettings cs, LPCWSTR remoteDirW)
{
    std::string pathUtf8 = NormalizePhpRemotePath(cs, remoteDirW);
    DWORD code = 0;
    std::wstring q = BuildQueryPathOnly(L"MKDIR", pathUtf8);
    int rc = SendSimpleRequest(cs, L"POST", L"MKDIR", q, nullptr, 0, &code, nullptr);
    if (rc != SFTP_OK)
        return rc;
    if (!IsHttpSuccess(code)) {
        ReportPhpAgentHttpError(cs, code, "MKDIR");
        return SFTP_FAILED;
    }
    return SFTP_OK;
}

int PhpAgentRenameMoveFileW(pConnectSettings cs, LPCWSTR oldNameW, LPCWSTR newNameW, bool overwrite)
{
    std::string oldUtf8 = NormalizePhpRemotePath(cs, oldNameW);
    std::string newUtf8 = NormalizePhpRemotePath(cs, newNameW);
    std::wstring q = L"op=RENAME&from=" + UrlEncodeUtf8(oldUtf8) + L"&to=" + UrlEncodeUtf8(newUtf8);
    q += overwrite ? L"&overwrite=1" : L"&overwrite=0";
    DWORD code = 0;
    int rc = SendSimpleRequest(cs, L"POST", L"RENAME", q, nullptr, 0, &code, nullptr);
    if (rc != SFTP_OK)
        return rc;
    if (!IsHttpSuccess(code)) {
        ReportPhpAgentHttpError(cs, code, "RENAME");
        return SFTP_FAILED;
    }
    return SFTP_OK;
}

int PhpAgentDeleteFileW(pConnectSettings cs, LPCWSTR remoteNameW, bool isdir)
{
    std::string pathUtf8 = NormalizePhpRemotePath(cs, remoteNameW);
    std::wstring q = BuildQueryPathOnly(isdir ? L"RMDIR" : L"DELETE", pathUtf8);
    DWORD code = 0;
    int rc = SendSimpleRequest(cs, L"POST", isdir ? L"RMDIR" : L"DELETE", q, nullptr, 0, &code, nullptr);
    if (rc != SFTP_OK)
        return rc;
    if (!IsHttpSuccess(code)) {
        ReportPhpAgentHttpError(cs, code, isdir ? "RMDIR" : "DELETE");
        return SFTP_FAILED;
    }
    return SFTP_OK;
}

int PhpShellExecuteCommand(pConnectSettings cs,
                           const char* command,
                           std::string& outText,
                           std::string* outCwdAbs,
                           const std::string* inCwdAbs)
{
    outText.clear();
    if (outCwdAbs)
        outCwdAbs->clear();
    if (!cs || !command || !command[0])
        return SFTP_FAILED;

    std::wstring query = L"op=SHELL_EXEC&cwd=";
    if (inCwdAbs && !inCwdAbs->empty())
        query += UrlEncodeUtf8(*inCwdAbs);
    else
        query += L".";
    query += L"&cmd=";
    query += UrlEncodeUtf8(command);

    DWORD code = 0;
    std::string body;
    int rc = SendSimpleRequest(cs, L"POST", L"SHELL_EXEC", query, nullptr, 0, &code, &body);
    if (rc != SFTP_OK)
        return rc;
    if (!IsHttpSuccess(code)) {
        std::string err;
        if (ExtractErrorMessage(body, &err) && !err.empty())
            outText = err;
        else
            outText = body.empty() ? "SHELL_EXEC failed." : body;
        return SFTP_FAILED;
    }

    std::string stdoutB64;
    std::string stderrB64;
    std::string cwdAbs;
    std::string cwdRel;
    int exitCode = 0;
    ExtractJsonStringField(body, "stdout_b64", &stdoutB64);
    ExtractJsonStringField(body, "stderr_b64", &stderrB64);
    ExtractJsonStringField(body, "cwd_abs", &cwdAbs);
    ExtractJsonStringField(body, "cwd", &cwdRel);
    ExtractJsonIntField(body, "exit_code", &exitCode);
    if (outCwdAbs) {
        if (!cwdAbs.empty())
            *outCwdAbs = cwdAbs;
        else
            *outCwdAbs = cwdRel;
    }

    const std::string stdoutText = Base64DecodeString(stdoutB64);
    const std::string stderrText = Base64DecodeString(stderrB64);
    outText = stdoutText;
    if (!stderrText.empty()) {
        if (!outText.empty() && outText.back() != '\n')
            outText.push_back('\n');
        outText += stderrText;
    }
    return (exitCode == 0) ? SFTP_OK : SFTP_FAILED;
}

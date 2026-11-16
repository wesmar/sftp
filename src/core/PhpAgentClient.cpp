#include "global.h"
#include "PhpAgentClient.h"
#include "res/resource.h"
#include <winhttp.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <array>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <algorithm>
#include <format>
#include <cctype>
#include <cstdlib>
#include <regex>
#include <unordered_map>
#include "CoreUtils.h"
#include "UnicodeHelpers.h"
#include "SftpInternal.h"
#include "PluginEntryPoints.h"

#pragma comment(lib, "winhttp.lib")

#define PHP_LOG(fmt, ...) SFTP_LOG("PHP", fmt, ##__VA_ARGS__)

// Load a translated string as UTF-8 (LNG takes priority, then RC).
static std::string PhpLngStr(UINT id, const char* fallback)
{
    const char* s = LngGetString(id);
    if (s) return s;
    std::array<char, 512> buf{};
    const int n = LoadStringA(hinst, id, buf.data(), static_cast<int>(buf.size()) - 1);
    return n > 0 ? std::string(buf.data(), static_cast<size_t>(n)) : (fallback ? fallback : "");
}

// Replace first occurrence of "{}" in templ with each arg in order.
static std::string PhpFmtStr(UINT id, const char* fallback, std::initializer_list<std::string> args)
{
    std::string s = PhpLngStr(id, fallback);
    for (const auto& a : args) {
        const auto p = s.find("{}");
        if (p == std::string::npos) break;
        s = s.substr(0, p) + a + s.substr(p + 2);
    }
    return s;
}

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

// The agent speaks UTF-8: paths go out and names come back in it.

static std::string NormalizePhpRemotePath(LPCWSTR pathW)
{
    std::string p = unicode_util::wstring_to_utf8(pathW ? pathW : L".");
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
    // The panel path is relative to the agent root as it is; nothing of the
    // agent URL is part of it, so no host or script name is cut from it.
    while (!p.empty() && p.front() == '/')
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

// ---------------------------------------------------------------------------
// Request signing, TCSFTP-HMAC-V2 (the agent side is require_auth in
// sftp.php). The PSK never travels: every request carries an HMAC-SHA256
// over method, operation, the whole query, the SHA-256 of its body, a
// timestamp and a nonce the agent accepts once.
// ---------------------------------------------------------------------------
constexpr char kAuthScheme[] = "TCSFTP-HMAC-V2";
constexpr char kEmptyBodySha256[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

static std::string HexLower(const unsigned char* data, size_t len)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += kHex[data[i] >> 4];
        out += kHex[data[i] & 0x0F];
    }
    return out;
}

static std::string Sha256Hex(const void* data, size_t len)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    size_t mdLen = 0;
    if (!EVP_Q_digest(nullptr, "SHA256", nullptr, data, len, md, &mdLen))
        return {};
    return HexLower(md, mdLen);
}

// SHA-256 fed piece by piece, for bodies streamed from disk.
class Sha256Stream {
public:
    Sha256Stream() : ctx_(EVP_MD_CTX_new()) { ok_ = ctx_ && EVP_DigestInit_ex2(ctx_, EVP_sha256(), nullptr); }
    ~Sha256Stream() { EVP_MD_CTX_free(ctx_); }
    Sha256Stream(const Sha256Stream&) = delete;
    Sha256Stream& operator=(const Sha256Stream&) = delete;

    void Update(const void* data, size_t len) { ok_ = ok_ && EVP_DigestUpdate(ctx_, data, len); }
    std::string FinalHex()
    {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdLen = 0;
        if (!ok_ || !EVP_DigestFinal_ex(ctx_, md, &mdLen))
            return {};
        return HexLower(md, mdLen);
    }

private:
    EVP_MD_CTX* ctx_;
    bool ok_ = false;
};

// SHA-256 of `length` bytes of the file from `offset`; the file pointer is
// left where it was found to be needed next: at `offset`.
static std::string Sha256FileRange(HANDLE file, int64_t offset, int64_t length)
{
    LARGE_INTEGER li{};
    li.QuadPart = offset;
    if (!SetFilePointerEx(file, li, nullptr, FILE_BEGIN))
        return {};
    Sha256Stream hash;
    std::vector<uint8_t> buf(65536);
    for (int64_t left = length; left > 0;) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>((std::min)(left, static_cast<int64_t>(buf.size())));
        if (!ReadFile(file, buf.data(), want, &got, nullptr) || got == 0)
            return {};
        hash.Update(buf.data(), got);
        left -= got;
    }
    if (!SetFilePointerEx(file, li, nullptr, FILE_BEGIN))
        return {};
    return hash.FinalHex();
}

static std::string HmacSha256Hex(const std::string& key, const std::string& message)
{
    unsigned char mac[EVP_MAX_MD_SIZE];
    size_t macLen = 0;
    if (!EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, key.data(), key.size(),
                   reinterpret_cast<const unsigned char*>(message.data()), message.size(),
                   mac, sizeof(mac), &macLen))
        return {};
    return HexLower(mac, macLen);
}

// The query the way sftp.php signs it (canonical_query): every parameter
// percent-decoded, sorted by name and then by value, encoded again per
// RFC 3986 - so the bytes on the wire need not match, only their meaning.
static std::string CanonicalQuery(std::string_view query)
{
    const auto decode = [](std::string_view s) {
        const auto hexValue = [](char c) {
            return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        };
        std::string out;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '%' && i + 2 < s.size() && hexValue(s[i + 1]) >= 0 && hexValue(s[i + 2]) >= 0) {
                out += static_cast<char>(hexValue(s[i + 1]) * 16 + hexValue(s[i + 2]));
                i += 2;
            } else {
                out += s[i];
            }
        }
        return out;
    };
    const auto encode = [](const std::string& s) {
        static constexpr char kHex[] = "0123456789ABCDEF";
        std::string out;
        for (unsigned char c : s) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '-' || c == '.' || c == '_' || c == '~') {
                out += static_cast<char>(c);
            } else {
                out += '%';
                out += kHex[c >> 4];
                out += kHex[c & 0x0F];
            }
        }
        return out;
    };

    std::vector<std::pair<std::string, std::string>> pairs;
    while (!query.empty()) {
        const size_t amp = query.find('&');
        const std::string_view part = query.substr(0, amp);
        query = amp == std::string_view::npos ? std::string_view() : query.substr(amp + 1);
        if (part.empty())
            continue;
        const size_t eq = part.find('=');
        pairs.emplace_back(decode(part.substr(0, eq)),
                           eq == std::string_view::npos ? std::string() : decode(part.substr(eq + 1)));
    }
    std::sort(pairs.begin(), pairs.end());
    std::string out;
    for (const auto& [name, value] : pairs) {
        if (!out.empty())
            out += '&';
        out += encode(name);
        out += '=';
        out += encode(value);
    }
    return out;
}

static int ProbeAgent(pConnectSettings cs, std::string* outBody, std::string* outError);

// The headers that authenticate one request: its operation, time, nonce,
// body hash and signature. False when the agent's scheme is unknown or not
// the one this plugin speaks; no request then goes out at all.
static bool AuthHeaders(pConnectSettings cs, const wchar_t* method, const wchar_t* op,
                        const std::wstring& object, const std::string& bodySha256, std::wstring& outHeaders)
{
    if (!cs->php_auth_known && ProbeAgent(cs, nullptr, nullptr) != SFTP_OK)
        return false;

    const size_t q = object.find(L'?');
    const std::string query = q == std::wstring::npos ? std::string() : unicode_util::wstring_to_utf8(object.substr(q + 1));
    const std::string ts = std::to_string(static_cast<long long>(std::time(nullptr)) + cs->php_clock_offset);
    unsigned char random[16];
    if (RAND_bytes(random, sizeof(random)) != 1)
        return false;
    const std::string nonce = HexLower(random, sizeof(random));

    std::string key;
    {
        // Built in place, so the PSK is not left behind in a temporary.
        std::string material = cs->php_auth_salt;
        material += ':';
        material += cs->password;
        key = Sha256Hex(material.data(), material.size());
        SecureZeroMemory(material.data(), material.size());
    }
    const std::string base = std::string(kAuthScheme) + '\n' + unicode_util::wstring_to_utf8(method) + '\n' +
                             unicode_util::wstring_to_utf8(op) + '\n' + CanonicalQuery(query) + '\n' +
                             bodySha256 + '\n' + ts + '\n' + nonce;
    const std::string signature = HmacSha256Hex(key, base);
    SecureZeroMemory(key.data(), key.size());
    if (signature.empty() || bodySha256.empty())
        return false;

    outHeaders = L"X-SFTP-OP: ";
    outHeaders += op;
    outHeaders += L"\r\nX-SFTP-TS: " + unicode_util::utf8_to_wstring(ts);
    outHeaders += L"\r\nX-SFTP-NONCE: " + unicode_util::utf8_to_wstring(nonce);
    outHeaders += L"\r\nX-SFTP-CONTENT-SHA256: " + unicode_util::utf8_to_wstring(bodySha256);
    outHeaders += L"\r\nX-SFTP-SIGNATURE-V2: " + unicode_util::utf8_to_wstring(signature);
    outHeaders += L"\r\n";
    return true;
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

// The response's Date header as Unix time, or 0 when it has none.
static int64_t ResponseUnixTime(HINTERNET request)
{
    SYSTEMTIME st{};
    DWORD size = sizeof(st);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_DATE | WINHTTP_QUERY_FLAG_SYSTEMTIME,
                             WINHTTP_HEADER_NAME_BY_INDEX, &st, &size, WINHTTP_NO_HEADER_INDEX))
        return 0;
    FILETIME ft{};
    if (!SystemTimeToFileTime(&st, &ft))
        return 0;
    const int64_t ticks = (static_cast<int64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return (ticks - 116444736000000000LL) / 10000000LL; // 100 ns since 1601 -> s since 1970
}

// PROBE goes out unsigned - it is what tells the client how to sign;
// every other operation is signed.
static int SendSimpleRequest(
    pConnectSettings cs,
    const wchar_t* method,
    const wchar_t* op,
    const std::wstring& query,
    const char* body,
    DWORD bodyLen,
    DWORD* outStatus,
    std::string* outBody,
    int64_t* outServerTime = nullptr)
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
    std::wstring headers = L"X-SFTP-OP: PROBE\r\n";
    if (wcscmp(op, L"PROBE") != 0) {
        const std::string bodySha = body && bodyLen ? Sha256Hex(body, bodyLen) : std::string(kEmptyBodySha256);
        if (!AuthHeaders(cs, method, op, object, bodySha, headers))
            return SFTP_FAILED;
    }
    h.request = WinHttpOpenRequest(h.connect, method, object.c_str(), nullptr, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, url.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!h.request)
        return SFTP_FAILED;

    BOOL ok = WinHttpSendRequest(h.request, headers.c_str(), (DWORD)-1L,
                                 const_cast<char*>(body), bodyLen, bodyLen, 0);
    if (!ok)
        return SFTP_FAILED;
    if (!WinHttpReceiveResponse(h.request, nullptr))
        return SFTP_FAILED;

    DWORD status = 0;
    if (!QueryStatus(h.request, &status))
        return SFTP_FAILED;
    if (outServerTime)
        *outServerTime = ResponseUnixTime(h.request);
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

// A failed transfer is reported by Total Commander - or offered for skipping
// within a batch - so it goes to the log only: a dialog of its own would
// repeat for every file of a batch, "Skip all" or not.
static void LogPhpAgentTransferError(DWORD code, const char* op)
{
    const std::string text = (code == 401 || code == 403)
        ? PhpFmtStr(IDS_PHP_ERR_WRONG_CREDS_HTTP, "Wrong credentials for PHP Agent (HTTP {}).", {std::to_string(static_cast<unsigned long>(code))})
        : PhpFmtStr(IDS_PHP_ERR_REQUEST_FAILED, "PHP Agent request failed for {} (HTTP {}).", {op ? op : "operation", std::to_string(static_cast<unsigned long>(code))});
    ShowStatus(text.c_str());
}

static void ReportPhpAgentHttpError(pConnectSettings cs, DWORD code, const char* op)
{
    if (!cs || !cs->feedback)
        return;
    if (code == 401 || code == 403) {
        cs->feedback->ShowError(PhpFmtStr(IDS_PHP_ERR_WRONG_CREDS_HTTP, "Wrong credentials for PHP Agent (HTTP {}).", {std::to_string(static_cast<unsigned long>(code))}),
                                PhpLngStr(IDS_PHP_AGENT_TITLE, "PHP Agent"));
        return;
    }
    if (code >= 400) {
        cs->feedback->ShowError(PhpFmtStr(IDS_PHP_ERR_REQUEST_FAILED, "PHP Agent request failed for {} (HTTP {}).", {op ? op : "operation", std::to_string(static_cast<unsigned long>(code))}),
                                PhpLngStr(IDS_PHP_AGENT_TITLE, "PHP Agent"));
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
    // A name cut to fit would point at a file that does not exist.
    if (ConvUTF8toUTF16(nameUtf8.c_str(), 0, fd.cFileName, std::size(fd.cFileName)) <= 0)
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

    std::wstring headers;
    if (!AuthHeaders(cs, L"GET", L"GET", object, kEmptyBodySha256, headers))
        return SFTP_FAILED;
    if (!WinHttpSendRequest(h.request, headers.c_str(), (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        return SFTP_FAILED;
    if (!WinHttpReceiveResponse(h.request, nullptr))
        return SFTP_FAILED;

    DWORD code = 0;
    if (!QueryStatus(h.request, &code) || !IsHttpSuccess(code)) {
        LogPhpAgentTransferError(code, "GET");
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
    // The chunk is read twice: once for the hash its signature covers, then
    // to send it. Sha256FileRange leaves the file at startOffset.
    const std::string bodySha = Sha256FileRange(hLocal, startOffset, chunkLength);
    if (bodySha.empty())
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

    std::wstring headers;
    if (!AuthHeaders(cs, method ? method : L"POST", L"PUT", object, bodySha, headers))
        return SFTP_FAILED;
    headers += L"Content-Type: application/octet-stream\r\n";

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
            LogPhpAgentTransferError(code, method ? (wcscmp(method, L"PUT") == 0 ? "PUT" : "POST") : "POST");
        return SFTP_WRITEFAILED;
    }
    return SFTP_OK;
}

// The agent's public PROBE: whether it speaks TCSFTP-HMAC-V2, its salt, and
// its clock, so that requests carry a time it accepts even when this
// computer's clock is off. An agent that does not sign is not used - the
// PSK is never sent instead.
static int ProbeAgent(pConnectSettings cs, std::string* outBody, std::string* outError)
{
    if (!cs)
        return SFTP_FAILED;
    DWORD code = 0;
    std::string body;
    int64_t serverTime = 0;
    const int rc = SendSimpleRequest(cs, L"GET", L"PROBE", L"op=PROBE", nullptr, 0, &code, &body, &serverTime);
    if (rc != SFTP_OK)
        return rc;
    if (!IsHttpSuccess(code))
        return SFTP_FAILED;

    std::string scheme;
    if (!ExtractJsonStringField(body, "scheme", &scheme) || scheme != kAuthScheme) {
        PHP_LOG("Agent does not speak %s (scheme '%s')", kAuthScheme, scheme.c_str());
        if (outError)
            *outError = PhpLngStr(IDS_PHP_ERR_AGENT_OUTDATED,
                                  "The PHP Agent on the server is too old for this plugin version: it does not "
                                  "accept signed requests. Upload the sftp.php that comes with the plugin.");
        return SFTP_FAILED;
    }
    std::string salt;
    ExtractJsonStringField(body, "salt", &salt); // no salt at all is a valid configuration
    cs->php_auth_salt = std::move(salt);
    cs->php_clock_offset = serverTime > 0 ? serverTime - static_cast<int64_t>(std::time(nullptr)) : 0;
    cs->php_auth_known = true;
    PHP_LOG("Agent signs with %s, clock offset %lld s", kAuthScheme, static_cast<long long>(cs->php_clock_offset));
    if (outBody)
        *outBody = std::move(body);
    return SFTP_OK;
}

} // namespace

int PhpAgentProbe(pConnectSettings cs, std::string& outErrorText)
{
    outErrorText.clear();
    PHP_LOG("Probe start url='%s'", (cs && !cs->server.empty()) ? cs->server.c_str() : "");
    std::string body;
    const int rc = ProbeAgent(cs, &body, &outErrorText);
    if (rc != SFTP_OK)
        return rc;
    {
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
    PHP_LOG("Probe done body_len=%u", (unsigned)body.size());
    return SFTP_OK;
}

int PhpAgentValidateAuth(pConnectSettings cs, std::string& outErrorText)
{
    outErrorText.clear();
    // An agent too old to verify signatures is reported as such, not as a
    // wrong password.
    if (cs && !cs->php_auth_known) {
        std::string probeError;
        if (ProbeAgent(cs, nullptr, &probeError) != SFTP_OK && !probeError.empty()) {
            outErrorText = probeError;
            return SFTP_FAILED;
        }
    }
    DWORD code = 0;
    std::string body;
    const int rc = SendSimpleRequest(cs, L"GET", L"LIST", L"op=LIST&path=.&format=plain", nullptr, 0, &code, &body);
    if (rc != SFTP_OK) {
        std::array<char, 256> msg{};
        const int n = LoadStr(msg, IDS_PHP_ERR_UNREACHABLE);
        outErrorText = (n > 0) ? msg.data() : "Cannot reach PHP agent endpoint.";
        return rc;
    }
    if (IsHttpSuccess(code))
        return SFTP_OK;

    std::string serverMsg;
    ExtractErrorMessage(body, &serverMsg);
    if (code == 401 || code == 403) {
        outErrorText = PhpFmtStr(IDS_PHP_ERR_WRONG_CREDS_HTTP, "Wrong credentials for PHP Agent (HTTP {}).", {std::to_string(static_cast<unsigned long>(code))});
    } else if (code == 404) {
        std::array<char, 512> msg{};
        const int n = LoadStr(msg, IDS_PHP_ERR_NOT_FOUND);
        outErrorText = (n > 0) ? msg.data() : "PHP agent endpoint not found (HTTP 404).\nCheck URL path/filename and upload sftp.php to that location.";
    } else if (code == 503) {
        std::array<char, 512> msg{};
        const int n = LoadStr(msg, IDS_PHP_ERR_UNCONFIGURED);
        outErrorText = (n > 0) ? msg.data() : "PHP agent is not configured on server (HTTP 503).\nSet AGENT_PSK / AGENT_PSK_SHA256 in sftp.php and upload again.";
    } else if (!serverMsg.empty()) {
        outErrorText = PhpFmtStr(IDS_PHP_ERR_REJECTED, "PHP Agent rejected request: {}", {serverMsg});
    } else {
        outErrorText = PhpFmtStr(IDS_PHP_ERR_VALIDATION, "PHP Agent validation failed (HTTP {}).", {std::to_string(static_cast<unsigned long>(code))});
    }
    return SFTP_FAILED;
}

int PhpAgentListDirectoryW(pConnectSettings cs, LPCWSTR remoteDir, std::vector<WIN32_FIND_DATAW>& outEntries)
{
    outEntries.clear();
    std::string pathUtf8 = NormalizePhpRemotePath(remoteDir ? remoteDir : L".");
    DWORD code = 0;
    std::string body;
    auto doList = [&](const std::string& p) -> int {
        std::wstring query = BuildQueryPathOnly(L"LIST", p);
        query += L"&format=plain";
        return SendSimpleRequest(cs, L"GET", L"LIST", query, nullptr, 0, &code, &body);
    };

    // A missing folder is an error, never the root listed under its name:
    // files copied there would land somewhere else than the panel shows.
    int rc = doList(pathUtf8);
    if (rc != SFTP_OK)
        return rc;
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

    std::string pathUtf8 = NormalizePhpRemotePath(remoteNameW);
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

    std::string pathUtf8 = NormalizePhpRemotePath(remoteNameW);
    // Resume may be invoked against an already-visible "*.part" entry.
    // Canonicalize to the final target name to avoid creating "*.part.part".
    if (resume && pathUtf8.size() > 5 && _stricmp(pathUtf8.c_str() + pathUtf8.size() - 5, ".part") == 0) {
        pathUtf8.resize(pathUtf8.size() - 5);
    }
    PHP_LOG("PUT normalized path='%s'", pathUtf8.c_str());

    int64_t offset = 0;
    // Continue a "<path>.part" only when the user asked to resume. A leftover
    // one may belong to another file: taking it up unasked would splice its
    // head onto this file's tail — or, at equal size, finalise it without a
    // byte sent — and a move would then delete the local original.
    if (resume) {
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
                PHP_LOG("PUT resume found .part size=%lld local=%lld",
                        (long long)partSize,
                        (long long)localSize);
            }
        }
    }

    if (localSize > 0 && offset == localSize) {
        // A resumed upload whose .part already holds everything: finalize
        // only. An empty file is not this case - it still has to create
        // its .part, which the loop below does.
        DWORD code = 0;
        std::wstring finOnly = BuildQueryPathOnly(L"FINALIZE", pathUtf8);
        int rc = SendSimpleRequest(cs, L"POST", L"FINALIZE", finOnly, nullptr, 0, &code, nullptr);
        if (rc != SFTP_OK)
            return rc;
        if (!IsHttpSuccess(code)) {
            LogPhpAgentTransferError(code, "FINALIZE");
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
        LogPhpAgentTransferError(code, "FINALIZE");
        return SFTP_WRITEFAILED;
    }
    if (localSize > 0)
        UpdatePercentBar(cs, 100, localNameW, remoteNameW);
    return SFTP_OK;
}

int PhpAgentCreateDirectoryW(pConnectSettings cs, LPCWSTR remoteDirW)
{
    std::string pathUtf8 = NormalizePhpRemotePath(remoteDirW);
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
    std::string oldUtf8 = NormalizePhpRemotePath(oldNameW);
    std::string newUtf8 = NormalizePhpRemotePath(newNameW);
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
    std::string pathUtf8 = NormalizePhpRemotePath(remoteNameW);
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

// The agent answers 404 for a missing path or a missing parent; anything
// else, a failed request included, leaves the question open.
bool PhpAgentPathMayExist(pConnectSettings cs, LPCWSTR remoteNameW)
{
    const std::string pathUtf8 = NormalizePhpRemotePath(remoteNameW);
    const std::wstring q = BuildQueryPathOnly(L"STAT", pathUtf8);
    DWORD code = 0;
    const int rc = SendSimpleRequest(cs, L"GET", L"STAT", q, nullptr, 0, &code, nullptr);
    return !(rc == SFTP_OK && code == 404);
}

// ---------------------------------------------------------------------------
// TAR streaming download (PHP Agent php_tar mode)
// ---------------------------------------------------------------------------

namespace {

struct TarRawHeader {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
};
static_assert(sizeof(TarRawHeader) == 512, "TarRawHeader must be 512 bytes");

static bool TarIsZeroBlock(const uint8_t* p)
{
    for (int i = 0; i < 512; ++i)
        if (p[i]) return false;
    return true;
}

static int64_t TarParseOctal(const char* s, int len)
{
    int64_t v = 0;
    for (int i = 0; i < len; ++i) {
        if (s[i] == ' ' || s[i] == '\0') break;
        if (s[i] >= '0' && s[i] <= '7')
            v = v * 8 + (s[i] - '0');
    }
    return v;
}

static bool TarIsSafePath(const std::string& p)
{
    if (p.empty() || p[0] == '/') return false;
    size_t i = 0;
    while (i <= p.size()) {
        size_t slash = p.find('/', i);
        if (slash == std::string::npos) slash = p.size();
        std::string_view comp(p.data() + i, slash - i);
        if (comp == ".." || comp == ".") return false;
        i = slash + 1;
    }
    return true;
}

static bool TarEnsureDirW(const std::wstring& path)
{
    std::wstring p = path;
    while (!p.empty() && (p.back() == L'\\' || p.back() == L'/'))
        p.pop_back();
    if (p.empty()) return true;
    DWORD attr = GetFileAttributesW(p.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES)
        return !!(attr & FILE_ATTRIBUTE_DIRECTORY);
    size_t sep = p.rfind(L'\\');
    if (sep == std::wstring::npos) sep = p.rfind(L'/');
    if (sep != std::wstring::npos && !TarEnsureDirW(p.substr(0, sep)))
        return false;
    return CreateDirectoryW(p.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}

// Buffered HTTP reader — keeps at least 512 KB in flight
struct TarReader {
    HINTERNET req;
    std::vector<uint8_t> buf;
    size_t pos = 0, end_ = 0;
    bool eof_ = false;

    explicit TarReader(HINTERNET r) : req(r), buf(512 * 1024) {}

    bool fill(size_t need) {
        while (!eof_ && (end_ - pos) < need) {
            if (pos > 0) {
                memmove(buf.data(), buf.data() + pos, end_ - pos);
                end_ -= pos;
                pos = 0;
            }
            if (end_ + need > buf.size())
                buf.resize(end_ + need + 64 * 1024);
            DWORD got = 0;
            if (!WinHttpReadData(req, buf.data() + end_,
                                 (DWORD)(buf.size() - end_), &got) || got == 0)
                eof_ = true;
            else
                end_ += got;
        }
        return (end_ - pos) >= need;
    }

    const uint8_t* peek(size_t n) { return fill(n) ? buf.data() + pos : nullptr; }
    void advance(size_t n) { pos += n; }
    void skip(size_t n) {
        while (n > 0) {
            if (pos >= end_) { if (!fill(1)) return; }
            size_t avail = end_ - pos;
            size_t s = n < avail ? n : avail;
            pos += s; n -= s;
        }
    }
};

} // namespace

int PhpAgentDownloadDirAsTar(pConnectSettings cs, LPCWSTR remoteDirW, LPCWSTR localDirW, bool overwrite)
{
    if (!cs || !remoteDirW || !localDirW)
        return SFTP_FAILED;

    AgentUrl url;
    if (!ParseAgentUrl(cs, &url))
        return SFTP_FAILED;

    HttpHandles h;
    h.session = WinHttpOpen(L"TC-SFTP-PHP-Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h.session) return SFTP_FAILED;
    WinHttpSetTimeouts(h.session, 15000, 15000, 300000, 300000);
    h.connect = WinHttpConnect(h.session, url.host.c_str(), url.port, 0);
    if (!h.connect) return SFTP_FAILED;

    const std::string pathUtf8 = NormalizePhpRemotePath(remoteDirW);
    const std::wstring query   = L"op=TAR_STREAM&path=" + UrlEncodeUtf8(pathUtf8);
    const std::wstring object  = BuildObjectPath(url.object, query);
    h.request = WinHttpOpenRequest(h.connect, L"GET", object.c_str(), nullptr,
                                   WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                   url.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!h.request) return SFTP_FAILED;

    std::wstring headers;
    if (!AuthHeaders(cs, L"GET", L"TAR_STREAM", object, kEmptyBodySha256, headers))
        return SFTP_FAILED;
    if (!WinHttpSendRequest(h.request, headers.c_str(), (DWORD)-1L,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        return SFTP_FAILED;
    if (!WinHttpReceiveResponse(h.request, nullptr))
        return SFTP_FAILED;

    DWORD httpCode = 0;
    if (!QueryStatus(h.request, &httpCode) || !IsHttpSuccess(httpCode)) {
        PHP_LOG("TAR_STREAM HTTP status=%lu", (unsigned long)httpCode);
        return SFTP_FAILED;
    }

    int64_t totalBytes = 0;
    QueryHeaderInt64(h.request, L"Content-Length", &totalBytes);

    if (!CreateDirectoryW(localDirW, nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        return SFTP_WRITEFAILED;

    std::wstring localRoot = localDirW;
    while (!localRoot.empty() && (localRoot.back() == L'\\' || localRoot.back() == L'/'))
        localRoot.pop_back();

    TarReader reader(h.request);
    int64_t bytesRead = 0;
    std::string pendingLongName;

    for (;;) {
        const uint8_t* hdrPtr = reader.peek(512);
        if (!hdrPtr) return SFTP_READFAILED;
        reader.advance(512);
        bytesRead += 512;

        if (TarIsZeroBlock(hdrPtr)) {
            const uint8_t* hdr2 = reader.peek(512);
            if (hdr2 && TarIsZeroBlock(hdr2)) { reader.advance(512); }
            break;
        }

        const auto* hdr = reinterpret_cast<const TarRawHeader*>(hdrPtr);
        const int64_t fileSize = TarParseOctal(hdr->size, 12);
        const char    typeflag = hdr->typeflag;

        // Build full path (ustar prefix + name)
        std::string entryPath;
        if (hdr->prefix[0] != '\0') {
            entryPath.assign(hdr->prefix, strnlen(hdr->prefix, 155));
            entryPath += '/';
        }
        entryPath += std::string(hdr->name, strnlen(hdr->name, 100));

        // GNU long name: data block contains the real filename
        if (typeflag == 'L') {
            if (fileSize > 0) {
                std::string longBuf(static_cast<size_t>(fileSize), '\0');
                size_t rem = longBuf.size(), off = 0;
                while (rem > 0) {
                    size_t want = rem < 65536 ? rem : 65536;
                    const uint8_t* p = reader.peek(want);
                    if (!p) { rem = 0; break; }
                    memcpy(longBuf.data() + off, p, want);
                    reader.advance(want);
                    bytesRead += (int64_t)want;
                    off += want; rem -= want;
                }
                const int64_t padded = ((fileSize + 511) / 512) * 512;
                const int64_t pad    = padded - (int64_t)off;
                if (pad > 0) { reader.skip((size_t)pad); bytesRead += pad; }
                while (!longBuf.empty() && longBuf.back() == '\0') longBuf.pop_back();
                pendingLongName = std::move(longBuf);
            }
            continue;
        }

        if (!pendingLongName.empty()) {
            entryPath = std::move(pendingLongName);
            pendingLongName.clear();
        }

        // Progress (also enables abort even when Content-Length is missing).
        int pct = 0;
        if (totalBytes > 0) {
            pct = (int)(bytesRead * 100 / totalBytes);
            if (pct > 100) pct = 100;
        }
        if (UpdatePercentBar(cs, pct, remoteDirW, localDirW))
            return SFTP_ABORT;

        // Normalise and sanitise path
        std::replace(entryPath.begin(), entryPath.end(), '\\', '/');
        while (!entryPath.empty() && entryPath[0] == '/') entryPath.erase(entryPath.begin());
        const bool isDirEntry = (typeflag == '5');
        while (!entryPath.empty() && entryPath.back() == '/') entryPath.pop_back();

        if (entryPath.empty() || !TarIsSafePath(entryPath)) {
            reader.skip((size_t)(((fileSize + 511) / 512) * 512));
            bytesRead += ((fileSize + 511) / 512) * 512;
            continue;
        }

        std::wstring localPath = localRoot + L'\\' + unicode_util::utf8_to_wstring(entryPath);
        std::replace(localPath.begin(), localPath.end(), L'/', L'\\');

        if (isDirEntry) {
            TarEnsureDirW(localPath);
            if (fileSize > 0) {
                reader.skip((size_t)(((fileSize + 511) / 512) * 512));
                bytesRead += ((fileSize + 511) / 512) * 512;
            }
            continue;
        }

        // Create parent directories
        {
            size_t sep = localPath.rfind(L'\\');
            if (sep != std::wstring::npos) TarEnsureDirW(localPath.substr(0, sep));
        }

        const DWORD createDisp = overwrite ? CREATE_ALWAYS : CREATE_NEW;
        HANDLE hf = CreateFileW(localPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                createDisp, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

        const int64_t paddedSize = ((fileSize + 511) / 512) * 512;

        if (hf == INVALID_HANDLE_VALUE) {
            reader.skip((size_t)paddedSize);
            bytesRead += paddedSize;
            continue;
        }
        AutoFileHandle localFile(hf);

        int64_t remaining = fileSize;
        while (remaining > 0) {
            size_t want = (size_t)(remaining < 65536 ? remaining : 65536);
            const uint8_t* p = reader.peek(want);
            if (!p) return SFTP_READFAILED;
            DWORD written = 0;
            if (!WriteFile(localFile.get(), p, static_cast<DWORD>(want), &written, nullptr) || written != want)
                return SFTP_WRITEFAILED;
            reader.advance(want);
            bytesRead += (int64_t)want;
            remaining -= (int64_t)want;
        }
        // Skip padding
        const int64_t dataConsumed = fileSize - remaining;
        const int64_t pad = paddedSize - dataConsumed;
        if (pad > 0) { reader.skip((size_t)pad); bytesRead += pad; }
    }

    UpdatePercentBar(cs, 100, remoteDirW, localDirW);
    return SFTP_OK;
}

// ---------------------------------------------------------------------------
// TAR streaming upload (PHP Agent php_tar mode)
// ---------------------------------------------------------------------------

namespace {

static std::array<uint8_t, 512> BuildTarUploadHeader(const std::string& name, int64_t size, time_t mtime, char type)
{
    std::array<uint8_t, 512> blk{};
    if (size > INT64_C(8589934591)) size = 0; // POSIX ustar limit: 11 octal digits = max ~8 GiB
    const size_t nameLen = std::min<size_t>(name.size(), 99);
    memcpy(blk.data() + 0, name.c_str(), nameLen);
    const char* mode = (type == '5') ? "0000755" : "0000644";
    memcpy(blk.data() + 100, mode, 7);
    memcpy(blk.data() + 108, "0000000", 7);
    memcpy(blk.data() + 116, "0000000", 7);
    char szbuf[12] = {};
    snprintf(szbuf, sizeof(szbuf), "%011llo", (unsigned long long)(uint64_t)size);
    memcpy(blk.data() + 124, szbuf, 11);
    char mtbuf[12] = {};
    snprintf(mtbuf, sizeof(mtbuf), "%011llo", (unsigned long long)(uint64_t)(time_t)mtime);
    memcpy(blk.data() + 136, mtbuf, 11);
    memset(blk.data() + 148, ' ', 8);
    blk[156] = (uint8_t)type;
    memcpy(blk.data() + 257, "ustar", 5);
    memcpy(blk.data() + 263, "00", 2);
    unsigned int chksum = 0;
    for (int i = 0; i < 512; ++i) chksum += blk[i];
    char ckbuf[8] = {};
    snprintf(ckbuf, 7, "%06o", chksum);
    ckbuf[7] = ' ';
    memcpy(blk.data() + 148, ckbuf, 8);
    return blk;
}

} // namespace

struct TarUploadSession {
    pConnectSettings          cs = nullptr;
    std::wstring              remoteBaseRel;
    std::vector<TarUploadEntry> entries;
    bool                      active = false;
};

static TarUploadSession s_tarSession;

void TarUploadSessionBegin(pConnectSettings cs)
{
    s_tarSession.cs = cs;
    s_tarSession.remoteBaseRel.clear();
    s_tarSession.entries.clear();
    s_tarSession.active = true;
}

void TarUploadSessionClear()
{
    s_tarSession.active = false;
    s_tarSession.cs = nullptr;
    s_tarSession.remoteBaseRel.clear();
    s_tarSession.entries.clear();
}

bool TarUploadSessionIsActive(pConnectSettings cs)
{
    return s_tarSession.active && (cs == nullptr || s_tarSession.cs == cs);
}

bool TarUploadSessionQueue(pConnectSettings cs, LPCWSTR localPath, const char* remotePath)
{
    if (!s_tarSession.active || s_tarSession.cs != cs || !localPath || !remotePath)
        return false;

    std::string remoteA = remotePath;
    for (char& c : remoteA) if (c == '\\') c = '/';

    // Compute remoteBase from first queued entry
    if (s_tarSession.remoteBaseRel.empty() && s_tarSession.entries.empty()) {
        size_t slash = remoteA.rfind('/');
        if (slash != std::string::npos)
            s_tarSession.remoteBaseRel = unicode_util::utf8_to_wstring(remoteA.substr(0, slash));
        else
            s_tarSession.remoteBaseRel = L".";
    }

    // Compute TAR name: strip remoteBase prefix
    std::string baseA = unicode_util::wstring_to_utf8(s_tarSession.remoteBaseRel);
    std::string tarName;
    if (!baseA.empty() && remoteA.size() > baseA.size() + 1
        && _strnicmp(remoteA.c_str(), baseA.c_str(), baseA.size()) == 0
        && remoteA[baseA.size()] == '/')
    {
        tarName = remoteA.substr(baseA.size() + 1);
    } else {
        tarName = remoteA;
    }
    if (tarName.empty()) return false;

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(localPath, GetFileExInfoStandard, &fad))
        return false;

    TarUploadEntry e;
    e.localPath = localPath;
    e.tarName   = tarName;
    e.isDir     = !!(fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
    if (!e.isDir) {
        LARGE_INTEGER sz;
        sz.LowPart  = fad.nFileSizeLow;
        sz.HighPart = (LONG)fad.nFileSizeHigh;
        e.fileSize  = sz.QuadPart;
    }
    ULARGE_INTEGER ull;
    ull.LowPart  = fad.ftLastWriteTime.dwLowDateTime;
    ull.HighPart = fad.ftLastWriteTime.dwHighDateTime;
    e.mtime = (time_t)((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);
    s_tarSession.entries.push_back(std::move(e));
    return true;
}

int TarUploadSessionExecuteAndClear()
{
    if (!s_tarSession.active) return SFTP_OK;
    if (s_tarSession.entries.empty()) {
        TarUploadSessionClear();
        return SFTP_OK;
    }
    pConnectSettings cs = s_tarSession.cs;
    std::wstring remoteBase = s_tarSession.remoteBaseRel;
    const int rc = PhpAgentUploadDirAsTar(cs, remoteBase.c_str(), s_tarSession.entries);
    TarUploadSessionClear();
    return rc;
}

// ---------------------------------------------------------------------------
// TAR batch download (PHP Agent php_tar mode)
// ---------------------------------------------------------------------------

struct TarDownloadSession {
    pConnectSettings             cs     = nullptr;
    std::vector<TarDownloadEntry> entries;
    bool                         active = false;
};

static TarDownloadSession s_tarDlSession;

void TarDownloadSessionBegin(pConnectSettings cs)
{
    s_tarDlSession.cs = cs;
    s_tarDlSession.entries.clear();
    s_tarDlSession.active = true;
}

void TarDownloadSessionClear()
{
    s_tarDlSession.active = false;
    s_tarDlSession.cs = nullptr;
    s_tarDlSession.entries.clear();
}

bool TarDownloadSessionIsActive(pConnectSettings cs)
{
    return s_tarDlSession.active && (cs == nullptr || s_tarDlSession.cs == cs);
}

bool TarDownloadSessionQueue(pConnectSettings cs, LPCWSTR localPath, LPCWSTR remotePath)
{
    if (!s_tarDlSession.active || s_tarDlSession.cs != cs || !localPath || !remotePath)
        return false;

    TarDownloadEntry e;
    e.remotePath = NormalizePhpRemotePath(remotePath);
    if (e.remotePath.empty() || e.remotePath == ".") return false;
    e.localPath = localPath;
    s_tarDlSession.entries.push_back(std::move(e));
    return true;
}

int TarDownloadSessionExecuteAndClear()
{
    if (!s_tarDlSession.active) return SFTP_OK;
    if (s_tarDlSession.entries.empty()) {
        TarDownloadSessionClear();
        return SFTP_OK;
    }
    pConnectSettings cs = s_tarDlSession.cs;
    std::vector<TarDownloadEntry> entries = std::move(s_tarDlSession.entries);
    TarDownloadSessionClear();
    return PhpAgentDownloadFilesAsTar(cs, entries);
}

int PhpAgentDownloadFilesAsTar(pConnectSettings cs, const std::vector<TarDownloadEntry>& entries)
{
    if (!cs || entries.empty())
        return SFTP_OK;

    // Build lookup map: remotePath -> localPath, and POST body (one path per line)
    std::unordered_map<std::string, std::wstring> pathMap;
    std::string postBody;
    pathMap.reserve(entries.size());
    for (const auto& e : entries) {
        pathMap[e.remotePath] = e.localPath;
        postBody += e.remotePath;
        postBody += '\n';
    }

    PHP_LOG("TAR_PACK download start entries=%u bodyLen=%u", (unsigned)entries.size(), (unsigned)postBody.size());
    ShowStatusId(IDS_LOG_TAR_UPLOAD, (" " + std::to_string(entries.size())).c_str(), true);

    AgentUrl url;
    if (!ParseAgentUrl(cs, &url)) {
        PHP_LOG("TAR_PACK ParseAgentUrl failed");
        return SFTP_FAILED;
    }
    PHP_LOG("TAR_PACK url host=%ls port=%u obj=%ls secure=%d",
            url.host.c_str(), url.port, url.object.c_str(), url.secure ? 1 : 0);

    HttpHandles h;
    h.session = WinHttpOpen(L"TC-SFTP-PHP-Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h.session) { PHP_LOG("TAR_PACK WinHttpOpen failed gle=%lu", GetLastError()); return SFTP_FAILED; }
    WinHttpSetTimeouts(h.session, 15000, 15000, 300000, 300000);
    h.connect = WinHttpConnect(h.session, url.host.c_str(), url.port, 0);
    if (!h.connect) { PHP_LOG("TAR_PACK WinHttpConnect failed gle=%lu", GetLastError()); return SFTP_FAILED; }

    const std::wstring object = BuildObjectPath(url.object, L"op=TAR_PACK");
    h.request = WinHttpOpenRequest(h.connect, L"POST", object.c_str(), nullptr,
                                   WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                   url.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!h.request) { PHP_LOG("TAR_PACK WinHttpOpenRequest failed gle=%lu", GetLastError()); return SFTP_FAILED; }

    std::wstring headers;
    if (!AuthHeaders(cs, L"POST", L"TAR_PACK", object, Sha256Hex(postBody.data(), postBody.size()), headers))
        return SFTP_FAILED;
    headers += L"Content-Type: text/plain\r\n";
    if (!WinHttpSendRequest(h.request, headers.c_str(), (DWORD)-1L,
                            WINHTTP_NO_REQUEST_DATA, 0, (DWORD)postBody.size(), 0)) {
        PHP_LOG("TAR_PACK WinHttpSendRequest failed gle=%lu", GetLastError());
        return SFTP_FAILED;
    }
    DWORD wr = 0;
    if (!WinHttpWriteData(h.request, postBody.c_str(), (DWORD)postBody.size(), &wr)) {
        PHP_LOG("TAR_PACK WinHttpWriteData failed gle=%lu", GetLastError());
        return SFTP_FAILED;
    }
    if (!WinHttpReceiveResponse(h.request, nullptr)) {
        PHP_LOG("TAR_PACK WinHttpReceiveResponse failed gle=%lu", GetLastError());
        return SFTP_FAILED;
    }

    DWORD httpCode = 0;
    if (!QueryStatus(h.request, &httpCode) || !IsHttpSuccess(httpCode)) {
        PHP_LOG("TAR_PACK HTTP status=%lu", (unsigned long)httpCode);
        return SFTP_FAILED;
    }
    PHP_LOG("TAR_PACK HTTP status=%lu OK", (unsigned long)httpCode);

    TarReader reader(h.request);
    std::string pendingLongName;
    int filesExtracted = 0;
    const int totalFiles = (int)pathMap.size();

    for (;;) {
        const uint8_t* hdrPtr = reader.peek(512);
        if (!hdrPtr) break;
        reader.advance(512);

        if (TarIsZeroBlock(hdrPtr)) {
            const uint8_t* hdr2 = reader.peek(512);
            if (hdr2 && TarIsZeroBlock(hdr2)) { reader.advance(512); }
            break;
        }

        const auto* hdr    = reinterpret_cast<const TarRawHeader*>(hdrPtr);
        const int64_t fileSize  = TarParseOctal(hdr->size, 12);
        const char    typeflag  = hdr->typeflag;

        std::string entryPath;
        if (hdr->prefix[0] != '\0') {
            entryPath.assign(hdr->prefix, strnlen(hdr->prefix, 155));
            entryPath += '/';
        }
        entryPath += std::string(hdr->name, strnlen(hdr->name, 100));

        if (typeflag == 'L') {
            if (fileSize > 0) {
                std::string longBuf(static_cast<size_t>(fileSize), '\0');
                size_t rem = longBuf.size(), off = 0;
                while (rem > 0) {
                    size_t want = rem < 65536 ? rem : 65536;
                    const uint8_t* p = reader.peek(want);
                    if (!p) { rem = 0; break; }
                    memcpy(longBuf.data() + off, p, want);
                    reader.advance(want);
                    off += want; rem -= want;
                }
                const int64_t padded = ((fileSize + 511) / 512) * 512;
                const int64_t pad    = padded - (int64_t)off;
                if (pad > 0) reader.skip((size_t)pad);
                while (!longBuf.empty() && longBuf.back() == '\0') longBuf.pop_back();
                pendingLongName = std::move(longBuf);
            }
            continue;
        }

        if (!pendingLongName.empty()) {
            entryPath = std::move(pendingLongName);
            pendingLongName.clear();
        }

        std::replace(entryPath.begin(), entryPath.end(), '\\', '/');
        while (!entryPath.empty() && entryPath[0] == '/') entryPath.erase(entryPath.begin());
        const bool isDirEntry = (typeflag == '5');
        while (!entryPath.empty() && entryPath.back() == '/') entryPath.pop_back();

        const int64_t paddedSize = ((fileSize + 511) / 512) * 512;

        if (isDirEntry || entryPath.empty()) {
            if (paddedSize > 0) reader.skip((size_t)paddedSize);
            continue;
        }

        // Progress
        if (totalFiles > 0) {
            const int pct = filesExtracted * 100 / totalFiles;
            if (UpdatePercentBar(cs, pct, nullptr, nullptr))
                return SFTP_ABORT;
        }

        auto it = pathMap.find(entryPath);
        if (it == pathMap.end()) {
            reader.skip((size_t)paddedSize);
            continue;
        }
        const std::wstring& localPath = it->second;

        {
            const size_t sep = localPath.rfind(L'\\');
            if (sep != std::wstring::npos) TarEnsureDirW(localPath.substr(0, sep));
        }

        HANDLE hf = CreateFileW(localPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            reader.skip((size_t)paddedSize);
            continue;
        }
        AutoFileHandle localFile(hf);

        int64_t remaining = fileSize;
        while (remaining > 0) {
            size_t want = (size_t)(remaining < 65536 ? remaining : 65536);
            const uint8_t* p = reader.peek(want);
            if (!p) return SFTP_READFAILED;
            DWORD written = 0;
            if (!WriteFile(localFile.get(), p, static_cast<DWORD>(want), &written, nullptr) || written != want)
                return SFTP_WRITEFAILED;
            reader.advance(want);
            remaining -= (int64_t)want;
        }
        const int64_t pad = paddedSize - fileSize;
        if (pad > 0) reader.skip((size_t)pad);
        ++filesExtracted;
    }

    UpdatePercentBar(cs, 100, nullptr, nullptr);
    PHP_LOG("TAR_PACK download done files=%d", filesExtracted);
    return SFTP_OK;
}

int PhpAgentUploadDirAsTar(pConnectSettings cs, LPCWSTR remoteDirW,
                            const std::vector<TarUploadEntry>& entries)
{
    if (!cs || !remoteDirW || entries.empty())
        return SFTP_OK;

    // --- Pass 1: compute total TAR stream size for Content-Length ---
    int64_t totalTarSize = 0;
    for (const auto& e : entries) {
        if (e.tarName.size() > 99) {
            int64_t lnameDataSize = (int64_t)e.tarName.size() + 1;
            totalTarSize += 512 + ((lnameDataSize + 511) / 512) * 512;
        }
        totalTarSize += 512; // entry header
        if (!e.isDir)
            totalTarSize += ((e.fileSize + 511) / 512) * 512;
    }
    totalTarSize += 1024; // end-of-archive

    ShowStatusId(IDS_LOG_TAR_UPLOAD, (" " + std::to_string(entries.size())).c_str(), true);
    PHP_LOG("TAR_EXTRACT upload start entries=%u size=%lld", (unsigned)entries.size(), (long long)totalTarSize);

    // The archive is produced twice, by the one function below: first for
    // the SHA-256 its signature covers, then to send. A file that changes in
    // between makes the two differ, and the agent then refuses the upload
    // before extracting anything.
    static const std::array<uint8_t, 512> s_zeroBlock{};
    const int totalFiles = static_cast<int>(entries.size());
    const auto emitTar = [&](const auto& sink, int progressFrom, int progressSpan) -> int {
        const auto writeBlock = [&](const std::array<uint8_t, 512>& blk) { return sink(blk.data(), blk.size()); };
        int filesDone = 0;
        for (const auto& e : entries) {
            if (UpdatePercentBar(cs, progressFrom + filesDone * progressSpan / (std::max)(1, totalFiles),
                                 e.localPath.c_str(), remoteDirW))
                return SFTP_ABORT;

            // GNU LongLink for a name longer than the header holds
            if (e.tarName.size() > 99) {
                const std::string lnameData = e.tarName + '\0';
                const int64_t pad = (static_cast<int64_t>(lnameData.size()) + 511) / 512 * 512 -
                                    static_cast<int64_t>(lnameData.size());
                if (!writeBlock(BuildTarUploadHeader("././@LongLink", static_cast<int64_t>(lnameData.size()), 0, 'L')) ||
                    !sink(lnameData.data(), lnameData.size()) ||
                    (pad > 0 && !sink(s_zeroBlock.data(), static_cast<size_t>(pad))))
                    return SFTP_WRITEFAILED;
            }

            // Entry header (dir names must end with '/')
            std::string entryName = e.tarName.substr(0, 99);
            if (e.isDir && !entryName.empty() && entryName.back() != '/')
                entryName += '/';
            if (!writeBlock(BuildTarUploadHeader(entryName, e.fileSize, e.mtime, e.isDir ? '5' : '0')))
                return SFTP_WRITEFAILED;

            if (!e.isDir && e.fileSize > 0) {
                const int64_t paddedSize = ((e.fileSize + 511) / 512) * 512;
                AutoFileHandle lf(CreateFileW(e.localPath.c_str(), GENERIC_READ,
                                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
                std::vector<uint8_t> buf(65536);
                if (lf.get() == INVALID_HANDLE_VALUE) {
                    // Zeros in place of an unreadable file keep the archive's length.
                    std::fill(buf.begin(), buf.end(), uint8_t{0});
                    for (int64_t left = paddedSize; left > 0;) {
                        const size_t n = static_cast<size_t>((std::min)(left, static_cast<int64_t>(buf.size())));
                        if (!sink(buf.data(), n))
                            return SFTP_WRITEFAILED;
                        left -= static_cast<int64_t>(n);
                    }
                } else {
                    for (int64_t left = e.fileSize; left > 0;) {
                        const DWORD want = static_cast<DWORD>((std::min)(left, static_cast<int64_t>(buf.size())));
                        DWORD got = 0;
                        if (!ReadFile(lf.get(), buf.data(), want, &got, nullptr) || got == 0)
                            return SFTP_READFAILED;
                        if (!sink(buf.data(), got))
                            return SFTP_WRITEFAILED;
                        left -= got;
                    }
                    const int64_t pad = paddedSize - e.fileSize;
                    if (pad > 0 && !sink(s_zeroBlock.data(), static_cast<size_t>(pad)))
                        return SFTP_WRITEFAILED;
                }
            }
            ++filesDone;
        }
        // End of archive: two zero blocks
        return writeBlock(s_zeroBlock) && writeBlock(s_zeroBlock) ? SFTP_OK : SFTP_WRITEFAILED;
    };

    Sha256Stream tarHash;
    int rc = emitTar([&](const void* data, size_t len) { tarHash.Update(data, len); return true; }, 0, 50);
    if (rc != SFTP_OK)
        return rc;
    const std::string tarSha = tarHash.FinalHex();
    if (tarSha.empty())
        return SFTP_FAILED;

    // --- Setup WinHTTP ---
    AgentUrl url;
    if (!ParseAgentUrl(cs, &url))
        return SFTP_FAILED;

    HttpHandles h;
    h.session = WinHttpOpen(L"TC-SFTP-PHP-Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h.session) return SFTP_FAILED;
    WinHttpSetTimeouts(h.session, 15000, 15000, 300000, 300000);
    h.connect = WinHttpConnect(h.session, url.host.c_str(), url.port, 0);
    if (!h.connect) return SFTP_FAILED;

    const std::string pathUtf8 = NormalizePhpRemotePath(remoteDirW);
    const std::wstring query   = L"op=TAR_EXTRACT&path=" + UrlEncodeUtf8(pathUtf8);
    const std::wstring object  = BuildObjectPath(url.object, query);
    h.request = WinHttpOpenRequest(h.connect, L"POST", object.c_str(), nullptr,
                                   WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                   url.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!h.request) return SFTP_FAILED;

    std::wstring headers;
    if (!AuthHeaders(cs, L"POST", L"TAR_EXTRACT", object, tarSha, headers))
        return SFTP_FAILED;
    headers += L"Content-Type: application/x-tar\r\n";
    headers += L"Content-Length: " + std::to_wstring(totalTarSize) + L"\r\n";

    if (!WinHttpSendRequest(h.request, headers.c_str(), (DWORD)-1L,
                            WINHTTP_NO_REQUEST_DATA, 0, WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH, 0))
        return SFTP_FAILED;

    rc = emitTar([&](const void* data, size_t len) {
        DWORD written = 0;
        return WinHttpWriteData(h.request, data, static_cast<DWORD>(len), &written) && written == len;
    }, 50, 50);
    if (rc != SFTP_OK)
        return rc;

    // Receive response
    if (!WinHttpReceiveResponse(h.request, nullptr))
        return SFTP_FAILED;
    DWORD code = 0;
    if (!QueryStatus(h.request, &code) || !IsHttpSuccess(code)) {
        PHP_LOG("TAR_EXTRACT HTTP status=%lu", (unsigned long)code);
        return SFTP_WRITEFAILED;
    }

    UpdatePercentBar(cs, 100, nullptr, remoteDirW);
    PHP_LOG("TAR_EXTRACT upload done files=%d", totalFiles);
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

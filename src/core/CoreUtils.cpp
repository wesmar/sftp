// CoreUtils.cpp - Modern C++ implementation
// Compatible with Visual Studio 2026 (v145 toolset) and C++20

#include "global.h"
#include "CoreUtils.h"
#include "fsplugin.h"

#include <intrin.h>
#include <strsafe.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <array>
#include <cstring>
#include <cwchar>

// ============================================================================
// Modern String Utilities Impl
// ============================================================================

namespace string_util {
    std::string ShellQuoteSingle(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 8);
        for (char c : s) {
            if (c == '\'') out += "'\\''";
            else out += c;
        }
        return out;
    }

    std::wstring ShellQuoteSingleW(const std::wstring& s) {
        std::wstring out;
        out.reserve(s.size() + 8);
        for (wchar_t c : s) {
            if (c == L'\'') out += L"'\\''";
            else out += c;
        }
        return out;
    }
}

// ============================================================================
// Legacy String Functions (for backward compatibility)
// ============================================================================

extern "C" {

LPSTR strcatbackslash(LPSTR thedir)
{
    if (!thedir || !thedir[0])
        return thedir;
    std::string s(thedir);
    if (s.back() != '\\')
        s += '\\';
    strncpy_s(thedir, MAX_PATH, s.c_str(), _TRUNCATE);
    return thedir;
}

LPSTR strlcatforwardslash(LPSTR thedir, size_t maxlen)
{
    if (!thedir || !thedir[0])
        return thedir;
    std::string s(thedir);
    if (s.back() != '/')
        s += '/';
    strncpy_s(thedir, maxlen, s.c_str(), _TRUNCATE);
    return thedir;
}

LPSTR strlcatbackslash(LPSTR thedir, size_t maxlen)
{
    if (!thedir || !thedir[0])
        return thedir;
    std::string s(thedir);
    if (s.back() != '\\')
        s += '\\';
    strncpy_s(thedir, maxlen, s.c_str(), _TRUNCATE);
    return thedir;
}

LPWSTR wcslcatbackslash(LPWSTR thedir, size_t maxlen)
{
    if (!thedir || !thedir[0])
        return thedir;
    std::wstring s(thedir);
    if (s.back() != L'\\')
        s += L'\\';
    wcsncpy_s(thedir, maxlen, s.c_str(), _TRUNCATE);
    return thedir;
}

void cutlastbackslash(LPSTR thedir)
{
    if (thedir) {
        const size_t len = strlen(thedir);
        if (len > 0 && thedir[len - 1] == '\\') {
            thedir[len - 1] = '\0';
        }
    }
}

LPSTR strlcpy(LPSTR p, LPCSTR p2, size_t maxlen)
{
    if (p && p2 && maxlen > 0) {
        size_t i = 0;
        const size_t limit = maxlen - 1;
        while (i < limit && p2[i]) {
            p[i] = p2[i];
            ++i;
        }
        p[i] = '\0';
    }
    return p;
}

LPWSTR wcslcpy2(LPWSTR p, LPCWSTR p2, size_t maxlen)
{
    if (p && p2 && maxlen > 0) {
        size_t i = 0;
        const size_t limit = maxlen - 1;
        while (i < limit && p2[i]) {
            p[i] = p2[i];
            ++i;
        }
        p[i] = L'\0';
    }
    return p;
}

// strlcat is different from strncat:
// strncat expects the maximum number of bytes to append.
// strlcat expects the total size of the destination buffer.
LPSTR strlcat(LPSTR p, LPCSTR p2, size_t maxlen)
{
    if (p && p2 && maxlen > 0) {
        size_t currentLen = strnlen_s(p, maxlen);
        if (currentLen >= maxlen) {
            p[maxlen - 1] = '\0';
            return p;
        }
        size_t i = 0;
        const size_t limit = maxlen - currentLen - 1;
        while (i < limit && p2[i]) {
            p[currentLen + i] = p2[i];
            ++i;
        }
        p[currentLen + i] = '\0';
    }
    return p;
}

LPSTR ReplaceBackslashBySlash(LPSTR thedir)
{
    if (!thedir)
        return thedir;
    std::string s(thedir);
    std::replace(s.begin(), s.end(), '\\', '/');
    strncpy_s(thedir, s.size() + 1, s.c_str(), _TRUNCATE);
    return thedir;
}

LPWSTR ReplaceBackslashBySlashW(LPWSTR thedir)
{
    if (!thedir)
        return thedir;
    std::wstring s(thedir);
    std::replace(s.begin(), s.end(), L'\\', L'/');
    wcsncpy_s(thedir, s.size() + 1, s.c_str(), _TRUNCATE);
    return thedir;
}

LPSTR ReplaceSlashByBackslash(LPSTR thedir)
{
    if (!thedir)
        return thedir;
    std::string s(thedir);
    std::replace(s.begin(), s.end(), '/', '\\');
    strncpy_s(thedir, s.size() + 1, s.c_str(), _TRUNCATE);
    return thedir;
}

LPWSTR ReplaceSlashByBackslashW(LPWSTR thedir)
{
    if (!thedir)
        return thedir;
    std::wstring s(thedir);
    std::replace(s.begin(), s.end(), L'/', L'\\');
    wcsncpy_s(thedir, s.size() + 1, s.c_str(), _TRUNCATE);
    return thedir;
}

} // extern "C"

// ============================================================================
// Time Functions - Modern Implementation using std::chrono
// ============================================================================

namespace {

// Anonymous namespace for internal utility functions

} // anonymous namespace

SYSTICKS get_sys_ticks() noexcept
{
    // Native GetTickCount64 is available on Windows Vista and later.
    // We target Windows 7+, so we can call it directly.
    return static_cast<SYSTICKS>(GetTickCount64());
}

// Legacy compatibility functions
extern "C" {

void SetInt64ToFileTime(FILETIME* ft, int64_t tm) noexcept {
    if (!ft)
        return;
    ULARGE_INTEGER src{};
    src.QuadPart = static_cast<ULONGLONG>(tm);
    ft->dwLowDateTime = src.LowPart;
    ft->dwHighDateTime = src.HighPart;
}

timeval gettimeval(size_t milliseconds) noexcept {
    timeval ret{};
    ret.tv_sec = static_cast<long>(milliseconds / 1000);
    ret.tv_usec = static_cast<long>((milliseconds % 1000) * 1000);
    return ret;
}

bool ConvSysTimeToFileTime(const LPSYSTEMTIME st, LPFILETIME ft)
{
    if (!st || !ft) return false;
    
    FILETIME tmp{};
    SYSTEMTIME s = *st;
    
    // Handle 2-digit years (assume 1900+ for years < 300)
    if (s.wYear < 300) {
        s.wYear += 1900;
    }
    
    s.wDayOfWeek = 0;
    s.wMilliseconds = 0;
    
    if (SystemTimeToFileTime(&s, &tmp)) {
        // Total Commander expects system-local file time.
        const BOOL rc = LocalFileTimeToFileTime(&tmp, ft);
        return rc ? true : false;
    }
    
    // Set to FS_TIME_UNKNOWN on failure
    SetInt64ToFileTime(ft, FS_TIME_UNKNOWN);
    return false;
}

#include <charconv>

bool ConvertIsoDateToDateTime(LPCSTR pdatetimefield, LPFILETIME ft)
{
    if (!pdatetimefield || !ft) return false;
    
    std::string_view sv(pdatetimefield);
    if (sv.length() < 14) return false;

    SYSTEMTIME st{};
    auto parse_num = [](std::string_view s, WORD& out) -> bool {
        int val = 0;
        auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), val);
        if (ec == std::errc{}) {
            out = static_cast<WORD>(val);
            return true;
        }
        return false;
    };

    if (!parse_num(sv.substr(0, 4), st.wYear) ||
        !parse_num(sv.substr(4, 2), st.wMonth) ||
        !parse_num(sv.substr(6, 2), st.wDay) ||
        !parse_num(sv.substr(8, 2), st.wHour) ||
        !parse_num(sv.substr(10, 2), st.wMinute) ||
        !parse_num(sv.substr(12, 2), st.wSecond)) {
        return false;
    }
    
    return ConvSysTimeToFileTime(&st, ft);
}

bool UnixTimeToLocalTime(const time_t* mtime, LPFILETIME ft)
{
    if (!mtime || !ft) return false;
    
    struct tm fttm{};
    if (gmtime_s(&fttm, mtime) != 0) return false;
    
    SYSTEMTIME st{};
    st.wYear   = static_cast<WORD>(fttm.tm_year + 1900);  // tm_year is years since 1900
    st.wMonth  = static_cast<WORD>(fttm.tm_mon + 1);      // tm_mon is 0-11
    st.wDay    = static_cast<WORD>(fttm.tm_mday);
    st.wHour   = static_cast<WORD>(fttm.tm_hour);
    st.wMinute = static_cast<WORD>(fttm.tm_min);
    st.wSecond = static_cast<WORD>(fttm.tm_sec);
    
    return ConvSysTimeToFileTime(&st, ft);
}

void Conv2Chars(LPSTR buf, int nr)
{
    if (!buf) return;
    
    if (nr <= 9) {
        buf[0] = '0';
        buf[1] = '0' + nr;
        buf[2] = '\0';
    } else {
        sprintf_s(buf, 3, "%02d", nr);
    }
}

bool CreateIsoDateString(LPFILETIME ft, LPSTR buf)
{
    if (!ft || !buf) return false;
    
    FILETIME ft2{};
    buf[0] = '\0';
    
    if (!FileTimeToLocalFileTime(ft, &ft2)) {
        return false;
    }
    
    SYSTEMTIME dt{};
    if (!FileTimeToSystemTime(&ft2, &dt)) {
        return false;
    }
    
    int rc = sprintf_s(buf, 32, "%04u%02u%02u%02u%02u", 
                       dt.wYear, dt.wMonth, dt.wDay, dt.wHour, dt.wMinute);
    return (rc > 0);
}

} // extern "C"

// ============================================================================
// BASE64 Encoding/Decoding
// ============================================================================

namespace {

constexpr char MimeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

[[nodiscard]] __forceinline char EncodeMIME(UCHAR ch) noexcept
{
    return MimeTable[ch & 0x3F];
}

[[nodiscard]] __forceinline void EncodeMimeTriple(
    const BYTE* inbuf, 
    size_t j, 
    char* outbuf) noexcept
{
    BYTE c1, c2, c3, c4;
    c1 = (inbuf[0] >> 2);
    c2 = (inbuf[0] << 4) & 0x30;
    c2 |= (inbuf[1] >> 4) & 0x0F;
    c3 = (inbuf[1] << 2) & 0x3C;
    c3 |= (inbuf[2] >> 6) & 0x03;
    c4 = (inbuf[2]) & 0x3F;
    
    outbuf[0] = EncodeMIME(c1);
    outbuf[1] = EncodeMIME(c2);
    outbuf[2] = (j > 1) ? EncodeMIME(c3) : '=';   // Last char padding
    outbuf[3] = (j > 2) ? EncodeMIME(c4) : '=';
    outbuf[4] = '\0';
}

} // anonymous namespace

extern "C" {

int MimeEncodeData(LPCVOID indata, size_t inlen, LPSTR outstr, size_t maxlen)
{
    if (!indata || !outstr || maxlen < 2) return 0;
    
    outstr[0] = '\0';
    const BYTE* p = static_cast<const BYTE*>(indata);
    
    std::string result;
    result.reserve(((inlen + 2) / 3) * 4);
    
    std::array<char, 8> buf{};
    for (SSIZE_T j = static_cast<SSIZE_T>(inlen); j > 0; j -= 3) {
        EncodeMimeTriple(p, static_cast<size_t>(j), buf.data());
        p += 3;
        result += buf.data();
    }
    
    if (result.size() < maxlen) {
        strcpy_s(outstr, maxlen, result.c_str());
    } else {
        result.copy(outstr, maxlen - 1);
        outstr[maxlen - 1] = '\0';
    }
    
    return static_cast<int>(strlen(outstr));
}

int MimeEncode(LPCSTR inputstr, LPSTR outputstr, size_t maxlen)
{
    if (!inputstr) return 0;
    return MimeEncodeData(inputstr, strlen(inputstr), outputstr, maxlen);
}

int MimeDecode(LPCSTR indata, size_t inlen, LPVOID outdata, size_t maxlen)
{
    if (!indata || !outdata || inlen == 0) return 0;
    
    static constexpr std::array<int8_t, 128> kDec = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,  
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, 
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, 
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  
    };
    
    BYTE* d = static_cast<BYTE*>(outdata);
    size_t outLen = 0;
    uint32_t buf = 0;
    int bits = 0;
    
    for (size_t i = 0; i < inlen; ++i) {
        unsigned char c = static_cast<unsigned char>(indata[i]);
        if (c == '\r' || c == '\n' || c == ' ' || c == '=' || c > 127) continue;
        int8_t v = kDec[c];
        if (v < 0) continue;
        
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (outLen < maxlen) {
                d[outLen++] = static_cast<BYTE>((buf >> bits) & 0xFF);
            }
        }
    }
    
    return static_cast<int>(outLen);
}

} // extern "C"

// ============================================================================
// String Formatting and Parsing
// ============================================================================

extern "C" {

// Replace %name% by environment variable
void ReplaceEnvVars(LPSTR buf, size_t buflen)
{
    if (!buf || buflen == 0) return;
    
    std::string buffer(buf);
    std::string result;
    result.reserve(buffer.size());
    
    size_t pos = 0;
    while (pos < buffer.size()) {
        const size_t percentPos = buffer.find('%', pos);
        if (percentPos == std::string::npos) {
            result += buffer.substr(pos);
            break;
        }
        
        // Add text before the %
        result += buffer.substr(pos, percentPos - pos);
        
        // Check for %% (escaped percent)
        if (percentPos + 1 < buffer.size() && buffer[percentPos + 1] == '%') {
            result += '%';
            pos = percentPos + 2;
            continue;
        }
        
        // Find closing %
        const size_t endPos = buffer.find('%', percentPos + 1);
        if (endPos == std::string::npos) {
            result += buffer.substr(percentPos);
            break;
        }
        
        // Extract environment variable name
        const std::string envName = buffer.substr(percentPos + 1, endPos - percentPos - 1);
        
        // Get environment variable value
        DWORD envLen = GetEnvironmentVariableA(envName.c_str(), nullptr, 0);
        if (envLen > 0 && envLen < MAX_PATH) {
            std::string envValue(envLen, '\0');
            GetEnvironmentVariableA(envName.c_str(), envValue.data(), envLen);
            envValue.pop_back();  // Remove null terminator from string
            result += envValue;
        }
        
        pos = endPos + 1;
    }
    
    strncpy_s(buf, buflen, result.c_str(), _TRUNCATE);
}

void ReplaceSubString(LPSTR buf, LPCSTR fromstr, LPCSTR tostr, size_t maxlen)
{
    if (!buf || !fromstr || !tostr || maxlen == 0) return;
    
    const size_t fromLen = strlen(fromstr);
    if (fromLen == 0) return;  // Nothing to do
    
    std::string buffer(buf);
    const std::string from(fromstr);
    const std::string to(tostr);
    
    size_t pos = 0;
    while ((pos = buffer.find(from, pos)) != std::string::npos) {
        buffer.replace(pos, fromLen, to);
        pos += to.length();
    }
    
    strncpy_s(buf, maxlen, buffer.c_str(), _TRUNCATE);
}

bool ParseAddress(LPCSTR serverstring, LPSTR addr, WORD* port, int defport)
{
    if (!serverstring || !addr || !port) {
        return false;
    }

    auto trim = [](std::string& s) {
        const auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) {
            s.clear();
            return;
        }
        const auto end = s.find_last_not_of(" \t\r\n");
        s = s.substr(start, end - start + 1);
    };

    std::string in(serverstring);
    trim(in);
    if (in.empty()) {
        return false;
    }

    // Accept inputs like sftp://host:22/path or ssh://host.
    const size_t schemePos = in.find("://");
    if (schemePos != std::string::npos) {
        in.erase(0, schemePos + 3);
    }

    // Strip userinfo if present: user@host
    const size_t atPos = in.rfind('@');
    if (atPos != std::string::npos) {
        in.erase(0, atPos + 1);
    }

    // Strip path/query/fragment.
    const size_t pathPos = in.find_first_of("/?#");
    if (pathPos != std::string::npos) {
        in.erase(pathPos);
    }
    trim(in);
    if (in.empty()) {
        return false;
    }

    WORD parsedPort = static_cast<WORD>(defport);
    std::string host;

    if (in.front() == '[') {
        // Bracketed numeric IPv6: [addr] or [addr]:port
        const size_t close = in.find(']');
        if (close == std::string::npos || close == 1) {
            return false;
        }
        host = in.substr(1, close - 1);
        if (close + 1 < in.size()) {
            if (in[close + 1] != ':') {
                return false;
            }
            const std::string portStr = in.substr(close + 2);
            if (portStr.empty()) {
                return false;
            }
            for (char ch : portStr) {
                if (ch < '0' || ch > '9') {
                    return false;
                }
            }
            const long v = strtol(portStr.c_str(), nullptr, 10);
            if (v <= 0 || v > 65535) {
                return false;
            }
            parsedPort = static_cast<WORD>(v);
        }
    } else {
        const size_t firstColon = in.find(':');
        const size_t lastColon = in.rfind(':');
        if (firstColon != std::string::npos && firstColon == lastColon) {
            // host:port (hostname or IPv4)
            host = in.substr(0, firstColon);
            const std::string portStr = in.substr(firstColon + 1);
            if (host.empty() || portStr.empty()) {
                return false;
            }
            for (char ch : portStr) {
                if (ch < '0' || ch > '9') {
                    return false;
                }
            }
            const long v = strtol(portStr.c_str(), nullptr, 10);
            if (v <= 0 || v > 65535) {
                return false;
            }
            parsedPort = static_cast<WORD>(v);
        } else {
            // hostname, IPv4, or unbracketed IPv6 without port
            host = in;
        }
    }

    trim(host);
    if (host.empty()) {
        return false;
    }

    strncpy_s(addr, MAX_PATH, host.c_str(), _TRUNCATE);
    *port = parsedPort;
    return true;
}

bool IsNumericIPv6(LPCSTR addr)
{
    if (!addr) return false;
    
    const char* p = strchr(addr, ':');
    const char* t = strrchr(addr, ':');
    
    if (p && p == t) return false;
    return p ? true : false;
}

} // extern "C"

// ============================================================================
// Wildcard Matching
// ============================================================================

namespace {

[[nodiscard]] size_t countdots(LPCWSTR buf) noexcept
{
    size_t retval = 0;
    while (*buf) {
        if (*buf == L'.') retval++;
        ++buf;
    }
    return retval;
}

[[nodiscard]] bool filematchw(LPWSTR swild, LPCWSTR slbox)
{
    if (!swild || !slbox) return false;

    std::array<WCHAR, 260> pattern{};
    std::array<WCHAR, 260> buffer{};

    wcscpy_s(pattern.data(), pattern.size(), swild);
    _wcsupr(pattern.data());
    wcscpy_s(buffer.data(), buffer.size(), slbox);
    _wcsupr(buffer.data());
    
    LPWSTR ppat = pattern.data();
    LPWSTR pbuf = buffer.data();
    LPWSTR pendbuf = pbuf + wcslen(pbuf);
    LPWSTR PosOfStar = pbuf;
    bool retval = false;
    bool failed = false;
    
    while (!retval && !failed) {
        if (ppat[0] == L'\0' && pbuf[0] == L'\0') {
            retval = true;
            continue;
        }
        
        if (ppat[0] == L'*') {
            PosOfStar = pbuf;
            ++ppat;
            if (!ppat[0]) {
                retval = true;  // * at the end means full match
            }
            continue;
        }
        
        if ((ppat[0] == L'?' && pbuf[0]) || ppat[0] == pbuf[0]) {
            ++ppat;
            ++pbuf;
            continue;
        }
        
        if (!pbuf[0] && ppat[0] == L'.') {
            if (ppat[1] == L'*' && !ppat[2]) {
                retval = true;  // xyz.* matches also xyz
                continue;
            }
            if (!ppat[1]) {
                // Special case: '.' at the end means buffer and pattern should have same number of '.'
                ppat[0] = L'\0';
                retval = countdots(buffer.data()) == countdots(pattern.data());
                failed = !retval;
                continue;
            }
        }
        
        // Backtrack
        while (ppat > pattern.data() && ppat[0] != L'*') --ppat;
        
        if (ppat[0] != L'*') {
            failed = true;
            continue;
        }
        
        ++ppat;
        ++PosOfStar;
        pbuf = PosOfStar;
        
        if (PosOfStar > pendbuf) {
            failed = true;
        }
    }
    
    return retval;
}

static LPWSTR NextWildcardToken(LPWSTR& cursor) noexcept
{
    if (!cursor)
        return nullptr;

    while (*cursor == L' ')
        ++cursor;
    if (*cursor == 0) {
        cursor = nullptr;
        return nullptr;
    }

    LPWSTR p1 = wcschr(cursor, L'"');
    LPWSTR p2 = wcschr(cursor, L' ');
    LPWSTR p3 = wcschr(cursor, L';');

    if (p3 && (!p2 || p2 > p3)) {
        p2 = p3;
    }

    if (!p1 || (p2 && p1 > p2)) {
        LPWSTR retval = cursor;
        cursor = p2;
        if (cursor) {
            *cursor = L'\0';
            ++cursor;
            while (*cursor == L' ')
                ++cursor;
            if (*cursor == 0)
                cursor = nullptr;
        }
        return retval;
    }

    // Quoted string.
    p3 = wcschr(p1 + 1, L'"');
    if (!p3) {
        cursor = nullptr;
        return p1 + 1;
    }

    *p3 = L'\0';
    cursor = p3 + 1;
    while (*cursor == L' ')
        ++cursor;
    if (*cursor == 0)
        cursor = nullptr;
    return p1 + 1;
}

} // anonymous namespace

extern "C" {

bool MultiFileMatchW(LPCWSTR wild, LPCWSTR name)
{
    if (!wild || !name) return false;
    
    std::array<WCHAR, 1024> sincl{};
    bool io = false;
    
    wcscpy_s(sincl.data(), sincl.size(), wild);
    
    // First, check for | symbol, all behind it is negated
    LPWSTR p = wcschr(sincl.data(), L'|');
    if (p) {
        if (p == sincl.data()) {
            io = true;
        }
        *p = L'\0';
        ++p;
        while (*p == L' ') ++p;
    }
    
    LPWSTR cursor = sincl.data();
    LPWSTR swild = NextWildcardToken(cursor);
    
    // Included files
    while (swild && !io) {
        if (filematchw(swild, name)) {
            io = true;
        }
        swild = NextWildcardToken(cursor);
    }
    
    // Excluded files
    if (io && p) {
        cursor = p;
        swild = NextWildcardToken(cursor);
        while (swild && io) {
            if (filematchw(swild, name)) {
                io = false;
            }
            swild = NextWildcardToken(cursor);
        }
    }
    
    return io;
}

} // extern "C"
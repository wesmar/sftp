#pragma once

#include "global.h"
#include <chrono>
#include <string>
#include <string_view>
#include <algorithm>
#include <memory>
#include <vector>
#include <array>
#include <atomic>
#include <optional>
#include <ctime>

// ============================================================================
// Modern C++ Helper Macros
// ============================================================================

#define FIN_IF(_cond_,_code_) do { if ((_cond_)) { hr = _code_; goto fin; } } while(0)
#define FIN(_code_)           do { hr = _code_; goto fin; } while(0)

#define LoadStr(s, i)  LoadStringA(hinst, (i), (s), static_cast<int>(countof(s)) - 1)

// ============================================================================
// Modern String Utilities
// ============================================================================

namespace string_util {

// Safe string copy with null termination
inline errno_t strcpy_s_safe(char* dest, size_t destSize, const char* src) noexcept {
    return strncpy_s(dest, destSize, src, _TRUNCATE);
}

inline errno_t wcscpy_s_safe(wchar_t* dest, size_t destSize, const wchar_t* src) noexcept {
    return wcsncpy_s(dest, destSize, src, _TRUNCATE);
}

// Safe string concatenation
inline errno_t strcat_s_safe(char* dest, size_t destSize, const char* src) noexcept {
    return strncat_s(dest, destSize, src, _TRUNCATE);
}

inline errno_t wcscat_s_safe(wchar_t* dest, size_t destSize, const wchar_t* src) noexcept {
    return wcsncat_s(dest, destSize, src, _TRUNCATE);
}

// String length with null check
inline size_t strlen_safe(const char* str) noexcept {
    return str ? strlen(str) : 0;
}

inline size_t wcslen_safe(const wchar_t* str) noexcept {
    return str ? wcslen(str) : 0;
}

// Modern string view helpers
inline std::string_view make_string_view(const char* str) noexcept {
    return str ? std::string_view(str) : std::string_view();
}

inline std::wstring_view make_string_view(const wchar_t* str) noexcept {
    return str ? std::wstring_view(str) : std::wstring_view();
}

// Bezpieczne wstrzykiwanie do powłoki
std::string ShellQuoteSingle(const std::string& s);
std::wstring ShellQuoteSingleW(const std::wstring& s);

} // namespace string_util

// ============================================================================
// Legacy Compatibility Functions (to be phased out)
// ============================================================================

extern "C" {

LPSTR  strlcpy(LPSTR p, LPCSTR p2, size_t maxlen);
LPSTR  strlcat(LPSTR p, LPCSTR p2, size_t maxlen);
LPWSTR wcslcpy2(LPWSTR p, LPCWSTR p2, size_t maxlen);
LPSTR  strcatbackslash(LPSTR thedir);
LPSTR  strlcatforwardslash(LPSTR thedir, size_t maxlen);
LPSTR  strlcatbackslash(LPSTR thedir, size_t maxlen);
LPWSTR wcslcatbackslash(LPWSTR thedir, size_t maxlen);
void   cutlastbackslash(LPSTR thedir);
LPSTR  ReplaceBackslashBySlash(LPSTR thedir);
LPWSTR ReplaceBackslashBySlashW(LPWSTR thedir);
LPSTR  ReplaceSlashByBackslash(LPSTR thedir);
LPWSTR ReplaceSlashByBackslashW(LPWSTR thedir);

// Legacy time functions (implemented in CoreUtils.cpp)
void SetInt64ToFileTime(FILETIME* ft, int64_t tm) noexcept;
timeval gettimeval(size_t milliseconds) noexcept;
bool ConvSysTimeToFileTime(const LPSYSTEMTIME st, LPFILETIME ft);
bool ConvertIsoDateToDateTime(LPCSTR pdatetimefield, LPFILETIME ft);
bool CreateIsoDateString(LPFILETIME ft, LPSTR buf);
bool UnixTimeToLocalTime(const time_t* mtime, LPFILETIME ft);

// BASE64 functions
int MimeEncodeData(LPCVOID indata, size_t inlen, LPSTR outstr, size_t maxlen);
int MimeEncode(LPCSTR inputstr, LPSTR outputstr, size_t maxlen);
int MimeDecode(LPCSTR inputstr, size_t inlen, LPVOID outdata, size_t maxlen);

// String formatting
void ReplaceEnvVars(LPSTR buf, size_t buflen);
void ReplaceSubString(LPSTR buf, LPCSTR fromstr, LPCSTR tostr, size_t maxlen);
bool ParseAddress(LPCSTR serverstring, LPSTR addr, WORD* port, int defport);
bool IsNumericIPv6(LPCSTR addr);

// Wildcard matching
bool MultiFileMatchW(LPCWSTR wild, LPCWSTR name);

} // extern "C"

// std::string overload helpers to ease incremental migration from C buffers.
inline LPSTR strlcpy(LPSTR p, const std::string& s, size_t maxlen) {
    return strlcpy(p, s.c_str(), maxlen);
}

inline LPSTR strlcat(LPSTR p, const std::string& s, size_t maxlen) {
    return strlcat(p, s.c_str(), maxlen);
}

inline std::string& strlcpy(std::string& dst, LPCSTR src, size_t /*maxlen*/) {
    dst = src ? src : "";
    return dst;
}

inline std::string& strlcpy(std::string& dst, const std::string& src, size_t /*maxlen*/) {
    dst = src;
    return dst;
}

inline std::string& strlcat(std::string& dst, LPCSTR src, size_t /*maxlen*/) {
    if (src)
        dst += src;
    return dst;
}

inline std::string& strlcat(std::string& dst, const std::string& src, size_t /*maxlen*/) {
    dst += src;
    return dst;
}

inline bool IsNumericIPv6(const std::string& addr) {
    return IsNumericIPv6(addr.c_str());
}

// ============================================================================
// Modern Time Utilities using std::chrono
// ============================================================================

namespace time_util {

// Type alias for system ticks (milliseconds since epoch)
using SysTicks = std::chrono::milliseconds::rep;

inline ULONGLONG FileTimeToUInt64(const FILETIME& ft) noexcept
{
    ULARGE_INTEGER value{};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

inline FILETIME UInt64ToFileTime(ULONGLONG value) noexcept
{
    ULARGE_INTEGER src{};
    src.QuadPart = value;
    FILETIME ft{};
    ft.dwLowDateTime = src.LowPart;
    ft.dwHighDateTime = src.HighPart;
    return ft;
}

// Get current system ticks (milliseconds)
inline SysTicks get_sys_ticks() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// Calculate elapsed milliseconds between two tick counts
inline int get_ticks_between(SysTicks prev, SysTicks now) noexcept {
    return static_cast<int>(now - prev);
}

// Calculate elapsed milliseconds from a previous tick count to now
inline int get_ticks_between(SysTicks prev) noexcept {
    return get_ticks_between(prev, get_sys_ticks());
}

// Convert Unix timestamp to FILETIME
inline void ConvUnixTimeToFileTime(LPFILETIME ft, int64_t utm) noexcept {
    constexpr int64_t DELTA_EPOCH_IN_SECS = 11644473600LL;
    constexpr int64_t WINDOWS_TICK = 10000000LL;

    if (!ft)
        return;
    const ULONGLONG value = static_cast<ULONGLONG>(utm * WINDOWS_TICK + (DELTA_EPOCH_IN_SECS * WINDOWS_TICK));
    *ft = UInt64ToFileTime(value);
}

// Get FILETIME from Unix timestamp
inline FILETIME GetFileTimeFromUnixTime(int64_t utm) noexcept {
    FILETIME ret{};
    ConvUnixTimeToFileTime(&ret, utm);
    return ret;
}

// Get Unix timestamp from FILETIME
inline int64_t GetUnixTime64(int64_t ms_time) noexcept {
    constexpr int64_t DELTA_EPOCH_IN_SECS = 11644473600LL;
    constexpr int64_t WINDOWS_TICK = 10000000LL;
    return (ms_time - DELTA_EPOCH_IN_SECS * WINDOWS_TICK) / WINDOWS_TICK;
}

// Get Unix time from FILETIME
inline LONG GetUnixTime(const LPFILETIME ft) noexcept {
    constexpr int64_t DELTA_EPOCH_IN_SECS = 11644473600LL;
    constexpr int64_t WINDOWS_TICK = 10000000LL;

    if (!ft)
        return 0;
    const int64_t ms_time = static_cast<int64_t>(FileTimeToUInt64(*ft));
    if (ms_time <= DELTA_EPOCH_IN_SECS * WINDOWS_TICK)
        return 0;
    return static_cast<LONG>(GetUnixTime64(ms_time) & 0xFFFFFFFF);
}

// Create timeval structure from milliseconds
inline timeval make_timeval(size_t milliseconds) noexcept {
    timeval ret{};
    ret.tv_sec = static_cast<long>(milliseconds / 1000);
    ret.tv_usec = static_cast<long>((milliseconds % 1000) * 1000);
    return ret;
}

// Set FILETIME from int64
inline void SetInt64ToFileTime(FILETIME* ft, int64_t tm) noexcept {
    if (!ft)
        return;
    *ft = UInt64ToFileTime(static_cast<ULONGLONG>(tm));
}

} // namespace time_util

// Legacy type alias for compatibility
using SYSTICKS = time_util::SysTicks;

// Legacy global helpers expected by existing plugin sources.
SYSTICKS get_sys_ticks() noexcept;

inline int get_ticks_between(SYSTICKS prev, SYSTICKS now) noexcept {
    return time_util::get_ticks_between(prev, now);
}

inline int get_ticks_between(SYSTICKS prev) noexcept {
    return time_util::get_ticks_between(prev);
}

inline void ConvUnixTimeToFileTime(LPFILETIME ft, int64_t utm) noexcept {
    time_util::ConvUnixTimeToFileTime(ft, utm);
}

inline LONG GetUnixTime(const LPFILETIME ft) noexcept {
    return time_util::GetUnixTime(ft);
}

// ============================================================================
// Modern RAII Wrappers for Windows Handles
// ============================================================================

namespace handle_util {

// Smart handle wrapper with automatic cleanup
template<typename HandleType, HandleType InvalidValue>
class AutoHandle {
public:
    using handle_type = HandleType;
    static constexpr handle_type invalid_value = InvalidValue;
    
    AutoHandle() noexcept : handle_(invalid_value) {}
    explicit AutoHandle(handle_type h) noexcept : handle_(h) {}
    
    ~AutoHandle() { reset(); }
    
    // Move semantics
    AutoHandle(AutoHandle&& other) noexcept : handle_(other.release()) {}
    AutoHandle& operator=(AutoHandle&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.release();
        }
        return *this;
    }
    
    // Non-copyable
    AutoHandle(const AutoHandle&) = delete;
    AutoHandle& operator=(const AutoHandle&) = delete;
    
    handle_type get() const noexcept { return handle_; }
    handle_type release() noexcept {
        handle_type tmp = handle_;
        handle_ = invalid_value;
        return tmp;
    }
    
    void reset(handle_type h = invalid_value) noexcept {
        if (handle_ != invalid_value) {
            CloseHandle(handle_);
        }
        handle_ = h;
    }
    
    explicit operator bool() const noexcept { return handle_ != invalid_value; }
    handle_type operator*() const noexcept { return handle_; }
    
private:
    handle_type handle_;
};

// Type aliases for common handle types
using FileHandle = AutoHandle<HANDLE, INVALID_HANDLE_VALUE>;
using FindHandle = AutoHandle<HANDLE, INVALID_HANDLE_VALUE>;

} // namespace handle_util
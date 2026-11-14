#pragma once

// Modern C++ SFTP Plugin for Total Commander
// Compatible with Visual Studio 2026 (v145 toolset)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Force static linking for libssh2 (removes __imp__ prefix)
#ifndef LIBSSH2_STATIC
    #define LIBSSH2_STATIC
#endif

// Windows headers; WIN32_LEAN_AND_MEAN keeps the old winsock.h out.
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <BaseTsd.h>
#include <stdlib.h>
#include <stdio.h>
#include <shlwapi.h>
#include <strsafe.h>

// C++ Standard Library headers
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cstdarg>
#include <atomic>
#include <iterator>
#include <mutex>

// Modern C++ namespace for plugin internals
#ifdef __cplusplus

#include "fsplugin.h"

// Modern type aliases
using ServerId = void*;
using ServerHandle = void*;

// Constant for directory path buffers
constexpr size_t wdirtypemax = 1024;

// ============================================================================
// Diagnostic log
// ============================================================================
// Off by default. [Configuration] DebugLog=1 in sftpplug.ini, or the
// environment variable SFTPPLUG_DEBUGLOG=1, turns it on. Lines go to
// OutputDebugString and to %LOCALAPPDATA%\SFTPplug\sftpplug.log - a per-user
// folder, never a shared one such as C:\temp. Crash reports (tag "CRASH")
// are written even while the log is off. Never log a secret.

namespace sftp_log {

inline std::atomic<bool>& EnabledFlag() noexcept
{
    static std::atomic<bool> enabled{[] {
        char value[8] = {};
        return GetEnvironmentVariableA("SFTPPLUG_DEBUGLOG", value, sizeof(value)) > 0 && value[0] == '1';
    }()};
    return enabled;
}

inline bool Enabled() noexcept { return EnabledFlag().load(std::memory_order_relaxed); }
inline void SetEnabled(bool on) noexcept { EnabledFlag().store(on, std::memory_order_relaxed); }

inline const wchar_t* FilePath() noexcept
{
    static wchar_t path[MAX_PATH] = {};
    static std::once_flag once;
    std::call_once(once, [] {
        wchar_t base[MAX_PATH] = {};
        const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
        if (n == 0 || n >= MAX_PATH - 32)
            return;
        wcscat_s(base, L"\\SFTPplug");
        CreateDirectoryW(base, nullptr);
        swprintf_s(path, L"%s\\sftpplug.log", base);
    });
    return path;
}

} // namespace sftp_log

inline void sftp_debug_emit_line(const char* line) noexcept
{
    if (!line) return;
    OutputDebugStringA(line);
    OutputDebugStringA("\n");
    const wchar_t* path = sftp_log::FilePath();
    if (!path[0])
        return;
    HANDLE hf = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(hf, line, static_cast<DWORD>(strlen(line)), &written, nullptr);
        WriteFile(hf, "\r\n", 2, &written, nullptr);
        CloseHandle(hf);
    }
}

inline void sftp_debug_logf(const char* tag, const char* fmt, ...) noexcept
{
    if (!sftp_log::Enabled() && !(tag && strcmp(tag, "CRASH") == 0))
        return;
    char msg[1024];
    msg[0] = 0;
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt ? fmt : "", args);
    va_end(args);

    // Local time to the millisecond, so a slow step shows as a gap between lines.
    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[1200];
    if (tag && tag[0]) {
        _snprintf_s(line, sizeof(line), _TRUNCATE, "%02u:%02u:%02u.%03u [%s] %s",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, tag, msg);
    } else {
        _snprintf_s(line, sizeof(line), _TRUNCATE, "%02u:%02u:%02u.%03u %s",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
    }
    sftp_debug_emit_line(line);
}

// The flag is tested before any argument is formatted.
#define SFTP_LOG(tag, fmt, ...) do { \
        if (sftp_log::Enabled() || strcmp(tag, "CRASH") == 0) \
            sftp_debug_logf(tag, fmt, ##__VA_ARGS__); \
    } while(0)
#define DEBUG_LOG(fmt, ...) SFTP_LOG("DBG", fmt, ##__VA_ARGS__)

#endif // __cplusplus


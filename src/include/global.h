#pragma once

// Modern C++ SFTP Plugin for Total Commander
// Compatible with Visual Studio 2026 (v145 toolset)

#define WIN32_LEAN_AND_MEAN

// Force static linking for libssh2 (removes __imp__ prefix)
#ifndef LIBSSH2_STATIC
    #define LIBSSH2_STATIC
#endif

/* Disable legacy WinSock.h and wsock32.lib */
#define _WINSOCKAPI_

// Modern Windows SDK headers
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

// Verify SDK requirements
#ifndef RESOURCE_ENUM_VALIDATE
#error "Please, update Microsoft SDKs to 6.1 or later"
#endif

// Type definitions for compatibility
#ifndef _LPCBYTE_DEFINED
#define _LPCBYTE_DEFINED
typedef const BYTE *LPCBYTE;
#endif

#ifndef _LPCVOID_DEFINED
#define _LPCVOID_DEFINED
typedef const VOID *LPCVOID;
#endif

// Modern replacement for countof macro
#ifndef countof
#define countof(array) (sizeof(array) / sizeof(array[0]))
#endif

// Safe string copy for legacy code compatibility
#ifndef _itoa_s
#define _itoa_s(nr,buf,sz,rdx)  _itoa((nr),(buf),(rdx))
#endif

// Modern C++ namespace for plugin internals
#ifdef __cplusplus

#include "fsplugin.h"

// Modern type aliases
using PluginId = int;
using ServerId = void*;
using ServerHandle = void*;

// Constant for directory path buffers
constexpr size_t wdirtypemax = 1024;

// ============================================================================
// Debug Configuration
// ============================================================================
// Main compile-time switch:
// Debug logging configuration
//   0 = no debug logs in binary (production)
//   1 = enable debug logs
// Default: OFF in Release (NDEBUG defined), ON in Debug
#ifndef SFTP_DEBUG_ENABLED
    #ifdef NDEBUG
        #define SFTP_DEBUG_ENABLED 0  // Production build - logging OFF
    #else
        #define SFTP_DEBUG_ENABLED 1  // Debug build - logging ON
    #endif
#endif

// Optional file logging to C:\temp\sftpplug_debug.log
//   0 = OutputDebugString only
//   1 = OutputDebugString + file append (SLOW - use only for debugging!)
#ifndef SFTP_DEBUG_TO_FILE
    #ifdef NDEBUG
        #define SFTP_DEBUG_TO_FILE 0  // Production - file logging OFF
    #else
        #define SFTP_DEBUG_TO_FILE 0  // Debug - still OFF by default, enable manually if needed
    #endif
#endif

#ifndef SFTP_DEBUG_FILE_PATH
    #define SFTP_DEBUG_FILE_PATH "C:\\temp\\sftpplug_debug.log"
#endif

// Backward compatibility for existing code paths.
#ifndef SFTP_DEBUG_LEVEL
    #if SFTP_DEBUG_ENABLED
        #define SFTP_DEBUG_LEVEL 2
    #else
        #define SFTP_DEBUG_LEVEL 0
    #endif
#endif

#if SFTP_DEBUG_ENABLED
inline void sftp_debug_emit_line(const char* line) noexcept
{
    if (!line) return;
    OutputDebugStringA(line);
    OutputDebugStringA("\n");
#if SFTP_DEBUG_TO_FILE
    char logPath[MAX_PATH] = SFTP_DEBUG_FILE_PATH;
    char dirPath[MAX_PATH] = {};
    strncpy_s(dirPath, logPath, _TRUNCATE);
    char* slash = strrchr(dirPath, '\\');
    if (slash) {
        *slash = 0;
        if (dirPath[0])
            CreateDirectoryA(dirPath, nullptr);
    }

    HANDLE hf = CreateFileA(logPath, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        char tmpDir[MAX_PATH] = {};
        DWORD n = GetTempPathA((DWORD)countof(tmpDir), tmpDir);
        if (n > 0 && n < countof(tmpDir) - 20) {
            strncat_s(tmpDir, "sftpplug_debug.log", _TRUNCATE);
            hf = CreateFileA(tmpDir, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        }
    }
    if (hf != INVALID_HANDLE_VALUE) {
        SetFilePointer(hf, 0, nullptr, FILE_END);
        DWORD written = 0;
        WriteFile(hf, line, (DWORD)strlen(line), &written, nullptr);
        WriteFile(hf, "\r\n", 2, &written, nullptr);
        CloseHandle(hf);
    }
#endif
}

inline void sftp_debug_logf(const char* tag, const char* fmt, ...) noexcept
{
    char msg[1024];
    msg[0] = 0;
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt ? fmt : "", args);
    va_end(args);

    char line[1200];
    if (tag && tag[0]) {
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] %s", tag, msg);
    } else {
        _snprintf_s(line, sizeof(line), _TRUNCATE, "%s", msg);
    }
    sftp_debug_emit_line(line);
}

    #define SFTP_LOG(tag, fmt, ...) do { \
        sftp_debug_logf(tag, fmt, ##__VA_ARGS__); \
    } while(0)
    #define DEBUG_LOG(fmt, ...) SFTP_LOG("DBG", fmt, ##__VA_ARGS__)
    #define ENABLE_SCP_DEBUG
#else
    #define SFTP_LOG(tag, fmt, ...) do {} while(0)
    #define DEBUG_LOG(fmt, ...) do {} while(0)
#endif

// Inline helper for safe string operations
namespace detail {
    template<typename T, size_t N>
    constexpr size_t array_size(T (&)[N]) noexcept { return N; }
}

#endif // __cplusplus


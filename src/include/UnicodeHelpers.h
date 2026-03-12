#pragma once

#include <windows.h>
#include "fsplugin.h"
#include "CoreUtils.h"
#include "UtfConversion.h"

// C++ Standard Library headers
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <algorithm>

// ============================================================================
// Constants
// ============================================================================

constexpr size_t WDRTYPEMAX = 1024;

// ============================================================================
// String Conversion Functions (C interface for legacy compatibility)
// ============================================================================

extern "C" {

// Safe string copy for wide characters
[[nodiscard]] LPWSTR wcslcpy(LPWSTR str1, LPCWSTR str2, size_t imaxlen) noexcept;

// Safe string concatenation for wide characters
[[nodiscard]] LPWSTR wcslcat(LPWSTR str1, LPCWSTR str2, size_t imaxlen) noexcept;

// Wide ANSI to Wide Unicode copy (ANSI -> WCHAR)
[[nodiscard]] LPWSTR awlcopy(LPWSTR outname, LPCSTR inname, size_t maxlen) noexcept;

// Wide ANSI to Wide Unicode copy with codepage
[[nodiscard]] LPWSTR awlcopyCP(int codepage, LPWSTR outname, LPCSTR inname, size_t maxlen) noexcept;

// Wide Unicode to ANSI copy (WCHAR -> ANSI)
[[nodiscard]] LPSTR walcopy(LPSTR outname, LPCWSTR inname, size_t maxlen) noexcept;

// Wide Unicode to ANSI copy with codepage
[[nodiscard]] LPSTR walcopyCP(int codepage, LPSTR outname, LPCWSTR inname, size_t maxlen) noexcept;

// UTF-16 to UTF-8 conversion
[[nodiscard]] int ConvUTF16toUTF8(
    LPCWSTR inbuf, 
    size_t inlen, 
    LPSTR outbuf, 
    size_t outmax, 
    bool nullterm = true) noexcept;

// UTF-8 to UTF-16 conversion
[[nodiscard]] int ConvUTF8toUTF16(
    LPCSTR inbuf, 
    size_t inlen, 
    LPWSTR outbuf, 
    size_t outmax, 
    bool nullterm = true) noexcept;

// Copy FIND_DATA structures between ANSI and Unicode versions
void copyfinddatawa(LPWIN32_FIND_DATA lpFindFileDataA, LPWIN32_FIND_DATAW lpFindFileDataW) noexcept;
void copyfinddataaw(LPWIN32_FIND_DATAW lpFindFileDataW, LPWIN32_FIND_DATA lpFindFileDataA) noexcept;

// Callback proxy functions
int ProgressProcT(int PluginNr, LPCWSTR SourceName, LPCWSTR TargetName, int PercentDone) noexcept;
void LogProcT(int PluginNr, int MsgType, LPCWSTR LogString) noexcept;
bool RequestProcT(int PluginNr, int RequestType, LPCWSTR CustomTitle, LPCWSTR CustomText, LPWSTR ReturnedText, size_t maxlen) noexcept;

// File operations with Unicode support
BOOL CopyFileT(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) noexcept;
BOOL CreateDirectoryT(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes) noexcept;
BOOL RemoveDirectoryT(LPCWSTR lpPathName) noexcept;
BOOL DeleteFileT(LPCWSTR lpFileName) noexcept;
BOOL MoveFileT(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) noexcept;
BOOL SetFileAttributesT(LPCWSTR lpFileName, DWORD dwFileAttributes) noexcept;

HANDLE CreateFileT(
    LPCWSTR lpFileName, 
    DWORD dwDesiredAccess, 
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, 
    HANDLE hTemplateFile) noexcept;

UINT ExtractIconExT(
    LPCWSTR lpszFile, 
    int nIconIndex, 
    HICON* phiconLarge, 
    HICON* phiconSmall, 
    UINT nIcons) noexcept;

HANDLE FindFirstFileT(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) noexcept;
BOOL FindNextFileT(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) noexcept;

} // extern "C"

// ============================================================================
// Modern C++ Helper Functions (in namespace)
// ============================================================================

namespace unicode_util {

// Check if we're running on Unicode-capable system (always true for modern Windows)
[[nodiscard]] constexpr bool usys() noexcept {
    return true;   /* Windows 7+ and TC 7.51+ */
}

// String conversion helpers using std::string
class utf8_to_utf16 {
public:
    explicit utf8_to_utf16(const char* utf8_str) {
        if (utf8_str) {
            const int len = MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, nullptr, 0);
            if (len > 0) {
                buffer_.resize(static_cast<size_t>(len));
                MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, buffer_.data(), len);
            }
        }
    }
    
    [[nodiscard]] const wchar_t* c_str() const noexcept {
        return buffer_.empty() ? L"" : buffer_.data();
    }
    
    [[nodiscard]] const std::wstring& str() const noexcept {
        return buffer_;
    }
    
    [[nodiscard]] operator const wchar_t*() const noexcept {
        return c_str();
    }

private:
    std::wstring buffer_;
};

class utf16_to_utf8 {
public:
    explicit utf16_to_utf8(const wchar_t* utf16_str) {
        if (utf16_str) {
            const int len = WideCharToMultiByte(CP_UTF8, 0, utf16_str, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                buffer_.resize(static_cast<size_t>(len));
                WideCharToMultiByte(CP_UTF8, 0, utf16_str, -1, buffer_.data(), len, nullptr, nullptr);
            }
        }
    }
    
    [[nodiscard]] const char* c_str() const noexcept {
        return buffer_.empty() ? "" : buffer_.data();
    }
    
    [[nodiscard]] const std::string& str() const noexcept {
        return buffer_;
    }
    
    [[nodiscard]] operator const char*() const noexcept {
        return c_str();
    }

private:
    std::string buffer_;
};

} // namespace unicode_util

// ============================================================================
// Modern C++20 String Helpers - safe alternatives to C-style functions
// These return std::string/std::wstring directly, no buffers needed
// ============================================================================

namespace unicode_util {

// Safe wide string copy - returns std::wstring, no buffer size needed
[[nodiscard]] std::wstring safe_wcsncpy(std::wstring_view src, size_t max_len = std::wstring_view::npos);

// Safe wide string concat - returns std::wstring
[[nodiscard]] std::wstring safe_wcscat(std::wstring_view str1, std::wstring_view str2);

// Wide to ANSI with automatic memory management
[[nodiscard]] std::string wide_to_narrow(std::wstring_view w, int codepage = CP_ACP);

// ANSI to Wide with automatic memory management  
[[nodiscard]] std::wstring narrow_to_wide(std::string_view a, int codepage = CP_ACP);

// UTF-8 to UTF-16 conversion (returns std::wstring)
[[nodiscard]] std::wstring utf8_to_wstring(std::string_view utf8);

// UTF-16 to UTF-8 conversion (returns std::string)
[[nodiscard]] std::string wstring_to_utf8(std::wstring_view wstr);

// Helper for WIN32_FIND_DATA conversion - returns wide version
[[nodiscard]] WIN32_FIND_DATAW convert_find_data_to_wide(const WIN32_FIND_DATAA& findA);

} // namespace unicode_util

// Legacy global alias kept for older plugin code paths.
[[nodiscard]] inline bool usys() noexcept {
    return unicode_util::usys();
}

// ============================================================================
// Legacy Compatibility Macros
// ============================================================================

#define wafilenamecopy(outname, inname)  walcopy(outname, inname, _countof(outname) - 1)
#define awfilenamecopy(outname, inname)  awlcopy(outname, inname, _countof(outname) - 1)


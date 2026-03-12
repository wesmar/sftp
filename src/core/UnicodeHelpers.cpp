// UnicodeHelpers.cpp - Modern C++ implementation
// Compatible with Visual Studio 2026 (v145 toolset) and C++20

#include "UnicodeHelpers.h"
#include "shellapi.h"

#include <string>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <array>

// External callback functions (defined in FileSystemPlugin.cpp)
extern tProgressProcW ProgressProcW;
extern tLogProcW      LogProcW;
extern tRequestProcW  RequestProcW;

// ============================================================================
// String Conversion Functions
// ============================================================================

LPWSTR wcslcpy(LPWSTR str1, LPCWSTR str2, size_t imaxlen) noexcept
{
    if (!str1 || !str2 || imaxlen == 0) return str1;

    size_t i = 0;
    const size_t limit = imaxlen - 1;
    while (i < limit && str2[i]) {
        str1[i] = str2[i];
        ++i;
    }
    str1[i] = L'\0';
    return str1;
}

LPWSTR wcslcat(LPWSTR str1, LPCWSTR str2, size_t imaxlen) noexcept
{
    if (!str1 || !str2 || imaxlen == 0) return str1;

    // Clamp existing length to the declared destination capacity.
    size_t len1 = 0;
    while (len1 < imaxlen && str1[len1]) {
        ++len1;
    }
    if (len1 >= imaxlen) {
        str1[imaxlen - 1] = L'\0';
        return str1;
    }

    size_t i = 0;
    const size_t limit = imaxlen - len1 - 1;
    while (i < limit && str2[i]) {
        str1[len1 + i] = str2[i];
        ++i;
    }
    str1[len1 + i] = L'\0';
    return str1;
}

LPSTR walcopy(LPSTR outname, LPCWSTR inname, size_t maxlen) noexcept
{
    return walcopyCP(CP_ACP, outname, inname, maxlen);
}

LPSTR walcopyCP(int codepage, LPSTR outname, LPCWSTR inname, size_t maxlen) noexcept
{
    if (!outname || !inname || maxlen == 0) return nullptr;

    outname[0] = '\0';
    const int result = WideCharToMultiByte(codepage, 0, inname, -1, outname, static_cast<int>(maxlen), nullptr, nullptr);
    if (result > 0 && static_cast<size_t>(result) <= maxlen) {
        outname[result - 1] = '\0';
    } else if (maxlen > 0) {
        outname[maxlen - 1] = '\0';
    }
    return outname;
}

LPWSTR awlcopy(LPWSTR outname, LPCSTR inname, size_t maxlen) noexcept
{
    return awlcopyCP(CP_ACP, outname, inname, maxlen);
}

LPWSTR awlcopyCP(int codepage, LPWSTR outname, LPCSTR inname, size_t maxlen) noexcept
{
    if (!outname || !inname || maxlen == 0) return nullptr;

    outname[0] = L'\0';
    const int result = MultiByteToWideChar(codepage, 0, inname, -1, outname, static_cast<int>(maxlen));
    if (result > 0 && static_cast<size_t>(result) <= maxlen) {
        outname[result - 1] = L'\0';
    } else if (maxlen > 0) {
        outname[maxlen - 1] = L'\0';
    }
    return outname;
}

int ConvUTF16toUTF8(LPCWSTR inbuf, size_t inlen, LPSTR outbuf, size_t outmax, bool nullterm) noexcept
{
    if (!inbuf || !outbuf || outmax < 2) return -1;
    
    if (nullterm) outbuf[0] = '\0';
    if (inlen == 0) inlen = wcslen(inbuf);
    if (inlen == 0) return 0;
    
    UTF16* source = reinterpret_cast<UTF16*>(const_cast<LPWSTR>(inbuf));
    UTF8* target = reinterpret_cast<UTF8*>(outbuf);
    
    const int rc = ConvertUTF16toUTF8(
        &source, 
        reinterpret_cast<const UTF16*>(inbuf + inlen),
        &target, 
        reinterpret_cast<const UTF8*>(outbuf + outmax - 1)
    );
    
    const size_t outlen = reinterpret_cast<size_t>(target) - reinterpret_cast<size_t>(outbuf);
    
    if (nullterm && outlen < outmax - 1) {
        outbuf[outlen] = '\0';
    }
    
    return (rc == CVT_OK) ? static_cast<int>(outlen) : -1;
}

int ConvUTF8toUTF16(LPCSTR inbuf, size_t inlen, LPWSTR outbuf, size_t outmax, bool nullterm) noexcept
{
    if (!inbuf || !outbuf || outmax < 2) return -1;
    
    if (nullterm) outbuf[0] = L'\0';
    if (inlen == 0) inlen = strlen(inbuf);
    if (inlen == 0) return 0;
    
    UTF8* source = reinterpret_cast<UTF8*>(const_cast<LPSTR>(inbuf));
    UTF16* target = reinterpret_cast<UTF16*>(outbuf);
    
    const int rc = ConvertUTF8toUTF16(
        &source, 
        reinterpret_cast<UTF8*>(const_cast<LPSTR>(inbuf + inlen)),
        &target, 
        reinterpret_cast<const UTF16*>(outbuf + outmax - 1)
    );
    
    const size_t outlen = (reinterpret_cast<size_t>(target) - reinterpret_cast<size_t>(outbuf)) / sizeof(WCHAR);
    
    if (nullterm && outlen < outmax - 1) {
        outbuf[outlen] = L'\0';
    }
    
    return (rc == CVT_OK) ? static_cast<int>(outlen) : -1;
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

namespace {

// Return true if name wasn't cut
[[nodiscard]] bool MakeExtraLongNameW(LPWSTR outbuf, LPCWSTR inbuf, size_t maxlen) noexcept
{
    if (!outbuf || !inbuf || maxlen == 0) return false;

    const size_t inLen = wcslen(inbuf);
    
    // Check bounds BEFORE calling wcscpy_s to avoid invalid parameter handler
    if (inLen >= MAX_PATH) {
        // Need space for "\\\\?\\" prefix + inLen + null terminator
        if (inLen + 5 > maxlen) return false;
        wcscpy_s(outbuf, maxlen, L"\\\\?\\");
        wcscat_s(outbuf, maxlen, inbuf);
    } else {
        // Need space for inLen + null terminator
        if (inLen + 1 > maxlen) return false;
        wcscpy_s(outbuf, maxlen, inbuf);
    }
    return true;
}

} // anonymous namespace

// ============================================================================
// FIND_DATA Conversion Functions
// ============================================================================

void copyfinddatawa(LPWIN32_FIND_DATA lpFindFileDataA, LPWIN32_FIND_DATAW lpFindFileDataW) noexcept
{
    if (!lpFindFileDataA || !lpFindFileDataW) return;
    
    // Convert WCHAR arrays to CHAR arrays
    for (size_t i = 0; i < _countof(lpFindFileDataA->cFileName) - 1 && i < _countof(lpFindFileDataW->cFileName); ++i) {
        lpFindFileDataA->cFileName[i] = static_cast<char>(lpFindFileDataW->cFileName[i] & 0xFF);
    }
    lpFindFileDataA->cFileName[_countof(lpFindFileDataA->cFileName) - 1] = '\0';
    
    for (size_t i = 0; i < _countof(lpFindFileDataA->cAlternateFileName) - 1 && i < _countof(lpFindFileDataW->cAlternateFileName); ++i) {
        lpFindFileDataA->cAlternateFileName[i] = static_cast<char>(lpFindFileDataW->cAlternateFileName[i] & 0xFF);
    }
    lpFindFileDataA->cAlternateFileName[_countof(lpFindFileDataA->cAlternateFileName) - 1] = '\0';
    
    lpFindFileDataA->dwFileAttributes = lpFindFileDataW->dwFileAttributes;
    lpFindFileDataA->ftCreationTime = lpFindFileDataW->ftCreationTime;
    lpFindFileDataA->ftLastAccessTime = lpFindFileDataW->ftLastAccessTime;
    lpFindFileDataA->ftLastWriteTime = lpFindFileDataW->ftLastWriteTime;
    lpFindFileDataA->nFileSizeHigh = lpFindFileDataW->nFileSizeHigh;
    lpFindFileDataA->nFileSizeLow = lpFindFileDataW->nFileSizeLow;
    lpFindFileDataA->dwReserved0 = lpFindFileDataW->dwReserved0;
    lpFindFileDataA->dwReserved1 = lpFindFileDataW->dwReserved1;
}

void copyfinddataaw(LPWIN32_FIND_DATAW lpFindFileDataW, LPWIN32_FIND_DATA lpFindFileDataA) noexcept
{
    if (!lpFindFileDataW || !lpFindFileDataA) return;
    
    // Convert CHAR arrays to WCHAR arrays
    for (size_t i = 0; i < _countof(lpFindFileDataW->cFileName) - 1 && i < _countof(lpFindFileDataA->cFileName); ++i) {
        lpFindFileDataW->cFileName[i] = static_cast<wchar_t>(static_cast<unsigned char>(lpFindFileDataA->cFileName[i]));
    }
    lpFindFileDataW->cFileName[_countof(lpFindFileDataW->cFileName) - 1] = L'\0';
    
    for (size_t i = 0; i < _countof(lpFindFileDataW->cAlternateFileName) - 1 && i < _countof(lpFindFileDataA->cAlternateFileName); ++i) {
        lpFindFileDataW->cAlternateFileName[i] = static_cast<wchar_t>(static_cast<unsigned char>(lpFindFileDataA->cAlternateFileName[i]));
    }
    lpFindFileDataW->cAlternateFileName[_countof(lpFindFileDataW->cAlternateFileName) - 1] = L'\0';
    
    lpFindFileDataW->dwFileAttributes = lpFindFileDataA->dwFileAttributes;
    lpFindFileDataW->ftCreationTime = lpFindFileDataA->ftCreationTime;
    lpFindFileDataW->ftLastAccessTime = lpFindFileDataA->ftLastAccessTime;
    lpFindFileDataW->ftLastWriteTime = lpFindFileDataA->ftLastWriteTime;
    lpFindFileDataW->nFileSizeHigh = lpFindFileDataA->nFileSizeHigh;
    lpFindFileDataW->nFileSizeLow = lpFindFileDataA->nFileSizeLow;
    lpFindFileDataW->dwReserved0 = lpFindFileDataA->dwReserved0;
    lpFindFileDataW->dwReserved1 = lpFindFileDataA->dwReserved1;
}

// ============================================================================
// Callback Proxy Functions
// ============================================================================

int ProgressProcT(int PluginNr, LPCWSTR SourceName, LPCWSTR TargetName, int PercentDone) noexcept
{
    if (ProgressProcW) {
        return ProgressProcW(PluginNr, SourceName, TargetName, PercentDone);
    }
    return 0;
}

void LogProcT(int PluginNr, int MsgType, LPCWSTR LogString) noexcept
{
    if (LogProcW) {
        LogProcW(PluginNr, MsgType, LogString);
    }
}

bool RequestProcT(int PluginNr, int RequestType, LPCWSTR CustomTitle, LPCWSTR CustomText, 
                  LPWSTR ReturnedText, size_t maxlen) noexcept
{
    if (RequestProcW) {
        const BOOL retval = RequestProcW(PluginNr, RequestType, CustomTitle, CustomText, 
                                         ReturnedText, static_cast<int>(maxlen));
        return retval ? true : false;
    }
    return false;
}

// ============================================================================
// File Operations with Long Path Support
// ============================================================================

BOOL CopyFileT(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) noexcept
{
    if (!lpExistingFileName || !lpNewFileName) return FALSE;
    
    std::array<WCHAR, wdirtypemax> wbuf1{};
    if (!MakeExtraLongNameW(wbuf1.data(), lpExistingFileName, wbuf1.size() - 1)) {
        return FALSE;
    }
    
    std::array<WCHAR, wdirtypemax> wbuf2{};
    if (!MakeExtraLongNameW(wbuf2.data(), lpNewFileName, wbuf2.size() - 1)) {
        return FALSE;
    }
    
    return CopyFileW(wbuf1.data(), wbuf2.data(), bFailIfExists);
}

BOOL CreateDirectoryT(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes) noexcept
{
    if (!lpPathName) return FALSE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpPathName, wbuf.size() - 1)) {
        return FALSE;
    }
    
    return CreateDirectoryW(wbuf.data(), lpSecurityAttributes);
}

BOOL RemoveDirectoryT(LPCWSTR lpPathName) noexcept
{
    if (!lpPathName) return FALSE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpPathName, wbuf.size() - 1)) {
        return FALSE;
    }
    
    return RemoveDirectoryW(wbuf.data());
}

BOOL DeleteFileT(LPCWSTR lpFileName) noexcept
{
    if (!lpFileName) return FALSE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpFileName, wbuf.size() - 1)) {
        return FALSE;
    }
    
    return DeleteFileW(wbuf.data());
}

BOOL MoveFileT(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) noexcept
{
    if (!lpExistingFileName || !lpNewFileName) return FALSE;
    
    std::array<WCHAR, wdirtypemax> wbuf1{};
    if (!MakeExtraLongNameW(wbuf1.data(), lpExistingFileName, wbuf1.size() - 1)) {
        return FALSE;
    }
    
    std::array<WCHAR, wdirtypemax> wbuf2{};
    if (!MakeExtraLongNameW(wbuf2.data(), lpNewFileName, wbuf2.size() - 1)) {
        return FALSE;
    }
    
    return MoveFileW(wbuf1.data(), wbuf2.data());
}

BOOL SetFileAttributesT(LPCWSTR lpFileName, DWORD dwFileAttributes) noexcept
{
    if (!lpFileName) return FALSE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpFileName, wbuf.size() - 1)) {
        return FALSE;
    }
    
    return SetFileAttributesW(wbuf.data(), dwFileAttributes);
}

HANDLE CreateFileT(
    LPCWSTR lpFileName, 
    DWORD dwDesiredAccess, 
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, 
    HANDLE hTemplateFile) noexcept
{
    if (!lpFileName) return INVALID_HANDLE_VALUE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpFileName, wbuf.size() - 1)) {
        return INVALID_HANDLE_VALUE;
    }
    
    return CreateFileW(wbuf.data(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
                       dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

UINT ExtractIconExT(
    LPCWSTR lpszFile, 
    int nIconIndex, 
    HICON* phiconLarge, 
    HICON* phiconSmall, 
    UINT nIcons) noexcept
{
    // Unfortunately this function cannot handle names longer than 259 characters
    return ExtractIconExW(lpszFile, nIconIndex, phiconLarge, phiconSmall, nIcons);
}

HANDLE FindFirstFileT(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) noexcept
{
    if (!lpFileName || !lpFindFileData) return INVALID_HANDLE_VALUE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpFileName, wbuf.size() - 1)) {
        return INVALID_HANDLE_VALUE;
    }
    
    return FindFirstFileW(wbuf.data(), lpFindFileData);
}

BOOL FindNextFileT(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) noexcept
{
    if (!hFindFile || !lpFindFileData) return FALSE;

    return FindNextFileW(hFindFile, lpFindFileData);
}

// ============================================================================
// Modern C++20 String Helpers - implementation
// ============================================================================

namespace unicode_util {

std::wstring safe_wcsncpy(std::wstring_view src, size_t max_len)
{
    if (src.empty()) {
        return {};
    }
    if (max_len == std::wstring_view::npos || src.size() <= max_len) {
        return std::wstring(src);
    }
    return std::wstring(src.substr(0, max_len));
}

std::wstring safe_wcscat(std::wstring_view str1, std::wstring_view str2)
{
    std::wstring result;
    result.reserve(str1.size() + str2.size());
    result.append(str1);
    result.append(str2);
    return result;
}

std::string wide_to_narrow(std::wstring_view w, int codepage)
{
    if (w.empty()) {
        return {};
    }
    const int len = WideCharToMultiByte(codepage, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        return {};
    }
    std::string result(len, '\0');
    WideCharToMultiByte(codepage, 0, w.data(), static_cast<int>(w.size()), result.data(), len, nullptr, nullptr);
    return result;
}

std::wstring narrow_to_wide(std::string_view a, int codepage)
{
    if (a.empty()) {
        return {};
    }
    const int len = MultiByteToWideChar(codepage, 0, a.data(), static_cast<int>(a.size()), nullptr, 0);
    if (len <= 0) {
        return {};
    }
    std::wstring result(len, L'\0');
    MultiByteToWideChar(codepage, 0, a.data(), static_cast<int>(a.size()), result.data(), len);
    return result;
}

std::wstring utf8_to_wstring(std::string_view utf8)
{
    return narrow_to_wide(utf8, CP_UTF8);
}

std::string wstring_to_utf8(std::wstring_view wstr)
{
    return wide_to_narrow(wstr, CP_UTF8);
}

WIN32_FIND_DATAW convert_find_data_to_wide(const WIN32_FIND_DATAA& findA)
{
    WIN32_FIND_DATAW result{};
    result.dwFileAttributes = findA.dwFileAttributes;
    result.ftCreationTime = findA.ftCreationTime;
    result.ftLastAccessTime = findA.ftLastAccessTime;
    result.ftLastWriteTime = findA.ftLastWriteTime;
    result.nFileSizeHigh = findA.nFileSizeHigh;
    result.nFileSizeLow = findA.nFileSizeLow;
    result.dwReserved0 = findA.dwReserved0;
    result.dwReserved1 = findA.dwReserved1;
    
    // Convert filenames using narrow_to_wide helper
    const auto wideName = narrow_to_wide(findA.cFileName, CP_ACP);
    const auto wideAltName = narrow_to_wide(findA.cAlternateFileName, CP_ACP);
    
    wcslcpy(result.cFileName, wideName.c_str(), _countof(result.cFileName));
    wcslcpy(result.cAlternateFileName, wideAltName.c_str(), _countof(result.cAlternateFileName));
    
    return result;
}

} // namespace unicode_util

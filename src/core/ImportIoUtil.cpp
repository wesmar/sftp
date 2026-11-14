#include "ImportIoUtil.h"
#include "SftpClient.h"

#include <commdlg.h>
#include <shlobj.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace sftp {

namespace {

int CALLBACK BrowseFolderInitCallback(HWND hwnd, UINT msg, LPARAM /*lParam*/, LPARAM lpData)
{
    if (msg == BFFM_INITIALIZED && lpData)
        SendMessageW(hwnd, BFFM_SETSELECTIONW, TRUE, lpData);
    return 0;
}


// Case-insensitive extension match. `name` is the leaf (e.g. "Session.INI"),
// `ext` is the required extension without a leading dot (e.g. "ini"). Empty
// `ext` matches every regular file.
bool ExtensionMatches(const std::wstring& name, const std::wstring& ext) noexcept
{
    if (ext.empty()) return true;
    if (name.size() <= ext.size() + 1) return false;
    if (name[name.size() - ext.size() - 1] != L'.') return false;
    return _wcsicmp(name.c_str() + name.size() - ext.size(), ext.c_str()) == 0;
}

// Build the relative DisplayName segment for a file. `parentRel` is the
// slash-joined relative path of the file's parent directory (empty at
// `root`); `leaf` is the file name with its extension already validated by
// ExtensionMatches. Trailing `.ext` is stripped from the leaf.
std::string BuildRelPath(const std::string& parentRel,
                          const std::wstring& leaf,
                          const std::wstring& ext)
{
    std::wstring baseW = leaf;
    if (!ext.empty() && baseW.size() > ext.size() + 1)
        baseW.resize(baseW.size() - ext.size() - 1);  // drop ".ext"

    // Wide → UTF-8 for the DisplayName segment.
    const int need = WideCharToMultiByte(CP_UTF8, 0,
        baseW.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string leafU8;
    if (need > 1) {
        leafU8.resize(static_cast<size_t>(need - 1));
        WideCharToMultiByte(CP_UTF8, 0, baseW.c_str(), -1,
            leafU8.data(), need, nullptr, nullptr);
    }
    if (parentRel.empty()) return leafU8;
    return parentRel + "/" + leafU8;
}

// Depth-first recursion body. Stops the whole walk (returns false all the
// way up) as soon as the visitor returns false.
bool WalkImpl(const std::wstring& dir,
              const std::string&  parentRel,
              const std::wstring& ext,
              WalkFileCallback&   onFile)
{
    const std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return true;

    std::vector<std::wstring> subdirs;

    bool keepGoing = true;
    do {
        const wchar_t* name = fd.cFileName;
        if (name[0] == L'.' &&
            (name[1] == L'\0' || (name[1] == L'.' && name[2] == L'\0')))
            continue;

        const std::wstring leaf(name);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            subdirs.push_back(dir + L"\\" + leaf);
            continue;
        }

        if (!ExtensionMatches(leaf, ext))
            continue;

        const std::wstring fullPath = dir + L"\\" + leaf;
        const std::string  relPath  = BuildRelPath(parentRel, leaf, ext);
        if (!onFile(fullPath, relPath)) {
            keepGoing = false;
            break;
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);

    if (!keepGoing) return false;

    for (const auto& sub : subdirs) {
        const size_t slash = sub.find_last_of(L'\\');
        const std::wstring leafW = (slash == std::wstring::npos)
            ? sub
            : sub.substr(slash + 1);
        const std::string childRel =
            BuildRelPath(parentRel, leafW, L"");  // no extension strip for dirs
        if (!WalkImpl(sub, childRel, ext, onFile))
            return false;
    }
    return true;
}

}  // namespace

namespace {

std::string TrimAscii(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' ||
                     s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

bool EqualsI(const std::string& a, const char* b) noexcept
{
    return _stricmp(a.c_str(), b) == 0;
}

bool StartsWithI(const std::string& s, const char* prefix) noexcept
{
    const size_t plen = std::strlen(prefix);
    if (s.size() < plen) return false;
    return _strnicmp(s.c_str(), prefix, plen) == 0;
}

}  // namespace

bool ParseLineCodePage(const std::string& raw,
                       int& outUtf8, int& outCodepage) noexcept
{
    outUtf8 = 0;
    outCodepage = 0;

    const std::string v = TrimAscii(raw);
    if (v.empty())
        return false;  // "Use font encoding" in PuTTY — leave plugin defaults

    if (EqualsI(v, "UTF-8") || EqualsI(v, "UTF8")) {
        outUtf8 = 1;
        return true;
    }

    // Cyrillic PuTTY presets.
    if (EqualsI(v, "KOI8-R") || EqualsI(v, "KOI8R")) {
        outCodepage = 20866;
        return true;
    }
    if (EqualsI(v, "KOI8-U") || EqualsI(v, "KOI8U")) {
        outCodepage = 21866;
        return true;
    }

    // ISO-8859-N — Windows codepage math: N in 1..14 maps to 28590+N,
    // and 15 is the outlier at 28605.
    if (StartsWithI(v, "ISO-8859-")) {
        const char* p = v.c_str() + std::strlen("ISO-8859-");
        char* end = nullptr;
        unsigned long n = std::strtoul(p, &end, 10);
        if (end && *end == '\0' && n > 0) {
            outCodepage = (n == 15) ? 28605 : (28590 + static_cast<int>(n));
            return true;
        }
    }

    // Windows / OEM codepages: "CP1251", "WIN-1252", "Windows-1250", or
    // bare "1251".
    const char* p = nullptr;
    if      (StartsWithI(v, "CP"))          p = v.c_str() + 2;
    else if (StartsWithI(v, "WINDOWS-"))    p = v.c_str() + std::strlen("WINDOWS-");
    else if (StartsWithI(v, "WINDOWS"))     p = v.c_str() + std::strlen("WINDOWS");
    else if (StartsWithI(v, "WIN"))         p = v.c_str() + 3;
    else                                    p = v.c_str();

    if (p && *p) {
        while (*p == '-' || *p == '_') ++p;
        char* end = nullptr;
        unsigned long cp = std::strtoul(p, &end, 10);
        if (end && *end == '\0' && cp > 0) {
            if (cp == 65001) {
                // Numeric UTF-8 alias — collapse to the utf8 flag.
                outUtf8 = 1;
                outCodepage = 0;
            } else {
                outCodepage = static_cast<int>(cp);
            }
            return true;
        }
    }
    return false;
}

void DescribeProxy(Proxy type, const std::string& host, DWORD port,
                   const std::string& user, SessionDependency& dep)
{
    if (host.empty())
        return;

    // The plugin assumes 8080 for HTTP and 1080 for SOCKS when the address
    // carries no port, so only a different one is spelled out — which also
    // lets the copy match a record typed in by hand. An IPv6 literal needs
    // brackets before a port can follow it.
    const DWORD assumed = type == Proxy::http ? 8080 : 1080;
    const bool  ipv6    = host.find(':') != std::string::npos && host.front() != '[';
    std::string server  = ipv6 ? "[" + host + "]" : host;
    if (port != 0 && port != assumed)
        server += ":" + std::to_string(port);

    dep.proxyType   = type;
    dep.proxyServer = server;
    dep.proxyUser   = user;
}

void DescribePuttyProxy(DWORD method, const std::string& host, DWORD port,
                        const std::string& user, SessionDependency& dep)
{
    Proxy type{};
    switch (method) {
        case 1: type = Proxy::socks4; break;
        case 2: type = Proxy::socks5; break;
        case 3: type = Proxy::http;   break;
        default: return;
    }
    DescribeProxy(type, host, port == 0 ? 80 : port, user, dep);
}

bool IniSectionExists(const std::string& section, LPCSTR iniPath) noexcept
{
    if (section.empty() || !iniPath || !iniPath[0]) return false;
    std::array<char, 16> buf{};
    if (GetPrivateProfileStringA(section.c_str(), "server", nullptr,
            buf.data(), static_cast<DWORD>(buf.size()), iniPath) > 0)
        return true;
    return GetPrivateProfileStringA(section.c_str(), "user", nullptr,
            buf.data(), static_cast<DWORD>(buf.size()), iniPath) > 0;
}

void WalkDirectoryFiles(const std::wstring& root,
                        const std::wstring& ext,
                        WalkFileCallback     onFile)
{
    if (root.empty() || !onFile) return;
    WalkImpl(root, {}, ext, onFile);
}

namespace {

std::string FileTimeText(const FILETIME& ft)
{
    return std::to_string((static_cast<unsigned long long>(ft.dwHighDateTime) << 32) |
                          ft.dwLowDateTime);
}

std::string WideToUtf8Text(const std::wstring& s)
{
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), n, nullptr, nullptr);
    return out;
}

void AppendFileStamp(std::string& stamp, const std::wstring& path)
{
    WIN32_FILE_ATTRIBUTE_DATA a{};
    const bool ok = GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &a) != 0;
    stamp += WideToUtf8Text(path) + '|' + (ok ? FileTimeText(a.ftLastWriteTime) : std::string("-")) + ';';
}

}  // namespace

std::string FileChangeStamp(const std::vector<std::wstring>& files)
{
    std::string stamp;
    for (const auto& f : files)
        AppendFileStamp(stamp, f);
    return stamp;
}

std::string FolderChangeStamp(const std::wstring& root)
{
    std::string stamp = WideToUtf8Text(root) + '>';
    WalkDirectoryFiles(root, L"", [&stamp](const std::wstring& fullPath, const std::string&) {
        AppendFileStamp(stamp, fullPath);
        return true;
    });
    return stamp;
}

std::wstring AnsiPathToWide(const std::string& path)
{
    const int n = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n - 1), L'\0');
    MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, out.data(), n);
    return out;
}

std::string RegistryChangeStamp(const char* subKey)
{
    std::string stamp = std::string(subKey) + '>';
    HKEY key = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, subKey, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return stamp + '-';
    FILETIME ft{};
    if (RegQueryInfoKeyA(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS)
        stamp += FileTimeText(ft) + ';';
    for (DWORD i = 0;; ++i) {
        std::array<char, 512> name{};
        DWORD len = static_cast<DWORD>(name.size());
        const LONG rc = RegEnumKeyExA(key, i, name.data(), &len, nullptr, nullptr, nullptr, &ft);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc == ERROR_SUCCESS)
            stamp += std::string(name.data(), len) + '|' + FileTimeText(ft) + ';';
    }
    RegCloseKey(key);
    return stamp;
}

namespace {

// Convert an ANSI, NUL-separated Win32 filter ("A\0*.a\0B\0*.b\0") into a
// wide, NUL-separated buffer with the required trailing double-NUL. Returns
// empty vector on empty input.
std::vector<wchar_t> WidenNulSeparatedFilter(const char* filter)
{
    if (!filter || !filter[0]) return {};

    // Total ANSI length up to and including the terminating double-NUL.
    size_t ansiLen = 0;
    while (true) {
        const size_t segLen = std::strlen(filter + ansiLen);
        ansiLen += segLen + 1;  // include the segment's NUL
        if (segLen == 0) break;  // empty segment marks the end
    }

    const int wchars = MultiByteToWideChar(CP_ACP, 0, filter,
        static_cast<int>(ansiLen), nullptr, 0);
    if (wchars <= 0) return {};
    std::vector<wchar_t> out(static_cast<size_t>(wchars), L'\0');
    MultiByteToWideChar(CP_ACP, 0, filter, static_cast<int>(ansiLen),
        out.data(), wchars);
    return out;
}

}  // namespace

bool BrowseForFile(HWND               owner,
                   const char*        title,
                   const char*        filter,
                   const char*        initialPath,
                   std::string&       outPath)
{
    wchar_t wTitle[256] = {};
    if (title && title[0])
        MultiByteToWideChar(CP_ACP, 0, title, -1, wTitle, 256);

    // GetOpenFileName expects a mutable buffer that both seeds the initial
    // selection and receives the picked path. Pre-fill with `initialPath`
    // when it's a full file path; a bare directory goes into lpstrInitialDir.
    wchar_t wFile[MAX_PATH] = {};
    wchar_t wInitDir[MAX_PATH] = {};
    if (initialPath && initialPath[0]) {
        const DWORD attrs = GetFileAttributesA(initialPath);
        if (attrs != INVALID_FILE_ATTRIBUTES &&
            (attrs & FILE_ATTRIBUTE_DIRECTORY))
        {
            MultiByteToWideChar(CP_ACP, 0, initialPath, -1,
                wInitDir, MAX_PATH);
        } else {
            MultiByteToWideChar(CP_ACP, 0, initialPath, -1,
                wFile, MAX_PATH);
        }
    }

    const std::vector<wchar_t> wFilter = WidenNulSeparatedFilter(filter);

    OPENFILENAMEW ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = owner;
    ofn.lpstrTitle   = wTitle[0] ? wTitle : nullptr;
    ofn.lpstrFile    = wFile;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrFilter  = wFilter.empty() ? nullptr : wFilter.data();
    ofn.lpstrInitialDir = wInitDir[0] ? wInitDir : nullptr;
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
                       OFN_HIDEREADONLY | OFN_NOCHANGEDIR;

    if (!GetOpenFileNameW(&ofn)) return false;

    char narrow[MAX_PATH * 4] = {};
    WideCharToMultiByte(CP_ACP, 0, wFile, -1,
                         narrow, sizeof(narrow), nullptr, nullptr);
    outPath.assign(narrow);
    return !outPath.empty();
}

bool BrowseForFolder(HWND               owner,
                     const char*        title,
                     const char*        initialPath,
                     std::string&       outPath)
{
    wchar_t wTitle[256] = {};
    if (title && title[0])
        MultiByteToWideChar(CP_ACP, 0, title, -1, wTitle, 256);

    wchar_t wInitial[MAX_PATH] = {};
    if (initialPath && initialPath[0])
        MultiByteToWideChar(CP_ACP, 0, initialPath, -1, wInitial, MAX_PATH);

    BROWSEINFOW bi = {};
    bi.hwndOwner = owner;
    bi.lpszTitle = wTitle[0] ? wTitle : nullptr;
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_USENEWUI;
    if (wInitial[0]) {
        bi.lpfn   = BrowseFolderInitCallback;
        bi.lParam = reinterpret_cast<LPARAM>(wInitial);
    }

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return false;

    wchar_t wpath[MAX_PATH] = {};
    const bool got = SHGetPathFromIDListW(pidl, wpath) != 0;
    CoTaskMemFree(pidl);
    if (!got) return false;

    char narrow[MAX_PATH * 4] = {};
    WideCharToMultiByte(CP_ACP, 0, wpath, -1,
                         narrow, sizeof(narrow), nullptr, nullptr);
    outPath.assign(narrow);
    return !outPath.empty();
}

void AssignImportedKeyFile(const std::string& path,
                            std::string& outPriv,
                            std::string& outPub)
{
    if (path.empty()) return;

    const size_t n = path.size();
    const bool isPub =
        n >= 4 &&
        _stricmp(path.c_str() + n - 4, ".pub") == 0;

    if (isPub) outPub  = path;
    else       outPriv = path;
}

int HexNibble(char c) noexcept
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

std::string PuttyUrlDecode(const std::string& encoded)
{
    std::string out;
    out.reserve(encoded.size());
    for (size_t i = 0; i < encoded.size(); ++i) {
        const char ch = encoded[i];
        if (ch == '%' && i + 2 < encoded.size()) {
            const int hi = HexNibble(encoded[i + 1]);
            const int lo = HexNibble(encoded[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(ch);
    }
    return out;
}

std::string PuttyUrlEncode(const std::string& raw)
{
    // Escape set that matches PuTTY's own on-disk names:
    //   any byte < 0x20 or > 0x7E   (controls and non-ASCII)
    //   space, '%', '\\', '*', '?'  (path-breaking characters)
    //   leading '.'                 (registry subkey rule)
    // Everything else — including '(', ')', '@', '+', '=', ';', '#', '&' —
    // stays literal, exactly as PuTTY stores it.
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(raw[i]);
        const bool needsEscape =
            ch < 0x20 || ch > 0x7E ||
            ch == ' ' || ch == '%' || ch == '\\' || ch == '*' || ch == '?' ||
            (i == 0 && ch == '.');
        if (needsEscape) {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", ch);
            out.append(buf);
        } else {
            out.push_back(static_cast<char>(ch));
        }
    }
    return out;
}

bool ReadRegString(HKEY key, const char* valueName, std::string& out)
{
    DWORD type = 0;
    DWORD bytes = 0;
    LONG rc = RegQueryValueExA(key, valueName, nullptr, &type, nullptr, &bytes);
    if (rc != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) ||
        bytes == 0)
        return false;
    std::string buffer(bytes, '\0');
    rc = RegQueryValueExA(key, valueName, nullptr, &type,
                           reinterpret_cast<LPBYTE>(buffer.data()), &bytes);
    if (rc != ERROR_SUCCESS) return false;
    while (!buffer.empty() && buffer.back() == '\0')
        buffer.pop_back();
    out = std::move(buffer);
    return !out.empty();
}

bool ReadRegDword(HKEY key, const char* valueName, DWORD& out) noexcept
{
    DWORD type = 0;
    DWORD value = 0;
    DWORD bytes = sizeof(value);
    LONG rc = RegQueryValueExA(key, valueName, nullptr, &type,
                                reinterpret_cast<LPBYTE>(&value), &bytes);
    if (rc != ERROR_SUCCESS || type != REG_DWORD) return false;
    out = value;
    return true;
}

std::string ExpandEnvA(const std::string& raw)
{
    if (raw.empty()) return raw;
    std::string expanded(MAX_PATH, '\0');
    DWORD len = ExpandEnvironmentStringsA(raw.c_str(), expanded.data(),
                                           static_cast<DWORD>(expanded.size()));
    // Too small a buffer comes back with the size it wants, so one retry
    // always fits. Without it a long path is returned with its %VARS%
    // intact and fails later, where the cause is no longer visible.
    if (len > expanded.size()) {
        expanded.assign(len, '\0');
        len = ExpandEnvironmentStringsA(raw.c_str(), expanded.data(),
                                        static_cast<DWORD>(expanded.size()));
    }
    if (len == 0 || len > expanded.size()) return raw;
    expanded.resize(len - 1);
    return expanded;
}

void SecureWipe(std::string& s) noexcept
{
    if (!s.empty())
        SecureZeroMemory(s.data(), s.size());
    s.clear();
}

void SecureWipe(std::vector<char>& v) noexcept
{
    if (!v.empty())
        SecureZeroMemory(v.data(), v.size());
    v.clear();
}

uint32_t Fnv1aHash(std::string_view s) noexcept
{
    uint32_t h = 0x811C9DC5u;
    for (unsigned char c : s) {
        h ^= c;
        h *= 0x01000193u;
    }
    return h;
}

}  // namespace sftp

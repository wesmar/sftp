#include "global.h"
#include "SessionImport.h"
#include "WindowsUserFeedback.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include "../res/resource.h"
#include "LngLoader.h"

extern HINSTANCE hinst;

#define IMPORT_LOG(fmt, ...) SFTP_LOG("IMPORT", fmt, ##__VA_ARGS__)

namespace {

enum class SessionSource {
    putty,
    winscp,
    kitty,
};

struct SessionDescriptor {
    SessionSource source = SessionSource::putty;
    std::string keyName;
    std::string displayName;
};

struct ImportedSessionData {
    std::string sectionName;
    std::string server;
    std::string userName;
    std::string pubkeyfile;
    std::string privkeyfile;
    bool useagent = false;
};

constexpr const char* kPuttySessionsRoot = "Software\\SimonTatham\\PuTTY\\Sessions";
constexpr const char* kWinScpSessionsRoot = "Software\\Martin Prikryl\\WinSCP 2\\Sessions";

const char* GetRootPath(SessionSource source) noexcept
{
    return source == SessionSource::putty ? kPuttySessionsRoot : kWinScpSessionsRoot;
}

const char* GetSourceLabel(SessionSource source) noexcept
{
    return source == SessionSource::putty ? "PuTTY" : "WinSCP";
}

bool EndsWithI(const std::string& value, const char* suffix) noexcept
{
    const size_t suffixLen = strlen(suffix);
    if (value.size() < suffixLen)
        return false;
    const size_t start = value.size() - suffixLen;
    for (size_t i = 0; i < suffixLen; ++i) {
        unsigned char a = static_cast<unsigned char>(value[start + i]);
        unsigned char b = static_cast<unsigned char>(suffix[i]);
        if (std::tolower(a) != std::tolower(b))
            return false;
    }
    return true;
}

bool EqualsI(const std::string& a, const char* b) noexcept
{
    size_t i = 0;
    for (; i < a.size() && b[i] != 0; ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return i == a.size() && b[i] == 0;
}

int HexToInt(char c) noexcept
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + c - 'a';
    if (c >= 'A' && c <= 'F')
        return 10 + c - 'A';
    return -1;
}

std::string UrlDecode(const std::string& encoded)
{
    std::string out;
    out.reserve(encoded.size());
    for (size_t i = 0; i < encoded.size(); ++i) {
        const char ch = encoded[i];
        if (ch == '%' && i + 2 < encoded.size()) {
            const int hi = HexToInt(encoded[i + 1]);
            const int lo = HexToInt(encoded[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        if (ch == '+')
            out.push_back(' ');
        else
            out.push_back(ch);
    }
    return out;
}

bool ReadRegString(HKEY key, const char* valueName, std::string& out)
{
    DWORD type = 0;
    DWORD bytes = 0;
    LONG rc = RegQueryValueExA(key, valueName, nullptr, &type, nullptr, &bytes);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || bytes == 0)
        return false;

    std::vector<char> buf(bytes + 1, 0);
    rc = RegQueryValueExA(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()), &bytes);
    if (rc != ERROR_SUCCESS)
        return false;

    out.assign(buf.data());
    return !out.empty();
}

bool ReadRegDword(HKEY key, const char* valueName, DWORD& out)
{
    DWORD type = 0;
    DWORD bytes = sizeof(DWORD);
    DWORD value = 0;
    LONG rc = RegQueryValueExA(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &bytes);
    if (rc == ERROR_SUCCESS && type == REG_DWORD) {
        out = value;
        return true;
    }

    std::string asString;
    if (!ReadRegString(key, valueName, asString))
        return false;

    char* end = nullptr;
    unsigned long parsed = strtoul(asString.c_str(), &end, 0);
    if (!end || *end != 0)
        return false;
    out = static_cast<DWORD>(parsed);
    return true;
}

bool OpenSessionKey(SessionSource source, const std::string& keyName, HKEY& out)
{
    out = nullptr;
    std::string fullPath = GetRootPath(source);
    fullPath += "\\";
    fullPath += keyName;
    return RegOpenKeyExA(HKEY_CURRENT_USER, fullPath.c_str(), 0, KEY_READ, &out) == ERROR_SUCCESS;
}

bool SessionExistsInIni(const std::string& section, LPCSTR iniFileName)
{
    std::array<char, 8> buffer{};
    DWORD len = GetPrivateProfileSectionA(section.c_str(), buffer.data(), buffer.size(), iniFileName);
    return len > 0;
}

std::string MakeUniqueIniSection(const std::string& baseName, SessionSource source, LPCSTR iniFileName)
{
    // Check if section already exists by looking for any key in it
    std::array<char, 16> buffer{};
    DWORD len = GetPrivateProfileStringA(baseName.c_str(), "server", nullptr, buffer.data(), buffer.size(), iniFileName);
    if (len > 0)
        return baseName;  // Section exists with server key
    
    // Fallback check using the "user" key.
    len = GetPrivateProfileStringA(baseName.c_str(), "user", nullptr, buffer.data(), buffer.size(), iniFileName);
    if (len > 0)
        return baseName;  // Section exists with user key
    
    // Section doesn't exist, use base name
    return baseName;
}

bool EnumerateSessions(SessionSource source, std::vector<SessionDescriptor>& out)
{
    HKEY root = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, GetRootPath(source), 0, KEY_READ, &root) != ERROR_SUCCESS)
        return false;

    DWORD index = 0;
    for (;;) {
        std::array<char, 512> keyName{};
        DWORD keyNameChars = static_cast<DWORD>(keyName.size());
        LONG rc = RegEnumKeyExA(root, index, keyName.data(), &keyNameChars, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        ++index;
        if (rc != ERROR_SUCCESS)
            continue;

        std::string rawName(keyName.data(), keyNameChars);
        if (EqualsI(rawName, "Default Settings") || EqualsI(rawName, "Default%20Settings"))
            continue;

        SessionDescriptor item;
        item.source = source;
        item.keyName = rawName;
        item.displayName = UrlDecode(rawName);
        out.push_back(std::move(item));
    }

    RegCloseKey(root);

    std::sort(out.begin(), out.end(), [](const SessionDescriptor& a, const SessionDescriptor& b) {
        std::string al = a.displayName;
        std::string bl = b.displayName;
        std::transform(al.begin(), al.end(), al.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(bl.begin(), bl.end(), bl.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return al < bl;
    });
    return !out.empty();
}

bool ImportSessionToIni(const SessionDescriptor& session, LPCSTR iniFileName, bool& unsupportedProtocol, ImportedSessionData* importedData)
{
    unsupportedProtocol = false;
    bool isScp = false;

    HKEY sessionKey = nullptr;
    if (!OpenSessionKey(session.source, session.keyName, sessionKey))
        return false;

    std::string host;
    const bool hasHost = ReadRegString(sessionKey, "HostName", host);
    if (!hasHost || host.empty()) {
        RegCloseKey(sessionKey);
        return false;
    }

    if (session.source == SessionSource::winscp) {
        DWORD fsProtocol = 0;
        if (ReadRegDword(sessionKey, "FSProtocol", fsProtocol)) {
            if (fsProtocol == 1) {
                // WinSCP SCP session - supported, import with explicit SCP flags.
                isScp = true;
            } else if (fsProtocol != 0) {
                unsupportedProtocol = true;
                RegCloseKey(sessionKey);
                return false;
            }
        }
    }

    DWORD port = 0;
    const bool hasPort = ReadRegDword(sessionKey, "PortNumber", port);

    std::string userName;
    ReadRegString(sessionKey, "UserName", userName);

    DWORD useAgent = 0;
    if (!ReadRegDword(sessionKey, "AgentFwd", useAgent))
        ReadRegDword(sessionKey, "AuthAgent", useAgent);

    std::string publicKeyFile;
    ReadRegString(sessionKey, "PublicKeyFile", publicKeyFile);

    RegCloseKey(sessionKey);

    host = UrlDecode(host);
    userName = UrlDecode(userName);
    publicKeyFile = UrlDecode(publicKeyFile);

    std::string serverField = host;
    if (hasPort && port > 0 && port != 22)
        serverField += std::format(":{}", port);

    const std::string sectionName = MakeUniqueIniSection(session.displayName, session.source, iniFileName);
    
    // Write settings one by one (same as original code)
    WritePrivateProfileStringA(sectionName.c_str(), "server", serverField.c_str(), iniFileName);
    if (!userName.empty())
        WritePrivateProfileStringA(sectionName.c_str(), "user", userName.c_str(), iniFileName);

    if (useAgent)
        WritePrivateProfileStringA(sectionName.c_str(), "useagent", "1", iniFileName);

    if (isScp) {
        // Force SCP path for WinSCP sessions explicitly configured as SCP.
        WritePrivateProfileStringA(sectionName.c_str(), "scponly", "1", iniFileName);
        WritePrivateProfileStringA(sectionName.c_str(), "scpfordata", "1", iniFileName);
        // Avoid post-auth auto-detection probes that execute shell commands.
        WritePrivateProfileStringA(sectionName.c_str(), "utf8", "0", iniFileName);
        WritePrivateProfileStringA(sectionName.c_str(), "unixlinebreaks", "1", iniFileName);
        WritePrivateProfileStringA(sectionName.c_str(), "largefilesupport", "0", iniFileName);
    } else {
        // Conservative defaults for imported non-SCP sessions.
        WritePrivateProfileStringA(sectionName.c_str(), "utf8", "0", iniFileName);
        WritePrivateProfileStringA(sectionName.c_str(), "unixlinebreaks", "0", iniFileName);
    }

    if (!publicKeyFile.empty()) {
        // Expand environment variables in key path (e.g. %USERPROFILE%)
        std::string expandedKeyFile(MAX_PATH, '\0');
        DWORD expandedLen = ExpandEnvironmentStringsA(publicKeyFile.c_str(), expandedKeyFile.data(), static_cast<DWORD>(expandedKeyFile.size()));
        if (expandedLen > 0 && expandedLen <= expandedKeyFile.size()) {
            expandedKeyFile.resize(expandedLen - 1);
            publicKeyFile = expandedKeyFile;
        }

        if (EndsWithI(publicKeyFile, ".ppk") || EndsWithI(publicKeyFile, ".pem")) {
            WritePrivateProfileStringA(sectionName.c_str(), "privkeyfile", publicKeyFile.c_str(), iniFileName);
            if (importedData)
                importedData->privkeyfile = publicKeyFile;
        } else if (EndsWithI(publicKeyFile, ".pub")) {
            WritePrivateProfileStringA(sectionName.c_str(), "pubkeyfile", publicKeyFile.c_str(), iniFileName);
            if (importedData)
                importedData->pubkeyfile = publicKeyFile;
        }
    }
    
    if (importedData) {
        importedData->sectionName = sectionName;
        importedData->server = serverField;
        importedData->userName = userName;
        importedData->useagent = (useAgent != 0);
    }
    return true;
}

int ImportAll(const std::vector<SessionDescriptor>& sessions, LPCSTR iniFileName, int& skippedUnsupported)
{
    int imported = 0;
    for (const auto& session : sessions) {
        bool unsupported = false;
        if (ImportSessionToIni(session, iniFileName, unsupported, nullptr))
            ++imported;
        else if (unsupported)
            ++skippedUnsupported;
    }
    return imported;
}


// ---------------------------------------------------------------------------
// Portable PuTTY / WinSCP INI import (file-based, not registry)
// ---------------------------------------------------------------------------

struct PortableSessionDescriptor {
    SessionSource source = SessionSource::putty;
    std::string   iniFile;       // path to the source .ini file
    std::string   sectionName;   // full section name inside that file
    std::string   displayName;   // human-readable session name
};

bool ReadIniString(const char* iniFile, const char* section, const char* key, std::string& out)
{
    std::array<char, 1024> buf{};
    const DWORD len = GetPrivateProfileStringA(section, key, "", buf.data(),
                                               static_cast<DWORD>(buf.size()), iniFile);
    if (len == 0)
        return false;
    out.assign(buf.data(), len);
    return true;
}

bool ReadIniDword(const char* iniFile, const char* section, const char* key, DWORD& out)
{
    std::string val;
    if (!ReadIniString(iniFile, section, key, val))
        return false;
    char* end = nullptr;
    const unsigned long parsed = strtoul(val.c_str(), &end, 0);
    if (!end || *end != '\0')
        return false;
    out = static_cast<DWORD>(parsed);
    return true;
}

// PuTTY portable: [Software\SimonTatham\PuTTY\Sessions\<name>]
// WinSCP portable: [Sessions\<name>]
constexpr const char* kPortablePuttyPrefix  = "Software\\SimonTatham\\PuTTY\\Sessions\\";
constexpr const char* kPortableWinScpPrefix = "Sessions\\";

void EnumeratePortableSessions(const char* iniFile, SessionSource source,
                                std::vector<PortableSessionDescriptor>& out)
{
    const char* prefix    = (source == SessionSource::putty) ? kPortablePuttyPrefix : kPortableWinScpPrefix;
    const size_t prefixLen = strlen(prefix);

    // GetPrivateProfileSectionNamesA returns a double-null-terminated list.
    std::vector<char> buf(65536, '\0');
    const DWORD len = GetPrivateProfileSectionNamesA(buf.data(),
                                                     static_cast<DWORD>(buf.size()), iniFile);
    if (len == 0)
        return;

    const char* p = buf.data();
    while (*p) {
        const std::string section(p);
        p += section.size() + 1;

        if (section.size() <= prefixLen)
            continue;

        // Case-insensitive prefix check
        bool prefixMatch = true;
        for (size_t i = 0; i < prefixLen; ++i) {
            if (std::tolower(static_cast<unsigned char>(section[i])) !=
                std::tolower(static_cast<unsigned char>(prefix[i]))) {
                prefixMatch = false;
                break;
            }
        }
        if (!prefixMatch)
            continue;

        const std::string keyName = section.substr(prefixLen);
        if (keyName.empty())
            continue;
        if (EqualsI(keyName, "Default Settings") || EqualsI(keyName, "Default%20Settings"))
            continue;

        PortableSessionDescriptor item;
        item.source      = source;
        item.iniFile     = iniFile;
        item.sectionName = section;
        item.displayName = UrlDecode(keyName);
        out.push_back(std::move(item));
    }

    std::sort(out.begin(), out.end(), [](const PortableSessionDescriptor& a,
                                         const PortableSessionDescriptor& b) {
        std::string al = a.displayName;
        std::string bl = b.displayName;
        std::transform(al.begin(), al.end(), al.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(bl.begin(), bl.end(), bl.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return al < bl;
    });
}

bool ImportPortableSessionToIni(const PortableSessionDescriptor& session, LPCSTR iniFileName,
                                 bool& unsupportedProtocol, ImportedSessionData* importedData)
{
    unsupportedProtocol = false;
    bool isScp = false;

    const char* src  = session.iniFile.c_str();
    const char* sect = session.sectionName.c_str();

    std::string host;
    if (!ReadIniString(src, sect, "HostName", host) || host.empty())
        return false;

    if (session.source == SessionSource::winscp) {
        DWORD fsProtocol = 0;
        if (ReadIniDword(src, sect, "FSProtocol", fsProtocol)) {
            if (fsProtocol == 1) {
                isScp = true;
            } else if (fsProtocol != 0) {
                unsupportedProtocol = true;
                return false;
            }
        }
    }

    DWORD port = 0;
    const bool hasPort = ReadIniDword(src, sect, "PortNumber", port);

    std::string userName;
    ReadIniString(src, sect, "UserName", userName);

    DWORD useAgent = 0;
    if (!ReadIniDword(src, sect, "AgentFwd", useAgent))
        ReadIniDword(src, sect, "AuthAgent", useAgent);

    std::string publicKeyFile;
    ReadIniString(src, sect, "PublicKeyFile", publicKeyFile);

    host          = UrlDecode(host);
    userName      = UrlDecode(userName);
    publicKeyFile = UrlDecode(publicKeyFile);

    std::string serverField = host;
    if (hasPort && port > 0 && port != 22)
        serverField += std::format(":{}", port);

    const std::string sectionName = MakeUniqueIniSection(session.displayName, session.source, iniFileName);

    WritePrivateProfileStringA(sectionName.c_str(), "server", serverField.c_str(), iniFileName);
    if (!userName.empty())
        WritePrivateProfileStringA(sectionName.c_str(), "user", userName.c_str(), iniFileName);
    if (useAgent)
        WritePrivateProfileStringA(sectionName.c_str(), "useagent", "1", iniFileName);

    if (isScp) {
        WritePrivateProfileStringA(sectionName.c_str(), "scponly",        "1", iniFileName);
        WritePrivateProfileStringA(sectionName.c_str(), "scpfordata",     "1", iniFileName);
        WritePrivateProfileStringA(sectionName.c_str(), "utf8",           "0", iniFileName);
        WritePrivateProfileStringA(sectionName.c_str(), "unixlinebreaks", "1", iniFileName);
        WritePrivateProfileStringA(sectionName.c_str(), "largefilesupport","0", iniFileName);
    } else {
        WritePrivateProfileStringA(sectionName.c_str(), "utf8",           "0", iniFileName);
        WritePrivateProfileStringA(sectionName.c_str(), "unixlinebreaks", "0", iniFileName);
    }

    if (!publicKeyFile.empty()) {
        std::string expandedKeyFile(MAX_PATH, '\0');
        const DWORD expandedLen = ExpandEnvironmentStringsA(publicKeyFile.c_str(),
                                                            expandedKeyFile.data(),
                                                            static_cast<DWORD>(expandedKeyFile.size()));
        if (expandedLen > 0 && expandedLen <= expandedKeyFile.size()) {
            expandedKeyFile.resize(expandedLen - 1);
            publicKeyFile = expandedKeyFile;
        }

        if (EndsWithI(publicKeyFile, ".ppk") || EndsWithI(publicKeyFile, ".pem")) {
            WritePrivateProfileStringA(sectionName.c_str(), "privkeyfile", publicKeyFile.c_str(), iniFileName);
            if (importedData)
                importedData->privkeyfile = publicKeyFile;
        } else if (EndsWithI(publicKeyFile, ".pub")) {
            WritePrivateProfileStringA(sectionName.c_str(), "pubkeyfile", publicKeyFile.c_str(), iniFileName);
            if (importedData)
                importedData->pubkeyfile = publicKeyFile;
        }
    }

    if (importedData) {
        importedData->sectionName = sectionName;
        importedData->server      = serverField;
        importedData->userName    = userName;
        importedData->useagent    = (useAgent != 0);
    }
    return true;
}

int ImportAllPortable(const std::vector<PortableSessionDescriptor>& sessions,
                      LPCSTR iniFileName, int& skippedUnsupported)
{
    int imported = 0;
    for (const auto& session : sessions) {
        bool unsupported = false;
        if (ImportPortableSessionToIni(session, iniFileName, unsupported, nullptr))
            ++imported;
        else if (unsupported)
            ++skippedUnsupported;
    }
    return imported;
}

// ---------------------------------------------------------------------------
// Recent import path rotation (up to 4 slots per key prefix)
// ---------------------------------------------------------------------------
static constexpr int kMaxImportPaths = 4;

static std::string LoadRecentImportPath(const char* iniFile, const char* keyPrefix)
{
    char buf[MAX_PATH] = {};
    const std::string key = std::string(keyPrefix) + "1";
    GetPrivateProfileStringA("ImportPaths", key.c_str(), "", buf, MAX_PATH, iniFile);
    return buf;
}

static void SaveRecentImportPaths(const char* iniFile, const char* keyPrefix, const std::string& newPath)
{
    if (newPath.empty()) return;
    std::vector<std::string> paths;
    paths.push_back(newPath);
    for (int i = 1; i <= kMaxImportPaths; ++i) {
        const std::string key = std::string(keyPrefix) + std::to_string(i);
        char buf[MAX_PATH] = {};
        GetPrivateProfileStringA("ImportPaths", key.c_str(), "", buf, MAX_PATH, iniFile);
        const std::string existing = buf;
        if (!existing.empty() && _stricmp(existing.c_str(), newPath.c_str()) != 0)
            paths.push_back(existing);
        if (static_cast<int>(paths.size()) >= kMaxImportPaths) break;
    }
    for (int i = 0; i < static_cast<int>(paths.size()); ++i) {
        const std::string key = std::string(keyPrefix) + std::to_string(i + 1);
        WritePrivateProfileStringA("ImportPaths", key.c_str(), paths[static_cast<size_t>(i)].c_str(), iniFile);
    }
    for (int i = static_cast<int>(paths.size()) + 1; i <= kMaxImportPaths; ++i) {
        const std::string key = std::string(keyPrefix) + std::to_string(i);
        WritePrivateProfileStringA("ImportPaths", key.c_str(), "", iniFile);
    }
}

// ---------------------------------------------------------------------------
// File / folder browse helpers
// ---------------------------------------------------------------------------

static bool BrowseForIniFile(HWND owner, const char* title, const char* initialDir, std::string& outPath)
{
    char buf[MAX_PATH] = {};
    OPENFILENAMEA ofn    = {};
    ofn.lStructSize      = sizeof(ofn);
    ofn.hwndOwner        = owner;
    ofn.lpstrFilter      = "INI files (*.ini)\0*.ini\0All files (*.*)\0*.*\0";
    ofn.lpstrFile        = buf;
    ofn.nMaxFile         = MAX_PATH;
    ofn.lpstrTitle       = title;
    ofn.lpstrInitialDir  = (initialDir && initialDir[0]) ? initialDir : nullptr;
    ofn.Flags            = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (!GetOpenFileNameA(&ofn))
        return false;
    outPath = buf;
    return true;
}

static int CALLBACK BrowseFolderInitCallback(HWND hwnd, UINT msg, LPARAM /*lParam*/, LPARAM lpData)
{
    if (msg == BFFM_INITIALIZED && lpData)
        SendMessageW(hwnd, BFFM_SETSELECTIONW, TRUE, lpData);
    return 0;
}

static bool BrowseForFolder(HWND owner, const char* title, const char* initialPath, std::string& outPath)
{
    wchar_t wTitle[256] = {};
    MultiByteToWideChar(CP_ACP, 0, title, -1, wTitle, 256);

    wchar_t wInitial[MAX_PATH] = {};
    if (initialPath && initialPath[0])
        MultiByteToWideChar(CP_ACP, 0, initialPath, -1, wInitial, MAX_PATH);

    BROWSEINFOW bi = {};
    bi.hwndOwner   = owner;
    bi.lpszTitle   = wTitle;
    bi.ulFlags     = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_USENEWUI;
    if (wInitial[0]) {
        bi.lpfn  = BrowseFolderInitCallback;
        bi.lParam = reinterpret_cast<LPARAM>(wInitial);
    }

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl)
        return false;

    wchar_t wPath[MAX_PATH] = {};
    const bool ok = SHGetPathFromIDListW(pidl, wPath) != 0;
    CoTaskMemFree(pidl);
    if (!ok)
        return false;

    char narrow[MAX_PATH] = {};
    WideCharToMultiByte(CP_ACP, 0, wPath, -1, narrow, MAX_PATH, nullptr, nullptr);
    outPath = narrow;
    return true;
}

// Recursively searches dir (up to maxDepth levels) for a file named putty.reg.
// Returns the full path if found, or empty string.
static std::string FindPuttyRegInFolder(const std::string& dir, int maxDepth = 4)
{
    if (maxDepth < 0)
        return {};

    const std::string pattern = dir + "\\*";
    WIN32_FIND_DATAA fd = {};
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return {};

    std::string result;
    std::vector<std::string> subdirs;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0)
                subdirs.push_back(dir + "\\" + fd.cFileName);
        } else {
            if (_stricmp(fd.cFileName, "putty.reg") == 0) {
                result = dir + "\\" + fd.cFileName;
                break;
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    if (!result.empty())
        return result;

    for (const auto& sub : subdirs) {
        result = FindPuttyRegInFolder(sub, maxDepth - 1);
        if (!result.empty())
            return result;
    }
    return {};
}

// Convert a Windows Registry text file (.reg) to a temporary INI file
// that GetPrivateProfileStringA can read.
// Handles UTF-16LE (FF FE BOM) or UTF-8/ANSI.
// Returns the path to the temp file; caller must DeleteFileA it when done.
std::string ConvertRegFileToTempIni(const std::string& regPath)
{
    HANDLE hFile = CreateFileA(regPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return {};

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return {};
    }

    std::vector<BYTE> rawBytes(fileSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, rawBytes.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    std::string content;
    if (bytesRead >= 2 && rawBytes[0] == 0xFF && rawBytes[1] == 0xFE) {
        // UTF-16LE — convert to ANSI
        const wchar_t* wData = reinterpret_cast<const wchar_t*>(rawBytes.data() + 2);
        const int wLen = static_cast<int>((bytesRead - 2) / 2);
        const int needed = WideCharToMultiByte(CP_ACP, 0, wData, wLen, nullptr, 0, nullptr, nullptr);
        if (needed > 0) {
            content.resize(needed);
            WideCharToMultiByte(CP_ACP, 0, wData, wLen, content.data(), needed, nullptr, nullptr);
        }
    } else {
        content.assign(reinterpret_cast<const char*>(rawBytes.data()), bytesRead);
    }

    char tempDir[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tempDir);
    char tempFile[MAX_PATH] = {};
    GetTempFileNameA(tempDir, "reg", 0, tempFile);

    HANDLE hOut = CreateFileA(tempFile, GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE)
        return {};

    const auto writeLine = [&](const std::string& line) {
        DWORD written = 0;
        const std::string withCRLF = line + "\r\n";
        WriteFile(hOut, withCRLF.c_str(), static_cast<DWORD>(withCRLF.size()), &written, nullptr);
    };

    constexpr const char* kHkcu = "HKEY_CURRENT_USER\\";
    const size_t kHkcuLen = 18; // strlen("HKEY_CURRENT_USER\\")

    size_t pos = 0;
    bool inSection = false;
    while (pos < content.size()) {
        size_t eol = content.find('\n', pos);
        std::string line;
        if (eol == std::string::npos) {
            line = content.substr(pos);
            pos = content.size();
        } else {
            line = content.substr(pos, eol - pos);
            pos = eol + 1;
        }
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        if (line.empty() || line[0] == ';' || line[0] == '#')
            continue;

        if (line[0] == '[') {
            const size_t end = line.rfind(']');
            if (end == std::string::npos)
                continue;
            std::string section = line.substr(1, end - 1);
            if (section.size() > kHkcuLen &&
                _strnicmp(section.c_str(), kHkcu, kHkcuLen) == 0)
                section = section.substr(kHkcuLen);
            writeLine("[" + section + "]");
            inSection = true;
            continue;
        }

        if (!inSection || line[0] != '"')
            continue;

        const size_t nameEnd = line.find('"', 1);
        if (nameEnd == std::string::npos)
            continue;
        const std::string name = line.substr(1, nameEnd - 1);

        const size_t eqPos = line.find('=', nameEnd + 1);
        if (eqPos == std::string::npos)
            continue;
        const std::string valueStr = line.substr(eqPos + 1);

        std::string value;
        if (!valueStr.empty() && valueStr[0] == '"') {
            const size_t vEnd = valueStr.rfind('"');
            if (vEnd == 0)
                continue;
            const std::string raw = valueStr.substr(1, vEnd - 1);
            std::string unescaped;
            unescaped.reserve(raw.size());
            for (size_t i = 0; i < raw.size(); ++i) {
                if (raw[i] == '\\' && i + 1 < raw.size()) {
                    ++i;
                    if (raw[i] == '"')       unescaped += '"';
                    else if (raw[i] == '\\') unescaped += '\\';
                    else { unescaped += '\\'; unescaped += raw[i]; }
                } else {
                    unescaped += raw[i];
                }
            }
            value = unescaped;
        } else if (valueStr.size() > 6 && _strnicmp(valueStr.c_str(), "dword:", 6) == 0) {
            char* endPtr = nullptr;
            const unsigned long dval = strtoul(valueStr.c_str() + 6, &endPtr, 16);
            value = std::to_string(dval);
        } else {
            continue;
        }

        writeLine(name + "=" + value);
    }

    CloseHandle(hOut);
    return std::string(tempFile);
}

// ---------------------------------------------------------------------------
// KiTTY Portable import (per-session files, Key\Value\ format)
// ---------------------------------------------------------------------------

struct KittySessionDescriptor {
    std::string filePath;    // full path to the session file
    std::string displayName; // URL-decoded session name
};

// Reads the value for a given key from a KiTTY session file.
// Format per line: KeyName\URL-encoded-value\
// Returns true if the key was found.
static bool ReadKittyString(const std::string& filePath, const char* key, std::string& out)
{
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return false;
    }

    std::string content(fileSize, '\0');
    DWORD bytesRead = 0;
    ReadFile(hFile, content.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);
    content.resize(bytesRead);

    const size_t keyLen = strlen(key);
    size_t pos = 0;
    while (pos < content.size()) {
        size_t eol = content.find('\n', pos);
        std::string line;
        if (eol == std::string::npos) {
            line = content.substr(pos);
            pos = content.size();
        } else {
            line = content.substr(pos, eol - pos);
            pos = eol + 1;
        }
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;

        // Line format: KeyName backslash URLencodedValue backslash
        const size_t sep = line.find('\\');
        if (sep == std::string::npos)
            continue;
        const std::string lineKey = line.substr(0, sep);
        if (_stricmp(lineKey.c_str(), key) != 0)
            continue;

        // Value is between first backslash and trailing backslash
        const size_t valStart = sep + 1;
        const size_t valEnd   = line.rfind('\\');
        if (valEnd == std::string::npos || valEnd <= sep)
            continue;
        out = UrlDecode(line.substr(valStart, valEnd - valStart));
        return true;
    }
    return false;
}

// Searches dir (up to maxDepth levels) for a folder named "Sessions".
static std::string FindKittySessionsFolder(const std::string& dir, int maxDepth = 4)
{
    if (maxDepth < 0)
        return {};

    const std::string pattern = dir + "\\*";
    WIN32_FIND_DATAA fd = {};
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return {};

    std::string result;
    std::vector<std::string> subdirs;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        if (_stricmp(fd.cFileName, "Sessions") == 0) {
            result = dir + "\\" + fd.cFileName;
            break;
        }
        subdirs.push_back(dir + "\\" + fd.cFileName);
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    if (!result.empty())
        return result;

    for (const auto& sub : subdirs) {
        result = FindKittySessionsFolder(sub, maxDepth - 1);
        if (!result.empty())
            return result;
    }
    return {};
}

// Enumerates session files in the KiTTY Sessions folder.
// A valid session file must contain "Protocol\ssh\" line.
static void EnumerateKittyFolder(const std::string& sessionsFolder,
                                  std::vector<KittySessionDescriptor>& out)
{
    const std::string pattern = sessionsFolder + "\\*";
    WIN32_FIND_DATAA fd = {};
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        const std::string filePath = sessionsFolder + "\\" + fd.cFileName;
        std::string protocol;
        ReadKittyString(filePath, "Protocol", protocol);
        if (!EqualsI(protocol, "ssh"))
            continue;

        KittySessionDescriptor item;
        item.filePath    = filePath;
        item.displayName = UrlDecode(fd.cFileName);
        out.push_back(std::move(item));
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    std::sort(out.begin(), out.end(), [](const KittySessionDescriptor& a,
                                         const KittySessionDescriptor& b) {
        std::string al = a.displayName;
        std::string bl = b.displayName;
        std::transform(al.begin(), al.end(), al.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(bl.begin(), bl.end(), bl.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return al < bl;
    });
}

static bool ImportKittySessionToIni(const KittySessionDescriptor& session,
                                     LPCSTR iniFileName,
                                     ImportedSessionData* importedData)
{
    std::string host;
    if (!ReadKittyString(session.filePath, "HostName", host) || host.empty())
        return false;

    std::string portStr;
    DWORD port = 0;
    bool hasPort = false;
    if (ReadKittyString(session.filePath, "PortNumber", portStr)) {
        char* end = nullptr;
        port = strtoul(portStr.c_str(), &end, 10);
        hasPort = (end && *end == '\0');
    }

    std::string userName;
    ReadKittyString(session.filePath, "UserName", userName);

    std::string publicKeyFile;
    ReadKittyString(session.filePath, "PublicKeyFile", publicKeyFile);

    std::string serverField = host;
    if (hasPort && port > 0 && port != 22)
        serverField += std::format(":{}", port);

    const std::string sectionName = MakeUniqueIniSection(session.displayName, SessionSource::putty, iniFileName);

    WritePrivateProfileStringA(sectionName.c_str(), "server", serverField.c_str(), iniFileName);
    if (!userName.empty())
        WritePrivateProfileStringA(sectionName.c_str(), "user", userName.c_str(), iniFileName);
    WritePrivateProfileStringA(sectionName.c_str(), "utf8",           "0", iniFileName);
    WritePrivateProfileStringA(sectionName.c_str(), "unixlinebreaks", "0", iniFileName);

    if (!publicKeyFile.empty()) {
        std::string expandedKeyFile(MAX_PATH, '\0');
        const DWORD expandedLen = ExpandEnvironmentStringsA(publicKeyFile.c_str(),
                                                            expandedKeyFile.data(),
                                                            static_cast<DWORD>(expandedKeyFile.size()));
        if (expandedLen > 0 && expandedLen <= expandedKeyFile.size()) {
            expandedKeyFile.resize(expandedLen - 1);
            publicKeyFile = expandedKeyFile;
        }
        if (EndsWithI(publicKeyFile, ".ppk") || EndsWithI(publicKeyFile, ".pem")) {
            WritePrivateProfileStringA(sectionName.c_str(), "privkeyfile", publicKeyFile.c_str(), iniFileName);
            if (importedData)
                importedData->privkeyfile = publicKeyFile;
        } else if (EndsWithI(publicKeyFile, ".pub")) {
            WritePrivateProfileStringA(sectionName.c_str(), "pubkeyfile", publicKeyFile.c_str(), iniFileName);
            if (importedData)
                importedData->pubkeyfile = publicKeyFile;
        }
    }

    if (importedData) {
        importedData->sectionName = sectionName;
        importedData->server      = serverField;
        importedData->userName    = userName;
        importedData->useagent    = false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Localization helpers (import dialog)
// ---------------------------------------------------------------------------

static std::wstring LngStrW(UINT id)
{
    const char* u8 = LngGetString(id);
    if (u8 && u8[0]) {
        const int n = MultiByteToWideChar(CP_UTF8, 0, u8, -1, nullptr, 0);
        if (n > 0) {
            std::wstring w; w.resize(static_cast<size_t>(n - 1));
            MultiByteToWideChar(CP_UTF8, 0, u8, -1, w.data(), n);
            return w;
        }
    }
    wchar_t buf[512] = {};
    const int n = LoadStringW(hinst, id, buf, 511);
    return n > 0 ? std::wstring(buf, static_cast<size_t>(n)) : std::wstring{};
}

static std::wstring FormatW(std::wstring templ, std::initializer_list<std::wstring_view> args)
{
    size_t pos = 0;
    for (const auto& arg : args) {
        const size_t at = templ.find(L"{}", pos);
        if (at == std::wstring::npos) break;
        templ.replace(at, 2, arg.data(), arg.size());
        pos = at + arg.size();
    }
    return templ;
}

static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s; s.resize(static_cast<size_t>(n - 1));
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

// ---------------------------------------------------------------------------
// Session picker dialog with checkboxes
// ---------------------------------------------------------------------------

struct SessionPickerDlgData {
    std::wstring                    title;
    std::wstring                    subtitle;
    const std::vector<std::string>* items;
    std::vector<size_t>             result;
};

static INT_PTR CALLBACK SessionPickerDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    auto* data = reinterpret_cast<SessionPickerDlgData*>(GetWindowLongPtrA(hDlg, DWLP_USER));
    switch (msg) {
    case WM_INITDIALOG: {
        data = reinterpret_cast<SessionPickerDlgData*>(lParam);
        SetWindowLongPtrA(hDlg, DWLP_USER, reinterpret_cast<LONG_PTR>(data));
        SetWindowTextW(hDlg, data->title.c_str());
        SetDlgItemTextW(hDlg, IDC_SESSION_SOURCE_LABEL, data->subtitle.c_str());

        const std::wstring selAll = LngStrW(IDS_IMP_BTN_SELECT_ALL);
        if (!selAll.empty())     SetDlgItemTextW(hDlg, IDC_SELECTALL,   selAll.c_str());
        const std::wstring deselAll = LngStrW(IDS_IMP_BTN_DESELECT_ALL);
        if (!deselAll.empty())   SetDlgItemTextW(hDlg, IDC_DESELECTALL, deselAll.c_str());
        const std::wstring impBtn = LngStrW(IDS_IMP_BTN_IMPORT);
        if (!impBtn.empty())     SetDlgItemTextW(hDlg, IDOK,            impBtn.c_str());
        const std::wstring cancelBtn = LngStrW(IDS_IMP_BTN_CANCEL);
        if (!cancelBtn.empty())  SetDlgItemTextW(hDlg, IDCANCEL,        cancelBtn.c_str());

        HWND hList = GetDlgItem(hDlg, IDC_SESSION_LIST);
        ListView_SetExtendedListViewStyle(hList, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT);

        RECT rc;
        GetClientRect(hList, &rc);
        LVCOLUMNA col = {};
        col.mask = LVCF_WIDTH;
        col.cx   = rc.right - GetSystemMetrics(SM_CXVSCROLL);
        ListView_InsertColumn(hList, 0, &col);

        LVITEMA item = {};
        item.mask = LVIF_TEXT;
        for (int i = 0; i < static_cast<int>(data->items->size()); ++i) {
            item.iItem   = i;
            item.pszText = const_cast<char*>((*data->items)[static_cast<size_t>(i)].c_str());
            ListView_InsertItem(hList, &item);
        }
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            HWND hList = GetDlgItem(hDlg, IDC_SESSION_LIST);
            data->result.clear();
            const int count = ListView_GetItemCount(hList);
            for (int i = 0; i < count; ++i)
                if (ListView_GetCheckState(hList, i))
                    data->result.push_back(static_cast<size_t>(i));
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        case IDC_SELECTALL: {
            HWND hList = GetDlgItem(hDlg, IDC_SESSION_LIST);
            const int count = ListView_GetItemCount(hList);
            for (int i = 0; i < count; ++i) ListView_SetCheckState(hList, i, TRUE);
            return TRUE;
        }
        case IDC_DESELECTALL: {
            HWND hList = GetDlgItem(hDlg, IDC_SESSION_LIST);
            const int count = ListView_GetItemCount(hList);
            for (int i = 0; i < count; ++i) ListView_SetCheckState(hList, i, FALSE);
            return TRUE;
        }
        }
        break;
    }
    return FALSE;
}

static std::vector<size_t> ShowSessionPickerDlg(
    HWND owner,
    std::wstring caption,
    std::wstring subtitle,
    const std::vector<std::string>& items)
{
    SessionPickerDlgData data;
    data.title    = std::move(caption);
    data.subtitle = std::move(subtitle);
    data.items    = &items;
    if (DialogBoxParamA(hinst, MAKEINTRESOURCE(IDD_SESSION_PICKER), owner,
                        SessionPickerDlgProc, reinterpret_cast<LPARAM>(&data)) != IDOK)
        return {};
    return data.result;
}

} // namespace

namespace sftp {

int ShowExternalSessionImportMenu(HWND owner,
                                  LPCSTR iniFileName,
                                  pConnectSettings applyTo,
                                  LPSTR importedSessionName,
                                  size_t importedSessionNameSize) noexcept
{
    if (importedSessionName && importedSessionNameSize > 0)
        importedSessionName[0] = 0;

    if (!iniFileName || !iniFileName[0])
        return 0;

    std::vector<SessionDescriptor> puttySessions;
    std::vector<SessionDescriptor> winScpSessions;
    const bool hasPutty = EnumerateSessions(SessionSource::putty, puttySessions);
    const bool hasWinScp = EnumerateSessions(SessionSource::winscp, winScpSessions);

    constexpr UINT kCmdPickPutty              = 50001;
    constexpr UINT kCmdPickWinScp             = 50002;
    constexpr UINT kCmdImportAll              = 50000;
    constexpr UINT kCmdImportFromWinScpIni    = 50004;
    constexpr UINT kCmdImportFromPuttyReg     = 50005;
    constexpr UINT kCmdImportFromKittyFolder  = 50006;

    HMENU menu = CreatePopupMenu();
    if (hasPutty)
        AppendMenuA(menu, MF_STRING, kCmdPickPutty,
                    std::format("PuTTY ({})...", puttySessions.size()).c_str());
    if (hasWinScp)
        AppendMenuA(menu, MF_STRING, kCmdPickWinScp,
                    std::format("WinSCP ({})...", winScpSessions.size()).c_str());
    if (hasPutty && hasWinScp) {
        std::wstring allTempl = LngStrW(IDS_IMP_MENU_ALL);
        if (allTempl.empty()) allTempl = L"Import all ({})";
        AppendMenuW(menu, MF_STRING, kCmdImportAll,
                    FormatW(allTempl, { std::to_wstring(puttySessions.size() + winScpSessions.size()) }).c_str());
    }
    AppendMenuA(menu, MF_SEPARATOR, 0, nullptr);
    {
        std::wstring fromPutty = LngStrW(IDS_IMP_MENU_FROM_PUTTY_PORT);
        if (fromPutty.empty()) fromPutty = L"Import from PuTTY Portable folder...";
        AppendMenuW(menu, MF_STRING, kCmdImportFromPuttyReg, fromPutty.c_str());
    }
    {
        std::wstring fromWinScp = LngStrW(IDS_IMP_MENU_FROM_WINSCP);
        if (fromWinScp.empty()) fromWinScp = L"Import from WinSCP.ini file...";
        AppendMenuW(menu, MF_STRING, kCmdImportFromWinScpIni, fromWinScp.c_str());
    }
    {
        std::wstring fromKitty = LngStrW(IDS_IMP_MENU_FROM_KITTY_PORT);
        if (fromKitty.empty()) fromKitty = L"Import from KiTTY Portable folder...";
        AppendMenuW(menu, MF_STRING, kCmdImportFromKittyFolder, fromKitty.c_str());
    }

    POINT pt;
    GetCursorPos(&pt);
    const UINT cmd = TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD | TPM_NONOTIFY,
                                    pt.x, pt.y, 0, owner, nullptr);
    DestroyMenu(menu);

    if (cmd == 0)
        return 0;

    int imported           = 0;
    int skippedUnsupported = 0;
    ImportedSessionData selectedData;

    auto maybeApply = [&]() {
        if (imported != 1) return;
        if (applyTo) {
            applyTo->server      = selectedData.server;
            applyTo->user        = selectedData.userName;
            applyTo->useagent    = selectedData.useagent;
            applyTo->pubkeyfile  = selectedData.pubkeyfile;
            applyTo->privkeyfile = selectedData.privkeyfile;
        }
        if (importedSessionName && importedSessionNameSize > 0 && !selectedData.sectionName.empty())
            strlcpy(importedSessionName, selectedData.sectionName.c_str(), importedSessionNameSize - 1);
    };

    auto showFeedback = [&](const char* skippedMsg) {
        WindowsUserFeedback fb(owner);
        if (imported > 0 && skippedUnsupported > 0)
            fb.ShowMessage(std::format("Imported {} session(s).\nSkipped {} {}.",
                                       imported, skippedUnsupported, skippedMsg), "SFTP");
        else if (imported > 0)
            fb.ShowMessage(std::format("Imported {} session(s).", imported), "SFTP");
        else if (skippedUnsupported > 0)
            fb.ShowMessage("No sessions imported (unsupported protocol type).", "SFTP");
        else
            fb.ShowMessage(WideToUtf8([&]{ auto s = LngStrW(IDS_IMP_MSG_NONE); return s.empty() ? std::wstring(L"No sessions imported.") : s; }()), "SFTP");
    };

    if (cmd == kCmdImportAll) {
        imported += ImportAll(puttySessions, iniFileName, skippedUnsupported);
        imported += ImportAll(winScpSessions, iniFileName, skippedUnsupported);
        showFeedback("unsupported session(s)");
        return imported;
    }

    auto pickRegistrySessions = [&](const std::vector<SessionDescriptor>& sessions,
                                    const char* source, UINT titleId) -> int {
        std::vector<std::string> names;
        names.reserve(sessions.size());
        for (const auto& s : sessions) names.push_back(s.displayName);
        std::wstring subTempl = LngStrW(IDS_IMP_FOUND_REG);
        if (subTempl.empty()) subTempl = L"Found {} {} sessions (registry):";
        const std::wstring sourceW(source, source + strlen(source));
        const std::wstring subtitle = FormatW(subTempl, {std::to_wstring(sessions.size()), sourceW});
        std::wstring caption = LngStrW(titleId);
        if (caption.empty()) caption = std::wstring(L"Import ") + sourceW + L" Sessions";
        const std::vector<size_t> sel = ShowSessionPickerDlg(owner, std::move(caption), subtitle, names);
        if (sel.empty()) return 0;
        int count = 0;
        for (size_t idx : sel) {
            bool unsupported = false;
            if (ImportSessionToIni(sessions[idx], iniFileName, unsupported, &selectedData))
                ++count;
            else if (unsupported)
                ++skippedUnsupported;
        }
        return count;
    };

    if (cmd == kCmdPickPutty) {
        imported = pickRegistrySessions(puttySessions, "PuTTY", IDS_IMP_TITLE_PUTTY);
        maybeApply();
        showFeedback("unsupported session(s)");
        return imported;
    }
    if (cmd == kCmdPickWinScp) {
        imported = pickRegistrySessions(winScpSessions, "WinSCP", IDS_IMP_TITLE_WINSCP);
        maybeApply();
        showFeedback("unsupported WinSCP session(s)");
        return imported;
    }

    auto handlePortableImport = [&](const std::vector<PortableSessionDescriptor>& sessions,
                                    UINT captionId, const char* sourceDesc) -> int {
        if (sessions.empty()) {
            WindowsUserFeedback fb(owner);
            std::wstring msgTempl = LngStrW(IDS_IMP_MSG_NOT_FOUND);
            if (msgTempl.empty()) msgTempl = L"No sessions found in {}.";
            const std::wstring descW(sourceDesc, sourceDesc + strlen(sourceDesc));
            fb.ShowMessage(WideToUtf8(FormatW(msgTempl, {descW})), "SFTP");
            return 0;
        }
        std::vector<std::string> names;
        names.reserve(sessions.size());
        for (const auto& s : sessions) names.push_back(s.displayName);
        std::wstring subTempl = LngStrW(IDS_IMP_FOUND_FILE);
        if (subTempl.empty()) subTempl = L"Found {} sessions in {}:";
        const std::wstring descW(sourceDesc, sourceDesc + strlen(sourceDesc));
        const std::wstring subtitle = FormatW(subTempl, {std::to_wstring(sessions.size()), descW});
        std::wstring captionW = LngStrW(captionId);
        if (captionW.empty()) captionW = std::wstring(L"Import ") + descW + L" Sessions";
        const std::vector<size_t> sel = ShowSessionPickerDlg(owner, std::move(captionW), subtitle, names);
        if (sel.empty()) return 0;
        int count = 0;
        for (size_t idx : sel) {
            bool unsupported = false;
            if (ImportPortableSessionToIni(sessions[idx], iniFileName, unsupported, &selectedData))
                ++count;
            else if (unsupported)
                ++skippedUnsupported;
        }
        return count;
    };

    if (cmd == kCmdImportFromWinScpIni) {
        const std::string lastDir = LoadRecentImportPath(iniFileName, "WinScpIni");
        std::string iniPath;
        if (!BrowseForIniFile(owner, "Select WinSCP.ini", lastDir.c_str(), iniPath))
            return 0;
        std::string iniDir = iniPath;
        const size_t slash = iniDir.find_last_of("\\/");
        if (slash != std::string::npos) iniDir.erase(slash);
        SaveRecentImportPaths(iniFileName, "WinScpIni", iniDir);

        std::vector<PortableSessionDescriptor> portableSessions;
        EnumeratePortableSessions(iniPath.c_str(), SessionSource::winscp, portableSessions);
        imported = handlePortableImport(portableSessions, IDS_IMP_TITLE_WINSCP, "WinSCP.ini");
        maybeApply();
        showFeedback("unsupported WinSCP session(s)");
        return imported;
    }

    if (cmd == kCmdImportFromPuttyReg) {
        const std::string lastFolder = LoadRecentImportPath(iniFileName, "PuttyFolder");
        std::string folderPath;
        if (!BrowseForFolder(owner, "Select PuTTY Portable folder", lastFolder.c_str(), folderPath))
            return 0;
        SaveRecentImportPaths(iniFileName, "PuttyFolder", folderPath);

        const std::string regFile = FindPuttyRegInFolder(folderPath);
        if (regFile.empty()) {
            WindowsUserFeedback fb(owner);
            fb.ShowMessage("putty.reg not found in the selected folder or its subfolders.", "SFTP");
            return 0;
        }
        const std::string tempIni = ConvertRegFileToTempIni(regFile);
        if (tempIni.empty()) {
            WindowsUserFeedback fb(owner);
            fb.ShowMessage("Failed to read or parse putty.reg.", "SFTP");
            return 0;
        }
        std::vector<PortableSessionDescriptor> portableSessions;
        EnumeratePortableSessions(tempIni.c_str(), SessionSource::putty, portableSessions);
        imported = handlePortableImport(portableSessions, IDS_IMP_TITLE_PUTTY_PORT, "putty.reg");
        DeleteFileA(tempIni.c_str());
        maybeApply();
        showFeedback("unsupported session(s)");
        return imported;
    }

    if (cmd == kCmdImportFromKittyFolder) {
        const std::string lastFolder = LoadRecentImportPath(iniFileName, "KittyFolder");
        std::string folderPath;
        if (!BrowseForFolder(owner, "Select KiTTY Portable folder", lastFolder.c_str(), folderPath))
            return 0;
        SaveRecentImportPaths(iniFileName, "KittyFolder", folderPath);

        const std::string sessionsFolder = FindKittySessionsFolder(folderPath);
        if (sessionsFolder.empty()) {
            WindowsUserFeedback fb(owner);
            fb.ShowMessage("Sessions folder not found in the selected KiTTY Portable directory.", "SFTP");
            return 0;
        }

        std::vector<KittySessionDescriptor> kittySessions;
        EnumerateKittyFolder(sessionsFolder, kittySessions);

        if (kittySessions.empty()) {
            WindowsUserFeedback fb(owner);
            std::wstring msgTempl = LngStrW(IDS_IMP_MSG_NOT_FOUND);
            if (msgTempl.empty()) msgTempl = L"No sessions found in {}.";
            fb.ShowMessage(WideToUtf8(FormatW(msgTempl, {L"KiTTY Portable"})), "SFTP");
            return 0;
        }

        std::vector<std::string> names;
        names.reserve(kittySessions.size());
        for (const auto& s : kittySessions) names.push_back(s.displayName);

        std::wstring subTempl = LngStrW(IDS_IMP_FOUND_FILE);
        if (subTempl.empty()) subTempl = L"Found {} sessions in {}:";
        const std::wstring subtitle = FormatW(subTempl, {std::to_wstring(kittySessions.size()), L"KiTTY Portable"});
        std::wstring captionW = LngStrW(IDS_IMP_TITLE_KITTY_PORT);
        if (captionW.empty()) captionW = L"Import KiTTY Portable Sessions";

        const std::vector<size_t> sel = ShowSessionPickerDlg(owner, std::move(captionW), subtitle, names);
        if (sel.empty()) return 0;

        for (size_t idx : sel) {
            if (ImportKittySessionToIni(kittySessions[idx], iniFileName, &selectedData))
                ++imported;
        }
        maybeApply();
        showFeedback("unsupported session(s)");
        return imported;
    }

    return 0;
}

} // namespace sftp

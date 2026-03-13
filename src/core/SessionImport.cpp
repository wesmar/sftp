#include "global.h"
#include "SessionImport.h"
#include "WindowsUserFeedback.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <commdlg.h>
#include <string>
#include <vector>

#define IMPORT_LOG(fmt, ...) SFTP_LOG("IMPORT", fmt, ##__VA_ARGS__)

namespace {

enum class SessionSource {
    putty,
    winscp,
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

void AppendSessionMenuItems(HMENU menu, UINT& nextId, const std::vector<SessionDescriptor>& sessions, std::vector<SessionDescriptor>& actions)
{
    for (const auto& session : sessions) {
        const UINT id = nextId++;
        AppendMenuA(menu, MF_STRING, id, session.displayName.c_str());
        actions.push_back(session);
    }
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

bool BrowseForIniFile(HWND owner, const char* title, std::string& outPath)
{
    char buf[MAX_PATH] = {};
    OPENFILENAMEA ofn    = {};
    ofn.lStructSize      = sizeof(ofn);
    ofn.hwndOwner        = owner;
    ofn.lpstrFilter      = "INI files (*.ini)\0*.ini\0All files (*.*)\0*.*\0";
    ofn.lpstrFile        = buf;
    ofn.nMaxFile         = MAX_PATH;
    ofn.lpstrTitle       = title;
    ofn.Flags            = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (!GetOpenFileNameA(&ofn))
        return false;
    outPath = buf;
    return true;
}

// Shows a session-picker popup for sessions enumerated from a portable ini.
// Returns imported count; updates outData/outApply for single-session import.
int ShowPortableImportMenu(HWND owner, LPCSTR iniFileName,
                           const std::vector<PortableSessionDescriptor>& sessions,
                           ImportedSessionData& outData, bool& outApply,
                           int& skippedUnsupported)
{
    constexpr UINT kCmdImportAll   = 60000;
    constexpr UINT kCmdSessionBase = 60100;

    HMENU menu = CreatePopupMenu();
    const std::string importAll = std::format("Import all ({})", sessions.size());
    AppendMenuA(menu, MF_STRING,    kCmdImportAll, importAll.c_str());
    AppendMenuA(menu, MF_SEPARATOR, 0, nullptr);

    UINT nextId = kCmdSessionBase;
    for (const auto& s : sessions)
        AppendMenuA(menu, MF_STRING, nextId++, s.displayName.c_str());

    POINT pt;
    GetCursorPos(&pt);
    const UINT cmd = TrackPopupMenu(menu,
                                    TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD | TPM_NONOTIFY,
                                    pt.x, pt.y, 0, owner, nullptr);
    DestroyMenu(menu);

    if (cmd == 0)
        return 0;

    if (cmd == kCmdImportAll)
        return ImportAllPortable(sessions, iniFileName, skippedUnsupported);

    if (cmd >= kCmdSessionBase) {
        const size_t idx = static_cast<size_t>(cmd - kCmdSessionBase);
        if (idx < sessions.size()) {
            bool unsupported = false;
            if (ImportPortableSessionToIni(sessions[idx], iniFileName, unsupported, &outData)) {
                outApply = true;
                return 1;
            }
            if (unsupported)
                ++skippedUnsupported;
        }
    }
    return 0;
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

    // Note: even with no registry sessions we still show the menu so the user
    // can use "Import from PuTTY.ini / WinSCP.ini file..." portable options.

    constexpr UINT kCmdImportAll           = 50000;
    constexpr UINT kCmdImportAllPutty      = 50001;
    constexpr UINT kCmdImportAllWinScp     = 50002;
    constexpr UINT kCmdImportFromPuttyIni  = 50003;
    constexpr UINT kCmdImportFromWinScpIni = 50004;
    constexpr UINT kCmdSessionBase         = 50100;

    HMENU menu = CreatePopupMenu();
    HMENU puttyMenu = CreatePopupMenu();
    HMENU winscpMenu = CreatePopupMenu();

    if (hasPutty) {
        const std::string puttyAll = std::format("Import all ({})", puttySessions.size());
        AppendMenuA(puttyMenu, MF_STRING, kCmdImportAllPutty, puttyAll.c_str());
        AppendMenuA(puttyMenu, MF_SEPARATOR, 0, nullptr);
    }
    if (hasWinScp) {
        const std::string winscpAll = std::format("Import all ({})", winScpSessions.size());
        AppendMenuA(winscpMenu, MF_STRING, kCmdImportAllWinScp, winscpAll.c_str());
        AppendMenuA(winscpMenu, MF_SEPARATOR, 0, nullptr);
    }

    std::vector<SessionDescriptor> sessionActions;
    UINT nextId = kCmdSessionBase;
    if (hasPutty)
        AppendSessionMenuItems(puttyMenu, nextId, puttySessions, sessionActions);
    if (hasWinScp)
        AppendSessionMenuItems(winscpMenu, nextId, winScpSessions, sessionActions);

    if (hasPutty) {
        const std::string puttyLabel = std::format("PuTTY ({})", puttySessions.size());
        AppendMenuA(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(puttyMenu), puttyLabel.c_str());
    }
    if (hasWinScp) {
        const std::string winscpLabel = std::format("WinSCP ({})", winScpSessions.size());
        AppendMenuA(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(winscpMenu), winscpLabel.c_str());
    }
    if (hasPutty && hasWinScp) {
        AppendMenuA(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuA(menu, MF_STRING, kCmdImportAll, "Import all (PuTTY + WinSCP)");
    }

    // Portable file-based import (always available)
    AppendMenuA(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(menu, MF_STRING, kCmdImportFromPuttyIni,  "Import from PuTTY.ini file...");
    AppendMenuA(menu, MF_STRING, kCmdImportFromWinScpIni, "Import from WinSCP.ini file...");

    POINT pt;
    GetCursorPos(&pt);
    const UINT cmd = TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD | TPM_NONOTIFY,
                                    pt.x, pt.y, 0, owner, nullptr);

    int imported = 0;
    int skippedUnsupported = 0;
    ImportedSessionData selectedData;
    bool applySelectedToCurrent = false;

    if (cmd == kCmdImportAll) {
        imported += ImportAll(puttySessions, iniFileName, skippedUnsupported);
        imported += ImportAll(winScpSessions, iniFileName, skippedUnsupported);
    } else if (cmd == kCmdImportAllPutty) {
        imported += ImportAll(puttySessions, iniFileName, skippedUnsupported);
    } else if (cmd == kCmdImportAllWinScp) {
        imported += ImportAll(winScpSessions, iniFileName, skippedUnsupported);
    } else if (cmd >= kCmdSessionBase) {
        const size_t idx = static_cast<size_t>(cmd - kCmdSessionBase);
        if (idx < sessionActions.size()) {
            bool unsupported = false;
            if (ImportSessionToIni(sessionActions[idx], iniFileName, unsupported, &selectedData)) {
                imported = 1;
                applySelectedToCurrent = true;
            } else if (unsupported)
                skippedUnsupported = 1;
        }
    }

    DestroyMenu(menu);

    // Handle portable import after the main menu is gone (needs file dialog + submenu)
    if (cmd == kCmdImportFromPuttyIni || cmd == kCmdImportFromWinScpIni) {
        const bool isPutty = (cmd == kCmdImportFromPuttyIni);
        const char* dlgTitle = isPutty ? "Select PuTTY.ini" : "Select WinSCP.ini";
        std::string iniPath;
        if (!BrowseForIniFile(owner, dlgTitle, iniPath))
            return 0;

        const SessionSource portableSource = isPutty ? SessionSource::putty : SessionSource::winscp;
        std::vector<PortableSessionDescriptor> portableSessions;
        EnumeratePortableSessions(iniPath.c_str(), portableSource, portableSessions);

        if (portableSessions.empty()) {
            WindowsUserFeedback tempFeedback(owner);
            tempFeedback.ShowMessage(
                std::format("No {} sessions found in the selected file.", isPutty ? "PuTTY" : "WinSCP"),
                "SFTP");
            return 0;
        }

        imported = ShowPortableImportMenu(owner, iniFileName, portableSessions,
                                          selectedData, applySelectedToCurrent,
                                          skippedUnsupported);

        // Report results and return early (duplicate feedback below would fire again)
        if (applyTo && applySelectedToCurrent && imported > 0) {
            applyTo->server    = selectedData.server;
            applyTo->user      = selectedData.userName;
            applyTo->useagent  = selectedData.useagent;
            applyTo->pubkeyfile  = selectedData.pubkeyfile;
            applyTo->privkeyfile = selectedData.privkeyfile;
        }
        if (importedSessionName && importedSessionNameSize > 0 && !selectedData.sectionName.empty())
            strlcpy(importedSessionName, selectedData.sectionName.c_str(), importedSessionNameSize - 1);

        WindowsUserFeedback tempFeedback(owner);
        if (imported > 0 && skippedUnsupported > 0)
            tempFeedback.ShowMessage(std::format("Imported {} session(s).\nSkipped {} unsupported session(s).", imported, skippedUnsupported), "SFTP");
        else if (imported > 0)
            tempFeedback.ShowMessage(std::format("Imported {} session(s).", imported), "SFTP");
        else if (skippedUnsupported > 0)
            tempFeedback.ShowMessage("No sessions imported (unsupported protocol type).", "SFTP");
        else
            tempFeedback.ShowMessage("No sessions imported.", "SFTP");
        return imported;
    }

    if (cmd == 0)
        return 0;

    if (applyTo && applySelectedToCurrent && imported > 0) {
        applyTo->server = selectedData.server;
        applyTo->user = selectedData.userName;
        applyTo->useagent = selectedData.useagent;
        applyTo->pubkeyfile = selectedData.pubkeyfile;
        applyTo->privkeyfile = selectedData.privkeyfile;
    }
    if (importedSessionName && importedSessionNameSize > 0 && !selectedData.sectionName.empty())
        strlcpy(importedSessionName, selectedData.sectionName.c_str(), importedSessionNameSize - 1);

    WindowsUserFeedback tempFeedback(owner);
    if (imported > 0 && skippedUnsupported > 0) {
        tempFeedback.ShowMessage(std::format("Imported {} session(s).\nSkipped {} unsupported WinSCP session(s).", imported, skippedUnsupported), "SFTP");
    } else if (imported > 0) {
        tempFeedback.ShowMessage(std::format("Imported {} session(s).", imported), "SFTP");
    } else if (skippedUnsupported > 0) {
        tempFeedback.ShowMessage("No sessions imported (unsupported protocol type).", "SFTP");
    } else {
        tempFeedback.ShowMessage("No sessions imported.", "SFTP");
    }

    return imported;
}

} // namespace sftp

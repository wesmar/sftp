#include "global.h"
#include <windows.h>
#include <algorithm>
#include <array>
#include <vector>
#include <format>
#include <sstream>
#include <string_view>
#include "SftpClient.h"
#include "SftpInternal.h"
#include "ConnectionDialog.h"
#include "ProfileSettings.h"
#include "PasswordCrypto.h"
#include "PluginEntryPoints.h"

// Which proxy records exist, in order. Numbering may have holes: deleting a
// record leaves the ones above it where they are, so that a number stays a
// stable identity for the sessions and imports that point at it. Counting up
// until a number is missing would stop at the first hole, so the sections
// themselves are what gets read. Record one is `[proxy]`, the rest `[proxyN]`.
std::vector<int> EnumerateProxyNumbers(LPCSTR iniFileName)
{
    std::vector<int> numbers;
    std::array<char, 8192> sections{};
    GetPrivateProfileSectionNamesA(sections.data(),
                                   static_cast<DWORD>(sections.size() - 1), iniFileName);
    for (const char* p = sections.data(); *p; p += strlen(p) + 1) {
        if (_strnicmp(p, "proxy", 5) != 0)
            continue;
        const char* tail = p + 5;
        if (!*tail) {
            numbers.push_back(1);
            continue;
        }
        // Only digits follow the prefix in a record name; `proxyjump` and the
        // like are other people's sections.
        int n = 0;
        for (const char* d = tail; *d; ++d) {
            if (*d < '0' || *d > '9') { n = 0; break; }
            n = n * 10 + (*d - '0');
        }
        if (n > 1)
            numbers.push_back(n);
    }
    std::sort(numbers.begin(), numbers.end());
    return numbers;
}

// The number a new proxy record may take. It has to clear two things, not one:
// every record that exists, and every number a session still points at. Stale
// references outlive their record — a session keeps `proxynr=1` long after
// `[proxy]` is gone — and handing that number to a new record would quietly
// route those sessions through it.
int NextFreeProxyNr(LPCSTR iniFileName)
{
    const std::vector<int> existing = EnumerateProxyNumbers(iniFileName);
    int highest = existing.empty() ? 0 : existing.back();

    std::array<char, wdirtypemax> name{};
    SERVERHANDLE hdl = FindFirstServer(name.data(), name.size() - 1);
    while (hdl) {
        const int referenced = static_cast<int>(GetPrivateProfileInt(name.data(), "proxynr", 0, iniFileName));
        if (referenced > highest)
            highest = referenced;
        hdl = FindNextServer(hdl, name.data(), name.size() - 1);
    }
    return highest + 1;
}

// The record that already describes this proxy, or 0 when none does. Identity
// is the route: kind, server and user name. The password takes no part —
// passwords do not travel between machines, so two records that differ only in
// whether one is stored describe the same proxy.
int FindMatchingProxyNr(int proxytype, const std::string& server,
                        const std::string& user, LPCSTR iniFileName)
{
    for (const int proxynr : EnumerateProxyNumbers(iniFileName)) {
        tConnectSettings data;
        if (!LoadProxySettingsFromNr(proxynr, &data, iniFileName))
            continue;
        if (static_cast<int>(data.proxytype) == proxytype &&
            _stricmp(data.proxyserver.c_str(), server.c_str()) == 0 &&
            _stricmp(data.proxyuser.c_str(), user.c_str()) == 0)
        {
            return proxynr;
        }
    }
    return 0;
}

namespace {

// One INI value, whole however long: GetPrivateProfileString reports a value
// that did not fit by returning size - 1, and the buffer then grows.
std::string ReadIniString(LPCSTR section, LPCSTR key, LPCSTR fallback, LPCSTR iniFileName)
{
    std::vector<char> buf(MAX_PATH);
    for (;;) {
        const DWORD n = GetPrivateProfileStringA(section, key, fallback, buf.data(),
                                                 static_cast<DWORD>(buf.size()), iniFileName);
        if (n + 1 < buf.size() || buf.size() >= 64 * 1024)
            return std::string(buf.data(), n);
        buf.resize(buf.size() * 2);
    }
}

// A stored password, decrypted; empty when none is stored.
std::string ReadIniPassword(LPCSTR section, LPCSTR key, LPCSTR iniFileName)
{
    const std::string stored = ReadIniString(section, key, "", iniFileName);
    if (stored == "!") // kept by Total Commander's password manager
        return CryptProc ? std::string(password_crypto::kMasterPasswordMarker) : std::string();
    return stored.empty() ? std::string() : password_crypto::Unprotect(stored);
}

} // namespace

bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName)
{
    if (proxynr > 0) {
        const std::string proxyentry = proxynr > 1 ? std::format("proxy{}", proxynr) : "proxy";
        ConnectResults->proxytype = sftp::Proxy::notused;
        const int type = static_cast<int>(GetPrivateProfileIntA(proxyentry.c_str(), "proxytype", -1, iniFileName));
        if (type >= 0)
            ConnectResults->proxytype = static_cast<sftp::Proxy>(type);
        ConnectResults->proxyserver = ReadIniString(proxyentry.c_str(), "proxyserver", "", iniFileName);
        ConnectResults->proxyuser = ReadIniString(proxyentry.c_str(), "proxyuser", "", iniFileName);
        ConnectResults->proxypassword = ReadIniPassword(proxyentry.c_str(), "proxypassword", iniFileName);
        return (type != -1 || proxynr == 1);
    } else {
        ConnectResults->proxytype = sftp::Proxy::notused;
        ConnectResults->proxyserver.clear();
        ConnectResults->proxyuser.clear();
        ConnectResults->proxypassword.clear();
        return false;
    }
}

bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults, LPCSTR iniFileName)
{
    ConnectResults->DisplayName = DisplayName ? DisplayName : "";
    ConnectResults->IniFileName = iniFileName ? iniFileName : "";
    ConnectResults->server = ReadIniString(DisplayName, "server", "", iniFileName);
    ConnectResults->protocoltype=GetPrivateProfileInt(DisplayName, "protocol", 0, iniFileName);
    ConnectResults->transfermode = GetPrivateProfileInt(DisplayName, "transfermode", 0, iniFileName);
    if (ConnectResults->transfermode < 0 || ConnectResults->transfermode > 3)
        ConnectResults->transfermode = 0;
    ConnectResults->user = ReadIniString(DisplayName, "user", "", iniFileName);
    ConnectResults->savedfingerprint = ReadIniString(DisplayName, "fingerprint", "", iniFileName);
    ConnectResults->pubkeyfile = ReadIniString(DisplayName, "pubkeyfile", "", iniFileName);
    ConnectResults->privkeyfile = ReadIniString(DisplayName, "privkeyfile", "", iniFileName);
    ConnectResults->useagent = GetPrivateProfileInt(DisplayName, "useagent", 0, iniFileName) != 0;

    ConnectResults->filemod = strtol(ReadIniString(DisplayName, "filemod", "644", iniFileName).c_str(), nullptr, 8);
    ConnectResults->dirmod = strtol(ReadIniString(DisplayName, "dirmod", "755", iniFileName).c_str(), nullptr, 8);

    ConnectResults->compressed = GetPrivateProfileInt(DisplayName, "compression", 0, iniFileName) != 0;
    ConnectResults->scpfordata = GetPrivateProfileInt(DisplayName, "scpfordata", 0, iniFileName) != 0;
    ConnectResults->scponly = GetPrivateProfileInt(DisplayName, "scponly", 0, iniFileName) != 0;
    if (ConnectResults->scponly)
        ConnectResults->scpfordata = true;
    ConnectResults->shell_transfer_dd = GetPrivateProfileInt(DisplayName, "shelltransfer", 0, iniFileName) != 0;
    ConnectResults->shell_transfer_force =
        GetPrivateProfileInt(DisplayName, "shelltransferforce",
                             ConnectResults->shell_transfer_dd ? 1 : 0,
                             iniFileName) != 0;
    ConnectResults->shell_dd_b64only  = false;
    ConnectResults->php_http_mode = GetPrivateProfileInt(DisplayName, "phphttpmode", 0, iniFileName);
    if (ConnectResults->php_http_mode < 0 || ConnectResults->php_http_mode > 2)
        ConnectResults->php_http_mode = 0;
    ConnectResults->php_chunk_mib = GetPrivateProfileInt(DisplayName, "phpchunkmb", 0, iniFileName);
    if (!(ConnectResults->php_chunk_mib == 0 || ConnectResults->php_chunk_mib == 1 ||
          ConnectResults->php_chunk_mib == 2 || ConnectResults->php_chunk_mib == 4 ||
          ConnectResults->php_chunk_mib == 8 || ConnectResults->php_chunk_mib == 16 ||
          ConnectResults->php_chunk_mib == 32 || ConnectResults->php_chunk_mib == 64))
        ConnectResults->php_chunk_mib = 0;
    ConnectResults->php_recommended_chunk_mib = 0;
    ConnectResults->php_tar = GetPrivateProfileInt(DisplayName, "phptar", 0, iniFileName) != 0;
    ConnectResults->lan_pair_role = GetPrivateProfileInt(DisplayName, "lanpairrole", 0, iniFileName);
    if (ConnectResults->lan_pair_role < 0 || ConnectResults->lan_pair_role > 2)
        ConnectResults->lan_pair_role = 0;
    ConnectResults->lan_pair_peer = ReadIniString(DisplayName, "lanpairpeer", "", iniFileName);
    ConnectResults->lan_pair_timeout_min = GetPrivateProfileInt(DisplayName, "lanpairtimeout", 0, iniFileName);
    if (ConnectResults->lan_pair_timeout_min < 0)
        ConnectResults->lan_pair_timeout_min = 0;
    ConnectResults->lan_pair_trusted_installer = GetPrivateProfileInt(DisplayName, "lanparti", 0, iniFileName) != 0;
    ConnectResults->trycustomlistcommand = 2;

    ConnectResults->detailedlog = GetPrivateProfileInt(DisplayName, "detailedlog", 0, iniFileName) != 0;
    // Tri-state settings (-1 auto, 0, 1); GetPrivateProfileInt returns the
    // default -1 as a UINT, so it goes through int first.
    ConnectResults->utf8names = static_cast<char>(static_cast<int>(GetPrivateProfileIntA(DisplayName, "utf8", -1, iniFileName)));
    ConnectResults->codepage = static_cast<int>(GetPrivateProfileIntA(DisplayName, "codepage", 0, iniFileName));
    ConnectResults->unixlinebreaks = static_cast<char>(static_cast<int>(GetPrivateProfileIntA(DisplayName, "unixlinebreaks", -1, iniFileName)));
    ConnectResults->scpserver64bit = static_cast<int>(GetPrivateProfileIntA(DisplayName, "largefilesupport", -1, iniFileName));
    ConnectResults->password.clear();
    // "!" stands for a password kept in Total Commander's password manager.
    if (ConnectResults->useagent) {
        if (ReadIniString(DisplayName, "password", "", iniFileName) == "!")
            ConnectResults->password = "\001";
    } else {
        ConnectResults->password = ReadIniPassword(DisplayName, "password", iniFileName);
    }
    ConnectResults->proxynr = GetPrivateProfileInt(DisplayName, "proxynr", 0, iniFileName);

    LoadProxySettingsFromNr(ConnectResults->proxynr, ConnectResults, iniFileName);

    // -----------------------------------------------------------------------
    // Jump host (ProxyJump) settings
    // -----------------------------------------------------------------------
    ConnectResults->use_jump_host = GetPrivateProfileInt(DisplayName, "usejumphost", 0, iniFileName) != 0;
    ConnectResults->jump_host        = ReadIniString(DisplayName, "jumphost", "", iniFileName);
    ConnectResults->jump_user        = ReadIniString(DisplayName, "jumpuser", "", iniFileName);
    ConnectResults->jump_pubkeyfile  = ReadIniString(DisplayName, "jumppubkeyfile", "", iniFileName);
    ConnectResults->jump_privkeyfile = ReadIniString(DisplayName, "jumpprivkeyfile", "", iniFileName);
    ConnectResults->jump_fingerprint = ReadIniString(DisplayName, "jumpfingerprint", "", iniFileName);
    ConnectResults->jump_port        = static_cast<unsigned short>(GetPrivateProfileIntA(DisplayName, "jumpport", 22, iniFileName));
    ConnectResults->jump_useagent    = GetPrivateProfileIntA(DisplayName, "jumpuseagent", 0, iniFileName) != 0;
    ConnectResults->jump_session_ref = ReadIniString(DisplayName, "jumpsessionref", "", iniFileName);
    ConnectResults->jump_password    = ReadIniPassword(DisplayName, "jumppassword", iniFileName);

    ConnectResults->neednewchannel = false;
    ConnectResults->connectsendcommand = ReadIniString(DisplayName, "sendcommand", "", iniFileName);
    ConnectResults->sendcommandmode = static_cast<int>(GetPrivateProfileIntA(DisplayName, "sendcommandmode", 0, iniFileName));
    ConnectResults->sftpservercommand = ReadIniString(DisplayName, "sftpservercommand", "", iniFileName);
    return !ConnectResults->server.empty();
}


void UpdateJumpRefsOnSessionRename(LPCSTR oldName, LPCSTR newName, LPCSTR iniFileName)
{
    if (!oldName || !oldName[0] || !iniFileName || !iniFileName[0])
        return;

    // GetPrivateProfileSectionNames returns section names as a
    // double-null-terminated list. 65535 is the documented hard limit.
    std::array<char, 65535> sectionList{};
    GetPrivateProfileSectionNamesA(sectionList.data(),
                                   static_cast<DWORD>(sectionList.size()),
                                   iniFileName);

    char* p = sectionList.data();
    while (p[0]) {
        std::array<char, MAX_PATH> currentRef{};
        GetPrivateProfileStringA(p, "jumpsessionref", "",
                                 currentRef.data(),
                                 static_cast<DWORD>(currentRef.size()),
                                 iniFileName);
        if (currentRef[0] && _stricmp(currentRef.data(), oldName) == 0) {
            // Exact match — rewrite (or clear if newName is null/empty).
            if (newName && newName[0])
                WritePrivateProfileStringA(p, "jumpsessionref", newName, iniFileName);
            else
                WritePrivateProfileStringA(p, "jumpsessionref", nullptr, iniFileName);
        }
        p += strlen(p) + 1;
    }
}

void UpdateJumpRefsOnFolderRename(LPCSTR oldPrefix, LPCSTR newPrefix, LPCSTR iniFileName)
{
    if (!oldPrefix || !oldPrefix[0] || !newPrefix || !newPrefix[0] ||
        !iniFileName || !iniFileName[0])
        return;

    const std::string oldNeedle = std::string(oldPrefix) + "/";
    const std::string newReplacement = std::string(newPrefix) + "/";

    std::array<char, 65535> sectionList{};
    GetPrivateProfileSectionNamesA(sectionList.data(),
                                   static_cast<DWORD>(sectionList.size()),
                                   iniFileName);

    char* p = sectionList.data();
    while (p[0]) {
        std::array<char, MAX_PATH> currentRef{};
        GetPrivateProfileStringA(p, "jumpsessionref", "",
                                 currentRef.data(),
                                 static_cast<DWORD>(currentRef.size()),
                                 iniFileName);
        const size_t reflen = strlen(currentRef.data());
        if (reflen > oldNeedle.size() &&
            _strnicmp(currentRef.data(), oldNeedle.c_str(), oldNeedle.size()) == 0)
        {
            std::string updated = newReplacement;
            updated.append(currentRef.data() + oldNeedle.size());
            WritePrivateProfileStringA(p, "jumpsessionref", updated.c_str(), iniFileName);
        }
        p += strlen(p) + 1;
    }
}

// ===========================================================================
// Import custom paths — [Imports] section
// ===========================================================================

namespace {

constexpr const char* kImportsSection = "Imports";

// Strip trailing `\` and `/` so equivalent paths normalise before dedup and
// remove-match comparisons.
std::string NormaliseImportPath(std::string_view s) noexcept
{
    while (!s.empty() && (s.back() == '\\' || s.back() == '/'))
        s.remove_suffix(1);
    return std::string(s);
}

// Split "a|b|c" into {"a","b","c"} (empty segments discarded, whitespace
// preserved — folder names may contain them). Accepts both `|` (current)
// and `;` (older stored form) as separators so a pre-existing INI value
// migrates transparently on the next save; `|` is illegal in Windows paths
// while `;` is not, so `|` is the only fully safe choice going forward.
std::vector<std::string> SplitByPipe(std::string_view value)
{
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= value.size()) {
        const size_t sep = value.find_first_of("|;", start);
        const size_t end = (sep == std::string_view::npos) ? value.size() : sep;
        if (end > start)
            out.emplace_back(value.substr(start, end - start));
        if (sep == std::string_view::npos)
            break;
        start = sep + 1;
    }
    return out;
}

std::string JoinByPipe(const std::vector<std::string>& parts)
{
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out.push_back('|');
        out.append(parts[i]);
    }
    return out;
}

std::string PathsKey(LPCSTR sourceId)
{
    std::string key(sourceId ? sourceId : "");
    key.append(".custom_paths");
    return key;
}

}  // namespace

std::vector<std::string> LoadImportCustomPaths(LPCSTR sourceId, LPCSTR iniFileName)
{
    if (!sourceId || !sourceId[0] || !iniFileName || !iniFileName[0])
        return {};
    // Custom paths list can be long; oversize the buffer generously vs
    // MAX_PATH so tens of concatenated paths fit.
    std::array<char, 8192> buf{};
    GetPrivateProfileStringA(kImportsSection, PathsKey(sourceId).c_str(), "",
                             buf.data(), static_cast<DWORD>(buf.size() - 1),
                             iniFileName);
    return SplitByPipe(buf.data());
}

bool SaveImportCustomPath(LPCSTR sourceId, LPCSTR path, LPCSTR iniFileName)
{
    if (!sourceId || !sourceId[0] || !path || !path[0] ||
        !iniFileName || !iniFileName[0])
        return false;

    const std::string normalized = NormaliseImportPath(path);
    if (normalized.empty())
        return false;

    std::vector<std::string> paths = LoadImportCustomPaths(sourceId, iniFileName);

    // Case-insensitive dedup — Windows paths compare that way.
    const auto exists = std::any_of(paths.begin(), paths.end(),
        [&](const std::string& p) {
            return _stricmp(NormaliseImportPath(p).c_str(), normalized.c_str()) == 0;
        });
    if (exists)
        return true;  // Already registered; treat as successful no-op.

    paths.push_back(normalized);
    const std::string joined = JoinByPipe(paths);
    return WritePrivateProfileStringA(kImportsSection,
        PathsKey(sourceId).c_str(),
        joined.empty() ? nullptr : joined.c_str(),
        iniFileName) != 0;
}

bool RemoveImportCustomPath(LPCSTR sourceId, LPCSTR path, LPCSTR iniFileName)
{
    if (!sourceId || !sourceId[0] || !path || !path[0] ||
        !iniFileName || !iniFileName[0])
        return false;

    const std::string normalized = NormaliseImportPath(path);
    std::vector<std::string> paths = LoadImportCustomPaths(sourceId, iniFileName);

    const auto before = paths.size();
    paths.erase(std::remove_if(paths.begin(), paths.end(),
        [&](const std::string& p) {
            return _stricmp(NormaliseImportPath(p).c_str(), normalized.c_str()) == 0;
        }), paths.end());
    if (paths.size() == before)
        return false;  // Nothing removed.

    const std::string joined = JoinByPipe(paths);
    return WritePrivateProfileStringA(kImportsSection,
        PathsKey(sourceId).c_str(),
        joined.empty() ? nullptr : joined.c_str(),
        iniFileName) != 0;
}

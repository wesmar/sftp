#include "WinScpAdapter.h"
#include "SftpClient.h"
#include "global.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "ImportIoUtil.h"

#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

namespace sftp {

namespace {

// Registry root the install-mode WinSCP writes to. Every session key sits
// under HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\<url-encoded name>.
constexpr const char* kWinScpSessionsRoot =
    "Software\\Martin Prikryl\\WinSCP 2\\Sessions";

// Portable WinSCP.ini prefixes session names with this literal.
constexpr const char* kIniSessionsPrefix = "Sessions\\";

// WinSCP MungeStr charset — every byte in this set is percent-encoded on
// disk (registry subkey name or INI section suffix):
//   0x00..0x1F                     control bytes
//   0x7F..0xFF                     DEL and every non-ASCII byte (so UTF-8
//                                  bytes in international session names
//                                  round-trip as %XX pairs)
//   ' '                            space (visible as %20 in "Default%20Settings")
//   '%'                            self-escape so UrlDecode round-trips
//   '\\'                           registry subkey separator
//   '/'                            folder separator inside a workspace path
//   '*' '?' '"' '<' '>' '|'        NTFS-illegal filename chars
//   leading '.'                    registry subkey rule
// Anything outside the set (printable ASCII except the above) passes through.
std::string UrlEncode(const std::string& raw)
{
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(raw[i]);
        const bool needsEscape =
            ch < 0x20 || ch >= 0x7F ||
            ch == ' '  || ch == '%'  || ch == '\\' || ch == '/' ||
            ch == '*'  || ch == '?'  || ch == '"'  ||
            ch == '<'  || ch == '>'  || ch == '|'  ||
            (i == 0 && ch == '.');
        if (!needsEscape) {
            out.push_back(static_cast<char>(ch));
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", ch);
            out.append(buf);
        }
    }
    return out;
}

// GetPrivateProfileString wrapper that returns "" when the key is missing
// (Win32 default_value semantics) so callers can test empty-string as absent.
std::string ReadIniString(const std::string& iniPath, const std::string& section,
                          const char* key)
{
    std::array<char, 4096> buf{};
    GetPrivateProfileStringA(section.c_str(), key, "",
        buf.data(), static_cast<DWORD>(buf.size() - 1),
        iniPath.c_str());
    return std::string(buf.data());
}

// GetPrivateProfileInt with default -1 so callers can distinguish "absent"
// from "present and zero".
int ReadIniDword(const std::string& iniPath, const std::string& section,
                  const char* key)
{
    return GetPrivateProfileIntA(section.c_str(), key, -1, iniPath.c_str());
}

// FSProtocol numeric enum stored in WinSCP session data:
//   0 = SCP-only     — SCP transport, no SFTP fallback
//   1 = SFTP         — SFTP with SCP fallback if the server rejects the subsystem
//   2 = SFTP-only    — SFTP transport only
//   5 = FTP          — plain FTP or FTPS (not supported by this plugin)
//   6 = WebDAV       — not supported
//   7 = S3           — not supported
// Absent value is treated as SFTP (WinSCP's default when the New Site dialog
// is used without touching advanced options).
enum class FsProtoResult { UseSftp, UseScp, Unsupported };

FsProtoResult ClassifyFsProto(int fsProto) noexcept
{
    switch (fsProto) {
        case 0:  return FsProtoResult::UseScp;   // SCP-only
        case 1:  return FsProtoResult::UseSftp;  // SFTP with SCP fallback
        case 2:  return FsProtoResult::UseSftp;  // SFTP-only
        default: return FsProtoResult::Unsupported;  // FTP / WebDAV / S3 / future
    }
}

}  // namespace

bool WinScpAdapter::DetectStandard() const noexcept
{
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, kWinScpSessionsRoot,
                             0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS) return false;
    RegCloseKey(key);
    return true;
}

std::string WinScpAdapter::ChangeStamp() const
{
    return RegistryChangeStamp(kWinScpSessionsRoot);
}

std::string WinScpAdapter::CustomPathStamp(const std::string& path) const
{
    return FileChangeStamp({ AnsiPathToWide(path) });
}

EnumerationResult WinScpAdapter::EnumerateStandard()
{
    EnumerationResult r;

    HKEY root = nullptr;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, kWinScpSessionsRoot,
                             0, KEY_READ, &root);
    if (rc != ERROR_SUCCESS) {
        SFTP_LOG("WINSCP", "EnumerateStandard: sessions root open failed rc=%ld", rc);
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    DWORD index = 0;
    int filtered = 0;
    for (;;) {
        std::array<char, 512> nameBuf{};
        DWORD nameLen = static_cast<DWORD>(nameBuf.size());
        rc = RegEnumKeyExA(root, index, nameBuf.data(), &nameLen,
                            nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        ++index;
        if (rc != ERROR_SUCCESS) continue;

        // Skip well-known non-session subkeys under Sessions\:
        //   Default Settings / Default%20Settings — template fallbacks
        //   Workspaces                              — per-workspace window layout
        if (_stricmp(nameBuf.data(), "Default%20Settings") == 0 ||
            _stricmp(nameBuf.data(), "Default Settings")   == 0 ||
            _stricmp(nameBuf.data(), "Workspaces")         == 0) { ++filtered; continue; }

        ExternalSessionEntry e;
        e.displayName  = PuttyUrlDecode(std::string(nameBuf.data(), nameLen));
        e.sourceOrigin = "standard";
        r.sessions.push_back(std::move(e));
    }
    RegCloseKey(root);
    SFTP_LOG("WINSCP", "EnumerateStandard done: sessions=%zu filtered=%d",
             r.sessions.size(), filtered);

    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

EnumerationResult WinScpAdapter::EnumerateCustomPath(const std::string& path)
{
    EnumerationResult r;

    // Sanity — the picker should already have filtered to `WinSCP.ini`,
    // but reject unreadable paths (missing file, protected folder)
    // upfront so the channel reports Unreachable rather than the caller
    // getting a mysterious OkEmpty.
    const DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    // Enumerate every section name in the INI, keep only those matching
    // "Sessions\<name>". GetPrivateProfileSectionNames returns a
    // double-NUL-terminated block; ~64 KB is enough for a portable
    // config with hundreds of sessions.
    std::array<char, 65536> sectBuf{};
    const DWORD gotLen = GetPrivateProfileSectionNamesA(
        sectBuf.data(),
        static_cast<DWORD>(sectBuf.size() - 1),
        path.c_str());
    if (gotLen == 0) {
        r.status = EnumerationStatus::OkEmpty;
        return r;
    }

    const size_t prefixLen = std::strlen(kIniSessionsPrefix);
    const char* p = sectBuf.data();
    while (*p) {
        const std::string section(p);
        p += section.size() + 1;

        if (section.size() <= prefixLen) continue;
        if (_strnicmp(section.c_str(), kIniSessionsPrefix, prefixLen) != 0)
            continue;

        const std::string keyName = section.substr(prefixLen);
        if (keyName.empty()) continue;
        // Any remaining `\` inside the tail means a nested subsection like
        // `Sessions\Workspaces\<name>\<row>` — WinSCP stores per-workspace
        // window layout there, never a real session.
        if (keyName.find('\\') != std::string::npos) continue;
        if (_stricmp(keyName.c_str(), "Default Settings") == 0 ||
            _stricmp(keyName.c_str(), "Default%20Settings") == 0)
            continue;

        ExternalSessionEntry e;
        e.displayName  = PuttyUrlDecode(keyName);
        e.sourceOrigin = path;
        r.sessions.push_back(std::move(e));
    }

    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

bool WinScpAdapter::LoadSettings(const ExternalSessionEntry& entry,
                                  pConnectSettings out,
                                  SessionDependency* dependency)
{
    if (!out) return false;

    const std::string subKeyName = UrlEncode(entry.displayName);
    SFTP_LOG("WINSCP", "LoadSettings display='%s'", entry.displayName.c_str());

    std::string host, userName, keyFile;
    DWORD port = 0, useAgent = 0, fsProtoRaw = 0;
    bool  hasPort = false, hasFsProto = false;
    // WinSCP's tunnel is an SSH session in front of the host, which is what
    // the plugin's jump host is.
    std::string tunnelHost, tunnelUser, tunnelKey;
    DWORD tunnel = 0, tunnelPort = 0, proxyMethod = 0;

    if (entry.sourceOrigin == "standard") {
        const std::string subKey =
            std::string(kWinScpSessionsRoot) + "\\" + subKeyName;
        HKEY key = nullptr;
        LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, subKey.c_str(),
                                 0, KEY_READ, &key);
        if (rc != ERROR_SUCCESS) return false;

        if (!ReadRegString(key, "HostName", host) || host.empty()) {
            RegCloseKey(key);
            return false;
        }
        host = PuttyUrlDecode(host);

        hasPort = ReadRegDword(key, "PortNumber", port);

        if (ReadRegString(key, "UserName", userName))
            userName = PuttyUrlDecode(userName);

        if (!ReadRegDword(key, "AgentFwd", useAgent))
            ReadRegDword(key, "AuthAgent", useAgent);

        if (ReadRegString(key, "PublicKeyFile", keyFile))
            keyFile = ExpandEnvA(PuttyUrlDecode(keyFile));

        hasFsProto = ReadRegDword(key, "FSProtocol", fsProtoRaw);

        // WinSCP omits every key sitting at its default, so the presence of a
        // non-zero value is the whole signal: `Tunnel` for an SSH session in
        // front of the host, `ProxyMethod` for a proxy.
        ReadRegDword(key, "Tunnel", tunnel);
        ReadRegDword(key, "ProxyMethod", proxyMethod);
        if (tunnel != 0) {
            ReadRegString(key, "TunnelHostName", tunnelHost);
            ReadRegDword(key, "TunnelPortNumber", tunnelPort);
            ReadRegString(key, "TunnelUserName", tunnelUser);
            ReadRegString(key, "TunnelPublicKeyFile", tunnelKey);
        }
        // A tunnel is dealt with below, together with any proxy beside it.
        if (dependency && tunnel == 0 && proxyMethod != 0) {
            std::string proxyHost, proxyUser;
            DWORD proxyPort = 0;
            ReadRegString(key, "ProxyHost", proxyHost);
            ReadRegDword(key, "ProxyPort", proxyPort);
            ReadRegString(key, "ProxyUsername", proxyUser);
            proxyHost = PuttyUrlDecode(proxyHost);
            dependency->kind   = SessionDependency::Kind::Proxy;
            dependency->detail = proxyHost;
            DescribePuttyProxy(proxyMethod, proxyHost, proxyPort,
                               PuttyUrlDecode(proxyUser), *dependency);
        }
        RegCloseKey(key);
    } else {
        // Portable channel: sourceOrigin is the literal WinSCP.ini path.
        // Section name is `Sessions\<encoded>`.
        const std::string section = std::string(kIniSessionsPrefix) + subKeyName;
        host = PuttyUrlDecode(ReadIniString(entry.sourceOrigin, section, "HostName"));
        if (host.empty()) return false;

        const int portRaw = ReadIniDword(entry.sourceOrigin, section, "PortNumber");
        if (portRaw >= 0) { port = static_cast<DWORD>(portRaw); hasPort = true; }

        userName = PuttyUrlDecode(ReadIniString(entry.sourceOrigin, section, "UserName"));

        const int agentRaw = ReadIniDword(entry.sourceOrigin, section, "AgentFwd");
        if (agentRaw >= 0) useAgent = static_cast<DWORD>(agentRaw);
        else {
            const int auth2 = ReadIniDword(entry.sourceOrigin, section, "AuthAgent");
            if (auth2 >= 0) useAgent = static_cast<DWORD>(auth2);
        }

        keyFile = ExpandEnvA(PuttyUrlDecode(ReadIniString(entry.sourceOrigin, section, "PublicKeyFile")));

        const int fsRaw = ReadIniDword(entry.sourceOrigin, section, "FSProtocol");
        if (fsRaw >= 0) { fsProtoRaw = static_cast<DWORD>(fsRaw); hasFsProto = true; }

        if (ReadIniDword(entry.sourceOrigin, section, "Tunnel") > 0) {
            tunnel     = 1;
            tunnelHost = ReadIniString(entry.sourceOrigin, section, "TunnelHostName");
            tunnelUser = ReadIniString(entry.sourceOrigin, section, "TunnelUserName");
            tunnelKey  = ReadIniString(entry.sourceOrigin, section, "TunnelPublicKeyFile");
            const int tp = ReadIniDword(entry.sourceOrigin, section, "TunnelPortNumber");
            if (tp > 0) tunnelPort = static_cast<DWORD>(tp);
        }
        const int method = ReadIniDword(entry.sourceOrigin, section, "ProxyMethod");
        if (method > 0) proxyMethod = static_cast<DWORD>(method);

        if (dependency && tunnel == 0 && method > 0) {
            const std::string proxyHost = PuttyUrlDecode(
                ReadIniString(entry.sourceOrigin, section, "ProxyHost"));
            const int proxyPort = ReadIniDword(entry.sourceOrigin, section, "ProxyPort");
            dependency->kind   = SessionDependency::Kind::Proxy;
            dependency->detail = proxyHost;
            DescribePuttyProxy(static_cast<DWORD>(method), proxyHost,
                               proxyPort > 0 ? static_cast<DWORD>(proxyPort) : 0,
                               PuttyUrlDecode(ReadIniString(entry.sourceOrigin, section,
                                                            "ProxyUsername")),
                               *dependency);
        }
    }

    // Unsupported protocols (FTP/WebDAV/S3) fail LoadSettings so the
    // row silently disappears rather than showing an entry that will
    // never connect.
    const FsProtoResult proto =
        hasFsProto ? ClassifyFsProto(static_cast<int>(fsProtoRaw))
                   : FsProtoResult::UseSftp;
    if (proto == FsProtoResult::Unsupported)
        return false;

    if (hasPort && port > 0 && port != 22) {
        char portBuf[16];
        std::snprintf(portBuf, sizeof(portBuf), ":%lu",
                      static_cast<unsigned long>(port));
        out->server = host + portBuf;
    } else {
        out->server = host;
    }
    out->user     = userName;
    out->useagent = (useAgent != 0);

    if (proto == FsProtoResult::UseScp) {
        // Pin the flags a minimal SCP server needs:
        //   scponly + scpfordata → force SCP transport, no SFTP subsystem probe
        //   unixlinebreaks=1     → skip shell-command probes for line-ending mode
        //   scpserver64bit=0     → skip the >2 GB shell-side capability probe
        out->scponly        = true;
        out->scpfordata     = true;
        out->unixlinebreaks = 1;
        out->scpserver64bit = 0;
    }

    if (!keyFile.empty())
        AssignImportedKeyFile(keyFile, out->privkeyfile, out->pubkeyfile);

    // The tunnel becomes the session's jump host. Its password stays behind
    // and is asked for on connect. Refused instead when there is no host to
    // go through, or when a proxy is set as well: the plugin's jump host
    // connects directly, so the proxy would be skipped.
    if (tunnel != 0) {
        tunnelHost = PuttyUrlDecode(tunnelHost);
        if (tunnelHost.empty() || proxyMethod != 0) {
            if (dependency) {
                dependency->kind   = SessionDependency::Kind::Tunnel;
                dependency->detail = tunnelHost;
            }
        } else {
            out->use_jump_host = true;
            out->jump_host     = tunnelHost;
            if (tunnelPort > 0 && tunnelPort <= 0xFFFF)
                out->jump_port = static_cast<unsigned short>(tunnelPort);
            out->jump_user = PuttyUrlDecode(tunnelUser);
            tunnelKey = ExpandEnvA(PuttyUrlDecode(tunnelKey));
            if (!tunnelKey.empty())
                AssignImportedKeyFile(tunnelKey, out->jump_privkeyfile, out->jump_pubkeyfile);
        }
    }

    return true;
}

}  // namespace sftp

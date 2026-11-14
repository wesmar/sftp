#include "SecureCrtAdapter.h"
#include "ImportIoUtil.h"
#include "VanDykeIniParser.h"
#include "SftpClient.h"

#define WIN32_LEAN_AND_MEAN
#include <shlobj.h>
#include <windows.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace sftp {

namespace {

// VanDyke's own default templates / folder metadata — never real sessions.
bool IsSkippableFileName(const char* name) noexcept
{
    return _stricmp(name, "__FolderData__.ini")     == 0
        || _stricmp(name, "Default.ini")            == 0
        || _stricmp(name, "Default_LocalShell.ini") == 0
        || _stricmp(name, "Default_RDP.ini")        == 0
        || _stricmp(name, "Default_Serial.ini")     == 0
        || _stricmp(name, "LocalShell.ini")         == 0;
}

// Resolves %APPDATA%\VanDyke\Config\Sessions.
std::string GetStandardSessionsRoot()
{
    wchar_t wpath[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, wpath) != S_OK)
        return {};
    char utf8[MAX_PATH * 4] = {};
    WideCharToMultiByte(CP_UTF8, 0, wpath, -1, utf8, sizeof(utf8), nullptr, nullptr);
    return std::string(utf8) + "\\VanDyke\\Config\\Sessions";
}

// Convert a UTF-8 path to wide for a Win32 filesystem call.
std::wstring ToWide(const std::string& s)
{
    const int wchars = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (wchars <= 0) return {};
    std::wstring out(static_cast<size_t>(wchars - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), wchars);
    return out;
}

// True if a filesystem path exists (file or directory).
bool PathExistsW(const std::wstring& wpath)
{
    return GetFileAttributesW(wpath.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// Collect every SSH2 session under `root` into `out`. `sourceOrigin` becomes
// the CachedSessionRef channel tag (either "standard" or the literal custom
// path). No file name is reserved beyond the VanDyke defaults filtered by
// IsSkippableFileName.
void CollectSessions(const std::string& root,
                     const std::string& sourceOrigin,
                     std::vector<ExternalSessionEntry>& out)
{
    WalkDirectoryFiles(ToWide(root), L"ini",
        [&](const std::wstring& fullPathW, const std::string& relPath) {
            // Extract the leaf name to run the skip-list check.
            const size_t slash = fullPathW.find_last_of(L"\\/");
            const std::wstring leafW = (slash == std::wstring::npos)
                ? fullPathW : fullPathW.substr(slash + 1);
            char leafU8[MAX_PATH * 4] = {};
            WideCharToMultiByte(CP_UTF8, 0, leafW.c_str(), -1,
                leafU8, sizeof(leafU8), nullptr, nullptr);
            if (IsSkippableFileName(leafU8))
                return true;

            char pathU8[MAX_PATH * 4] = {};
            WideCharToMultiByte(CP_UTF8, 0, fullPathW.c_str(), -1,
                pathU8, sizeof(pathU8), nullptr, nullptr);
            const VanDykeFile file = ParseVanDykeFile(pathU8);
            if (file.empty())
                return true;

            // SSH2 only — other protocols are surfaced by other adapters or
            // not at all.
            const std::string protocol = GetString(file, "Protocol Name");
            if (_stricmp(protocol.c_str(), "SSH2") != 0)
                return true;

            ExternalSessionEntry e;
            e.displayName  = relPath;
            e.sourceOrigin = sourceOrigin;
            out.push_back(std::move(e));
            return true;
        });
}

// Reverse the DisplayName-to-file mapping. DisplayName segments map 1:1
// to on-disk folder segments (no name is treated as reserved). Returns
// empty on miss.
std::string ResolveSessionPath(const std::string& channelRoot,
                                const std::string& displayName)
{
    std::string rel = displayName;
    std::replace(rel.begin(), rel.end(), '/', '\\');
    rel += ".ini";
    const std::string direct = channelRoot + "\\" + rel;
    return PathExistsW(ToWide(direct)) ? direct : std::string{};
}

// Copy the connect fields SecureCRT exposes into `out`. The password is left
// out and prompted for on first connect; the route to the host is read
// separately, from "Firewall Name".
void FillConnectSettings(const VanDykeFile& file, tConnectSettings* out)
{
    if (!out) return;

    const std::string host = GetString(file, "Hostname");
    const uint32_t    port = GetDWord (file, "[SSH2] Port", 22);
    if (!host.empty()) {
        out->server = (port != 22 && port != 0)
            ? (host + ":" + std::to_string(port))
            : host;
    }

    out->user        = GetString(file, "Username");
    // Same route as the other adapters: expand any %VARS% first, then let
    // the shared helper decide public vs private by extension.
    AssignImportedKeyFile(ExpandEnvA(GetString(file, "Identity Filename V2")),
                          out->privkeyfile, out->pubkeyfile);

    // "Output Transformer Name" = "UTF-8" is the common modern encoding.
    // Anything else we leave as auto-detect (-1, which is the default).
    if (_stricmp(GetString(file, "Output Transformer Name").c_str(), "UTF-8") == 0)
        out->utf8names = 1;
}

// Firewall records live in Firewalls\ beside the Sessions folder, one
// <name>.ini each. A record that exists is a proxy; one of a kind the plugin
// speaks also has its address and user filled in. A missing record leaves
// `dep` as it is, since nothing says what stood in the way.
void DescribeFirewallRecord(const std::string& sessionsRoot,
                            const std::string& name,
                            SessionDependency& dep)
{
    const size_t slash = sessionsRoot.find_last_of("\\/");
    if (slash == std::string::npos)
        return;
    const VanDykeFile record = ParseVanDykeFile(
        sessionsRoot.substr(0, slash) + "\\Firewalls\\" + name + ".ini");
    if (record.empty())
        return;
    dep.kind = SessionDependency::Kind::Proxy;

    // Plain HTTP is the no-authentication kind, so a user name left in the
    // record from an earlier type is not carried over.
    const std::string type = GetString(record, "Firewall Type");
    Proxy proxyType{};
    bool  withUser = true;
    if      (_stricmp(type.c_str(), "SOCKSv4") == 0)        proxyType = Proxy::socks4;
    else if (_stricmp(type.c_str(), "SOCKSv5") == 0)        proxyType = Proxy::socks5;
    else if (_stricmp(type.c_str(), "HTTP_BASICAUTH") == 0) proxyType = Proxy::http;
    else if (_stricmp(type.c_str(), "HTTP") == 0)         { proxyType = Proxy::http; withUser = false; }
    else return;

    DescribeProxy(proxyType, GetString(record, "Firewall Address"),
                  GetDWord(record, "Firewall Port", 0),
                  withUser ? GetString(record, "Firewall User") : std::string(), dep);
}

// A session tunnelled through another SecureCRT session gets that session as
// its jump host. Only a direct SSH2 session qualifies: the plugin's jump host
// takes one hop and connects to it without a proxy, so a session that has a
// firewall of its own cannot be reproduced. Returns false to refuse.
bool FillJumpFromSession(const std::string& channelRoot,
                         const std::string& name,
                         tConnectSettings* out)
{
    const std::string path = ResolveSessionPath(channelRoot, name);
    if (path.empty())
        return false;
    const VanDykeFile jump = ParseVanDykeFile(path);
    if (jump.empty() || _stricmp(GetString(jump, "Protocol Name").c_str(), "SSH2") != 0)
        return false;
    const std::string firewall = GetString(jump, "Firewall Name");
    if (!firewall.empty() && _stricmp(firewall.c_str(), "None") != 0)
        return false;
    const std::string host = GetString(jump, "Hostname");
    if (host.empty())
        return false;

    out->use_jump_host = true;
    out->jump_host     = host;
    const uint32_t port = GetDWord(jump, "[SSH2] Port", 22);
    if (port != 0 && port <= 0xFFFF)
        out->jump_port = static_cast<unsigned short>(port);
    out->jump_user = GetString(jump, "Username");
    AssignImportedKeyFile(ExpandEnvA(GetString(jump, "Identity Filename V2")),
                          out->jump_privkeyfile, out->jump_pubkeyfile);
    return true;
}

}  // namespace

bool SecureCrtAdapter::DetectStandard() const noexcept
{
    const std::string root = GetStandardSessionsRoot();
    if (root.empty()) return false;
    return PathExistsW(ToWide(root + "\\Default.ini"));
}

std::string SecureCrtAdapter::ChangeStamp() const
{
    const std::string root = GetStandardSessionsRoot();
    if (root.empty()) return {};
    const size_t slash = root.find_last_of("\\/");
    std::string stamp = FolderChangeStamp(ToWide(root));
    if (slash != std::string::npos)
        stamp += FolderChangeStamp(ToWide(root.substr(0, slash) + "\\Firewalls"));
    return stamp;
}

// Read the same way EnumerateCustomPath reads it, Firewalls beside it.
std::string SecureCrtAdapter::CustomPathStamp(const std::string& path) const
{
    std::string root = path;
    while (!root.empty() && (root.back() == '\\' || root.back() == '/'))
        root.pop_back();
    const size_t slash = root.find_last_of("\\/");
    std::string stamp = FolderChangeStamp(ToWide(root));
    if (slash != std::string::npos)
        stamp += FolderChangeStamp(ToWide(root.substr(0, slash) + "\\Firewalls"));
    return stamp;
}

EnumerationResult SecureCrtAdapter::EnumerateStandard()
{
    EnumerationResult r;
    const std::string root = GetStandardSessionsRoot();
    if (root.empty() || !DetectStandard()) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }
    CollectSessions(root, "standard", r.sessions);
    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

EnumerationResult SecureCrtAdapter::EnumerateCustomPath(const std::string& path)
{
    EnumerationResult r;
    const std::wstring wpath = ToWide(path);
    const DWORD attrs = GetFileAttributesW(wpath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }
    CollectSessions(path, path, r.sessions);
    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

bool SecureCrtAdapter::LoadSettings(const ExternalSessionEntry& entry,
                                     pConnectSettings out,
                                     SessionDependency* dependency)
{
    if (!out) return false;

    // sourceOrigin identifies which channel produced this entry.
    // "standard" → standard %APPDATA% root; everything else is a literal
    // custom-path stored verbatim during enumeration.
    const std::string channelRoot = (entry.sourceOrigin == "standard")
        ? GetStandardSessionsRoot()
        : entry.sourceOrigin;
    if (channelRoot.empty()) return false;

    const std::string path = ResolveSessionPath(channelRoot, entry.displayName);
    if (path.empty()) return false;

    const VanDykeFile file = ParseVanDykeFile(path);
    if (file.empty()) return false;

    FillConnectSettings(file, out);

    // "Firewall Name" is how a session says it does not reach its host
    // directly. It holds "None" when there is nothing in the way, and
    // otherwise one of two forms: the name of a record under Firewalls\,
    // which carries the address and credentials, or "Session:<path>" naming
    // another SecureCRT session to tunnel through. A session to tunnel through
    // becomes the jump host; a record of a proxy kind the plugin speaks is
    // described so the session can be copied with it. Anything else — a
    // tunnel session we cannot reproduce, another firewall type, a record
    // that is missing — refuses instead of connecting straight to the target.
    const std::string firewall = GetString(file, "Firewall Name");
    if (!firewall.empty() && _stricmp(firewall.c_str(), "None") != 0) {
        constexpr std::string_view kSessionForm = "Session:";
        const bool viaSession = firewall.starts_with(kSessionForm);
        const std::string name = viaSession ? firewall.substr(kSessionForm.size()) : firewall;
        if (viaSession && FillJumpFromSession(channelRoot, name, out))
            return true;
        if (dependency) {
            dependency->kind   = SessionDependency::Kind::Bastion;
            dependency->detail = name;
            if (!viaSession)
                DescribeFirewallRecord(channelRoot, firewall, *dependency);
        }
    }
    return true;
}

}  // namespace sftp

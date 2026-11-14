#include "PuttyAdapter.h"
#include "ImportIoUtil.h"
#include "SftpClient.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace sftp {

namespace {

// The registry root every PuTTY-compatible tool writes into.
// Software\SimonTatham\PuTTY\Sessions under HKEY_CURRENT_USER.
constexpr const char* kPuttySessionsRoot = "Software\\SimonTatham\\PuTTY\\Sessions";

// Load a `.reg` file into a UTF-8 `std::string`. Handles the three encodings
// that appear in the wild: UTF-16 LE with BOM, UTF-8 with BOM, and headerless
// ANSI. BOM detection first, then CP_ACP fallback.
bool ReadRegFileAsUtf8(const std::string& path, std::string& outUtf8)
{
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    if (sz.QuadPart <= 0 || sz.QuadPart > 100 * 1024 * 1024) {
        // Reject empty and > 100 MB — Regedit exports of a single PuTTY
        // Sessions branch are typically tens of KB; anything larger is
        // either a mistake or someone trying to feed us a full
        // NTUSER.DAT-sized dump.
        CloseHandle(h);
        return false;
    }

    std::vector<uint8_t> raw(static_cast<size_t>(sz.QuadPart));
    DWORD readBytes = 0;
    const BOOL ok = ReadFile(h, raw.data(),
                              static_cast<DWORD>(raw.size()),
                              &readBytes, nullptr);
    CloseHandle(h);
    if (!ok || readBytes == 0) return false;
    raw.resize(readBytes);

    // BOM detection.
    if (raw.size() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE) {
        // UTF-16 LE.
        const wchar_t* wide = reinterpret_cast<const wchar_t*>(raw.data() + 2);
        const int wideCount = static_cast<int>((raw.size() - 2) / sizeof(wchar_t));
        const int need = WideCharToMultiByte(CP_UTF8, 0, wide, wideCount,
                                              nullptr, 0, nullptr, nullptr);
        if (need <= 0) return false;
        outUtf8.assign(static_cast<size_t>(need), '\0');
        WideCharToMultiByte(CP_UTF8, 0, wide, wideCount,
                             outUtf8.data(), need, nullptr, nullptr);
        return true;
    }
    if (raw.size() >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF) {
        // UTF-8 with BOM — strip and hand back as-is.
        outUtf8.assign(reinterpret_cast<const char*>(raw.data() + 3),
                        raw.size() - 3);
        return true;
    }
    // No BOM — treat the bytes as CP_ACP (ANSI).
    const int need = MultiByteToWideChar(CP_ACP, 0,
        reinterpret_cast<const char*>(raw.data()),
        static_cast<int>(raw.size()), nullptr, 0);
    if (need <= 0) {
        // Fall back to raw bytes; parser only needs ASCII-safe control
        // characters (`[`, `]`, `"`, `=`, digits, letters).
        outUtf8.assign(reinterpret_cast<const char*>(raw.data()), raw.size());
        return true;
    }
    std::wstring wide(static_cast<size_t>(need), L'\0');
    MultiByteToWideChar(CP_ACP, 0,
        reinterpret_cast<const char*>(raw.data()),
        static_cast<int>(raw.size()), wide.data(), need);
    const int u8Need = WideCharToMultiByte(CP_UTF8, 0,
        wide.data(), need, nullptr, 0, nullptr, nullptr);
    outUtf8.assign(static_cast<size_t>(u8Need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), need,
                        outUtf8.data(), u8Need, nullptr, nullptr);
    return true;
}

// Un-escape a Regedit-quoted string value: `\\` → `\`, `\"` → `"`, drop
// surrounding quotes. Anything else stays literal. `input` is the raw
// content between the two `"` delimiters (inclusive is fine — we strip
// them here).
std::string UnescapeRegString(std::string_view input)
{
    if (input.size() >= 2 && input.front() == '"' && input.back() == '"')
        input = input.substr(1, input.size() - 2);
    std::string out;
    out.reserve(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '\\' && i + 1 < input.size()) {
            char nxt = input[i + 1];
            if (nxt == '\\' || nxt == '"') { out.push_back(nxt); ++i; continue; }
        }
        out.push_back(input[i]);
    }
    return out;
}

// Parsed contents of a `.reg` file. `sessions` lists the URL-encoded
// Sessions\<name> subkeys; per-session fields sit in `strings` / `dwords`
// keyed as "<sess>::<name>".
struct RegFileParsed {
    std::vector<std::string>                       sessions;   // URL-encoded names
    std::unordered_map<std::string, std::string>   strings;    // "<sess>::<name>" → REG_SZ
    std::unordered_map<std::string, uint32_t>      dwords;     // "<sess>::<name>" → REG_DWORD
};

// Parse a `.reg` file's text form (already converted to UTF-8 by
// ReadRegFileAsUtf8). Only interested in Sessions\<name> subkeys — every
// other branch (Jumplist, SshHostKeys, the empty Sessions\ header, etc.)
// is skipped. Value types other than REG_SZ / REG_DWORD are silently
// ignored — PuTTY session fields we care about are all in those two.
void ParseRegFile(const std::string& utf8, RegFileParsed& out)
{
    static const std::string kSessionsPrefix =
        "HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\";

    std::string currentSession;  // empty when the current section is not a session

    auto flushLine = [&](std::string_view line) {
        // Trim CR (line endings from CRLF files).
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' ||
                                  line.back() == ' ' || line.back() == '\t'))
            line.remove_suffix(1);
        if (line.empty()) return;

        // Section header?
        if (line.front() == '[' && line.back() == ']') {
            std::string_view inner = line.substr(1, line.size() - 2);
            if (inner.size() > kSessionsPrefix.size() &&
                _strnicmp(inner.data(), kSessionsPrefix.data(),
                          kSessionsPrefix.size()) == 0)
            {
                std::string sess(inner.substr(kSessionsPrefix.size()));
                // Only leaf sessions — reject any nested subkey with `\` inside.
                if (sess.find('\\') == std::string::npos && !sess.empty()) {
                    currentSession = std::move(sess);
                    out.sessions.push_back(currentSession);
                    return;
                }
            }
            currentSession.clear();
            return;
        }

        if (currentSession.empty()) return;

        // Value line: `"Name"=...`
        if (line.size() < 4 || line.front() != '"') return;
        const size_t nameEnd = line.find('"', 1);
        if (nameEnd == std::string_view::npos) return;
        const std::string name(line.substr(1, nameEnd - 1));
        const size_t eq = line.find('=', nameEnd);
        if (eq == std::string_view::npos) return;
        std::string_view rhs = line.substr(eq + 1);
        // REG_SZ: `"value"` (escaped \" or \\ handled; multi-line
        // continuation not reassembled — session fields never use it).
        if (!rhs.empty() && rhs.front() == '"') {
            const std::string key = currentSession + "::" + name;
            out.strings[key] = UnescapeRegString(rhs);
            return;
        }
        // REG_DWORD: `dword:XXXXXXXX` (8 hex digits, big-endian text but
        // logically a plain little-endian u32 on the wire).
        static const char kDwordPrefix[] = "dword:";
        if (rhs.size() >= sizeof(kDwordPrefix) - 1 &&
            _strnicmp(rhs.data(), kDwordPrefix, sizeof(kDwordPrefix) - 1) == 0)
        {
            std::string_view hex = rhs.substr(sizeof(kDwordPrefix) - 1);
            uint32_t v = 0;
            for (char c : hex) {
                if (c >= '0' && c <= '9') v = (v << 4) | uint32_t(c - '0');
                else if (c >= 'a' && c <= 'f') v = (v << 4) | uint32_t(10 + c - 'a');
                else if (c >= 'A' && c <= 'F') v = (v << 4) | uint32_t(10 + c - 'A');
                else break;
            }
            out.dwords[currentSession + "::" + name] = v;
        }
        // Everything else (hex(...):, hex(7):, "..." continued lines) is
        // ignored — none of the fields we consume are stored that way.
    };

    // Split into lines and hand each to flushLine. Handles both CRLF and
    // LF-only files.
    size_t start = 0;
    for (size_t i = 0; i <= utf8.size(); ++i) {
        if (i == utf8.size() || utf8[i] == '\n') {
            flushLine(std::string_view(utf8.data() + start, i - start));
            start = i + 1;
        }
    }
}

// PuTTY's SSH proxy (ProxyMethod 6, "SSH to proxy and use port forwarding")
// is a jump host. Its ProxyHost may name a saved session, in which case that
// session describes the jump; the fields below are read from it, from the
// same channel as the session going through it.
struct JumpSessionFields {
    std::string host, user, keyFile;
    DWORD       port = 0, proxyMethod = 0;
};

bool ReadJumpSession(const std::string& sourceOrigin,
                     const std::string& name,
                     JumpSessionFields& f)
{
    const std::string subKeyName = PuttyUrlEncode(name);
    if (sourceOrigin == "standard") {
        const std::string subKey = std::string(kPuttySessionsRoot) + "\\" + subKeyName;
        HKEY key = nullptr;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS)
            return false;
        ReadRegString(key, "HostName", f.host);
        ReadRegDword(key, "PortNumber", f.port);
        ReadRegString(key, "UserName", f.user);
        ReadRegString(key, "PublicKeyFile", f.keyFile);
        ReadRegDword(key, "ProxyMethod", f.proxyMethod);
        RegCloseKey(key);
    } else {
        std::string text;
        if (!ReadRegFileAsUtf8(sourceOrigin, text))
            return false;
        RegFileParsed parsed;
        ParseRegFile(text, parsed);
        const std::string prefix = subKeyName + "::";
        if (auto it = parsed.strings.find(prefix + "HostName"); it != parsed.strings.end())
            f.host = it->second;
        if (auto it = parsed.dwords.find(prefix + "PortNumber"); it != parsed.dwords.end())
            f.port = it->second;
        if (auto it = parsed.strings.find(prefix + "UserName"); it != parsed.strings.end())
            f.user = it->second;
        if (auto it = parsed.strings.find(prefix + "PublicKeyFile"); it != parsed.strings.end())
            f.keyFile = it->second;
        if (auto it = parsed.dwords.find(prefix + "ProxyMethod"); it != parsed.dwords.end())
            f.proxyMethod = it->second;
    }
    f.host    = PuttyUrlDecode(f.host);
    f.user    = PuttyUrlDecode(f.user);
    f.keyFile = ExpandEnvA(PuttyUrlDecode(f.keyFile));
    return !f.host.empty();
}

}  // namespace

bool PuttyAdapter::DetectStandard() const noexcept
{
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, kPuttySessionsRoot,
                             0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS) return false;
    RegCloseKey(key);
    return true;
}

std::string PuttyAdapter::ChangeStamp() const
{
    return RegistryChangeStamp(kPuttySessionsRoot);
}

std::string PuttyAdapter::CustomPathStamp(const std::string& path) const
{
    return FileChangeStamp({ AnsiPathToWide(path) });
}

EnumerationResult PuttyAdapter::EnumerateStandard()
{
    EnumerationResult r;

    HKEY root = nullptr;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, kPuttySessionsRoot,
                             0, KEY_READ, &root);
    if (rc != ERROR_SUCCESS) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    DWORD index = 0;
    for (;;) {
        std::array<char, 512> nameBuf{};
        DWORD nameLen = static_cast<DWORD>(nameBuf.size());
        rc = RegEnumKeyExA(root, index, nameBuf.data(), &nameLen,
                            nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        ++index;
        if (rc != ERROR_SUCCESS)
            continue;

        // "Default Settings" / "Default%20Settings" carry PuTTY's template
        // fallback field values, never a real session.
        if (_stricmp(nameBuf.data(), "Default%20Settings") == 0 ||
            _stricmp(nameBuf.data(), "Default Settings")   == 0)
            continue;

        ExternalSessionEntry e;
        e.displayName  = PuttyUrlDecode(std::string(nameBuf.data(), nameLen));
        e.sourceOrigin = "standard";
        r.sessions.push_back(std::move(e));
    }
    RegCloseKey(root);

    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

EnumerationResult PuttyAdapter::EnumerateCustomPath(const std::string& path)
{
    EnumerationResult r;

    std::string text;
    if (!ReadRegFileAsUtf8(path, text)) {
        // File missing or unreadable — treat as Unreachable so the
        // channel's cached entries survive per the standard prune rules.
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    RegFileParsed parsed;
    ParseRegFile(text, parsed);

    for (const auto& sessKeyName : parsed.sessions) {
        // Same skip as EnumerateStandard — PuTTY's "Default Settings"
        // template row is never a real session.
        if (_stricmp(sessKeyName.c_str(), "Default%20Settings") == 0)
            continue;

        ExternalSessionEntry e;
        e.displayName  = PuttyUrlDecode(sessKeyName);
        e.sourceOrigin = path;   // literal file path — see LoadSettings
        r.sessions.push_back(std::move(e));
    }

    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

bool PuttyAdapter::LoadSettings(const ExternalSessionEntry& entry,
                                 pConnectSettings out,
                                 SessionDependency* dependency)
{
    if (!out) return false;

    // Round-trip the displayName back through URL encoding to hit the
    // exact subkey PuTTY stored it under — the same encoding scheme is
    // used both in the registry and in .reg export files.
    const std::string subKeyName = PuttyUrlEncode(entry.displayName);

    // Field values, populated from whichever channel this entry came
    // from. Empty string / zero here means "field not present".
    std::string host, userName, keyFile, lineCodePage, proxyHost, proxyUser;
    DWORD       port = 0, useAgent = 0, enterSendsCrLf = 0, proxyMethod = 0, proxyPort = 0;
    bool        hasPort = false, hasEnterSendsCrLf = false, hasProxyMethod = false,
                hasProxyPort = false;

    if (entry.sourceOrigin == "standard") {
        // Standard channel: fields live under
        // HKCU\Software\SimonTatham\PuTTY\Sessions\<encoded name>.
        const std::string subKey =
            std::string(kPuttySessionsRoot) + "\\" + subKeyName;
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

        ReadRegString(key, "LineCodePage", lineCodePage);
        hasEnterSendsCrLf = ReadRegDword(key, "EnterSendsCrLf", enterSendsCrLf);
        hasProxyMethod = ReadRegDword(key, "ProxyMethod", proxyMethod);
        if (ReadRegString(key, "ProxyHost", proxyHost))
            proxyHost = PuttyUrlDecode(proxyHost);
        ReadRegDword(key, "ProxyPort", proxyPort);
        if (ReadRegString(key, "ProxyUsername", proxyUser))
            proxyUser = PuttyUrlDecode(proxyUser);
        RegCloseKey(key);
    } else {
        // Custom channel: entry.sourceOrigin is the literal path to a
        // `putty.reg` export file. Re-parse the whole file (small,
        // rarely called — user F5-refresh + first enter per session),
        // then pull the fields for this specific session from the
        // parsed map.
        std::string text;
        if (!ReadRegFileAsUtf8(entry.sourceOrigin, text))
            return false;
        RegFileParsed parsed;
        ParseRegFile(text, parsed);

        const std::string prefix = subKeyName + "::";
        auto pickString = [&](const char* name, std::string& out_) {
            auto it = parsed.strings.find(prefix + name);
            if (it != parsed.strings.end())
                out_ = it->second;
        };
        auto pickDword = [&](const char* name, DWORD& out_, bool& hasIt) {
            auto it = parsed.dwords.find(prefix + name);
            if (it != parsed.dwords.end()) {
                out_ = it->second;
                hasIt = true;
            }
        };

        pickString("HostName", host);
        host = PuttyUrlDecode(host);
        if (host.empty()) return false;

        pickDword("PortNumber", port, hasPort);

        pickString("UserName", userName);
        userName = PuttyUrlDecode(userName);

        bool hadAgent = false;
        pickDword("AgentFwd", useAgent, hadAgent);
        if (!hadAgent)
            pickDword("AuthAgent", useAgent, hadAgent);

        pickString("PublicKeyFile", keyFile);
        keyFile = ExpandEnvA(PuttyUrlDecode(keyFile));

        pickString("LineCodePage", lineCodePage);
        pickDword("EnterSendsCrLf", enterSendsCrLf, hasEnterSendsCrLf);
        pickDword("ProxyMethod", proxyMethod, hasProxyMethod);
        pickString("ProxyHost", proxyHost);
        proxyHost = PuttyUrlDecode(proxyHost);
        pickDword("ProxyPort", proxyPort, hasProxyPort);
        pickString("ProxyUsername", proxyUser);
        proxyUser = PuttyUrlDecode(proxyUser);
    }

    // Method 6 is an SSH session in front of the host, which becomes the
    // jump host. A saved session named as the proxy host describes it, and
    // qualifies only when it connects directly: the plugin's jump host takes
    // one hop, with no proxy before it. A plain address carries no key; the
    // password is asked for on connect.
    constexpr DWORD kProxySshForward = 6;
    bool viaJump = false;
    if (hasProxyMethod && proxyMethod == kProxySshForward && !proxyHost.empty()) {
        JumpSessionFields saved;
        if (ReadJumpSession(entry.sourceOrigin, proxyHost, saved)) {
            if (saved.proxyMethod == 0) {
                out->jump_host = saved.host;
                if (saved.port > 0 && saved.port <= 0xFFFF)
                    out->jump_port = static_cast<unsigned short>(saved.port);
                out->jump_user = saved.user;
                AssignImportedKeyFile(saved.keyFile, out->jump_privkeyfile, out->jump_pubkeyfile);
                viaJump = true;
            }
        } else {
            out->jump_host = proxyHost;
            if (proxyPort > 0 && proxyPort <= 0xFFFF)
                out->jump_port = static_cast<unsigned short>(proxyPort);
            out->jump_user = proxyUser;
            viaJump = true;
        }
        out->use_jump_host = viaJump;
    }

    // Any other method but zero means the session does not reach its host
    // directly, so it refuses rather than connect past the proxy. A method
    // the plugin speaks also carries the proxy itself, which lets F5 bring
    // it across instead.
    if (dependency && hasProxyMethod && proxyMethod != 0 && !viaJump) {
        dependency->kind   = SessionDependency::Kind::Proxy;
        dependency->detail = proxyHost;
        DescribePuttyProxy(proxyMethod, proxyHost, proxyPort, proxyUser, *dependency);
    }

    // Compose the connect fields the cache writer will persist. The
    // sentinel-based policy in ImportCache::WriteSessionSection means
    // fields we leave at their default (empty string, false, -1) never
    // reach the cache — no need to zero anything out explicitly.
    if (hasPort && port > 0 && port != 22) {
        char portBuf[16];
        std::snprintf(portBuf, sizeof(portBuf), ":%lu",
                      static_cast<unsigned long>(port));
        out->server = host + portBuf;
    } else {
        out->server = host;
    }
    out->user = userName;
    out->useagent = (useAgent != 0);

    // PuTTY calls it "PublicKeyFile" but always stores the *private*
    // key path; the `.pub` companion is a separate concept. Route via
    // the shared helper — `.pub` → pubkeyfile, everything else →
    // privkeyfile. `PpkConverter` handles the `.ppk` → OpenSSH
    // temp-file conversion downstream in SftpAuth.
    AssignImportedKeyFile(keyFile, out->privkeyfile, out->pubkeyfile);

    // LineCodePage strings ("UTF-8", "KOI8-R", "CP1251", "WIN-1252", …)
    // map to the (utf8, codepage) pair used by the plugin's INI. Blank or
    // unrecognised → leave existing defaults.
    if (!lineCodePage.empty()) {
        int cpUtf8 = 0, cpNum = 0;
        if (ParseLineCodePage(lineCodePage, cpUtf8, cpNum)) {
            out->utf8names = static_cast<char>(cpUtf8);
            if (!cpUtf8 && cpNum > 0)
                out->codepage = cpNum;
        }
    }

    if (hasEnterSendsCrLf)
        out->unixlinebreaks = enterSendsCrLf ? 1 : 0;

    return true;
}

}  // namespace sftp

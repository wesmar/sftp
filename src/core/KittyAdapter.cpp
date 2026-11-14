#include "KittyAdapter.h"
#include "SftpClient.h"
#include "SftpInternal.h"     // EncryptString for password re-wrap
#include "KittyDecrypt.h"     // DecryptKittyPassword (native, no external exe)
#include "global.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "ImportIoUtil.h"
#include "PasswordCrypto.h"

#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

namespace sftp {

namespace {

// KiTTY session files live in a `Sessions` subdirectory of the install root.
// This name is fixed by KiTTY itself and does not vary between versions.
constexpr const char* kSessionsDirName = "Sessions";

bool PathIsDirectory(const std::string& path) noexcept
{
    const DWORD a = GetFileAttributesA(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

bool PathIsFile(const std::string& path) noexcept
{
    const DWORD a = GetFileAttributesA(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::string JoinPath(const std::string& a, const char* b)
{
    if (a.empty()) return b;
    if (a.back() == '\\' || a.back() == '/') return a + b;
    return a + "\\" + b;
}

// -------------------------------------------------------------------------
// KiTTY session file reader
//
// Format is intentionally NOT INI:
//   HostName\example.com\
//   PortNumber\22\
//   Protocol\ssh\
//   ...
// Each line: `KeyName<backslash>URL-encoded value<backslash>`. The value is
// bounded by the first '\' and the **last** '\' on the same line — values
// that contain a literal '\' get percent-encoded (as `%5C`) so the parser
// can rely on the last-slash rule. Empty lines and lines without a '\'
// separator are silently skipped.
//
// Value is returned URL-decoded. Missing key → false, no `out` write.
// -------------------------------------------------------------------------
bool ReadKittyString(const std::string& filePath,
                     const char* key,
                     std::string& out)
{
    HANDLE h = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (2 * 1024 * 1024)) {
        CloseHandle(h);
        return false;    // reject absurd sizes; KiTTY session files are ~2 KB.
    }
    std::string content(static_cast<size_t>(sz.QuadPart), '\0');
    DWORD read = 0;
    const BOOL ok = ReadFile(h, content.data(),
                              static_cast<DWORD>(content.size()), &read, nullptr);
    CloseHandle(h);
    if (!ok) return false;
    content.resize(read);

    const size_t keyLen = std::strlen(key);
    size_t pos = 0;
    while (pos < content.size()) {
        const size_t eol = content.find('\n', pos);
        std::string line;
        if (eol == std::string::npos) {
            line.assign(content, pos, content.size() - pos);
            pos = content.size();
        } else {
            line.assign(content, pos, eol - pos);
            pos = eol + 1;
        }
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        const size_t firstSep = line.find('\\');
        if (firstSep == std::string::npos) continue;
        if (firstSep != keyLen) continue;
        if (_strnicmp(line.c_str(), key, keyLen) != 0) continue;

        const size_t lastSep = line.rfind('\\');
        if (lastSep <= firstSep) continue;

        out = PuttyUrlDecode(line.substr(firstSep + 1, lastSep - firstSep - 1));
        return true;
    }
    return false;
}

bool ReadKittyDword(const std::string& filePath,
                    const char* key, DWORD& out)
{
    std::string s;
    if (!ReadKittyString(filePath, key, s) || s.empty()) return false;
    char* endp = nullptr;
    const unsigned long v = std::strtoul(s.c_str(), &endp, 10);
    if (endp == s.c_str()) return false;
    out = static_cast<DWORD>(v);
    return true;
}

// -------------------------------------------------------------------------
// Standard-location detection
//
// Three cheap file probes cover the common install layouts:
//   %APPDATA%\KiTTY\Sessions\          — portable ZIP dropped into AppData
//   %LOCALAPPDATA%\KiTTY\Sessions\     — likewise, Windows 10/11 preference
//   %USERPROFILE%\KiTTY\Sessions\      — user-home extract
// If none match, HKCR\.kitty (registered by the installer for the `.kitty`
// script file association) points at the KiTTY exe; strip its filename and
// probe `<dir>\Sessions\` there too.
// -------------------------------------------------------------------------
constexpr const char* kProbeSuffix = "\\KiTTY\\Sessions";

std::string TryEnvProbe(const char* envVarPercent)
{
    const std::string base = ExpandEnvA(envVarPercent);
    // ExpandEnv leaves `%FOO%` untouched when FOO is not set — reject that.
    if (base.empty() || base == envVarPercent) return {};
    const std::string full = base + kProbeSuffix;
    return PathIsDirectory(full) ? full : std::string();
}

// Parse `HKCR\.kitty` (default value = ProgID) → `HKCR\<ProgID>\shell\open\
// command` (default value = handler cmdline) → extract the exe path (first
// quoted token or first whitespace-terminated token) → strip filename.
// Empty result if any step fails.
std::string TryHkcrProbe()
{
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExA(HKEY_CLASSES_ROOT, ".kitty", 0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS) return {};

    std::array<char, 256> progId{};
    DWORD progIdBytes = static_cast<DWORD>(progId.size());
    DWORD type = 0;
    rc = RegQueryValueExA(key, nullptr, nullptr, &type,
                           reinterpret_cast<LPBYTE>(progId.data()), &progIdBytes);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_SZ || progId[0] == 0) return {};

    const std::string cmdKey = std::string(progId.data()) + "\\shell\\open\\command";
    rc = RegOpenKeyExA(HKEY_CLASSES_ROOT, cmdKey.c_str(), 0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS) return {};

    std::array<char, 1024> cmd{};
    DWORD cmdBytes = static_cast<DWORD>(cmd.size());
    rc = RegQueryValueExA(key, nullptr, nullptr, &type,
                           reinterpret_cast<LPBYTE>(cmd.data()), &cmdBytes);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return {};

    std::string handler = cmd.data();
    if (type == REG_EXPAND_SZ) handler = ExpandEnvA(handler);

    // Extract exe path: quoted form `"C:\Path\kitty.exe" "%1"` or bare form
    // `C:\Path\kitty.exe %1`.
    std::string exe;
    if (!handler.empty() && handler.front() == '"') {
        const size_t end = handler.find('"', 1);
        if (end != std::string::npos) exe = handler.substr(1, end - 1);
    } else {
        const size_t sp = handler.find(' ');
        exe = handler.substr(0, sp == std::string::npos ? handler.size() : sp);
    }
    if (exe.empty()) return {};

    const size_t sl = exe.find_last_of("\\/");
    if (sl == std::string::npos) return {};
    const std::string dir = exe.substr(0, sl);
    const std::string full = JoinPath(dir, kSessionsDirName);
    return PathIsDirectory(full) ? full : std::string();
}

// One-stop shop: return the first sessions directory that exists, or empty.
std::string ResolveStandardSessionsDir()
{
    std::string p;
    p = TryEnvProbe("%APPDATA%");      if (!p.empty()) return p;
    p = TryEnvProbe("%LOCALAPPDATA%"); if (!p.empty()) return p;
    p = TryEnvProbe("%USERPROFILE%");  if (!p.empty()) return p;
    return TryHkcrProbe();
}

// A user-picked path can point at either the sessions directory itself or
// at the KiTTY install root (which contains `Sessions\` as a sibling of
// `kitty.exe`). Accept both and return the actual sessions directory,
// empty string if neither shape holds.
std::string NormalizeCustomPath(const std::string& raw)
{
    if (raw.empty()) return {};
    // Direct hit: the caller pointed at `Sessions\` already.
    if (PathIsDirectory(raw)) {
        // Heuristic — a `Sessions\` folder does not usually contain other
        // `Sessions\`; the install root does. Prefer descending when a
        // child `Sessions\` exists.
        const std::string child = JoinPath(raw, kSessionsDirName);
        if (PathIsDirectory(child)) return child;
        return raw;
    }
    return {};
}

// -------------------------------------------------------------------------
// Enumeration
//
// Walk the sessions directory, keep every regular file whose
// `Protocol=ssh`. `Default%20Settings` is KiTTY's template fallback
// and must be filtered out.
// -------------------------------------------------------------------------
EnumerationResult EnumerateSessionsDir(const std::string& dir,
                                       const std::string& sourceOrigin)
{
    EnumerationResult r;
    if (dir.empty() || !PathIsDirectory(dir)) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    const std::string pattern = JoinPath(dir, "*");
    WIN32_FIND_DATAA fd{};
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        r.status = EnumerationStatus::OkEmpty;
        return r;
    }

    int filtered = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        const std::string encName = fd.cFileName;
        if (encName.empty() || encName == "." || encName == "..") continue;
        if (_stricmp(encName.c_str(), "Default%20Settings") == 0) { ++filtered; continue; }

        const std::string filePath = JoinPath(dir, encName.c_str());
        std::string proto;
        if (!ReadKittyString(filePath, "Protocol", proto)) continue;
        if (_stricmp(proto.c_str(), "ssh") != 0) { ++filtered; continue; }

        ExternalSessionEntry e;
        e.displayName  = PuttyUrlDecode(encName);
        e.sourceOrigin = sourceOrigin;
        r.sessions.push_back(std::move(e));
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    SFTP_LOG("KITTY", "EnumerateSessionsDir dir='%s' sessions=%zu filtered=%d",
             dir.c_str(), r.sessions.size(), filtered);

    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

// Password import: read KiTTY's obfuscated `Password` blob, decode with our
// built-in KittyDecrypt, re-wrap with the plugin's own EncryptString so the
// resulting cache row stores the same DPAPI-shaped string sftpplug.ini uses.
// Silent no-op when nothing is stored — KiTTY leaves `Password` absent for
// sessions the user did not opt to save.
void ImportKittyPassword(const std::string& filePath,
                          const std::string& host,
                          pConnectSettings out)
{
    std::string encPass;
    sftp::ScopedWipe wipeEnc(encPass);
    if (!ReadKittyString(filePath, "Password", encPass) || encPass.empty())
        return;

    std::string term;
    if (!ReadKittyString(filePath, "TerminalType", term) || term.empty())
        term = "xterm";

    std::string plain;
    sftp::ScopedWipe wipePlain(plain);
    if (!DecryptKittyPassword(encPass, host, term, plain) || plain.empty()) {
        SFTP_LOG("KITTY", "  password present but decrypt failed for host='%s'",
                 host.c_str());
        return;
    }

    out->password = password_crypto::Protect(plain);
}

}  // namespace

bool KittyAdapter::DetectStandard() const noexcept
{
    return !ResolveStandardSessionsDir().empty();
}

std::string KittyAdapter::ChangeStamp() const
{
    const std::string dir = ResolveStandardSessionsDir();
    if (dir.empty()) return {};
    std::wstring wide(dir.size() + 1, L'\0');
    const int n = MultiByteToWideChar(CP_ACP, 0, dir.c_str(), -1, wide.data(), static_cast<int>(wide.size()));
    if (n <= 0) return {};
    wide.resize(static_cast<size_t>(n - 1));
    return FolderChangeStamp(wide);
}

std::string KittyAdapter::CustomPathStamp(const std::string& path) const
{
    // The picked folder may be the install root; the sessions sit below it.
    const std::string dir = NormalizeCustomPath(path);
    return dir.empty() ? FileChangeStamp({ AnsiPathToWide(path) })
                       : FolderChangeStamp(AnsiPathToWide(dir));
}

EnumerationResult KittyAdapter::EnumerateStandard()
{
    const std::string dir = ResolveStandardSessionsDir();
    SFTP_LOG("KITTY", "EnumerateStandard: dir='%s'", dir.c_str());
    return EnumerateSessionsDir(dir, "standard");
}

EnumerationResult KittyAdapter::EnumerateCustomPath(const std::string& path)
{
    const std::string dir = NormalizeCustomPath(path);
    SFTP_LOG("KITTY", "EnumerateCustomPath: raw='%s' resolved='%s'",
             path.c_str(), dir.c_str());
    // sourceOrigin carries the user-supplied path verbatim so LoadSettings
    // can re-normalise later.
    return EnumerateSessionsDir(dir, path);
}

bool KittyAdapter::LoadSettings(const ExternalSessionEntry& entry,
                                 pConnectSettings out,
                                 SessionDependency* dependency)
{
    if (!out) return false;

    // Resolve the directory this entry lives in.
    std::string dir;
    if (entry.sourceOrigin == "standard") {
        dir = ResolveStandardSessionsDir();
    } else {
        dir = NormalizeCustomPath(entry.sourceOrigin);
    }
    if (dir.empty()) return false;

    const std::string filePath = JoinPath(dir, PuttyUrlEncode(entry.displayName).c_str());
    if (!PathIsFile(filePath)) {
        SFTP_LOG("KITTY", "LoadSettings: file missing '%s'", filePath.c_str());
        return false;
    }

    // Protocol gate — same as EnumerateSessionsDir, in case a subsequent
    // KiTTY edit changed the transport away from SSH.
    std::string proto;
    if (!ReadKittyString(filePath, "Protocol", proto) ||
        _stricmp(proto.c_str(), "ssh") != 0) {
        return false;
    }

    std::string host;
    if (!ReadKittyString(filePath, "HostName", host) || host.empty()) return false;

    DWORD port = 0;
    const bool hasPort = ReadKittyDword(filePath, "PortNumber", port);

    std::string userName, keyFile, lineCodePage;
    ReadKittyString(filePath, "UserName", userName);
    if (ReadKittyString(filePath, "PublicKeyFile", keyFile))
        keyFile = ExpandEnvA(keyFile);
    ReadKittyString(filePath, "LineCodePage", lineCodePage);

    DWORD useAgent = 0;
    if (!ReadKittyDword(filePath, "AgentFwd", useAgent))
        ReadKittyDword(filePath, "AuthAgent", useAgent);

    DWORD enterSendsCrLf = 0;
    const bool hasEnterSendsCrLf = ReadKittyDword(filePath, "EnterSendsCrLf",
                                                    enterSendsCrLf);

    // KiTTY inherits PuTTY's key names and method numbers, so a non-zero
    // method means the same thing here: the session goes through a proxy,
    // which F5 can bring across when it is one the plugin speaks.
    DWORD proxyMethod = 0;
    if (dependency && ReadKittyDword(filePath, "ProxyMethod", proxyMethod) && proxyMethod != 0) {
        std::string proxyHost, proxyUser;
        DWORD proxyPort = 0;
        ReadKittyString(filePath, "ProxyHost", proxyHost);
        ReadKittyDword(filePath, "ProxyPort", proxyPort);
        ReadKittyString(filePath, "ProxyUsername", proxyUser);
        proxyHost = PuttyUrlDecode(proxyHost);
        dependency->kind   = SessionDependency::Kind::Proxy;
        dependency->detail = proxyHost;
        DescribePuttyProxy(proxyMethod, proxyHost, proxyPort,
                           PuttyUrlDecode(proxyUser), *dependency);
    }

    // Compose the connect fields.
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

    AssignImportedKeyFile(keyFile, out->privkeyfile, out->pubkeyfile);

    if (!lineCodePage.empty()) {
        int cpUtf8 = 0, cpNum = 0;
        if (ParseLineCodePage(lineCodePage, cpUtf8, cpNum)) {
            out->utf8names = static_cast<char>(cpUtf8);
            if (!cpUtf8 && cpNum > 0) out->codepage = cpNum;
        }
    }

    if (hasEnterSendsCrLf)
        out->unixlinebreaks = enterSendsCrLf ? 1 : 0;

    // Password decoder derives its key from the raw HostName field, not
    // the composed `host:port` string — pass `host` here, never `out->server`.
    ImportKittyPassword(filePath, host, out);

    SFTP_LOG("KITTY",
             "LoadSettings ok: display='%s' server='%s' user='%s' priv='%s' pass=%s",
             entry.displayName.c_str(), out->server.c_str(), out->user.c_str(),
             out->privkeyfile.c_str(), out->password.empty() ? "no" : "yes");
    return true;
}

}  // namespace sftp

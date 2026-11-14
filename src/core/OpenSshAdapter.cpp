#include "OpenSshAdapter.h"
#include "SftpClient.h"
#include "global.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include "ImportIoUtil.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace sftp {

namespace {

// One keyword line of the config, with its arguments split the way `ssh`
// splits them: whitespace or a single '=' between keyword and value,
// double quotes around arguments that contain spaces.
struct ConfigLine {
    std::string              key;    // lower case
    std::vector<std::string> args;
};

// Include nesting is capped as `ssh` caps it, which also stops a file that
// includes itself.
constexpr int kMaxIncludeDepth = 16;

std::wstring Utf8ToWide(const std::string& s)
{
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), n);
    return out;
}

std::string WideToUtf8(const std::wstring& s)
{
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), n, nullptr, nullptr);
    return out;
}

// The plugin keeps file paths in the ANSI code page, as the other adapters do.
std::string Utf8ToAnsi(const std::string& s)
{
    const std::wstring w = Utf8ToWide(s);
    const int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring AnsiToWide(const std::string& s)
{
    const int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n - 1), L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, out.data(), n);
    return out;
}

// %USERPROFILE%, UTF-8. `~` and %d stand for it.
std::string HomeDir()
{
    wchar_t buf[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, SHGFP_TYPE_CURRENT, buf)))
        return {};
    return WideToUtf8(buf);
}

std::string LocalUserName()
{
    wchar_t buf[256] = {};
    DWORD len = static_cast<DWORD>(std::size(buf));
    return GetUserNameW(buf, &len) ? WideToUtf8(buf) : std::string();
}

std::wstring StandardConfigPath()
{
    const std::string home = HomeDir();
    return home.empty() ? std::wstring() : Utf8ToWide(home + "\\.ssh\\config");
}

std::string Lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool ReadFileUtf8(const std::wstring& path, std::string& out)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 || sz.QuadPart > 4 * 1024 * 1024) {
        CloseHandle(h);
        return false;
    }
    out.resize(static_cast<size_t>(sz.QuadPart));
    DWORD read = 0;
    const BOOL ok = out.empty() || ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(h);
    if (!ok || read != out.size()) { out.clear(); return false; }
    if (out.size() >= 3 && static_cast<unsigned char>(out[0]) == 0xEF &&
        static_cast<unsigned char>(out[1]) == 0xBB && static_cast<unsigned char>(out[2]) == 0xBF)
        out.erase(0, 3);
    return true;
}

// Split the argument part of a line: whitespace-separated, double quotes
// keep spaces inside one argument.
std::vector<std::string> SplitArgs(std::string_view s)
{
    std::vector<std::string> args;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        if (i >= s.size()) break;
        std::string arg;
        if (s[i] == '"') {
            ++i;
            while (i < s.size() && s[i] != '"') arg += s[i++];
            if (i < s.size()) ++i;
        } else {
            while (i < s.size() && s[i] != ' ' && s[i] != '\t') arg += s[i++];
        }
        args.push_back(std::move(arg));
    }
    return args;
}

// Files read while parsing, the config and its includes, for ChangeStamp.
using VisitedFiles = std::vector<std::wstring>;

void ParseFile(const std::wstring& path, std::vector<ConfigLine>& out, int depth,
               VisitedFiles* visited = nullptr);

// `Include` takes paths relative to ~/.ssh and may hold wildcards; matches
// are read in name order, as `ssh` reads them.
void ExpandInclude(const std::string& pattern, std::vector<ConfigLine>& out, int depth,
                   VisitedFiles* visited)
{
    std::string p = pattern;
    if (p.starts_with("~"))
        p = HomeDir() + p.substr(1);
    std::replace(p.begin(), p.end(), '/', '\\');
    const bool absolute = p.size() > 1 && (p[1] == ':' || p.starts_with("\\\\"));
    if (!absolute)
        p = HomeDir() + "\\.ssh\\" + p;

    const std::wstring wpattern = Utf8ToWide(p);
    const size_t slash = wpattern.find_last_of(L'\\');
    const std::wstring dir = slash == std::wstring::npos ? std::wstring() : wpattern.substr(0, slash + 1);

    std::vector<std::wstring> files;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(wpattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            files.push_back(dir + fd.cFileName);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    std::sort(files.begin(), files.end());
    for (const auto& f : files)
        ParseFile(f, out, depth + 1, visited);
}

void ParseFile(const std::wstring& path, std::vector<ConfigLine>& out, int depth,
               VisitedFiles* visited)
{
    if (depth > kMaxIncludeDepth)
        return;
    if (visited)
        visited->push_back(path);
    std::string text;
    if (!ReadFileUtf8(path, text))
        return;

    size_t pos = 0;
    while (pos <= text.size()) {
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        std::string_view line(text.data() + pos, eol - pos);
        pos = eol + 1;

        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            line.remove_suffix(1);
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
            line.remove_prefix(1);
        if (line.empty() || line.front() == '#')
            continue;

        size_t k = 0;
        while (k < line.size() && line[k] != ' ' && line[k] != '\t' && line[k] != '=') ++k;
        ConfigLine cl;
        cl.key = Lower(std::string(line.substr(0, k)));
        std::string_view rest = line.substr(k);
        while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) rest.remove_prefix(1);
        if (!rest.empty() && rest.front() == '=') rest.remove_prefix(1);
        cl.args = SplitArgs(rest);
        if (cl.key.empty() || cl.args.empty())
            continue;

        if (cl.key == "include") {
            for (const auto& arg : cl.args)
                ExpandInclude(arg, out, depth, visited);
            continue;
        }
        out.push_back(std::move(cl));
    }
}

// `ssh` pattern: '*' and '?' wildcards, compared without case.
bool WildcardMatch(const char* pat, const char* str)
{
    while (*pat) {
        if (*pat == '*') {
            ++pat;
            if (!*pat) return true;
            for (; *str; ++str)
                if (WildcardMatch(pat, str)) return true;
            return false;
        }
        if (!*str) return false;
        if (*pat != '?' && std::tolower(static_cast<unsigned char>(*pat)) !=
                           std::tolower(static_cast<unsigned char>(*str)))
            return false;
        ++pat;
        ++str;
    }
    return !*str;
}

// A `Host` line applies when one of its patterns matches and none of its
// negated (`!`) patterns does.
bool HostLineMatches(const std::vector<std::string>& patterns, const std::string& alias)
{
    bool matched = false;
    for (const auto& p : patterns) {
        if (p.starts_with("!")) {
            if (WildcardMatch(p.c_str() + 1, alias.c_str()))
                return false;
        } else if (WildcardMatch(p.c_str(), alias.c_str())) {
            matched = true;
        }
    }
    return matched;
}

bool IsConcreteName(const std::string& p)
{
    return p.find_first_of("*?!") == std::string::npos;
}

struct HostConfig {
    std::string hostName, user, identityFile, proxyJump, proxyCommand;
    int         port = 0;
};

// What `ssh <alias>` would use: lines before the first `Host` apply to
// every host, `Match` blocks are skipped, and the first value seen for a
// keyword wins.
HostConfig Resolve(const std::vector<ConfigLine>& lines, const std::string& alias)
{
    HostConfig c;
    bool hasPort = false;
    bool active = true;
    for (const auto& l : lines) {
        if (l.key == "host")       { active = HostLineMatches(l.args, alias); continue; }
        if (l.key == "match")      { active = false; continue; }
        if (!active) continue;
        const std::string& v = l.args.front();
        if      (l.key == "hostname"     && c.hostName.empty())     c.hostName = v;
        else if (l.key == "user"         && c.user.empty())         c.user = v;
        else if (l.key == "identityfile" && c.identityFile.empty()) c.identityFile = v;
        else if (l.key == "proxyjump"    && c.proxyJump.empty())    c.proxyJump = v;
        else if (l.key == "proxycommand" && c.proxyCommand.empty()) {
            // The command runs to the end of the line, spaces included.
            for (const auto& a : l.args)
                c.proxyCommand += (c.proxyCommand.empty() ? "" : " ") + a;
        }
        else if (l.key == "port" && !hasPort) {
            c.port = std::atoi(v.c_str());
            hasPort = true;
        }
    }
    return c;
}

// The tokens `ssh` expands in paths and names: ~ at the start, %d home,
// %u local user, %h remote host, %r remote user, %% a percent sign.
std::string ExpandTokens(const std::string& in, const std::string& host, const std::string& user)
{
    std::string s = in;
    if (s.starts_with("~"))
        s = HomeDir() + s.substr(1);
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '%' || i + 1 >= s.size()) { out += s[i]; continue; }
        switch (s[++i]) {
            case 'd': out += HomeDir(); break;
            case 'u': out += LocalUserName(); break;
            case 'h': out += host; break;
            case 'r': out += user; break;
            case '%': out += '%'; break;
            default:  out += '%'; out += s[i]; break;
        }
    }
    return out;
}

bool IsNone(const std::string& v)
{
    return v.empty() || _stricmp(v.c_str(), "none") == 0;
}

std::wstring ChannelPath(const std::string& sourceOrigin)
{
    return sourceOrigin == "standard" ? StandardConfigPath() : AnsiToWide(sourceOrigin);
}

EnumerationResult EnumerateFile(const std::wstring& path, const std::string& sourceOrigin)
{
    EnumerationResult r;
    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (path.empty() || attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }
    std::vector<ConfigLine> lines;
    ParseFile(path, lines, 0);

    std::vector<std::string> seen;
    for (const auto& l : lines) {
        if (l.key != "host") continue;
        for (const auto& name : l.args) {
            if (!IsConcreteName(name)) continue;
            if (std::find(seen.begin(), seen.end(), Lower(name)) != seen.end()) continue;
            seen.push_back(Lower(name));
            ExternalSessionEntry e;
            e.displayName  = name;
            e.sourceOrigin = sourceOrigin;
            r.sessions.push_back(std::move(e));
        }
    }
    r.status = r.sessions.empty() ? EnumerationStatus::OkEmpty : EnumerationStatus::OkWithSessions;
    return r;
}

}  // namespace

bool OpenSshAdapter::DetectStandard() const noexcept
{
    const std::wstring p = StandardConfigPath();
    if (p.empty()) return false;
    const DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::string OpenSshAdapter::ChangeStamp() const
{
    const std::wstring path = StandardConfigPath();
    if (path.empty())
        return {};
    std::vector<ConfigLine> lines;
    VisitedFiles visited;
    ParseFile(path, lines, 0, &visited);

    return FileChangeStamp(visited);
}

std::string OpenSshAdapter::CustomPathStamp(const std::string& path) const
{
    std::vector<ConfigLine> lines;
    VisitedFiles visited;
    ParseFile(AnsiToWide(path), lines, 0, &visited);
    return FileChangeStamp(visited);
}

EnumerationResult OpenSshAdapter::EnumerateStandard()
{
    EnumerationResult r = EnumerateFile(StandardConfigPath(), "standard");
    SFTP_LOG("OPENSSH", "EnumerateStandard: status=%d hosts=%zu",
             static_cast<int>(r.status), r.sessions.size());
    return r;
}

EnumerationResult OpenSshAdapter::EnumerateCustomPath(const std::string& path)
{
    EnumerationResult r = EnumerateFile(AnsiToWide(path), path);
    SFTP_LOG("OPENSSH", "EnumerateCustomPath: status=%d hosts=%zu path='%s'",
             static_cast<int>(r.status), r.sessions.size(), path.c_str());
    return r;
}

bool OpenSshAdapter::LoadSettings(const ExternalSessionEntry& entry,
                                  pConnectSettings out,
                                  SessionDependency* dependency)
{
    if (!out) return false;
    const std::wstring path = ChannelPath(entry.sourceOrigin);
    if (path.empty()) return false;
    std::vector<ConfigLine> lines;
    ParseFile(path, lines, 0);
    if (lines.empty()) return false;

    const std::string& alias = entry.displayName;
    const HostConfig c = Resolve(lines, alias);

    const std::string host = c.hostName.empty() ? alias : ExpandTokens(c.hostName, alias, c.user);
    const std::string user = c.user.empty() ? LocalUserName() : c.user;
    out->server = (c.port > 0 && c.port != 22) ? host + ":" + std::to_string(c.port) : host;
    out->user   = user;
    // The config says nothing about encoding or line endings. Settling
    // them here spares the shell probes that would otherwise run on every
    // first connect — a few seconds on a router whose exec channel is
    // slow to open. UTF-8 and LF are what an OpenSSH user's servers use.
    out->utf8names      = 1;
    out->unixlinebreaks = 1;
    if (!c.identityFile.empty()) {
        std::string key = ExpandTokens(c.identityFile, host, user);
        std::replace(key.begin(), key.end(), '/', '\\');
        AssignImportedKeyFile(Utf8ToAnsi(key), out->privkeyfile, out->pubkeyfile);
    }

    // A command in front of the host is nothing the plugin can run.
    if (!IsNone(c.proxyCommand)) {
        if (dependency) {
            dependency->kind   = SessionDependency::Kind::Bastion;
            dependency->detail = "ProxyCommand " + c.proxyCommand;
        }
        return true;
    }

    // ProxyJump [user@]host[:port], one hop. The jump host is looked up as
    // an alias of its own, so its entry supplies what the spec leaves out;
    // a jump host that needs a jump or a command itself is a chain.
    if (!IsNone(c.proxyJump)) {
        auto refuse = [&] {
            if (dependency) {
                dependency->kind   = SessionDependency::Kind::Bastion;
                dependency->detail = "ProxyJump " + c.proxyJump;
            }
            return true;
        };
        if (c.proxyJump.find(',') != std::string::npos)
            return refuse();

        std::string spec = c.proxyJump, jumpUser, jumpAlias;
        int jumpPort = 0;
        if (const size_t at = spec.rfind('@'); at != std::string::npos) {
            jumpUser = spec.substr(0, at);
            spec = spec.substr(at + 1);
        }
        if (const size_t colon = spec.rfind(':'); colon != std::string::npos && spec.find(']') == std::string::npos) {
            jumpPort = std::atoi(spec.c_str() + colon + 1);
            spec = spec.substr(0, colon);
        }
        jumpAlias = spec;

        const HostConfig j = Resolve(lines, jumpAlias);
        if (!IsNone(j.proxyJump) || !IsNone(j.proxyCommand))
            return refuse();

        const std::string jumpHost = j.hostName.empty() ? jumpAlias : ExpandTokens(j.hostName, jumpAlias, j.user);
        if (jumpUser.empty())
            jumpUser = j.user.empty() ? LocalUserName() : j.user;
        if (jumpPort <= 0)
            jumpPort = j.port > 0 ? j.port : 22;

        out->use_jump_host = true;
        out->jump_host     = jumpHost;
        out->jump_port     = static_cast<unsigned short>(jumpPort);
        out->jump_user     = jumpUser;
        if (!j.identityFile.empty()) {
            std::string key = ExpandTokens(j.identityFile, jumpHost, jumpUser);
            std::replace(key.begin(), key.end(), '/', '\\');
            AssignImportedKeyFile(Utf8ToAnsi(key), out->jump_privkeyfile, out->jump_pubkeyfile);
        }
    }

    SFTP_LOG("OPENSSH", "LoadSettings '%s' server='%s' user='%s' key='%s' jump='%s'",
             alias.c_str(), out->server.c_str(), out->user.c_str(),
             out->privkeyfile.c_str(), out->jump_host.c_str());
    return true;
}

}  // namespace sftp

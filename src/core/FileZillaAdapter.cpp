#include "FileZillaAdapter.h"
#include "SftpClient.h"
#include "SftpInternal.h"     // EncryptString
#include "CoreUtils.h"        // MimeDecode (base64)
#include "global.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include "ImportIoUtil.h"
#include "PasswordCrypto.h"

#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace sftp {

namespace {

// FileZilla client stores its site manager in a single XML file that lives
// next to the user's application data. On portable installs the same file
// name appears wherever the user placed the FileZilla directory tree, so
// the custom channel just accepts an absolute path to that file.
constexpr const wchar_t* kStandardRelativePath = L"FileZilla\\sitemanager.xml";

std::wstring GetStandardSitemanagerPath()
{
    wchar_t buf[MAX_PATH] = {};
    HRESULT hr = SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr,
                                    SHGFP_TYPE_CURRENT, buf);
    if (FAILED(hr) || !buf[0]) return {};
    std::wstring full = buf;
    if (!full.empty() && full.back() != L'\\') full.push_back(L'\\');
    full += kStandardRelativePath;
    return full;
}

bool ReadFileAsBytes(const std::wstring& path, std::string& out)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (64 * 1024 * 1024)) {
        CloseHandle(h);
        return false;   // Refuse absurdly large files — sitemanager.xml is tiny.
    }
    out.resize(static_cast<size_t>(sz.QuadPart));
    DWORD read = 0;
    const BOOL ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(h);
    if (!ok || read != out.size()) { out.clear(); return false; }
    return true;
}

// FileZilla always writes UTF-8 (with or without BOM); a BE/LE UTF-16 BOM
// would mean the file was hand-edited in Notepad and is unusable, so just
// strip UTF-8 BOM if present.
void StripUtf8Bom(std::string& s)
{
    if (s.size() >= 3 &&
        static_cast<unsigned char>(s[0]) == 0xEF &&
        static_cast<unsigned char>(s[1]) == 0xBB &&
        static_cast<unsigned char>(s[2]) == 0xBF) {
        s.erase(0, 3);
    }
}

// -------------------------------------------------------------------------
// Minimal XML reader
//
// FileZilla sitemanager.xml is a well-known, machine-written file with a
// tiny subset of XML: elements, text nodes, and a handful of attributes.
// No DTDs, no namespaces, no processing instructions beyond the leading
// `<?xml ... ?>` prolog, no CDATA in the fields we read — a small hand-
// written parser is enough and keeps the plugin free of MSXML COM.
// -------------------------------------------------------------------------

struct XmlNode {
    std::string                                        name;
    std::vector<std::pair<std::string, std::string>>   attrs;
    std::string                                        text;   // concatenated direct text nodes
    std::vector<XmlNode>                               children;
};

std::string DecodeEntities(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ) {
        if (in[i] != '&') { out.push_back(in[i++]); continue; }
        const size_t semi = in.find(';', i + 1);
        if (semi == std::string::npos || semi - i > 8) {
            out.push_back(in[i++]);
            continue;
        }
        const std::string ent = in.substr(i + 1, semi - i - 1);
        if      (ent == "amp")  out.push_back('&');
        else if (ent == "lt")   out.push_back('<');
        else if (ent == "gt")   out.push_back('>');
        else if (ent == "quot") out.push_back('"');
        else if (ent == "apos") out.push_back('\'');
        else if (!ent.empty() && ent[0] == '#') {
            // Numeric char ref — best-effort, single byte only.
            const bool hex = ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X');
            unsigned cp = 0;
            const char* start = ent.c_str() + (hex ? 2 : 1);
            char* endp = nullptr;
            cp = static_cast<unsigned>(std::strtoul(start, &endp, hex ? 16 : 10));
            if (cp && cp < 0x80) {
                out.push_back(static_cast<char>(cp));
            } else if (cp < 0x800) {
                out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            } else if (cp < 0x10000) {
                out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            }
        } else {
            // Unknown entity — pass through literally.
            out.append(in, i, semi - i + 1);
        }
        i = semi + 1;
    }
    return out;
}

class XmlReader {
public:
    explicit XmlReader(const std::string& text) noexcept
        : m_p(text.data()), m_end(text.data() + text.size()) {}

    // Parse until the first non-prolog top-level element and return it.
    bool ParseDocument(XmlNode& out)
    {
        SkipTrivia();
        if (!ReadElement(out)) return false;
        return true;
    }

private:
    const char* m_p;
    const char* m_end;

    bool Eof() const noexcept { return m_p >= m_end; }

    void SkipWhitespace()
    {
        while (!Eof()) {
            const unsigned char c = static_cast<unsigned char>(*m_p);
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') ++m_p;
            else break;
        }
    }

    // Skip `<?xml ...?>`, `<!-- ... -->`, `<!DOCTYPE ...>` and whitespace.
    void SkipTrivia()
    {
        for (;;) {
            SkipWhitespace();
            if (Eof() || *m_p != '<') return;
            if (m_p + 1 >= m_end) return;
            const char c1 = m_p[1];
            if (c1 == '?') {
                const char* q = std::strstr(m_p, "?>");
                if (!q || q >= m_end) { m_p = m_end; return; }
                m_p = q + 2;
            } else if (c1 == '!') {
                if (m_p + 3 < m_end && m_p[2] == '-' && m_p[3] == '-') {
                    const char* e = std::strstr(m_p, "-->");
                    if (!e || e >= m_end) { m_p = m_end; return; }
                    m_p = e + 3;
                } else {
                    // <!DOCTYPE ...> or <![CDATA[...]]> — for our subset we
                    // only need to skip to the next matching '>'. Not fully
                    // correct for nested `[` … `]` but sitemanager.xml has
                    // neither DOCTYPE nor CDATA.
                    const char* e = static_cast<const char*>(
                        std::memchr(m_p, '>', m_end - m_p));
                    if (!e) { m_p = m_end; return; }
                    m_p = e + 1;
                }
            } else {
                return;
            }
        }
    }

    static bool IsNameStart(unsigned char c) noexcept
    {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               c == '_' || c == ':' || c >= 0x80;
    }
    static bool IsNameChar(unsigned char c) noexcept
    {
        return IsNameStart(c) || (c >= '0' && c <= '9') ||
               c == '-' || c == '.';
    }

    bool ReadName(std::string& out)
    {
        if (Eof() || !IsNameStart(static_cast<unsigned char>(*m_p))) return false;
        const char* start = m_p;
        while (!Eof() && IsNameChar(static_cast<unsigned char>(*m_p))) ++m_p;
        out.assign(start, m_p - start);
        return true;
    }

    bool ReadQuotedAttr(std::string& out)
    {
        if (Eof()) return false;
        const char q = *m_p;
        if (q != '"' && q != '\'') return false;
        ++m_p;
        const char* start = m_p;
        while (!Eof() && *m_p != q) ++m_p;
        if (Eof()) return false;
        out.assign(start, m_p - start);
        out = DecodeEntities(out);
        ++m_p;
        return true;
    }

    // Called with m_p pointing at the opening '<' of an element.
    bool ReadElement(XmlNode& node)
    {
        if (Eof() || *m_p != '<') return false;
        ++m_p;
        if (!ReadName(node.name)) return false;

        // Attributes.
        for (;;) {
            SkipWhitespace();
            if (Eof()) return false;
            if (*m_p == '>' || *m_p == '/') break;
            std::string aname, aval;
            if (!ReadName(aname)) return false;
            SkipWhitespace();
            if (Eof() || *m_p != '=') return false;
            ++m_p;
            SkipWhitespace();
            if (!ReadQuotedAttr(aval)) return false;
            node.attrs.emplace_back(std::move(aname), std::move(aval));
        }

        if (*m_p == '/') {
            // Self-closing element: <Foo/>.
            ++m_p;
            if (Eof() || *m_p != '>') return false;
            ++m_p;
            return true;
        }
        // Regular element: consume '>' then parse content.
        ++m_p;

        std::string textBuf;
        for (;;) {
            if (Eof()) return false;
            if (*m_p != '<') {
                textBuf.push_back(*m_p++);
                continue;
            }
            // '<' — could be child, comment, end tag.
            if (m_p + 1 < m_end && m_p[1] == '!') {
                // Comment or CDATA — skip cheaply.
                if (m_p + 3 < m_end && m_p[2] == '-' && m_p[3] == '-') {
                    const char* e = std::strstr(m_p, "-->");
                    if (!e || e >= m_end) return false;
                    m_p = e + 3;
                } else if (m_p + 8 < m_end && std::strncmp(m_p, "<![CDATA[", 9) == 0) {
                    const char* e = std::strstr(m_p, "]]>");
                    if (!e || e >= m_end) return false;
                    textBuf.append(m_p + 9, e - (m_p + 9));
                    m_p = e + 3;
                } else {
                    const char* e = static_cast<const char*>(
                        std::memchr(m_p, '>', m_end - m_p));
                    if (!e) return false;
                    m_p = e + 1;
                }
                continue;
            }
            if (m_p + 1 < m_end && m_p[1] == '/') {
                // End tag: </Name>
                m_p += 2;
                std::string endName;
                if (!ReadName(endName)) return false;
                SkipWhitespace();
                if (Eof() || *m_p != '>') return false;
                ++m_p;
                if (endName != node.name) {
                    SFTP_LOG("FILEZILLA", "  XML: end-tag mismatch open='%s' close='%s'",
                             node.name.c_str(), endName.c_str());
                    return false;
                }
                node.text = DecodeEntities(textBuf);
                return true;
            }
            // Child element.
            XmlNode child;
            if (!ReadElement(child)) return false;
            node.children.push_back(std::move(child));
        }
    }
};

// Trim ASCII whitespace on both ends. Used on element text nodes — the
// name of a session is the trimmed text of its `<Server>` element.
std::string TrimAscii(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && (unsigned char)s[a] <= 0x20) ++a;
    while (b > a && (unsigned char)s[b - 1] <= 0x20) --b;
    return s.substr(a, b - a);
}

const XmlNode* FindChild(const XmlNode& parent, const char* name) noexcept
{
    for (const auto& c : parent.children)
        if (_stricmp(c.name.c_str(), name) == 0) return &c;
    return nullptr;
}

std::string ChildText(const XmlNode& parent, const char* name)
{
    const XmlNode* c = FindChild(parent, name);
    return c ? TrimAscii(c->text) : std::string();
}

// FileZilla stores the display name of a `<Server>` or `<Folder>` element
// as its text node — not as a child `<Name>` element. Preserve that but
// also fall back to `<Name>` for very old / hand-edited files.
std::string ElementDisplayName(const XmlNode& node)
{
    std::string t = TrimAscii(node.text);
    if (!t.empty()) return t;
    return ChildText(node, "Name");
}

// FileZilla `<Protocol>` numeric enum stored in sitemanager.xml.
// Only SFTP is in scope for this plugin — everything else is skipped.
//   0 = FTP (with optional encryption)
//   1 = SFTP                                    ← accepted
//   3 = FTPS (implicit)
//   4 = FTPES (explicit)
//   5 = INSECURE_FTP
//   6 = INSECURE_WEBDAV
//   7 = WEBDAV                                  (non-numeric in newer builds)
//   8 = S3
// Anything else is a non-SSH transport we cannot serve.
bool ProtocolIsSftp(int protoRaw) noexcept { return protoRaw == 1; }

// -------------------------------------------------------------------------
// Session tree walk
//
// Sessions live under <Servers>. Each direct child of <Servers> is either
// another <Server> (a leaf) or a <Folder> (a subtree). Flatten the tree
// to `/`-joined display names so nested folders render as nested
// subfolders in the panel.
// -------------------------------------------------------------------------

void CollectSessions(const XmlNode& node,
                     const std::string& prefix,
                     const std::string& sourceOrigin,
                     EnumerationResult& r)
{
    for (const auto& child : node.children) {
        if (_stricmp(child.name.c_str(), "Server") == 0) {
            // Skip non-SFTP entries so FTP / FTPS / S3 / WebDAV rows do
            // not appear in the panel only to fail silently on Enter.
            const std::string protoStr = ChildText(child, "Protocol");
            const int protoRaw = protoStr.empty() ? 0 : std::atoi(protoStr.c_str());
            if (!ProtocolIsSftp(protoRaw)) continue;

            std::string leaf = ElementDisplayName(child);
            if (leaf.empty()) leaf = ChildText(child, "Host");
            if (leaf.empty()) continue;
            std::string full = prefix.empty() ? leaf : (prefix + "/" + leaf);

            ExternalSessionEntry e;
            e.displayName  = std::move(full);
            e.sourceOrigin = sourceOrigin;
            r.sessions.push_back(std::move(e));
        } else if (_stricmp(child.name.c_str(), "Folder") == 0) {
            std::string folderName = ElementDisplayName(child);
            if (folderName.empty()) folderName = "(unnamed)";
            std::string newPrefix = prefix.empty()
                ? folderName
                : (prefix + "/" + folderName);
            CollectSessions(child, newPrefix, sourceOrigin, r);
        }
    }
}

// Locate a specific <Server> node by its flattened DisplayName path.
// Returns nullptr when the path no longer matches — the sitemanager.xml
// may have been edited between enumeration and the LoadSettings call.
const XmlNode* FindServerByPath(const XmlNode& node,
                                 const std::string& path,
                                 const std::string& prefix)
{
    for (const auto& child : node.children) {
        if (_stricmp(child.name.c_str(), "Server") == 0) {
            std::string leaf = ElementDisplayName(child);
            if (leaf.empty()) leaf = ChildText(child, "Host");
            if (leaf.empty()) continue;
            std::string full = prefix.empty() ? leaf : (prefix + "/" + leaf);
            if (full == path) return &child;
        } else if (_stricmp(child.name.c_str(), "Folder") == 0) {
            std::string folderName = ElementDisplayName(child);
            if (folderName.empty()) folderName = "(unnamed)";
            std::string newPrefix = prefix.empty()
                ? folderName
                : (prefix + "/" + folderName);
            const XmlNode* hit = FindServerByPath(child, path, newPrefix);
            if (hit) return hit;
        }
    }
    return nullptr;
}

// Load `<Servers>` root from an XML file path. Returns false if the
// file is missing / malformed / lacks the expected root elements.
bool LoadServersRoot(const std::wstring& xmlPath, XmlNode& outServers)
{
    std::string bytes;
    if (!ReadFileAsBytes(xmlPath, bytes)) return false;
    StripUtf8Bom(bytes);

    XmlNode doc;
    XmlReader reader(bytes);
    if (!reader.ParseDocument(doc)) return false;

    // Root should be <FileZilla3>, containing exactly one <Servers>.
    const XmlNode* servers = FindChild(doc, "Servers");
    if (!servers) return false;
    outServers = *servers;   // copy (small)
    return true;
}

// Enumerate a specific XML file into `r`. Used by both the standard
// and portable channels — they only differ by which path they hand in.
EnumerationResult EnumerateFile(const std::wstring& xmlPath,
                                 const std::string& sourceOrigin)
{
    EnumerationResult r;

    const DWORD attrs = GetFileAttributesW(xmlPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    XmlNode servers;
    if (!LoadServersRoot(xmlPath, servers)) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    CollectSessions(servers, "", sourceOrigin, r);

    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

}  // namespace

bool FileZillaAdapter::DetectStandard() const noexcept
{
    const std::wstring p = GetStandardSitemanagerPath();
    if (p.empty()) return false;
    const DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::string FileZillaAdapter::ChangeStamp() const
{
    const std::wstring p = GetStandardSitemanagerPath();
    if (p.empty()) return {};
    const size_t slash = p.find_last_of(L'\\');
    return FileChangeStamp({ p, p.substr(0, slash + 1) + L"filezilla.xml" });
}

std::string FileZillaAdapter::CustomPathStamp(const std::string& path) const
{
    const std::wstring p = AnsiPathToWide(path);
    const size_t slash = p.find_last_of(L'\\');
    if (slash == std::wstring::npos) return FileChangeStamp({ p });
    return FileChangeStamp({ p, p.substr(0, slash + 1) + L"filezilla.xml" });
}

EnumerationResult FileZillaAdapter::EnumerateStandard()
{
    const std::wstring p = GetStandardSitemanagerPath();
    SFTP_LOG("FILEZILLA", "EnumerateStandard: path present=%d", !p.empty());
    if (p.empty()) {
        EnumerationResult r;
        r.status = EnumerationStatus::Unreachable;
        return r;
    }
    EnumerationResult r = EnumerateFile(p, "standard");
    SFTP_LOG("FILEZILLA", "EnumerateStandard done: status=%d sessions=%zu",
             static_cast<int>(r.status), r.sessions.size());
    return r;
}

EnumerationResult FileZillaAdapter::EnumerateCustomPath(const std::string& path)
{
    // The picker delivers an ANSI path — round-trip through UTF-8→wide so
    // non-ASCII directory names in the user's chosen file survive.
    std::wstring wide(MAX_PATH, L'\0');
    const int n = MultiByteToWideChar(CP_ACP, 0, path.c_str(),
                                        static_cast<int>(path.size()),
                                        wide.data(), static_cast<int>(wide.size()));
    if (n <= 0) {
        EnumerationResult r;
        r.status = EnumerationStatus::Unreachable;
        return r;
    }
    wide.resize(n);

    EnumerationResult r = EnumerateFile(wide, path);
    SFTP_LOG("FILEZILLA", "EnumerateCustomPath done: status=%d sessions=%zu path='%s'",
             static_cast<int>(r.status), r.sessions.size(), path.c_str());
    return r;
}

// FileZilla keeps one proxy for the whole program in `filezilla.xml`, beside
// `sitemanager.xml`; a site says only whether it opts out. So the question
// "does this site go through a proxy" is answered by two files, and a site
// that opts out is unaffected however the global setting is configured.
// A proxy of a kind the plugin speaks is described in `dep` so the site can
// be copied with it; any other kind is only marked, and stays a refusal.
static void DescribeGlobalProxy(const std::wstring& sitemanagerPath, SessionDependency& dep)
{
    const size_t slash = sitemanagerPath.find_last_of(L'\\');
    if (slash == std::wstring::npos)
        return;
    const std::wstring settingsPath =
        sitemanagerPath.substr(0, slash + 1) + L"filezilla.xml";

    std::string text;
    if (!ReadFileAsBytes(settingsPath, text))
        return;

    // The settings file is a flat list of <Setting name="...">value</Setting>,
    // so it is read by name rather than walked as a tree.
    auto settingValue = [&text](const char* name) -> std::string {
        const std::string open = std::string("<Setting name=\"") + name + "\">";
        const size_t at = text.find(open);
        if (at == std::string::npos)
            return {};
        const size_t from = at + open.size();
        const size_t to = text.find('<', from);
        return to == std::string::npos ? std::string() : DecodeEntities(text.substr(from, to - from));
    };

    const int method = std::atoi(settingValue("Proxy type").c_str());
    if (method == 0)
        return;

    const std::string host = settingValue("Proxy host");
    dep.kind   = SessionDependency::Kind::Proxy;
    dep.detail = host;

    // FileZilla numbers its generic proxy 1 HTTP, 2 SOCKS5, 3 SOCKS4.
    Proxy type{};
    switch (method) {
        case 1: type = Proxy::http;   break;
        case 2: type = Proxy::socks5; break;
        case 3: type = Proxy::socks4; break;
        default: return;
    }
    const int port = std::atoi(settingValue("Proxy port").c_str());
    DescribeProxy(type, host, port > 0 ? static_cast<DWORD>(port) : 0,
                  settingValue("Proxy user"), dep);
}

bool FileZillaAdapter::LoadSettings(const ExternalSessionEntry& entry,
                                     pConnectSettings out,
                                     SessionDependency* dependency)
{
    if (!out) return false;

    // Pick the sitemanager.xml path for the entry's channel. Standard
    // entries resolve to %APPDATA%\FileZilla\sitemanager.xml; portable
    // entries carry the literal picked path in sourceOrigin.
    std::wstring xmlPath;
    if (entry.sourceOrigin == "standard") {
        xmlPath = GetStandardSitemanagerPath();
    } else {
        std::wstring wide(MAX_PATH, L'\0');
        const int n = MultiByteToWideChar(CP_ACP, 0,
                                            entry.sourceOrigin.c_str(),
                                            static_cast<int>(entry.sourceOrigin.size()),
                                            wide.data(),
                                            static_cast<int>(wide.size()));
        if (n <= 0) return false;
        wide.resize(n);
        xmlPath = std::move(wide);
    }
    if (xmlPath.empty()) return false;

    XmlNode servers;
    if (!LoadServersRoot(xmlPath, servers)) return false;

    const XmlNode* srv = FindServerByPath(servers, entry.displayName, "");
    if (!srv) {
        SFTP_LOG("FILEZILLA", "LoadSettings: server not found for path='%s'",
                 entry.displayName.c_str());
        return false;
    }

    // Protocol gate — anything that is not SFTP silently disappears.
    // Absent <Protocol> defaults to 0 (FTP) which is unsupported, so
    // the check also excludes malformed / partial rows.
    const std::string protoStr = ChildText(*srv, "Protocol");
    const int protoRaw = protoStr.empty() ? 0 : std::atoi(protoStr.c_str());
    if (!ProtocolIsSftp(protoRaw)) {
        SFTP_LOG("FILEZILLA", "  protocol %d — skipped", protoRaw);
        return false;
    }

    const std::string host = ChildText(*srv, "Host");
    if (host.empty()) return false;

    if (dependency && ChildText(*srv, "BypassProxy") != "1")
        DescribeGlobalProxy(xmlPath, *dependency);

    const std::string portStr = ChildText(*srv, "Port");
    const int port = portStr.empty() ? 0 : std::atoi(portStr.c_str());

    if (port > 0 && port != 22) {
        char portBuf[16];
        std::snprintf(portBuf, sizeof(portBuf), ":%d", port);
        out->server = host + portBuf;
    } else {
        out->server = host;
    }

    const std::string user = ChildText(*srv, "User");
    if (!user.empty()) out->user = user;

    // <Keyfile> holds the private-key path for LogonType 4 (Key file).
    // Absent for any other LogonType.
    std::string keyFile = ExpandEnvA(ChildText(*srv, "Keyfile"));
    AssignImportedKeyFile(keyFile, out->privkeyfile, out->pubkeyfile);

    // <EncodingType>: "Auto" → leave defaults; "UTF-8" → utf8=1;
    // "Custom" → resolve via <CustomEncoding>. Any other literal (rare)
    // is passed to ParseLineCodePage as-is.
    const std::string encType   = ChildText(*srv, "EncodingType");
    const std::string customEnc = ChildText(*srv, "CustomEncoding");
    std::string encName;
    if (_stricmp(encType.c_str(), "UTF-8") == 0)      encName = "UTF-8";
    else if (_stricmp(encType.c_str(), "Custom") == 0) encName = customEnc;
    else if (!encType.empty() &&
             _stricmp(encType.c_str(), "Auto") != 0)   encName = encType;

    if (!encName.empty()) {
        int cpUtf8 = 0, cpNum = 0;
        if (ParseLineCodePage(encName, cpUtf8, cpNum)) {
            out->utf8names = static_cast<char>(cpUtf8);
            if (!cpUtf8 && cpNum > 0) out->codepage = cpNum;
        }
    }

    // Optional password import. `<Pass encoding="base64">` is a plain
    // reversible obfuscation FileZilla writes when the "Save password"
    // radio is chosen. Master-password mode uses `encoding="crypt"`
    // (Argon2 + AES-GCM under the master password) — skipped, the plugin
    // falls back to the interactive prompt on connect.
    const XmlNode* passNode = FindChild(*srv, "Pass");
    if (passNode) {
        std::string encAttr;
        for (const auto& a : passNode->attrs) {
            if (_stricmp(a.first.c_str(), "encoding") == 0) { encAttr = a.second; break; }
        }
        const std::string b64 = TrimAscii(passNode->text);
        if (!b64.empty() && _stricmp(encAttr.c_str(), "base64") == 0) {
            std::vector<char> decoded(b64.size());
            const int n = MimeDecode(b64.c_str(), b64.size(),
                                       decoded.data(), decoded.size());
            if (n > 0) {
                out->password = password_crypto::Protect({ decoded.data(), static_cast<size_t>(n) });
            }
            sftp::SecureWipe(decoded);
        }
    }

    SFTP_LOG("FILEZILLA",
             "LoadSettings ok display='%s' server='%s' user='%s' pass=%s",
             entry.displayName.c_str(), out->server.c_str(),
             out->user.c_str(), out->password.empty() ? "no" : "yes");
    return true;
}

}  // namespace sftp

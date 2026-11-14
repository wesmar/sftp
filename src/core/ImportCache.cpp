#include "ImportCache.h"
#include "ImportIoUtil.h"
#include "PluginEntryPointsInternal.h"
#include "SftpClient.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>
#include <vector>

namespace sftp {

namespace {

constexpr const char* kSectionPrefix    = "__import.";
constexpr size_t      kSectionPrefixLen = 9;

// Resolve on-disk cache path from the plugin's inifilename[] global.
// Cache file lives in the same directory as sftpplug.ini.
std::string ResolveCachePath()
{
    if (inifilename[0] == '\0')
        return {};
    std::string p(inifilename);
    const size_t sep = p.find_last_of("\\/");
    std::string dir = (sep == std::string::npos) ? std::string(".") : p.substr(0, sep);
    return dir + "\\sftpplug-imports-cache.ini";
}

std::string ChannelTag(std::string_view channel) noexcept
{
    char buf[16];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%08x", Fnv1aHash(channel));
    return buf;
}

// Split "__import.<sourceId>.<channelTag>.<displayName>" back into
// components. Both sourceId and channelTag are `.`-free — sourceId is a
// fixed adapter identifier (e.g. "securecrt") and channelTag is 8 hex
// chars — so the first two `.` separators are unambiguous. displayName
// can contain `.` freely and is whatever follows.
bool ParseSectionName(const std::string& section,
                      std::string& outSourceId,
                      std::string& outChannelTag,
                      std::string& outDisplayName)
{
    if (section.compare(0, kSectionPrefixLen, kSectionPrefix) != 0)
        return false;
    const size_t dot1 = section.find('.', kSectionPrefixLen);
    if (dot1 == std::string::npos) return false;
    const size_t dot2 = section.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return false;
    outSourceId    = section.substr(kSectionPrefixLen, dot1 - kSectionPrefixLen);
    outChannelTag  = section.substr(dot1 + 1, dot2 - dot1 - 1);
    outDisplayName = section.substr(dot2 + 1);
    return true;
}

std::string ReadSourceTag(const std::string& section, const std::string& iniPath)
{
    std::array<char, 512> buf{};
    GetPrivateProfileStringA(section.c_str(), "_source", "",
                              buf.data(), static_cast<DWORD>(buf.size()),
                              iniPath.c_str());
    return buf.data();
}

// The dependency is stored under keys prefixed with `_`, the same shape the
// channel tag uses: metadata about the row rather than a field of the session.
const char* DependencyKindTag(SessionDependency::Kind kind)
{
    switch (kind) {
        case SessionDependency::Kind::Proxy:   return "proxy";
        case SessionDependency::Kind::Bastion: return "bastion";
        case SessionDependency::Kind::Tunnel:  return "tunnel";
        case SessionDependency::Kind::None:    break;
    }
    return "";
}

// Persist one adapter-produced session as an INI section.
//
// Contract: the adapter populates any subset of tConnectSettings it can
// recover; the writer persists exactly the fields that carry a non-sentinel
// value. Sentinel = "adapter did not touch this key":
//   * std::string  — empty
//   * bool         — false
//   * utf8names / unixlinebreaks — -1 (the tri-state "auto")
// A field left at its sentinel means "unknown, don't cache" (not "off"):
// downstream materialise omits the corresponding INI key and native code
// paths fall back to their own defaults.
void WriteSessionSection(const std::string& section,
                         const std::string& iniPath,
                         const tConnectSettings* s,
                         const std::string& sourceOrigin)
{
    // Clear any previous section content, then rewrite.
    WritePrivateProfileStringA(section.c_str(), nullptr, nullptr, iniPath.c_str());
    if (!s) return;

    // Channel provenance tag. Always present.
    WritePrivateProfileStringA(section.c_str(), "_source",
                                sourceOrigin.c_str(), iniPath.c_str());

    if (!s->server.empty())
        WritePrivateProfileStringA(section.c_str(), "server",
                                    s->server.c_str(), iniPath.c_str());
    if (!s->user.empty())
        WritePrivateProfileStringA(section.c_str(), "user",
                                    s->user.c_str(), iniPath.c_str());
    if (!s->pubkeyfile.empty())
        WritePrivateProfileStringA(section.c_str(), "pubkeyfile",
                                    s->pubkeyfile.c_str(), iniPath.c_str());
    if (!s->privkeyfile.empty())
        WritePrivateProfileStringA(section.c_str(), "privkeyfile",
                                    s->privkeyfile.c_str(), iniPath.c_str());
    if (s->useagent)
        WritePrivateProfileStringA(section.c_str(), "useagent",
                                    "1", iniPath.c_str());

    // SCP-only transfer mode. Populated by adapters whose source can
    // configure a session for SCP instead of SFTP (WinSCP with
    // FSProtocol == 1). Persisted as "1" only — a default `false` is
    // the sentinel meaning "adapter did not set this"; unsetting an
    // existing scponly flag would need explicit "0", which no adapter
    // currently does.
    if (s->scponly)
        WritePrivateProfileStringA(section.c_str(), "scponly",
                                    "1", iniPath.c_str());
    if (s->scpfordata)
        WritePrivateProfileStringA(section.c_str(), "scpfordata",
                                    "1", iniPath.c_str());

    // Password is stored DPAPI-obfuscated — the same shape sftpplug.ini uses.
    if (!s->password.empty())
        WritePrivateProfileStringA(section.c_str(), "password",
                                    s->password.c_str(), iniPath.c_str());

    // utf8names / unixlinebreaks are tri-state (-1 = auto, 0 = no, 1 = yes).
    // -1 means "not populated by the adapter" — skip.
    if (s->utf8names == 0 || s->utf8names == 1)
        WritePrivateProfileStringA(section.c_str(), "utf8",
                                    s->utf8names == 1 ? "1" : "0",
                                    iniPath.c_str());
    if (s->unixlinebreaks == 0 || s->unixlinebreaks == 1)
        WritePrivateProfileStringA(section.c_str(), "unixlinebreaks",
                                    s->unixlinebreaks == 1 ? "1" : "0",
                                    iniPath.c_str());

    // codepage: 0 = not populated. Meaningful only when utf8names == 0;
    // adapters that map LineCodePage-style names write both — utf8names=0
    // plus a numeric Windows codepage.
    if (s->codepage > 0) {
        char cpBuf[16];
        std::snprintf(cpBuf, sizeof(cpBuf), "%d", s->codepage);
        WritePrivateProfileStringA(section.c_str(), "codepage",
                                    cpBuf, iniPath.c_str());
    }

    // scpserver64bit is tri-state (-1 = auto, 0 = no, 1 = yes) and is
    // persisted under the INI key `largefilesupport`. Written explicitly
    // as 0 for SCP-only sessions so the plugin skips the >2 GB shell probe.
    if (s->scpserver64bit == 0 || s->scpserver64bit == 1)
        WritePrivateProfileStringA(section.c_str(), "largefilesupport",
                                    s->scpserver64bit == 1 ? "1" : "0",
                                    iniPath.c_str());

    // Jump host, under the same keys a saved session uses, so connecting,
    // copying and exporting the row all take it along. Written only with a
    // host to go through; the port only when it is not the default 22.
    if (s->use_jump_host && !s->jump_host.empty()) {
        WritePrivateProfileStringA(section.c_str(), "usejumphost",
                                    "1", iniPath.c_str());
        WritePrivateProfileStringA(section.c_str(), "jumphost",
                                    s->jump_host.c_str(), iniPath.c_str());
        if (s->jump_port != 0 && s->jump_port != 22)
            WritePrivateProfileStringA(section.c_str(), "jumpport",
                                        std::to_string(s->jump_port).c_str(),
                                        iniPath.c_str());
        if (!s->jump_user.empty())
            WritePrivateProfileStringA(section.c_str(), "jumpuser",
                                        s->jump_user.c_str(), iniPath.c_str());
        if (!s->jump_pubkeyfile.empty())
            WritePrivateProfileStringA(section.c_str(), "jumppubkeyfile",
                                        s->jump_pubkeyfile.c_str(), iniPath.c_str());
        if (!s->jump_privkeyfile.empty())
            WritePrivateProfileStringA(section.c_str(), "jumpprivkeyfile",
                                        s->jump_privkeyfile.c_str(), iniPath.c_str());
        if (s->jump_useagent)
            WritePrivateProfileStringA(section.c_str(), "jumpuseagent",
                                        "1", iniPath.c_str());
    }
}

}  // namespace

ImportCache& GetImportCache()
{
    static ImportCache instance;
    // Load the on-disk cache exactly once, right after the singleton is
    // constructed. Uses a local-static-with-lambda so C++11's thread-safe
    // static init guarantees Load() runs at most once even if the first
    // access races between panel threads. Without this call the in-memory
    // map stays empty across TC restarts and every [Imports]\<Source>\
    // listing shows only the pseudo entries until the user hits [Refresh],
    // even though the cache file on disk is intact.
    [[maybe_unused]] static const bool _loaded = (instance.Load(), true);
    return instance;
}

ImportCache::ImportCache()
    : m_cachePath(ResolveCachePath())
{
}

std::string ImportCache::SectionName(const std::string& sourceId,
                                      const std::string& channel,
                                      const std::string& displayName) noexcept
{
    return std::string(kSectionPrefix) + sourceId + "." +
           ChannelTag(channel) + "." + displayName;
}

std::string ImportCache::SectionNameForConnect(const std::string& sourceId,
                                                const std::string& displayName) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& r : m_sessions) {
        if (r.sourceId == sourceId && r.displayName == displayName)
            return SectionName(sourceId, r.sourceOrigin, displayName);
    }
    return {};
}

void ImportCache::Load()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_loaded) return;
    m_loaded = true;

    // Cache path may resolve empty if Load() is called before FsSetDefaultParams
    // has populated inifilename[]. In that case we silently skip; the next
    // access is expected to happen after plugin init.
    if (m_cachePath.empty())
        return;

    // Enumerate every section in the cache INI, filter by our prefix,
    // reconstruct in-memory refs. Read _source tag inline to remember
    // channel provenance across TC restarts.
    std::vector<char> buf(65536, '\0');
    const DWORD len = GetPrivateProfileSectionNamesA(buf.data(),
                                                      static_cast<DWORD>(buf.size()),
                                                      m_cachePath.c_str());
    if (len == 0) return;

    const char* p = buf.data();
    while (*p) {
        const std::string section(p);
        p += section.size() + 1;

        std::string sourceId, channelTag, displayName;
        if (!ParseSectionName(section, sourceId, channelTag, displayName))
            continue;

        CachedSessionRef ref;
        ref.sourceId     = std::move(sourceId);
        ref.displayName  = std::move(displayName);
        // sourceOrigin is the literal channel string (e.g. "standard" or a
        // Windows path); it's stored inside the section as `_source`. We
        // cannot recover it from the hashed channelTag alone.
        ref.sourceOrigin = ReadSourceTag(section, m_cachePath);
        m_sessions.push_back(std::move(ref));
    }
}

std::vector<CachedSessionRef>
ImportCache::ListSource(const std::string& sourceId) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<CachedSessionRef> out;
    for (const auto& s : m_sessions) {
        if (s.sourceId == sourceId)
            out.push_back(s);
    }
    return out;
}

bool ImportCache::HasSession(const std::string& sourceId,
                             const std::string& displayName) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& s : m_sessions) {
        if (s.sourceId == sourceId &&
            _stricmp(s.displayName.c_str(), displayName.c_str()) == 0)
            return true;
    }
    return false;
}

// Sections are per (sourceId, channel, displayName) — each channel owns
// its own set of disk sections and independent memory refs. Prune and
// Replace touch only the requested channel's rows; other channels are
// oblivious. Display-time de-duplication in BuildImportsSourceListing
// hides the fact that multiple channels can share a displayName.
void ImportCache::EraseChannelLocked(const std::string& sourceId,
                                      const std::string& channel)
{
    auto is_target = [&](const CachedSessionRef& r) {
        return r.sourceId == sourceId && r.sourceOrigin == channel;
    };
    for (const auto& r : m_sessions) {
        if (is_target(r)) {
            const std::string section = SectionName(r.sourceId, channel, r.displayName);
            WritePrivateProfileStringA(section.c_str(), nullptr, nullptr,
                                        m_cachePath.c_str());
        }
    }
    m_sessions.erase(
        std::remove_if(m_sessions.begin(), m_sessions.end(), is_target),
        m_sessions.end());
}

SessionDependency ImportCache::ReadDependency(const std::string& section,
                                              const std::string& iniPath)
{
    SessionDependency out;
    std::array<char, 32> kind{};
    GetPrivateProfileStringA(section.c_str(), "_blocked", "",
                              kind.data(), static_cast<DWORD>(kind.size()),
                              iniPath.c_str());
    if (!kind[0])
        return out;

    if (_stricmp(kind.data(), "proxy") == 0)
        out.kind = SessionDependency::Kind::Proxy;
    else if (_stricmp(kind.data(), "tunnel") == 0)
        out.kind = SessionDependency::Kind::Tunnel;
    else
        out.kind = SessionDependency::Kind::Bastion;

    std::array<char, 512> via{};
    GetPrivateProfileStringA(section.c_str(), "_blockedvia", "",
                              via.data(), static_cast<DWORD>(via.size()),
                              iniPath.c_str());
    out.detail = via.data();

    // Present only when the adapter could describe the proxy in our terms.
    const int proxyType = static_cast<int>(
        GetPrivateProfileIntA(section.c_str(), "_blockedproxytype", 0, iniPath.c_str()));
    if (proxyType > 0) {
        std::array<char, 512> server{};
        std::array<char, 512> user{};
        GetPrivateProfileStringA(section.c_str(), "_blockedproxyserver", "",
                                  server.data(), static_cast<DWORD>(server.size()),
                                  iniPath.c_str());
        GetPrivateProfileStringA(section.c_str(), "_blockedproxyuser", "",
                                  user.data(), static_cast<DWORD>(user.size()),
                                  iniPath.c_str());
        out.proxyType   = static_cast<Proxy>(proxyType);
        out.proxyServer = server.data();
        out.proxyUser   = user.data();
    }
    return out;
}

void ImportCache::ReplaceChannel(const std::string& sourceId,
                                  const std::string& channel,
                                  const std::vector<CacheWriteEntry>& newSessions)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_cachePath.empty()) return;

    // What connecting wrote into a row — an accepted host key, a probe's
    // answer — is not in the source and would be lost with the row. Keep it
    // across the rewrite while the row still names the same host: a host
    // key belongs to the host, so a changed address asks again.
    struct Learned {
        std::string server, jumphost;
        std::vector<std::pair<const char*, std::string>> keys;
    };
    static constexpr const char* kLearnedKeys[] = {
        "fingerprint", "jumpfingerprint", "utf8", "unixlinebreaks", "largefilesupport" };
    auto readKey = [this](const std::string& section, const char* key) {
        std::array<char, 512> buf{};
        GetPrivateProfileStringA(section.c_str(), key, "", buf.data(),
                                 static_cast<DWORD>(buf.size()), m_cachePath.c_str());
        return std::string(buf.data());
    };
    std::vector<Learned> learned(newSessions.size());
    for (size_t i = 0; i < newSessions.size(); ++i) {
        const std::string section = SectionName(sourceId, channel, newSessions[i].displayName);
        learned[i].server   = readKey(section, "server");
        learned[i].jumphost = readKey(section, "jumphost");
        for (const char* key : kLearnedKeys) {
            std::string v = readKey(section, key);
            if (!v.empty())
                learned[i].keys.emplace_back(key, std::move(v));
        }
    }

    EraseChannelLocked(sourceId, channel);

    // Add the new scan results as fresh sections + memory refs. All rows
    // added here share the same `channel` provenance, so a later
    // PruneChannel or [Manage custom locations] removal (also keyed on
    // channel) matches every row this call inserted.
    for (size_t i = 0; i < newSessions.size(); ++i) {
        const auto& w = newSessions[i];
        const std::string section =
            SectionName(sourceId, channel, w.displayName);
        WriteSessionSection(section, m_cachePath, w.settings, channel);

        // Back only where the adapter wrote nothing, and only for the same
        // host; the jump host's key only for the same jump host.
        const Learned& old = learned[i];
        const bool sameHost = !old.server.empty() && old.server == readKey(section, "server");
        const bool sameJump = !old.jumphost.empty() && old.jumphost == readKey(section, "jumphost");
        for (const auto& [key, value] : old.keys) {
            const bool isJumpKey = std::strcmp(key, "jumpfingerprint") == 0;
            if (!(isJumpKey ? sameJump : sameHost) || !readKey(section, key).empty())
                continue;
            WritePrivateProfileStringA(section.c_str(), key, value.c_str(), m_cachePath.c_str());
        }
        if (w.dependency.blocks()) {
            WritePrivateProfileStringA(section.c_str(), "_blocked",
                                        DependencyKindTag(w.dependency.kind),
                                        m_cachePath.c_str());
            if (!w.dependency.detail.empty())
                WritePrivateProfileStringA(section.c_str(), "_blockedvia",
                                            w.dependency.detail.c_str(),
                                            m_cachePath.c_str());
            if (w.dependency.transferable()) {
                const std::string type =
                    std::to_string(static_cast<int>(w.dependency.proxyType));
                WritePrivateProfileStringA(section.c_str(), "_blockedproxytype",
                                            type.c_str(), m_cachePath.c_str());
                WritePrivateProfileStringA(section.c_str(), "_blockedproxyserver",
                                            w.dependency.proxyServer.c_str(),
                                            m_cachePath.c_str());
                if (!w.dependency.proxyUser.empty())
                    WritePrivateProfileStringA(section.c_str(), "_blockedproxyuser",
                                                w.dependency.proxyUser.c_str(),
                                                m_cachePath.c_str());
            }
        }
        CachedSessionRef ref;
        ref.sourceId     = sourceId;
        ref.displayName  = w.displayName;
        ref.sourceOrigin = channel;
        m_sessions.push_back(std::move(ref));
    }
}

void ImportCache::PruneChannel(const std::string& sourceId,
                                const std::string& channel)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_cachePath.empty()) return;
    EraseChannelLocked(sourceId, channel);
}

}  // namespace sftp

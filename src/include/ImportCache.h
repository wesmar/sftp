#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "IExternalSessionSource.h"

struct tConnectSettings;
typedef tConnectSettings* pConnectSettings;

namespace sftp {

// Lightweight reference to one cached session. Held in the in-memory map;
// enough for enumeration. Actual field values live in the on-disk cache INI
// and are read via LoadServerSettings when a virtual session is connected.
struct CachedSessionRef {
    std::string sourceId;       // "securecrt", "putty", ...
    std::string displayName;    // "dron/hz-1"
    std::string sourceOrigin;   // "standard" | literal custom path
};

// One session about to be persisted: display name plus a non-owning pointer
// to filled tConnectSettings. The pointer must outlive the ReplaceChannel
// call. The channel string is passed once to ReplaceChannel, not per entry.
struct CacheWriteEntry {
    std::string             displayName;
    const tConnectSettings* settings;
    SessionDependency       dependency;   // why the session must refuse, if it must
};

class ImportCache {
public:
    // Read cache INI from disk into memory. Called once at plugin startup
    // (idempotent — subsequent calls no-op).
    void Load();

    // Path to the on-disk cache INI. Used by LoadServerSettings during
    // virtual session connect.
    const std::string& CacheFilePath() const noexcept { return m_cachePath; }

    // Full on-disk INI section name for a channel-specific entry:
    // "__import.<sourceId>.<channelTag>.<displayName>". The channel tag
    // is a stable short hash of the channel string (sourceOrigin), so
    // different channels writing the same displayName produce distinct
    // sections and independent prune/replace semantics.
    static std::string SectionName(const std::string& sourceId,
                                   const std::string& channel,
                                   const std::string& displayName) noexcept;

    // Full on-disk INI section name of *any* channel that currently caches
    // the (sourceId, displayName). Used by callers that need to read a
    // session's fields (virtual connect / F5 materialise / F5 export)
    // without knowing which channel produced them — every channel's copy
    // has the same connect fields, so the first hit is authoritative.
    // Returns empty string if the session is not cached.
    std::string SectionNameForConnect(const std::string& sourceId,
                                       const std::string& displayName) const;

    // The dependency a cached session cannot be served without, empty when it
    // has none. Read straight from the section so callers that already hold
    // one do not need the in-memory map.
    static SessionDependency ReadDependency(const std::string& section,
                                            const std::string& iniPath);

    // List all sessions currently cached for the given source. Called during
    // FsFindFirst on [Imports]\[<Source>]\.
    std::vector<CachedSessionRef> ListSource(const std::string& sourceId) const;

    // Answers the one question the icon handler asks, without handing out a
    // copy of the whole list to search. That path runs once per row, so a
    // copy there costs three string allocations per cached session per row.
    bool HasSession(const std::string& sourceId,
                    const std::string& displayName) const;

    // Replace all cached sessions for (sourceId, channel) with `newSessions`.
    // Corresponds to a refresh whose channel result was OkWithSessions.
    // Wipes the affected `[__import.<sourceId>.<channelHash>.*]` sections
    // then writes the new ones via WritePrivateProfileString.
    void ReplaceChannel(const std::string& sourceId,
                        const std::string& channel,
                        const std::vector<CacheWriteEntry>& newSessions);

    // Drop all cached sessions for (sourceId, channel). Corresponds to a
    // refresh whose channel result was OkEmpty, and to explicit custom-path
    // removal from [Manage custom locations…].
    void PruneChannel(const std::string& sourceId,
                      const std::string& channel);

private:
    // Delete every disk section and drop every in-memory ref for
    // (sourceId, channel). Caller must already hold m_mutex.
    // Shared body of ReplaceChannel (step 1) and PruneChannel.
    void EraseChannelLocked(const std::string& sourceId,
                            const std::string& channel);

    ImportCache();
    ImportCache(const ImportCache&)            = delete;
    ImportCache& operator=(const ImportCache&) = delete;

    friend ImportCache& GetImportCache();

    mutable std::mutex            m_mutex;
    std::string                   m_cachePath;   // Resolved once in ctor
    bool                          m_loaded = false;
    std::vector<CachedSessionRef> m_sessions;    // All sessions, all sources
};

// Meyers singleton.
ImportCache& GetImportCache();

}  // namespace sftp

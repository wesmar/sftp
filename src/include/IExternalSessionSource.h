#pragma once

#include <string>
#include <vector>

struct tConnectSettings;
typedef tConnectSettings* pConnectSettings;

namespace sftp {

enum class Proxy : int;   // SftpClient.h

// One session reported by an adapter.
// displayName uses '/' as folder separator (round-trips through our path
// normalisation). sourceOrigin identifies the channel the entry came from:
// literal `"standard"` for the auto-detected system location, or the full
// user-supplied path for a custom location. Stored as the `_source` tag
// in the on-disk cache to support per-channel prune rules.
struct ExternalSessionEntry {
    std::string displayName;
    std::string sourceOrigin;
};

// What the source says about reaching the host, beyond the fields we copy.
// A session may depend on something we cannot reproduce — a proxy, a bastion,
// a tunnel — and importing it without that dependency would send the next
// connection straight to the target, past the very thing the user put in the
// way. The adapter names the dependency here so the session can refuse
// instead of quietly going around it.
struct SessionDependency {
    enum class Kind { None, Proxy, Bastion, Tunnel };

    Kind        kind = Kind::None;
    std::string detail;   // the record's name where the source gives one

    // The proxy itself, filled only when it is a kind the plugin speaks
    // (HTTP, SOCKS4, SOCKS5). Copying such a session into the user's list
    // then brings a matching proxy record along instead of refusing; any
    // other dependency still refuses. No password: it is asked for on the
    // first connect, which is why the user name has to come across.
    Proxy       proxyType{};   // notused unless the source names a kind we speak
    std::string proxyServer;   // host, or host:port when the port is not the default
    std::string proxyUser;

    bool blocks() const noexcept { return kind != Kind::None; }
    bool transferable() const noexcept {
        return kind == Kind::Proxy && static_cast<int>(proxyType) != 0 &&
               !proxyServer.empty();
    }
};

// Adapter's verdict for one channel probe. Drives cache prune behaviour:
// Unreachable → keep existing cached entries; OkEmpty → prune this channel;
// OkWithSessions → replace this channel's cached entries with `sessions`.
enum class EnumerationStatus {
    Unreachable,
    OkEmpty,
    OkWithSessions
};

struct EnumerationResult {
    EnumerationStatus                 status = EnumerationStatus::Unreachable;
    std::vector<ExternalSessionEntry> sessions;
};

// Chrome the plugin should use for the [Add custom location…] pseudo entry.
// Every adapter declares one:
//   None    — the entry is hidden entirely. Use for adapters with no
//             portable/custom-path concept (e.g. a strict registry-only
//             source whose sessions all live in one well-known place).
//   Folder  — a folder is picked; passed to EnumerateCustomPath() as-is.
//             Fits portable-install trees (SecureCRT, KiTTY, WinSCP
//             portable directory, …).
//   File    — a single file is picked; passed to EnumerateCustomPath() as
//             the full file path. Fits export-file sources (putty.reg,
//             sitemanager.xml). The adapter also supplies a Win32 filter
//             string via CustomPathFileFilter().
enum class CustomPathPickerKind { None, Folder, File };

// One adapter per source program (SecureCRT, PuTTY, ...).
// Registered in ImportSourceRegistry at plugin startup.
class IExternalSessionSource {
public:
    virtual ~IExternalSessionSource() = default;

    // Lowercase ASCII identifier. Used as prefix in cache section names
    // ("__import.<sourceId>.<name>") and ini keys ("<sourceId>.custom_paths").
    virtual const char* SourceId() const noexcept = 0;

    // User-facing folder name in the plugin root, e.g. "[SecureCRT]".
    virtual const char* FolderName() const noexcept = 0;

    // Cheap probe. True if the source is available at its standard location
    // (registry key present, canonical %APPDATA% marker file exists, ...).
    virtual bool DetectStandard() const noexcept = 0;

    // Full walk of the standard location. Populates result.sessions on
    // OkWithSessions. Called on [Refresh]; also on plugin startup as part of
    // detection-driven visibility.
    virtual EnumerationResult EnumerateStandard() = 0;

    // Full walk of one user-supplied path. Called on [Refresh] per configured
    // path, and immediately after [Add custom location…].
    virtual EnumerationResult EnumerateCustomPath(const std::string& path) = 0;

    // Fills tConnectSettings for a specific session previously reported by
    // one of the Enumerate* calls. Password fields intentionally left
    // untouched — the plugin surfaces the standard interactive prompt on
    // first connect. Returns true on success.
    virtual bool LoadSettings(const ExternalSessionEntry& entry,
                              tConnectSettings* out,
                              SessionDependency* dependency) = 0;

    // See CustomPathPickerKind. Consulted by BuildImportsSourceListing to
    // decide whether to surface [Add custom location…] at all, and by
    // FsExecuteFileW to pick between the folder- and file-picker.
    virtual CustomPathPickerKind CustomPathPicker() const noexcept = 0;

    // A short string that changes whenever the standard location may have
    // changed — file names and modification times, say. Opening the source
    // folder compares it with the last one and re-scans on a difference, so
    // edits show without [Refresh]. Empty (the default) means the adapter
    // does not track changes and only [Refresh] re-scans it.
    virtual std::string ChangeStamp() const { return {}; }

    // The same for one user-supplied path. A path that has gone missing
    // still yields a stamp of its own, so its going away triggers a re-scan
    // — which reports it Unreachable and keeps its cached sessions.
    virtual std::string CustomPathStamp(const std::string& /*path*/) const { return {}; }

    // Only meaningful when CustomPathPicker() == File. NUL-separated Win32
    // filter string ("PuTTY export\0*.reg\0All files\0*.*\0"). Adapters
    // returning Folder or None can leave the default nullptr — callers never
    // dereference it in those cases.
    virtual const char* CustomPathFileFilter() const noexcept { return nullptr; }
};

}  // namespace sftp

#pragma once

#include <optional>
#include <string>

namespace sftp {

// Descriptor of one open virtual (Imports-cache-backed) session. Enough to
// re-display the connection under its human-readable name in the [Active
// Sessions] listing and for diagnostics.
struct VirtualSessionInfo {
    std::string sourceId;      // adapter identifier, e.g. "securecrt"
    std::string cacheSection;  // full "__import.<sourceId>.<hash>.<display>"
    std::string displayName;   // human-readable name inside the source
};

// Compose the TC-safe registry key for a virtual session. Format:
//   __vimp_<sourceId>_<8hex-fnv1a-of-cacheSection>
// - No dots, brackets, slashes, or backslashes — TC treats it as a single
//   path segment and its toolbar/disconnect tracking works normally.
// - The double-underscore prefix marks it as an internal registry entry so
//   BuildPluginFolderListing filters it out of the plugin root view.
std::string MakeVirtualSessionAlias(const std::string& sourceId,
                                    const std::string& cacheSection);

// True iff `name` matches the alias pattern above (starts with __vimp_).
// Cheap constant-prefix check; safe to call from listing hot paths.
bool IsVirtualSessionAlias(const char* name) noexcept;

// Bind alias → (sourceId, cacheSection, displayName). Called once per
// successful virtual session Enter after SetServerIdForName.
void RegisterVirtualSession(const std::string& alias,
                             VirtualSessionInfo info);

// Reverse lookup used by [Active Sessions] to show the human-readable
// display name instead of the internal alias. Returns nullopt when the
// alias is not registered (session already closed, or the name was never a
// virtual alias).
std::optional<VirtualSessionInfo> LookupVirtualSession(const std::string& alias);

// Remove the alias binding when the session disconnects. Called from
// FsDisconnect. No-op if the alias is not in the map.
void UnregisterVirtualSession(const std::string& alias);

}  // namespace sftp

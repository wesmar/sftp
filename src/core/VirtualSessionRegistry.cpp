#include "VirtualSessionRegistry.h"
#include "ImportIoUtil.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <mutex>
#include <string_view>
#include <unordered_map>

namespace sftp {

namespace {

constexpr const char* kAliasPrefix    = "__vimp_";
constexpr size_t      kAliasPrefixLen = 7;

std::mutex&                                    Mutex()
{
    static std::mutex m;
    return m;
}

std::unordered_map<std::string, VirtualSessionInfo>& Map()
{
    static std::unordered_map<std::string, VirtualSessionInfo> m;
    return m;
}

}  // namespace

std::string MakeVirtualSessionAlias(const std::string& sourceId,
                                    const std::string& cacheSection)
{
    // Hash the full cache-section name so identical (sourceId, displayName)
    // input always produces the same alias — reconnect after disconnect
    // routes to the same slot, and mismatched sourceId cannot collide with
    // a session from a different adapter.
    char hex[16];
    std::snprintf(hex, sizeof(hex), "%08x", Fnv1aHash(cacheSection));

    std::string out(kAliasPrefix);
    out.append(sourceId);
    out.push_back('_');
    out.append(hex);
    return out;
}

bool IsVirtualSessionAlias(const char* name) noexcept
{
    if (!name) return false;
    return std::strncmp(name, kAliasPrefix, kAliasPrefixLen) == 0;
}

void RegisterVirtualSession(const std::string& alias, VirtualSessionInfo info)
{
    std::lock_guard<std::mutex> lock(Mutex());
    Map()[alias] = std::move(info);
}

std::optional<VirtualSessionInfo> LookupVirtualSession(const std::string& alias)
{
    std::lock_guard<std::mutex> lock(Mutex());
    auto it = Map().find(alias);
    if (it == Map().end())
        return std::nullopt;
    return it->second;
}

void UnregisterVirtualSession(const std::string& alias)
{
    std::lock_guard<std::mutex> lock(Mutex());
    Map().erase(alias);
}

}  // namespace sftp

#include "global.h"
#include <windows.h>
#include <stdio.h>
#include "ServerRegistry.h"
#include "CoreUtils.h"
#include "SftpInternal.h"
#include "PluginEntryPoints.h"
#include "SftpClient.h"
#include <algorithm>
#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <algorithm>

struct SERVERENTRY {
    std::string name;
    SERVERID serverid = nullptr;
    DWORD threadid = 0;
    bool is_background = false;
};

static std::mutex g_registryMutex;
static std::vector<std::unique_ptr<SERVERENTRY>> g_servers;
extern DWORD mainthreadid;

void InitMultiServer() noexcept
{
}

void ShutdownMultiServer() noexcept
{
    FreeServerList();
}

static SERVERENTRY* FindEntry(DWORD tid, LPCSTR name, bool is_bg)
{
    for (const auto& srv : g_servers) {
        if (srv->is_background == is_bg && _stricmp(srv->name.c_str(), name) == 0) {
            if (!is_bg || srv->threadid == tid)
                return srv.get();
        }
    }
    return nullptr;
}

SERVERID GetServerIdFromName(LPCSTR name, DWORD threadId) noexcept
{
    if (!name || !name[0])
        return nullptr;
        
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    bool is_bg = (threadId != mainthreadid && threadId != 0);
    SERVERENTRY* entry = FindEntry(threadId, name, is_bg);
    return entry ? entry->serverid : nullptr;
}

size_t DisconnectServerByName(LPCSTR name) noexcept
{
    if (!name || !name[0]) return 0;

    pConnectSettings toClose = nullptr;
    size_t removed = 0;
    {
        std::lock_guard<std::mutex> lock(g_registryMutex);

        // Collect the unique tConnectSettings pointer (any registry entry
        // for the same session name must reference the same heap object —
        // there is only one connection per DisplayName). Then drop every
        // matching entry regardless of its thread/is_background flag so
        // the session cannot leak on background-thread FsDisconnect calls.
        for (const auto& srv : g_servers) {
            if (_stricmp(srv->name.c_str(), name) == 0) {
                if (!toClose && srv->serverid)
                    toClose = static_cast<pConnectSettings>(srv->serverid);
                srv->serverid = nullptr;   // decouple before erase (defensive)
            }
        }
        const size_t before = g_servers.size();
        g_servers.erase(
            std::remove_if(g_servers.begin(), g_servers.end(),
                [&](const std::unique_ptr<SERVERENTRY>& e) {
                    return _stricmp(e->name.c_str(), name) == 0;
                }),
            g_servers.end());
        removed = before - g_servers.size();
    }

    // SftpCloseConnection and delete happen outside the registry lock —
    // libssh2 shutdown can block on socket send for the SSH_MSG_DISCONNECT
    // packet, and holding the registry mutex through it would starve any
    // parallel FsFindFirst on other sessions.
    if (toClose) {
        SftpCloseConnection(toClose);
        delete toClose;
    }
    return removed;
}

bool SetServerIdForName(LPCSTR name, SERVERID id) noexcept
{
    if (!name || !name[0])
        return false;
        
    pConnectSettings old_cs = nullptr;
    bool success = false;
    {
        std::lock_guard<std::mutex> lock(g_registryMutex);
        DWORD tid = GetCurrentThreadId();
        bool is_bg = (tid != mainthreadid);
        
        SERVERENTRY* entry = FindEntry(tid, name, is_bg);
        
        if (entry) {
            if (entry->serverid != id) {
                old_cs = static_cast<pConnectSettings>(entry->serverid);
            }
            if (id) {
                entry->serverid = id;
            } else {
                entry->serverid = nullptr;
                auto it = std::remove_if(g_servers.begin(), g_servers.end(), [&](const std::unique_ptr<SERVERENTRY>& e) {
                    return e.get() == entry;
                });
                g_servers.erase(it, g_servers.end());
            }
            success = true;
        } else if (id) {
            auto new_entry = std::make_unique<SERVERENTRY>();
            new_entry->name = name;
            new_entry->serverid = id;
            new_entry->threadid = tid;
            new_entry->is_background = is_bg;
            
            if (is_bg) {
                g_servers.insert(g_servers.begin(), std::move(new_entry));
            } else {
                g_servers.push_back(std::move(new_entry));
                auto it_start = std::stable_partition(g_servers.begin(), g_servers.end(), [](const std::unique_ptr<SERVERENTRY>& e) {
                    return e->is_background;
                });
                std::sort(it_start, g_servers.end(), [](const std::unique_ptr<SERVERENTRY>& a, const std::unique_ptr<SERVERENTRY>& b) {
                    return _stricmp(a->name.c_str(), b->name.c_str()) < 0;
                });
            }
            success = true;
        }
    }
    
    if (old_cs) {
        SftpCloseConnection(old_cs);
        delete old_cs;
    }
    
    return success;
}

static void AnsiToWide(LPCSTR ansi, wchar_t* wide, int maxlen) noexcept
{
    if (!wide || maxlen <= 0)
        return;
    MultiByteToWideChar(CP_ACP, 0, ansi ? ansi : "", -1, wide, maxlen);
}

int LoadServersFromIniW(LPCWSTR inifilename, LPCSTR quickconnectname) noexcept
{
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    int servercount = 0;
    std::array<wchar_t, 65535> serverlist{};
    
    GetPrivateProfileStringW(nullptr, nullptr, L"", serverlist.data(), static_cast<DWORD>(serverlist.size()), inifilename);
    
    std::vector<std::string> ini_servers;
    if (quickconnectname)
        ini_servers.push_back(quickconnectname);
        
    wchar_t* wp = serverlist.data();
    while (wp[0]) {
        std::array<char, MAX_PATH> sectionA{};
        WideCharToMultiByte(CP_ACP, 0, wp, -1, sectionA.data(), static_cast<int>(sectionA.size()), nullptr, nullptr);
        
        std::array<wchar_t, 512> serverval{};
        GetPrivateProfileStringW(wp, L"server", L"", serverval.data(), static_cast<DWORD>(serverval.size()), inifilename);
        const int transferMode = GetPrivateProfileIntW(wp, L"transfermode", 0, inifilename);
        
        if (serverval[0] || transferMode == 3) {
            ini_servers.push_back(sectionA.data());
        }
        wp += wcslen(wp) + 1;
    }
    
    auto it = std::remove_if(g_servers.begin(), g_servers.end(), [&](const std::unique_ptr<SERVERENTRY>& e) {
        if (e->is_background || e->serverid != nullptr) return false;
        return std::find_if(ini_servers.begin(), ini_servers.end(), [&](const std::string& name) {
            return _stricmp(name.c_str(), e->name.c_str()) == 0;
        }) == ini_servers.end();
    });
    g_servers.erase(it, g_servers.end());
    
    for (const auto& name : ini_servers) {
        if (!FindEntry(0, name.c_str(), false)) {
            auto new_entry = std::make_unique<SERVERENTRY>();
            new_entry->name = name;
            g_servers.push_back(std::move(new_entry));
            servercount++;
        }
    }
    
    auto it_start = std::stable_partition(g_servers.begin(), g_servers.end(), [](const std::unique_ptr<SERVERENTRY>& e) {
        return e->is_background;
    });
    std::sort(it_start, g_servers.end(), [](const std::unique_ptr<SERVERENTRY>& a, const std::unique_ptr<SERVERENTRY>& b) {
        return _stricmp(a->name.c_str(), b->name.c_str()) < 0;
    });
    
    return servercount;
}

bool DeleteServerFromIniW(LPCSTR servername, LPCWSTR inifilename) noexcept
{
    std::array<wchar_t, MAX_PATH> wsection{};
    AnsiToWide(servername, wsection.data(), static_cast<int>(wsection.size()));
    return WritePrivateProfileStringW(wsection.data(), nullptr, nullptr, inifilename) != 0;
}

int CopyMoveServerInIniW(LPCSTR oldservername, LPCSTR newservername,
                         bool Move, bool OverWrite, LPCWSTR inifilename) noexcept
{
    if (_stricmp(oldservername, newservername) == 0)
        return FS_FILE_OK;

    std::array<wchar_t, MAX_PATH> woldsect{};
    std::array<wchar_t, MAX_PATH> wnewsect{};
    AnsiToWide(oldservername, woldsect.data(), static_cast<int>(woldsect.size()));
    AnsiToWide(newservername, wnewsect.data(), static_cast<int>(wnewsect.size()));

    std::array<wchar_t, 1024> captlist{};
    GetPrivateProfileStringW(woldsect.data(), nullptr, L"", captlist.data(), static_cast<DWORD>(captlist.size() - 1), inifilename);
    if (captlist[0]) {
        if (!OverWrite) {
            std::array<wchar_t, 100> testlist{};
            GetPrivateProfileStringW(wnewsect.data(), nullptr, L"", testlist.data(), static_cast<DWORD>(testlist.size() - 1), inifilename);
            if (testlist[0])
                return FS_FILE_EXISTS;
        }

        DeleteServerFromIniW(newservername, inifilename);

        wchar_t* pcapt = captlist.data();
        while (pcapt[0]) {
            std::array<wchar_t, 1024> valuebuf{};
            GetPrivateProfileStringW(woldsect.data(), pcapt, L"", valuebuf.data(), static_cast<DWORD>(valuebuf.size() - 1), inifilename);
            WritePrivateProfileStringW(wnewsect.data(), pcapt, valuebuf.data(), inifilename);
            pcapt += wcslen(pcapt) + 1;
        }
        if (Move)
            DeleteServerFromIniW(oldservername, inifilename);
        return FS_FILE_OK;
    }
    return FS_FILE_NOTFOUND;
}

int LoadServersFromIni(LPCSTR inifilename, LPCSTR quickconnectname) noexcept
{
    if (!inifilename || !inifilename[0])
        return 0;
    std::array<wchar_t, MAX_PATH> wpath{};
    AnsiToWide(inifilename, wpath.data(), static_cast<int>(wpath.size()));
    return LoadServersFromIniW(wpath.data(), quickconnectname);
}

bool DeleteServerFromIni(LPCSTR servername, LPCSTR inifilename) noexcept
{
    if (!servername || !servername[0] || !inifilename || !inifilename[0])
        return false;
    std::array<wchar_t, MAX_PATH> wpath{};
    AnsiToWide(inifilename, wpath.data(), static_cast<int>(wpath.size()));
    return DeleteServerFromIniW(servername, wpath.data());
}

int CopyMoveServerInIni(LPCSTR oldservername, LPCSTR newservername,
                        bool Move, bool OverWrite, LPCSTR inifilename) noexcept
{
    if (!oldservername || !oldservername[0] || !newservername || !newservername[0] ||
        !inifilename || !inifilename[0]) {
        return FS_FILE_NOTFOUND;
    }
    std::array<wchar_t, MAX_PATH> wpath{};
    AnsiToWide(inifilename, wpath.data(), static_cast<int>(wpath.size()));
    return CopyMoveServerInIniW(oldservername, newservername, Move, OverWrite, wpath.data());
}

void FreeServerList() noexcept
{
    std::vector<pConnectSettings> to_close;
    {
        std::lock_guard<std::mutex> lock(g_registryMutex);
        for (auto& entry : g_servers) {
            if (entry->serverid) {
                to_close.push_back(static_cast<pConnectSettings>(entry->serverid));
                entry->serverid = nullptr;
            }
        }
        g_servers.clear();
    }
    for (auto cs : to_close) {
        SftpCloseConnection(cs);
        delete cs;
    }
}

void GetDisplayNameFromPath(LPCSTR Path, LPSTR DisplayName, size_t maxlen) noexcept
{
    if (!DisplayName || maxlen == 0) {
        return;
    }
    if (!Path || !Path[0]) {
        DisplayName[0] = '\0';
        return;
    }
    // Folder-aware: ask the resolver for the longest matching session prefix.
    // For flat (slash-free) session names this is the same first-segment
    // string the legacy code produced, so no regression.
    const PathResolution r = ResolvePathKind(Path);
    if (!r.displayName.empty()) {
        strlcpy(DisplayName, r.displayName.c_str(), maxlen);
        return;
    }
    // Fallback: path doesn't match any known session or folder yet (e.g. a
    // brand-new quick-connect name about to be saved). Use the legacy
    // first-segment extraction so downstream code gets a usable name.
    LPCSTR p = Path;
    while (*p == '\\' || *p == '/')
        p++;
    strlcpy(DisplayName, p, maxlen);
    LPSTR out = DisplayName;
    while (*out && *out != '\\' && *out != '/')
        out++;
    *out = 0;
}

namespace {

std::string NormaliseTcPath(std::string_view path) noexcept
{
    while (!path.empty() && (path.front() == '\\' || path.front() == '/'))
        path.remove_prefix(1);
    std::string out(path);
    std::replace(out.begin(), out.end(), '\\', '/');
    return out;
}

// Returns the canonical (case-preserving) session name if a session exists
// with a case-insensitive match for `name`; empty string otherwise.
// Caller must hold g_registryMutex.
std::string RegistryFindSession(const std::string& name) noexcept
{
    for (const auto& e : g_servers) {
        if (!e->is_background && _stricmp(e->name.c_str(), name.c_str()) == 0)
            return e->name;
    }
    return {};
}

// True if at least one session in the registry has a name starting with
// prefix + "/" (i.e. lives strictly under that folder prefix).
// Caller must hold g_registryMutex.
bool RegistryHasAnyUnderFolder(const std::string& prefix) noexcept
{
    const std::string needle = prefix + "/";
    for (const auto& e : g_servers) {
        if (!e->is_background &&
            e->name.size() > needle.size() &&
            _strnicmp(e->name.c_str(), needle.c_str(), needle.size()) == 0)
            return true;
    }
    return false;
}

}  // anonymous namespace

PathResolution ResolvePathKind(LPCSTR path) noexcept
{
    PathResolution out;
    if (!path)
        return out;
    const std::string norm = NormaliseTcPath(path);

    std::lock_guard<std::mutex> lock(g_registryMutex);

    // Root ("\\" or "/" or empty) → folder, no display name.
    if (norm.empty()) {
        out.kind = PathKind::Folder;
        return out;
    }

    // Longest-prefix-match: full path first, then drop trailing segments.
    std::string candidate = norm;
    while (!candidate.empty()) {
        std::string canonical = RegistryFindSession(candidate);
        if (!canonical.empty()) {
            out.displayName = std::move(canonical);
            if (candidate.size() == norm.size()) {
                out.kind = PathKind::SessionLeaf;
            } else {
                out.kind = PathKind::SessionWithSubpath;
                // After candidate length the next char is '/'; restore to '\'.
                std::string rel = norm.substr(candidate.size());
                std::replace(rel.begin(), rel.end(), '/', '\\');
                out.relative = std::move(rel);
            }
            return out;
        }
        const size_t lastSlash = candidate.find_last_of('/');
        if (lastSlash == std::string::npos)
            break;
        candidate.resize(lastSlash);
    }

    // No session matches; folder iff at least one session lives under it.
    if (RegistryHasAnyUnderFolder(norm)) {
        out.kind = PathKind::Folder;
        out.displayName = norm;
    }
    return out;
}

PathResolution ResolvePathKindW(LPCWSTR path) noexcept
{
    if (!path)
        return {};
    const int needed = WideCharToMultiByte(CP_ACP, 0, path, -1,
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 1)
        return {};
    std::string narrow(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_ACP, 0, path, -1,
                        narrow.data(), needed, nullptr, nullptr);
    // Session names are INI section names, so matching them in the ANSI
    // code page is exact; the remote part is taken from the Unicode path.
    PathResolution out = ResolvePathKind(narrow.c_str());
    if (out.kind != PathKind::SessionWithSubpath)
        return out;

    std::wstring_view wide(path);
    while (!wide.empty() && (wide.front() == L'\\' || wide.front() == L'/'))
        wide.remove_prefix(1);
    // Skip as many segments as the session name has ("folder/name" has two).
    size_t segments = 1 + static_cast<size_t>(std::count(out.displayName.begin(), out.displayName.end(), '/'));
    size_t pos = 0;
    while (segments > 0 && pos < wide.size()) {
        const size_t next = wide.find_first_of(L"\\/", pos);
        if (next == std::wstring_view::npos) {
            pos = wide.size();
            break;
        }
        pos = next + 1;
        --segments;
    }
    if (pos > 0 && pos <= wide.size()) {
        out.relativeW.assign(L"\\");
        out.relativeW.append(wide.substr(pos));
        std::replace(out.relativeW.begin(), out.relativeW.end(), L'/', L'\\');
    }
    return out;
}

std::string PathToDisplayName(LPCSTR path) noexcept
{
    if (!path)
        return {};
    return NormaliseTcPath(path);
}

std::string PathToDisplayNameW(LPCWSTR path) noexcept
{
    if (!path)
        return {};
    const int needed = WideCharToMultiByte(CP_ACP, 0, path, -1,
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 1)
        return {};
    std::string narrow(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_ACP, 0, path, -1,
                        narrow.data(), needed, nullptr, nullptr);
    return NormaliseTcPath(narrow);
}

struct ServerEnumContext {
    size_t index;
};

SERVERHANDLE FindFirstServer(LPSTR displayname, size_t maxlen) noexcept
{
    if (!displayname || maxlen == 0)
        return nullptr;

    std::lock_guard<std::mutex> lock(g_registryMutex);
    for (size_t i = 0; i < g_servers.size(); ++i) {
        if (!g_servers[i]->is_background) {
            strlcpy(displayname, g_servers[i]->name.c_str(), maxlen);
            auto ctx = std::make_unique<ServerEnumContext>(ServerEnumContext{i});
            return static_cast<SERVERHANDLE>(ctx.release());
        }
    }
    return nullptr;
}

SERVERHANDLE FindNextServer(SERVERHANDLE searchhandle, LPSTR displayname, size_t maxlen) noexcept
{
    if (!searchhandle || !displayname || maxlen == 0) return nullptr;
    auto ctx = static_cast<ServerEnumContext*>(searchhandle);
    
    std::lock_guard<std::mutex> lock(g_registryMutex);
    for (size_t i = ctx->index + 1; i < g_servers.size(); ++i) {
        if (!g_servers[i]->is_background) {
            strlcpy(displayname, g_servers[i]->name.c_str(), maxlen);
            ctx->index = i;
            return searchhandle;
        }
    }
    
    delete ctx;
    return nullptr;
}

void FindCloseServer(SERVERHANDLE searchhandle) noexcept
{
    if (searchhandle) {
        auto ctx = static_cast<ServerEnumContext*>(searchhandle);
        delete ctx;
    }
}


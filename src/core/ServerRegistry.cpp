#include "global.h"
#include <windows.h>
#include <stdio.h>
#include "ServerRegistry.h"
#include "CoreUtils.h"
#include "SftpInternal.h"
#include "PluginEntryPoints.h"
#include "SftpClient.h"
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
    LPCSTR p = Path;
    while (*p == '\\' || *p == '/')
        p++;
    strlcpy(DisplayName, p, maxlen);
    LPSTR out = DisplayName;
    while (*out && *out != '\\' && *out != '/')
        out++;
    *out = 0;
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


#include <winsock2.h>
#include <windows.h>
#include <shlobj.h>
#include <stdlib.h>
#include <array>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <algorithm>
#include <vector>
#include "fsplugin.h"
#include "CoreUtils.h"
#include "res/resource.h"
#include "SftpClient.h"
#include "SftpInternal.h"
#include "ServerRegistry.h"
#include "UnicodeHelpers.h"
#include "PluginEntryPoints.h"
#include "ConnectionDialog.h"
#include "TransferUtils.h"
#include "ProfileSettings.h"
#include "DllExceptionBarrier.h"
#include "LanPairSession.h"
#include "PluginEntryPointsInternal.h"
#include "PhpAgentClient.h"
#include "ImportSourceRegistry.h"
#include "ImportCache.h"
#include "ImportIoUtil.h"
#include "VirtualSessionRegistry.h"
#include "BuildInfo.h"
#include "DownloadErrorBatch.h"

// Serialise one session INI section into a human-readable INI-format text
// file. Used by FsGetFile when TC copies (or "views"/"edits") a session
// entry from the plugin panel out to a real filesystem path. The plugin
// internal `_` metadata keys (provenance, refusal) are filtered out; the `[header]` in
// the output uses `exportSection` (typically the DisplayName) rather than
// the raw storage section name, so cache-prefixed virtual entries land as
// a clean `[dron/hz-1]` header rather than the ugly cache name.
// The proxy record travels under a fixed section name: the number it had in
// the file it came from means nothing in the file it is going to.
static constexpr const char* kExportProxySection = "[proxy]";
static constexpr const char* RN = "\r\n";
// Names, in an exported snippet, a route the plugin could not rebuild.
// Importing the snippet refuses on it rather than create a session that
// would connect straight to the host.
static constexpr const char* kUnsupportedRouteKey = "unsupportedroute";

static const char* DependencyName(sftp::SessionDependency::Kind kind)
{
    switch (kind) {
        case sftp::SessionDependency::Kind::Proxy:   return "proxy";
        case sftp::SessionDependency::Kind::Bastion: return "jump host";
        case sftp::SessionDependency::Kind::Tunnel:  return "tunnel";
        case sftp::SessionDependency::Kind::None:    break;
    }
    return "";
}

static int ExportSessionAsIniFile(
    LPCSTR srcSection, LPCSTR srcIni,
    LPCSTR exportSection, LPCSTR headerComment,
    LPCWSTR destFile, BOOL OverWrite,
    const sftp::SessionDependency* dependency = nullptr)
{
    if (!OverWrite) {
        const DWORD attrs = GetFileAttributesW(destFile);
        if (attrs != INVALID_FILE_ATTRIBUTES &&
            !(attrs & FILE_ATTRIBUTE_DIRECTORY))
        {
            return FS_FILE_EXISTS;
        }
    }

    std::string content;
    content.reserve(1024);
    if (headerComment && headerComment[0])
        content.append("; ").append(headerComment).append("\r\n");
    content.append("[").append(exportSection).append("]\r\n");

    std::array<char, 8192> keyList{};
    GetPrivateProfileStringA(srcSection, nullptr, "",
        keyList.data(),
        static_cast<DWORD>(keyList.size() - 1),
        srcIni);
    const char* p = keyList.data();
    while (p[0]) {
        if (p[0] != '_') {
            std::array<char, 2048> valueBuf{};
            GetPrivateProfileStringA(srcSection, p, "",
                valueBuf.data(),
                static_cast<DWORD>(valueBuf.size() - 1),
                srcIni);
            content.append(p).append("=").append(valueBuf.data()).append("\r\n");
        }
        p += strlen(p) + 1;
    }

    // A session from [Imports] has no record to copy: its proxy exists only
    // as the source described it. It is written the way a record would be,
    // under the same fixed name, so importing the snippet resolves it alike.
    // A route the plugin cannot rebuild is named instead of left out, so the
    // settings can still be viewed while the way back stays shut.
    if (dependency && dependency->transferable()) {
        content.append("proxynr=1").append(RN);
        content.append(kExportProxySection).append(RN);
        content.append("proxytype=")
               .append(std::to_string(static_cast<int>(dependency->proxyType)))
               .append(RN);
        content.append("proxyserver=").append(dependency->proxyServer).append(RN);
        if (!dependency->proxyUser.empty())
            content.append("proxyuser=").append(dependency->proxyUser).append(RN);
    } else if (dependency && dependency->blocks()) {
        std::string route = DependencyName(dependency->kind);
        if (!dependency->detail.empty())
            route.append(" ").append(dependency->detail);
        content.append("; Reaches the host through a ").append(route)
               .append(", which the plugin does not reproduce.").append(RN)
               .append("; Importing this file is refused while the next line is here.")
               .append(RN);
        content.append(kUnsupportedRouteKey).append("=").append(route).append(RN);
    }

    // A session that goes through a proxy takes the record with it. `proxynr`
    // alone would be meaningless anywhere else: it would land on whatever
    // record holds that number there, or on none at all, which reads as a
    // direct connection to the host. The record travels without its number,
    // since the number is local to the file it came from, and without its
    // password, which is machine-bound where it is stored at all.
    {
        const int proxynr = GetPrivateProfileInt(srcSection, "proxynr", 0, srcIni);
        if (proxynr > 0) {
            const std::string proxySection = proxynr > 1
                ? std::format("proxy{}", proxynr) : std::string("proxy");
            std::array<char, 4096> proxyKeys{};
            GetPrivateProfileStringA(proxySection.c_str(), nullptr, "",
                proxyKeys.data(), static_cast<DWORD>(proxyKeys.size() - 1), srcIni);
            if (proxyKeys[0]) {
                content.append(kExportProxySection).append(RN);
                for (const char* k = proxyKeys.data(); *k; k += strlen(k) + 1) {
                    if (_stricmp(k, "proxypassword") == 0)
                        continue;
                    std::array<char, 2048> value{};
                    GetPrivateProfileStringA(proxySection.c_str(), k, "",
                        value.data(), static_cast<DWORD>(value.size() - 1), srcIni);
                    content.append(k).append("=").append(value.data()).append(RN);
                }
            }
        }
    }

    HANDLE h = CreateFileW(destFile, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return FS_FILE_WRITEERROR;
    DWORD written = 0;
    WriteFile(h, content.data(),
              static_cast<DWORD>(content.size()),
              &written, nullptr);
    CloseHandle(h);
    return FS_FILE_OK;
}

static bool CopyIniSectionAcrossFiles(LPCSTR srcSection, LPCSTR srcIni,
                                       LPCSTR dstSection, LPCSTR dstIni);

// Try to import an uploaded file as a session-INI. Returns nullopt when the
// destination path is (or could resolve to) a real session — FsPutFile then
// proceeds with the normal upload flow. Returns FS_FILE_* when the file was
// consumed as a session-import gesture: success, a user-visible validation
// failure with an explanatory MessageBox, or a name collision. Callers must
// return the wrapped value immediately.
// A cached session that names a dependency we did not import must not be
// served: connecting would reach the host directly, past the proxy or bastion
// the source put in front of it, and look like success. The refusal names the
// record where the source gave one, on a line of its own so the sentence
// itself needs no grammar for it.
static void ShowDependencyRefusal(const sftp::SessionDependency& dep)
{
    std::string text = LngStrU8(IDS_IMPORT_BLOCKED,
        "This session reaches its host through something that was not imported "
        "with it: a proxy, a jump host or a tunnel. Connecting now would go "
        "straight to the target instead, past the very thing that was put in "
        "the way, so it is refused.");
    if (!dep.detail.empty())
        text.append("\r\n\r\n").append(dep.detail);
    // Only connecting refuses such a proxy: copying the session creates the
    // record it needs, which a plain connect has no business doing.
    if (dep.transferable())
        text.append("\r\n\r\n").append(LngStrU8(IDS_IMPORT_BLOCKED_COPY,
            "The proxy is one the plugin can rebuild: copy the session into "
            "your own list with F5 and the proxy comes with it. Its password, "
            "if it needs one, is asked for on the first connect."));

    const std::wstring message = unicode_util::utf8_to_wstring(text);
    const std::wstring title   = unicode_util::utf8_to_wstring(
        LngStrU8(IDS_SIMPORT_TITLE, "SFTP plugin - session import"));
    if (RequestProcW) {
        RequestProcW(PluginNumber, RT_MsgOK,
                     const_cast<WCHAR*>(title.c_str()),
                     const_cast<WCHAR*>(message.c_str()), nullptr, 0);
    } else {
        MessageBoxW(FindWindowA("TTOTAL_CMD", nullptr),
                    message.c_str(), title.c_str(), MB_OK | MB_ICONSTOP);
    }
}

static bool RefuseIfDependencyBlocks(const std::string& cacheSection)
{
    const std::string& cachePath = sftp::GetImportCache().CacheFilePath();
    if (cacheSection.empty() || cachePath.empty())
        return false;

    const sftp::SessionDependency dep =
        sftp::ImportCache::ReadDependency(cacheSection, cachePath);
    if (!dep.blocks())
        return false;
    ShowDependencyRefusal(dep);
    return true;
}

// The session a transfer names, opened in this thread if it is only open in
// another one.
//
// Connections are per thread: the registry is keyed by name *and* thread id, so
// a session listed in one panel is a different connection from the one a
// transfer thread would use. Listing has always handled that by connecting on
// demand; transfers did not, and returned a read error before touching the
// network — which is what copying between two plugin panels ran into, since the
// copy runs in one panel's thread while the other panel's session lives in its
// own.
static pConnectSettings ResolveTransferSession(LPCWSTR RemoteName,
                                               LPWSTR relativeOut, size_t maxlen)
{
    if (pConnectSettings serverid =
            GetServerIdAndRelativePathFromPathW(RemoteName, relativeOut, maxlen))
    {
        return serverid;
    }

    const PathResolution r = ResolvePathKindW(RemoteName);
    if (r.kind != PathKind::SessionLeaf && r.kind != PathKind::SessionWithSubpath)
        return nullptr;

    pConnectSettings fresh = nullptr;
    if (sftp::IsVirtualSessionAlias(r.displayName.c_str())) {
        // A session from [Imports] keeps its fields in the scan cache, not in
        // our INI, and is reachable only through the alias its Enter registered.
        const auto info = sftp::LookupVirtualSession(r.displayName.c_str());
        const std::string& cachePath = sftp::GetImportCache().CacheFilePath();
        if (!info || cachePath.empty())
            return nullptr;
        fresh = SftpConnectToServer(info->cacheSection.c_str(), cachePath.c_str(),
                                    nullptr, r.displayName.c_str());
    } else {
        fresh = SftpConnectToServer(r.displayName.c_str(), inifilename, nullptr);
    }
    if (!fresh)
        return nullptr;

    SetServerIdForName(r.displayName.c_str(), static_cast<SERVERID>(fresh));
    return GetServerIdAndRelativePathFromPathW(RemoteName, relativeOut, maxlen);
}

static std::optional<int> TryImportSessionFromUpload(
    LPCWSTR LocalName, LPCWSTR RemoteName, BOOL OverWrite)
{
    std::array<WCHAR, wdirtypemax> probeDir{};
    pConnectSettings probeServer = GetServerIdAndRelativePathFromPathW(
        RemoteName, probeDir.data(), probeDir.size() - 1);
    if (probeServer)
        return std::nullopt;

    // probeServer == null means "not registered in this thread's g_servers
    // slot". The path may still resolve to a real saved session (present in
    // the global registry but not yet opened in this thread) or to a session
    // sub-path. Only paths that resolve to nothing at all are legitimate
    // session-import targets; anything else is an ordinary upload whose
    // auto-connect will happen elsewhere.
    const PathResolution pr = ResolvePathKindW(RemoteName);
    if (pr.kind == PathKind::SessionLeaf ||
        pr.kind == PathKind::SessionWithSubpath)
    {
        return FS_FILE_WRITEERROR;
    }

    // Any validation failure surfaces through ShowPluginMessage, so TC does
    // not stack its generic "Error uploading file" popup on top. Returned as
    // FS_FILE_USERABORT so TC treats it as a user-driven cancel — no
    // additional error dialog.
    auto abortWithMessage = [&](UINT msgId) -> int {
        ShowPluginMessage(msgId, "", IDS_SIMPORT_TITLE,
                          "SFTP plugin - session import");
        return FS_FILE_USERABORT;
    };

    // Quick source-file sanity checks — openable, non-empty.
    {
        HANDLE hCheck = CreateFileW(LocalName, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hCheck == INVALID_HANDLE_VALUE)
            return abortWithMessage(IDS_SIMPORT_ERR_OPEN);
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hCheck, &fileSize);
        CloseHandle(hCheck);
        if (fileSize.QuadPart == 0)
            return abortWithMessage(IDS_SIMPORT_ERR_EMPTY);
    }

    std::array<char, MAX_PATH * 4> localA{};
    WideCharToMultiByte(CP_ACP, 0, LocalName, -1,
        localA.data(), static_cast<int>(localA.size()),
        nullptr, nullptr);

    std::array<char, 8192> sectionNames{};
    const DWORD gotSects = GetPrivateProfileSectionNamesA(
        sectionNames.data(),
        static_cast<DWORD>(sectionNames.size() - 1),
        localA.data());
    if (gotSects == 0)
        return abortWithMessage(IDS_SIMPORT_ERR_NO_SECTIONS);

    // Look for the first section with a non-empty `server=`.
    const char* sp = sectionNames.data();
    std::string chosenSection;
    while (sp[0]) {
        std::array<char, 512> serverProbe{};
        GetPrivateProfileStringA(sp, "server", "",
            serverProbe.data(),
            static_cast<DWORD>(serverProbe.size() - 1),
            localA.data());
        if (serverProbe[0]) {
            chosenSection = sp;
            break;
        }
        sp += strlen(sp) + 1;
    }
    if (chosenSection.empty())
        return abortWithMessage(IDS_SIMPORT_ERR_NO_SERVER);

    // A snippet exported from [Imports] names a route the plugin could not
    // rebuild; a session made from it would connect straight to the host.
    {
        std::array<char, 512> route{};
        GetPrivateProfileStringA(chosenSection.c_str(), kUnsupportedRouteKey, "",
            route.data(), static_cast<DWORD>(route.size() - 1), localA.data());
        if (route[0]) {
            sftp::SessionDependency dep;
            dep.kind   = sftp::SessionDependency::Kind::Bastion;
            dep.detail = route.data();
            ShowDependencyRefusal(dep);
            return FS_FILE_USERABORT;
        }
    }

    // Destination DisplayName: strip leading `\` and, if present, a
    // trailing .ini extension. Folder structure is retained.
    std::string display = PathToDisplayNameW(RemoteName);
    if (display.size() > 4) {
        const std::string tail = display.substr(display.size() - 4);
        if (_stricmp(tail.c_str(), ".ini") == 0)
            display.resize(display.size() - 4);
    }
    if (display.empty())
        return abortWithMessage(IDS_SIMPORT_ERR_EMPTY_DEST);

    if (!OverWrite && sftp::IniSectionExists(display, inifilename))
        return FS_FILE_EXISTS;

    if (!CopyIniSectionAcrossFiles(chosenSection.c_str(),
            localA.data(), display.c_str(), inifilename))
    {
        return abortWithMessage(IDS_SIMPORT_ERR_WRITE);
    }

    // The session's `proxynr` came from another file, where that number meant
    // another record. Resolve it here: reuse a local record describing the
    // same route, create one when the route is new, and drop the reference
    // when nothing describes it — a number left pointing at a stranger is how
    // a session ends up quietly on the wrong proxy, or on none at all.
    if (GetPrivateProfileInt(display.c_str(), "proxynr", 0, inifilename) > 0) {
        std::array<char, 512> proxyServer{}, proxyUser{};
        const int proxytype = GetPrivateProfileInt("proxy", "proxytype", -1, localA.data());
        GetPrivateProfileStringA("proxy", "proxyserver", "", proxyServer.data(),
                                  static_cast<DWORD>(proxyServer.size() - 1), localA.data());
        GetPrivateProfileStringA("proxy", "proxyuser", "", proxyUser.data(),
                                  static_cast<DWORD>(proxyUser.size() - 1), localA.data());

        int localNr = 0;
        if (proxytype > 0 && proxyServer[0]) {
            localNr = FindMatchingProxyNr(proxytype, proxyServer.data(),
                                          proxyUser.data(), inifilename);
            if (localNr == 0) {
                localNr = NextFreeProxyNr(inifilename);
                const std::string dest = localNr > 1
                    ? std::format("proxy{}", localNr) : std::string("proxy");
                // The record arrives without its password: whatever held it
                // was bound to the machine it came from. A proxy that needs
                // one is asked for it on connect, which is why the user name
                // has to survive the trip.
                CopyIniSectionAcrossFiles("proxy", localA.data(), dest.c_str(), inifilename);
            }
        }

        std::array<char, 16> buf{};
        _itoa_s(localNr, buf.data(), buf.size(), 10);
        WritePrivateProfileString(display.c_str(), "proxynr", buf.data(), inifilename);
        if (localNr == 0)
            ShowPluginMessage(IDS_SIMPORT_PROXY_LOST, "", IDS_SIMPORT_TITLE,
                              "SFTP plugin - session import");
    }

    LoadServersFromIniW(inifilenameW, s_quickconnect);
    HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
    if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
    return FS_FILE_OK;
}

// Enumerate every INI section name in `iniFileNameW` and return the ones
// that live under `folderPrefix + '/'` — i.e. saved sessions organised
// beneath a folder. ANSI names (via CP_ACP conversion) match the on-disk
// section-name storage convention used everywhere else in this file. Used
// by folder-rename (F6 on a folder) and folder-delete (F8 on a folder);
// both first collect the affected session list, then mutate the INI.
static std::vector<std::string> CollectSessionsUnderFolder(
    const std::string& folderPrefix, LPCWSTR iniFileNameW)
{
    std::vector<std::string> out;
    std::array<wchar_t, 65535> serverlist{};
    GetPrivateProfileStringW(nullptr, nullptr, L"", serverlist.data(),
                              static_cast<DWORD>(serverlist.size()),
                              iniFileNameW);
    const std::string needle = folderPrefix + "/";
    wchar_t* wp = serverlist.data();
    while (wp[0]) {
        std::array<char, MAX_PATH> sectionA{};
        WideCharToMultiByte(CP_ACP, 0, wp, -1, sectionA.data(),
                             static_cast<int>(sectionA.size()),
                             nullptr, nullptr);
        const size_t len = strlen(sectionA.data());
        if (len > needle.size() &&
            _strnicmp(sectionA.data(), needle.c_str(), needle.size()) == 0)
        {
            out.emplace_back(sectionA.data(), len);
        }
        wp += wcslen(wp) + 1;
    }
    return out;
}

// Copy every key/value pair from `srcSection` in `srcIni` into `dstSection`
// in `dstIni`. The plugin-internal `_` metadata keys (provenance, refusal)
// are filtered out so the materialised session in the user's own INI carries
// only the user-visible connect fields. The destination section is cleared first so
// an overwrite is a full clean replace — leftover keys from a prior session
// (password, proxy, jump-host refs) never survive materialisation.
// Returns true if at least one key was copied.
static bool CopyIniSectionAcrossFiles(LPCSTR srcSection, LPCSTR srcIni,
                                       LPCSTR dstSection, LPCSTR dstIni)
{
    std::array<char, 4096> keyList{};
    GetPrivateProfileStringA(srcSection, nullptr, "",
                              keyList.data(),
                              static_cast<DWORD>(keyList.size() - 1),
                              srcIni);
    if (!keyList[0]) return false;

    WritePrivateProfileStringA(dstSection, nullptr, nullptr, dstIni);

    bool any = false;
    char* p = keyList.data();
    while (p[0]) {
        if (p[0] != '_') {
            std::array<char, 2048> valueBuf{};
            GetPrivateProfileStringA(srcSection, p, "",
                                     valueBuf.data(),
                                     static_cast<DWORD>(valueBuf.size() - 1),
                                     srcIni);
            WritePrivateProfileStringA(dstSection, p,
                                       valueBuf[0] ? valueBuf.data() : nullptr,
                                       dstIni);
            any = true;
        }
        p += strlen(p) + 1;
    }
    return any;
}

// The local record for a proxy an imported session goes through: the one
// that already describes the same route, or a new one under a number no
// session still points at. Written without a password.
static int ProxyRecordForDependency(const sftp::SessionDependency& dep, LPCSTR iniFile)
{
    const int type = static_cast<int>(dep.proxyType);
    int nr = FindMatchingProxyNr(type, dep.proxyServer, dep.proxyUser, iniFile);
    if (nr > 0)
        return nr;

    nr = NextFreeProxyNr(iniFile);
    const std::string section = nr > 1 ? std::format("proxy{}", nr) : std::string("proxy");
    WritePrivateProfileStringA(section.c_str(), "proxytype",
                               std::to_string(type).c_str(), iniFile);
    WritePrivateProfileStringA(section.c_str(), "proxyserver",
                               dep.proxyServer.c_str(), iniFile);
    if (!dep.proxyUser.empty())
        WritePrivateProfileStringA(section.c_str(), "proxyuser",
                                   dep.proxyUser.c_str(), iniFile);
    return nr;
}

// F5 materialise: copy a virtual session from the import cache into the
// user's own sftpplug.ini as a real saved session. `sourceId` identifies
// the adapter (e.g. "securecrt"), `subPath` is the virtual DisplayName
// inside the source (e.g. "my/ha1_remote"), NewName is the destination
// TC path the user copied to. The materialised session keeps what the
// adapter cached (host, user, key file, encoding) plus, when the source
// put a proxy the plugin speaks in front of it, that proxy as a local
// record. The password is never carried; it is asked for on connect.
static int MaterialiseVirtualSession(const std::string& sourceId,
                                      const std::string& subPath,
                                      LPCWSTR NewName,
                                      BOOL OverWrite)
{
    // Reject any subPath that is a pseudo entry, not a real cached session.
    if (subPath == kRefreshEntry || subPath == kAddCustomEntry ||
        subPath == kManageCustomFolder ||
        subPath.find(" not currently detected") != std::string::npos)
    {
        return FS_FILE_NOTSUPPORTED;
    }

    const std::string newDisplay = PathToDisplayNameW(NewName);
    if (newDisplay.empty())
        return FS_FILE_NOTFOUND;

    // Refuse overwrite unless TC's OverWrite flag is set.
    if (!OverWrite && sftp::IniSectionExists(newDisplay, inifilename))
        return FS_FILE_EXISTS;

    const std::string cacheSection =
        sftp::GetImportCache().SectionNameForConnect(sourceId, subPath);
    const std::string& cachePath = sftp::GetImportCache().CacheFilePath();
    if (cacheSection.empty() || cachePath.empty())
        return FS_FILE_NOTFOUND;

    // Materialising is not a way around the refusal: the copy would land in our
    // own list as an ordinary session, where nothing records that it was meant
    // to go through a bastion, and the first connect would go direct. Only a
    // proxy the plugin can rebuild gets through, and it comes along.
    const sftp::SessionDependency dep =
        sftp::ImportCache::ReadDependency(cacheSection, cachePath);
    if (!dep.transferable() && RefuseIfDependencyBlocks(cacheSection))
        return FS_FILE_USERABORT;

    if (!CopyIniSectionAcrossFiles(cacheSection.c_str(), cachePath.c_str(),
                                    newDisplay.c_str(), inifilename))
    {
        return FS_FILE_NOTFOUND;
    }

    if (dep.transferable()) {
        const int proxynr = ProxyRecordForDependency(dep, inifilename);
        WritePrivateProfileStringA(newDisplay.c_str(), "proxynr",
                                   std::to_string(proxynr).c_str(), inifilename);
    }

    // Sync g_servers so the new session shows up in the plugin panel on the
    // next FsFindFirst; refresh TC so the user sees the row immediately.
    LoadServersFromIniW(inifilenameW, s_quickconnect);
    HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
    if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
    return FS_FILE_OK;
}

// Modal folder-picker for [Add custom location...]. Wrapped narrow because
// the plugin's INI paths are ANSI throughout — the WFX API is ANSI at the
// icon layer too. Returns false on Cancel or on a folder that cannot be
// converted to a filesystem path (e.g. namespace-only selections).
// The picker itself lives in ImportIoUtil so every future adapter's custom-
// path enrollment reuses the same modern shell dialog.

// Apply one enumeration result to the cache per the prune rules:
//   Unreachable    → keep the cached entries (do nothing)
//   OkEmpty        → prune this channel's cached entries
//   OkWithSessions → replace this channel's cached entries with the new list
static void ApplyEnumerationToCache(sftp::IExternalSessionSource* adapter,
                                     const std::string& sourceId,
                                     const std::string& channelTag,
                                     sftp::EnumerationResult&& result)
{
    switch (result.status) {
        case sftp::EnumerationStatus::Unreachable:
            return;
        case sftp::EnumerationStatus::OkEmpty:
            sftp::GetImportCache().PruneChannel(sourceId, channelTag);
            return;
        case sftp::EnumerationStatus::OkWithSessions: {
            // Fill tConnectSettings for every enumerated entry. The vector is
            // pre-sized so its element addresses remain stable for the
            // duration of the ReplaceChannel call (CacheWriteEntry holds a
            // non-owning pointer to each).
            std::vector<tConnectSettings> settingsStore(result.sessions.size());
            std::vector<sftp::CacheWriteEntry> writes;
            writes.reserve(result.sessions.size());
            for (size_t i = 0; i < result.sessions.size(); ++i) {
                sftp::SessionDependency dependency;
                if (!adapter->LoadSettings(result.sessions[i], &settingsStore[i], &dependency))
                    continue;
                sftp::CacheWriteEntry w;
                w.displayName = result.sessions[i].displayName;
                w.settings    = &settingsStore[i];
                w.dependency  = std::move(dependency);
                writes.push_back(std::move(w));
            }
            sftp::GetImportCache().ReplaceChannel(sourceId, channelTag, writes);
            return;
        }
    }
}

// Re-scan every configured channel of one import source (the standard
// registry / %APPDATA% location plus every user-added custom path) and
// update the on-disk cache accordingly. Called from FsExecuteFileW when
// the user activates [Refresh] inside an [Imports]\<Source>\ folder.
void RefreshImportSource(const std::string& sourceId)
{
    auto* adapter = sftp::GetImportSourceRegistry().Find(sourceId.c_str());
    if (!adapter) return;

    ApplyEnumerationToCache(adapter, sourceId, "standard",
                            adapter->EnumerateStandard());

    for (const auto& path : LoadImportCustomPaths(sourceId.c_str(), inifilename)) {
        ApplyEnumerationToCache(adapter, sourceId, path,
                                adapter->EnumerateCustomPath(path));
    }
}

// Length (in wide chars) of the session's displayName once embedded in a
// TC-style path — i.e. the number of wchars between the leading '\\' and the
// '\\' that starts the server-side sub-path. Used to truncate RemoteName at
// the session boundary instead of at the first internal slash (which would
// be wrong for folder-nested sessions like "\\folder\\session\\subpath").
static size_t SessionPrefixWideLen(const std::string& displayName) noexcept
{
    if (displayName.empty()) return 0;
    const int wlen = MultiByteToWideChar(CP_ACP, 0, displayName.c_str(), -1,
                                          nullptr, 0);
    return wlen > 1 ? static_cast<size_t>(wlen - 1) : 0;
}

int WINAPI FsExecuteFileW(HWND MainWin, LPWSTR RemoteName, LPCWSTR Verb)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_EXEC_ERROR, [&]() -> int {
        std::array<char, wdirtypemax> remoteserver{};
        std::array<WCHAR, wdirtypemax> remotedir{};
        if (_wcsicmp(Verb, L"open") == 0) {   // follow symlink
            // Rows inside the [Active Sessions] magic folder are virtual
            // markers, not real files. Enter on them must NOT fall through
            // to TC's "download then shell-open" path. Two cases:
            //   1. [Disconnect All] — Enter performs the bulk action (same
            //      gesture as F8 on it). There's nothing to navigate to,
            //      so Enter == "execute" makes sense here.
            //   2. A live session row — Enter is a silent no-op so an
            //      accidental arrow-and-Enter doesn't kill a connection.
            //      F8 stays the deliberate disconnect gesture.
            // Enter on a row inside [Proxies] opens that record's editor. The
            // row name begins with the record's number, which is what makes
            // the row identify a record even after other records come and go.
            {
                std::string proxyEntry;
                if (IsProxiesPath(RemoteName, &proxyEntry) && !proxyEntry.empty()) {
                    const int proxynr = ProxyNrFromRowName(proxyEntry);
                    if (proxynr > 0)
                        ShowProxyRecordDialog(proxynr, inifilename);
                    return FS_EXEC_OK;
                }
            }

            {
                std::string activeEntry;
                if (IsActiveSessionsPath(RemoteName, &activeEntry)) {
                    if (!activeEntry.empty() &&
                        _stricmp(activeEntry.c_str(), kDisconnectAllEntry) == 0)
                    {
                        FsDeleteFileW(RemoteName);
                        // After Disconnect All the [Active Sessions] folder
                        // is empty (and gone from root since no active
                        // sessions remain). Auto-navigate the panel back to
                        // plugin root via TC's documented symlink-follow
                        // protocol: rewrite RemoteName in place to the
                        // target path and return FS_EXEC_SYMLINK.
                        RemoteName[0] = L'\\';
                        RemoteName[1] = 0;
                        return FS_EXEC_SYMLINK;
                    }
                    return FS_EXEC_OK;
                }
            }

            // Pseudo helper entry "[F7 = new connection]" opens the
            // new-connection dialog directly, no resolver involvement.
            if (RemoteName[0] && RemoteName[1] &&
                _wcsicmp(RemoteName + 1, s_f7newconnectionW.data()) == 0) {
                pConnectSettings serveridQuick = SftpConnectToServer(s_quickconnect, inifilename, nullptr);
                LoadServersFromIniW(inifilenameW, s_quickconnect);
                return serveridQuick ? FS_EXEC_OK : FS_EXEC_YOURSELF;
            }

            // Entries inside the [Imports] magic folder — dispatch by the
            // classification. Umbrella / unknown-source Enter events land
            // here from TC too; those are navigations, not actions, so we
            // return FS_EXEC_OK to keep TC from falling through to the
            // download path.
            {
                std::string sourceId, subPath;
                const ImportsPathKind kind = ClassifyImportsPath(RemoteName,
                    &sourceId, &subPath);
                if (kind != ImportsPathKind::NotImports) {
                    if (kind == ImportsPathKind::Umbrella ||
                        kind == ImportsPathKind::UnknownSource)
                        return FS_EXEC_OK;

                    if (subPath == kRefreshEntry) {
                        // Re-scan every configured channel (standard +
                        // custom paths).
                        RefreshImportSource(sourceId);
                        // Symlink back to the parent source folder so TC
                        // rebuilds the listing with any new cache content.
                        auto* adapter = sftp::GetImportSourceRegistry().Find(sourceId.c_str());
                        if (adapter) {
                            std::wstring target;
                            target += L'\\';
                            target += kImportsFolderW;
                            target += L'\\';
                            target += unicode_util::narrow_to_wide(adapter->FolderName());
                            wcslcpy(RemoteName, target.c_str(), wdirtypemax - 1);
                            return FS_EXEC_SYMLINK;
                        }
                        return FS_EXEC_OK;
                    }

                    // [Add custom location...] — modal picker (folder or
                    // file, per adapter capability), persist the chosen
                    // path, immediately scan it into the cache, then
                    // FS_EXEC_SYMLINK back to the source folder so TC
                    // rebuilds the listing with the new sessions included
                    // and [Manage custom locations] surfaced.
                    if (subPath == kAddCustomEntry) {
                        HWND tcMain = FindWindowA("TTOTAL_CMD", nullptr);
                        auto* pickerAdapter =
                            sftp::GetImportSourceRegistry().Find(sourceId.c_str());
                        if (!pickerAdapter)
                            return FS_EXEC_OK;
                        std::string chosen;
                        bool picked = false;
                        switch (pickerAdapter->CustomPathPicker()) {
                            case sftp::CustomPathPickerKind::None:
                                // Adapter declared no custom-path concept —
                                // the entry should not have been surfaced,
                                // but silently no-op if TC ever routes here.
                                return FS_EXEC_OK;
                            case sftp::CustomPathPickerKind::Folder:
                                picked = sftp::BrowseForFolder(tcMain,
                                    "Select folder to import sessions from",
                                    nullptr, chosen);
                                break;
                            case sftp::CustomPathPickerKind::File:
                                picked = sftp::BrowseForFile(tcMain,
                                    "Select file to import sessions from",
                                    pickerAdapter->CustomPathFileFilter(),
                                    nullptr, chosen);
                                break;
                        }
                        if (!picked)
                            return FS_EXEC_OK;  // user cancelled
                        if (!SaveImportCustomPath(sourceId.c_str(),
                                chosen.c_str(), inifilename))
                        {
                            // Save failure (e.g. duplicate) — still scan the
                            // path once so a duplicate-add still refreshes
                            // that channel's cache. SaveImportCustomPath
                            // reports true for duplicates too, so a false
                            // return here is a genuine write failure and we
                            // skip the scan to avoid dangling channel state.
                            return FS_EXEC_OK;
                        }
                        auto* adapter = pickerAdapter;
                        ApplyEnumerationToCache(adapter, sourceId, chosen,
                            adapter->EnumerateCustomPath(chosen));
                        // Symlink back to `[Imports]\<Source>\`.
                        std::wstring target;
                        target += L'\\';
                        target += kImportsFolderW;
                        target += L'\\';
                        target += unicode_util::narrow_to_wide(adapter->FolderName());
                        wcslcpy(RemoteName, target.c_str(), wdirtypemax - 1);
                        return FS_EXEC_SYMLINK;
                    }
                    // Enter into [Manage custom locations] or one of its
                    // listed path entries — no side-effect action. TC just
                    // displays the folder view built by the listing code;
                    // F8 on an entry deletes it via FsDeleteFile.
                    if (subPath == kManageCustomFolder ||
                        (subPath.size() > strlen(kManageCustomFolder) &&
                         subPath.compare(0, strlen(kManageCustomFolder), kManageCustomFolder) == 0))
                    {
                        return FS_EXEC_OK;
                    }

                    // Virtual session Enter: subPath is the session's
                    // DisplayName inside the source (e.g. "dron/hz-1-test2").
                    // The cache-INI section name carries the fields; connect
                    // reads them silently when complete (host, user, key
                    // file). Any missing password falls back to the standard
                    // interactive prompt exactly as a real saved session
                    // would — the cache writer never persists passwords for
                    // adapters that don't recover them.
                    //
                    // We do NOT connect here — we only pre-register the
                    // alias so the follow-up FsFindFirstW knows which cache
                    // section to load, then redirect TC via FS_EXEC_SYMLINK
                    // to the alias path. The SSH connect happens inside
                    // that FsFindFirstW, which TC treats as an in-flight
                    // navigation and decorates with its native progress UI
                    // — the same UI real sessions get on Enter. Doing the
                    // connect here (as this code used to) hides the
                    // handshake from TC's UI accounting and makes the
                    // panel look frozen on slow first-connects.
                    const std::string cacheSection =
                        sftp::GetImportCache().SectionNameForConnect(sourceId, subPath);
                    const std::string& cachePath =
                        sftp::GetImportCache().CacheFilePath();
                    if (cacheSection.empty() || cachePath.empty()) {
                        return FS_EXEC_OK;
                    }
                    if (RefuseIfDependencyBlocks(cacheSection))
                        return FS_EXEC_OK;

                    // TC-safe alias: no dots, brackets, slashes — TC treats
                    // it as a single-segment session name, so its toolbar
                    // Disconnect button works normally instead of forcing a
                    // fallback to the real filesystem on click. The
                    // BuildPluginFolderListing filter hides names starting
                    // with the alias prefix from the plugin root view.
                    const std::string aliasName =
                        sftp::MakeVirtualSessionAlias(sourceId, cacheSection);

                    // Idempotent pre-registration: repeat Enters overwrite
                    // the same alias entry (same sourceId+cacheSection hash
                    // to the same alias). Info is picked up by FsFindFirstW
                    // on the redirect target below.
                    sftp::RegisterVirtualSession(aliasName,
                        {sourceId, cacheSection, subPath});

                    std::wstring target = L"\\";
                    target += unicode_util::narrow_to_wide(aliasName);
                    wcslcpy(RemoteName, target.c_str(), wdirtypemax - 1);
                    return FS_EXEC_SYMLINK;
                }
            }

            const PathResolution r = ResolvePathKindW(RemoteName);

            // Path enters a session and continues with a server-side sub-path
            // → resolve symlink on the remote.
            if (r.kind == PathKind::SessionWithSubpath) {
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
                if (!serverid)
                    return FS_EXEC_YOURSELF;

                if (!SftpLinkFolderTargetW(serverid, remotedir.data(), wdirtypemax - 1)) {
                    // Tilde home shortcut — never let TC download it.
                    std::wstring_view rv(remotedir.data());
                    while (!rv.empty() && (rv.front() == L'\\' || rv.front() == L'/'))
                        rv.remove_prefix(1);
                    if (rv == L"~") {
                        // Shell was stale (e.g. after PHP→SCP session switch). Reconnect once and retry.
                        SftpCloseConnection(serverid);
                        Sleep(500);
                        if (SftpConnect(serverid) == SFTP_OK &&
                            SftpLinkFolderTargetW(serverid, remotedir.data(), wdirtypemax - 1)) {
                            // fall through to success path below
                        } else {
                            return FS_EXEC_ERROR;  // fail hard — never download "~" as a file
                        }
                    } else {
                        return FS_EXEC_YOURSELF;
                    }
                }

                // Build the target: session prefix + resolved remote path.
                // Truncate at the session boundary (which can span multiple
                // path segments when the session is in a folder), then append
                // the symlink target the server gave us.
                const size_t prefixLen = SessionPrefixWideLen(r.displayName);
                if (prefixLen == 0 || prefixLen + 1 > wcslen(RemoteName))
                    return FS_EXEC_ERROR;
                RemoteName[1 + prefixLen] = 0;
                wcslcat(RemoteName, remotedir.data(), wdirtypemax-1);
                ReplaceSlashByBackslashW(RemoteName);
                return FS_EXEC_SYMLINK;
            }

            // Path is a leaf session (root-level OR nested in a folder).
            // Lazy-connect (or pick up an existing connection) and expand the
            // path to include the session's last-active / base directory so
            // TC navigates inside the remote filesystem on Enter.
            if (r.kind == PathKind::SessionLeaf) {
                strlcpy(remoteserver.data(), r.displayName.c_str(), remoteserver.size() - 1);
                LPWSTR p = RemoteName + wcslen(RemoteName);
                int pmaxlen = wdirtypemax - static_cast<int>(p - RemoteName) - 1;

                pConnectSettings serverid = static_cast<pConnectSettings>(
                    GetServerIdFromName(remoteserver.data(), GetCurrentThreadId()));
                if (serverid) {
                    SftpGetLastActivePathW(serverid, p, pmaxlen);
                } else if (_stricmp(remoteserver.data(), s_quickconnect) == 0) {
                    // Quick connect: connect here, otherwise the selected sub-path can't be applied.
                    serverid = SftpConnectToServer(remoteserver.data(), inifilename, nullptr);
                    if (!serverid)
                        return FS_EXEC_OK; // cancelled or save-only from quick dialog
                    SetServerIdForName(remoteserver.data(), static_cast<SERVERID>(serverid));
                    SftpGetLastActivePathW(serverid, p, pmaxlen);
                } else {
                    // Convert the (potentially slash-separated) DisplayName to wide
                    // and read the session's base path from INI without connecting.
                    std::array<wchar_t, wdirtypemax> displayNameW{};
                    MultiByteToWideChar(CP_ACP, 0, r.displayName.c_str(), -1,
                                        displayNameW.data(), static_cast<int>(displayNameW.size()));
                    SftpGetServerBasePathW(displayNameW.data(), p, pmaxlen, inifilename);
                }
                if (p[0] == 0)
                    wcslcat(RemoteName, L"/", wdirtypemax-1);
                ReplaceSlashByBackslashW(RemoteName);
                return FS_EXEC_SYMLINK;
            }

            // Folder or Invalid → let TC do whatever it does (folders navigate
            // via FsFindFirstW, not FsExecuteFile, so we usually don't get
            // called for them; invalid paths fall back to TC).
            return FS_EXEC_YOURSELF;
        }
        if (_wcsicmp(Verb, L"properties") == 0) {
            // A session under [Imports] is not in the registry, so the
            // resolver below cannot classify it and the handler would return
            // in silence. Say why instead, and point at what does work.
            if (IsImportsPath(RemoteName)) {
                ShowPluginMessage(IDS_IMPORTS_NO_EDIT,
                                  "This session belongs to another program and cannot be edited here.\n"
                                  "Press F3 to see its settings, or F5 to copy it into your own session list.",
                                  IDS_TITLE_SFTP, "SFTP", MB_ICONINFORMATION);
                return FS_EXEC_OK;
            }

            const PathResolution r = ResolvePathKindW(RemoteName);

            // SessionLeaf (root-level OR nested in a folder) → open the Edit
            // Session dialog. Pseudo helper entries are skipped silently.
            if (r.kind == PathKind::SessionLeaf) {
                if (_stricmp(r.displayName.c_str(), s_f7newconnection) != 0 &&
                    _stricmp(r.displayName.c_str(), s_quickconnect)    != 0)
                {
                    if (SftpConfigureServer(r.displayName.c_str(), inifilename)) {
                        LoadServersFromIniW(inifilenameW, s_quickconnect);
                        if (MainWin) PostMessage(MainWin, WM_USER + 51, 540, 0);

                        // Force a disconnect so the next listing rebuilds the
                        // connection with the edited settings (TC by itself
                        // does not drop the active session on Alt+Enter).
                        std::string disconnPath;
                        disconnPath.reserve(r.displayName.size() + 1);
                        disconnPath.append("\\").append(r.displayName);
                        FsDisconnect(disconnPath.c_str());
                    }
                }
                return FS_EXEC_OK;
            }

            // SessionWithSubpath → server-side properties on a real file.
            if (r.kind == PathKind::SessionWithSubpath) {
                std::array<WCHAR, wdirtypemax> remotenameW{};
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotenameW.data(), remotenameW.size() - 1);
                if (serverid)
                    SftpShowPropertiesW(serverid, remotenameW.data());
                else
                    return FS_EXEC_ERROR;
                return FS_EXEC_OK;
            }

            // Folder / Invalid / pseudo entries → nothing useful to show.
            return FS_EXEC_OK;
        }
        if (_wcsnicmp(Verb, L"chmod ", 6) == 0) {
            const PathResolution rc = ResolvePathKindW(RemoteName);
            if (rc.kind == PathKind::SessionWithSubpath) {
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
                if (serverid && SftpChmodW(serverid, remotedir.data(), Verb+6))
                    return FS_EXEC_OK;
            }
            return FS_EXEC_ERROR;
        }
        if (_wcsnicmp(Verb, L"quote ", 6) == 0) {
            const PathResolution rq = ResolvePathKindW(RemoteName);
            if (wcsncmp(Verb+6, L"cd ", 3) == 0) {
                // first get the start path within the plugin
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
                if (!serverid)
                    return FS_EXEC_ERROR;
                if (Verb[9] != '\\' && Verb[9] != '/') {     // relative path?
                    wcslcatbackslash(remotedir.data(), remotedir.size() - 1);
                    wcslcat(remotedir.data(), Verb+9, remotedir.size() - 1);
                } else
                    wcslcpy(remotedir.data(), Verb+9, remotedir.size() - 1);
                ReplaceSlashByBackslashW(remotedir.data());

                // Truncate at the session boundary, then append the new dir.
                const size_t prefixLen = SessionPrefixWideLen(rq.displayName);
                if (prefixLen == 0 || prefixLen + 1 > wcslen(RemoteName))
                    return FS_EXEC_ERROR;
                RemoteName[1 + prefixLen] = 0;
                wcslcat(RemoteName, remotedir.data(), wdirtypemax-1);
                ReplaceSlashByBackslashW(RemoteName);
                return FS_EXEC_SYMLINK;
            } else {
                if (rq.kind == PathKind::SessionWithSubpath || rq.kind == PathKind::SessionLeaf) {
                    std::array<WCHAR, wdirtypemax> quoteRemotedir{};
                    pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, quoteRemotedir.data(), quoteRemotedir.size() - 1);
                    if (serverid && SftpQuoteCommand2W(serverid, quoteRemotedir.data(), Verb+6, nullptr, 0) != 0)
                        return FS_EXEC_OK;
                }
            }
            return FS_EXEC_ERROR;
        }
        if (_wcsnicmp(Verb, L"mode ", 5) == 0) {   // Binary/Text/Auto
            SftpSetTransferModeW(Verb+5);
            return FS_EXEC_OK;
        }
        return FS_EXEC_ERROR;
    });
}

int WINAPI FsExecuteFile(HWND MainWin, LPSTR RemoteName, LPCSTR Verb)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_EXEC_ERROR, [&]() -> int {
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        std::array<WCHAR, wdirtypemax> verbW{};
        int ret = FsExecuteFileW(MainWin, awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), awlcopy(verbW.data(), Verb, verbW.size() - 1));
        if (ret == FS_EXEC_SYMLINK)
            walcopy(RemoteName, remoteNameW.data(), MAX_PATH-1);
        return ret;
    });
}

static bool CopyMoveEncryptedPassword(LPCSTR OldName, LPSTR NewName, bool Move)
{
    if (!CryptProc)
        return false;
    int mode = Move ? FS_CRYPT_MOVE_PASSWORD : FS_CRYPT_COPY_PASSWORD;
    int rc = CryptProc(PluginNumber, CryptoNumber, mode, OldName, NewName, 0);
    return (rc == FS_FILE_OK) ? true : false;
}

// Whether the session may already hold that file. Only a server that clearly
// answers "no such file" makes it absent; anything it could not answer counts
// as present, so Total Commander asks before the upload overwrites rather
// than the upload overwriting on a guess.
static bool RemoteFileExists(pConnectSettings cs, LPCWSTR remoteRelative)
{
    if (!cs || !remoteRelative || !remoteRelative[0])
        return false;

    if (IsPhpAgentTransport(cs))
        return PhpAgentPathMayExist(cs, remoteRelative);

    if (cs->scponly) {
        // The wide path goes to the shell helper, which applies the session's
        // encoding once; a narrow, already converted one would be converted
        // again and name a file that does not exist. `test -e` answers 1 for
        // a missing path — any other answer leaves the question open.
        std::wstring pathW(remoteRelative);
        std::replace(pathW.begin(), pathW.end(), L'\\', L'/');
        const std::wstring cmdW = L"test -e '" + string_util::ShellQuoteSingleW(pathW.c_str()) + L"'";
        return SftpQuoteCommand2W(cs, nullptr, cmdW.c_str(), nullptr, 0) != 1;
    }

    if (cs->sftpsession) {
        const std::string pathA = ToRemotePathA(cs, remoteRelative);
        if (pathA.empty())
            return true;
        LIBSSH2_SFTP_ATTRIBUTES attr{};
        int rc = 0;
        do {
            rc = cs->sftpsession->lstat(pathA.c_str(), &attr);
            if (rc == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(cs->sock);
        } while (rc == LIBSSH2_ERROR_EAGAIN);
        if (rc >= 0)
            return true;
        const unsigned long fx =
            (rc == LIBSSH2_ERROR_SFTP_PROTOCOL) ? cs->sftpsession->lastError() : 0;
        return fx != LIBSSH2_FX_NO_SUCH_FILE && fx != LIBSSH2_FX_NO_SUCH_PATH;
    }
    return true;
}

// Copy one file from one session to another, which no single SFTP operation
// can do: the data travels down to this machine and back up regardless, so it
// lands in a temporary file on the way. Directories are refused — Total
// Commander walks a tree itself, creating each directory through FsMkDir and
// calling here once per file.
// Lends one session a slice of the progress bar, and the pair of names the
// user should see, for as long as its leg of a two-leg copy runs.
class ProgressSlice {
public:
    ProgressSlice(pConnectSettings cs, int from, int span, LPCWSTR source, LPCWSTR target) noexcept
        : m_cs(cs)
    {
        if (!m_cs) return;
        m_cs->progressFrom = from;
        m_cs->progressSpan = span;
        m_cs->progressSourceOverride = source;
        m_cs->progressTargetOverride = target;
    }
    ~ProgressSlice()
    {
        if (!m_cs) return;
        m_cs->progressFrom = 0;
        m_cs->progressSpan = 100;
        m_cs->progressSourceOverride = nullptr;
        m_cs->progressTargetOverride = nullptr;
    }
    ProgressSlice(const ProgressSlice&) = delete;
    ProgressSlice& operator=(const ProgressSlice&) = delete;
private:
    pConnectSettings m_cs;
};

// Whether two sessions name one file: the same account on the same server
// and the same path. A PHP agent is identified by its whole URL, since two
// agents on one host may serve different roots. Only what the sessions say
// is compared, so another name for the same host is not recognised.
static bool SameRemoteFile(pConnectSettings a, const std::wstring& aPath,
                           pConnectSettings b, const std::wstring& bPath)
{
    if (aPath != bPath || a->user != b->user)
        return false;
    if (IsPhpAgentTransport(a) || IsPhpAgentTransport(b))
        return IsPhpAgentTransport(a) && IsPhpAgentTransport(b) &&
               _stricmp(a->server.c_str(), b->server.c_str()) == 0;

    std::array<char, MAX_PATH> hostA{}, hostB{};
    WORD portA = 0, portB = 0;
    if (!ParseAddress(a->server.c_str(), hostA.data(), &portA, 22) ||
        !ParseAddress(b->server.c_str(), hostB.data(), &portB, 22))
        return false;
    return portA == portB && _stricmp(hostA.data(), hostB.data()) == 0;
}

static int CopyBetweenSessions(LPCWSTR OldName, LPCWSTR NewName,
                               bool Move, bool OverWrite, RemoteInfoStruct* ri)
{
    if (ri && (ri->Attr & FILE_ATTRIBUTE_DIRECTORY))
        return FS_FILE_NOTSUPPORTED;

    std::wstring srcRel(wdirtypemax, L'\0');
    std::wstring dstRel(wdirtypemax, L'\0');
    pConnectSettings src = ResolveTransferSession(OldName, srcRel.data(), srcRel.size() - 1);
    pConnectSettings dst = ResolveTransferSession(NewName, dstRel.data(), dstRel.size() - 1);
    srcRel.resize(wcslen(srcRel.data()));
    dstRel.resize(wcslen(dstRel.data()));
    if (!src || !dst)
        return FS_FILE_NOTFOUND;

    // The two legs run on the SFTP-family transfer paths, which LAN Pair
    // does not go through; it is refused rather than reached with no
    // session underneath.
    if (IsLanPairTransport(src) || IsLanPairTransport(dst))
        return FS_FILE_NOTSUPPORTED;

    // Copied onto itself, the file is cut short by the upload before its
    // copy is written back, and a move would then delete it. Inside one
    // session Total Commander catches this; across two it cannot tell.
    if (SameRemoteFile(src, srcRel, dst, dstRel)) {
        SFTP_LOG("ENTRY", "CopyBetweenSessions refused: same file '%S'", srcRel.c_str());
        ShowPluginMessage(IDS_ERR_SAME_FILE,
            "Source and destination are the same file: both sessions point at "
            "the same account on the same server, at the same path. Copying a "
            "file onto itself would cut it short, so this is refused.",
            IDS_TITLE_SFTP, "SFTP");
        return FS_FILE_USERABORT;
    }

    std::array<wchar_t, MAX_PATH> tempDir{};
    std::array<wchar_t, MAX_PATH> tempFile{};
    if (!GetTempPathW(static_cast<DWORD>(tempDir.size()), tempDir.data()) ||
        !GetTempFileNameW(tempDir.data(), L"sftp", 0, tempFile.data()))
    {
        return FS_FILE_WRITEERROR;
    }

    // Total Commander expects to be told when the destination is taken: it
    // asks the user and calls again with the flag set. The upload underneath
    // truncates without looking, so without this the answer would be given by
    // overwriting the file.
    if (!OverWrite && RemoteFileExists(dst, dstRel.c_str()))
        return FS_FILE_EXISTS;

    SFTP_LOG("ENTRY", "CopyBetweenSessions '%S' -> '%S' via '%S'",
             srcRel.c_str(), dstRel.c_str(), tempFile.data());

    // Reading owns the first half of the bar, writing the second, and both
    // report the two remote names so the temporary file never shows up.
    int rc = 0;
    {
        ProgressSlice _slice(src, 0, 50, OldName, NewName);
        rc = SftpDownloadFileW(src, srcRel.c_str(), tempFile.data(), true,
                               ri ? ri->Size64 : 0,
                               ri ? &ri->LastWriteTime : nullptr, false);
    }
    SFTP_LOG("ENTRY", "CopyBetweenSessions download rc=%d", rc);
    if (rc != SFTP_OK) {
        DeleteFileW(tempFile.data());
        return (rc == SFTP_ABORT) ? FS_FILE_USERABORT : FS_FILE_READERROR;
    }

    {
        // The upload runs against the other session, so its status lines and
        // progress belong to that one.
        SessionContextGuard _dstGuard(dst);
        ProgressSlice _slice(dst, 50, 50, OldName, NewName);
        rc = SftpUploadFileW(dst, tempFile.data(), dstRel.c_str(), false, true);
    }
    SFTP_LOG("ENTRY", "CopyBetweenSessions upload rc=%d", rc);
    DeleteFileW(tempFile.data());

    switch (rc) {
        case SFTP_OK: break;
        case SFTP_EXISTS:      return FS_FILE_EXISTS;
        case SFTP_ABORT:       return FS_FILE_USERABORT;
        default:               return FS_FILE_WRITEERROR;
    }

    // A move is the same copy with the source taken away once the destination
    // is safely written. Leaving it behind would turn the move into a copy in
    // silence, so a refusal to delete is reported.
    if (Move) {
        SessionContextGuard _srcGuard(src);
        if (SftpDeleteFileW(src, srcRel.c_str(), false) != SFTP_OK) {
            SFTP_LOG("ENTRY", "CopyBetweenSessions: the source survived the move");
            ShowStatusId(IDS_ERR_DELETE, nullptr, true);
        }
    }
    return FS_FILE_OK;
}

int WINAPI FsRenMovFileW(LPCWSTR OldName, LPCWSTR NewName, BOOL Move, BOOL OverWrite, RemoteInfoStruct * ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        SFTP_LOG("ENTRY", "FsRenMovFileW start old='%S' new='%S' move=%d overwrite=%d",
                 OldName ? OldName : L"(null)", NewName ? NewName : L"(null)",
                 Move ? 1 : 0, OverWrite ? 1 : 0);

        // \[Imports]\ interactions with FsRenMovFile:
        //   OldName in Imports + NewName outside → materialise (both F5 copy
        //     and F6 move; the "delete source" leg of a move is a no-op for
        //     virtual entries — the source is a mirror of the third-party
        //     app's state and will simply reappear on the next refresh, so
        //     move degrades to copy without any user-visible weirdness).
        //   OldName outside + NewName in Imports → refuse (Imports is
        //     read-only from outside).
        //   Both in Imports → refuse (virtual→virtual has no semantics).
        {
            std::string oldSourceId, oldSubPath;
            const ImportsPathKind oldKind = ClassifyImportsPath(OldName,
                &oldSourceId, &oldSubPath);
            const bool newInImports = IsImportsPath(NewName);
            if (oldKind != ImportsPathKind::NotImports || newInImports) {
                if (newInImports)
                    return FS_FILE_NOTSUPPORTED;
                // Only a real virtual session (adapter matched + concrete
                // sub-path) materialises; umbrella / source-root / unknown-
                // source / pseudo-entry gestures refuse.
                if (oldKind != ImportsPathKind::SourceSubPath)
                    return FS_FILE_NOTSUPPORTED;
                return MaterialiseVirtualSession(oldSourceId, oldSubPath,
                                                  NewName, OverWrite);
            }
        }

        const PathResolution rOld = ResolvePathKindW(OldName);
        const PathResolution rNew = ResolvePathKindW(NewName);

        // --- 1. Session rename / move ---
        // Covers all of: flat-flat rename, flat→folder move, folder→flat move,
        // and cross-folder move. The new DisplayName comes from the path
        // itself (PathToDisplayName), since the destination session can't
        // exist in the registry yet (otherwise we'd be overwriting).
        if (rOld.kind == PathKind::SessionLeaf) {
            const std::string newDisplay = PathToDisplayNameW(NewName);
            if (newDisplay.empty())
                return FS_FILE_NOTFOUND;
            if (_stricmp(rOld.displayName.c_str(), newDisplay.c_str()) == 0)
                return FS_FILE_OK;
            if (!OverWrite && (rNew.kind == PathKind::SessionLeaf ||
                               rNew.kind == PathKind::Folder))
                return FS_FILE_EXISTS;

            // Disconnect the live connection (if any) before yanking the INI
            // section out from under it — see the original F6 rename note.
            if (Move) {
                std::string disconnPath;
                disconnPath.reserve(rOld.displayName.size() + 1);
                disconnPath.append("\\").append(rOld.displayName);
                FsDisconnect(disconnPath.c_str());
            }
            int rc = CopyMoveServerInIniW(rOld.displayName.c_str(),
                                          newDisplay.c_str(),
                                          !!Move, !!OverWrite, inifilenameW);
            if (rc == FS_FILE_OK) {
                std::string newDisplayMut = newDisplay;
                CopyMoveEncryptedPassword(rOld.displayName.c_str(),
                                          newDisplayMut.data(), !!Move);
                if (Move) {
                    UpdateJumpRefsOnSessionRename(rOld.displayName.c_str(),
                                                  newDisplay.c_str(),
                                                  inifilename);
                }
                LoadServersFromIniW(inifilenameW, s_quickconnect);
                // cm_RereadSource is needed after rename because the source
                // DisplayName TC still holds no longer exists in our registry.
                // For copy (Move=FALSE) TC's own post-copy refresh handles the
                // panel, and posting cm_RereadSource on top races with TC's
                // same-panel navigation on Shift+F5, throwing the user out of
                // the plugin.
                if (Move) {
                    HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
                    if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
                }
                return FS_FILE_OK;
            }
            if (rc == FS_FILE_EXISTS)
                return FS_FILE_EXISTS;
            return FS_FILE_NOTFOUND;
        }

        // --- 2. Folder rename / move (bulk) ---
        // Every saved session whose name starts with `oldPrefix + "/"` is
        // renamed to `newPrefix + "/" + leaf`, with jump-host references
        // updated by prefix.
        if (rOld.kind == PathKind::Folder && !rOld.displayName.empty()) {
            const std::string newFolder = PathToDisplayNameW(NewName);
            if (newFolder.empty())
                return FS_FILE_NOTFOUND;
            if (_stricmp(rOld.displayName.c_str(), newFolder.c_str()) == 0)
                return FS_FILE_OK;
            if (!OverWrite && (rNew.kind == PathKind::SessionLeaf ||
                               rNew.kind == PathKind::Folder))
                return FS_FILE_EXISTS;

            // Build the {old, new} rename list up front so we don't mutate
            // INI while enumerating its section list.
            const std::vector<std::string> oldNames =
                CollectSessionsUnderFolder(rOld.displayName, inifilenameW);
            if (oldNames.empty())
                return FS_FILE_NOTFOUND;
            std::vector<std::pair<std::string, std::string>> renames;
            renames.reserve(oldNames.size());
            const std::string needle = rOld.displayName + "/";
            for (const auto& oldName : oldNames) {
                std::string newName =
                    newFolder + "/" + oldName.substr(needle.size());
                renames.emplace_back(oldName, std::move(newName));
            }

            for (const auto& [oldName, newName] : renames) {
                if (Move) {
                    std::string disconnPath;
                    disconnPath.reserve(oldName.size() + 1);
                    disconnPath.append("\\").append(oldName);
                    FsDisconnect(disconnPath.c_str());
                }
                CopyMoveServerInIniW(oldName.c_str(), newName.c_str(),
                                      !!Move, !!OverWrite, inifilenameW);
                std::string newNameMut = newName;
                CopyMoveEncryptedPassword(oldName.c_str(), newNameMut.data(), !!Move);
            }
            if (Move) {
                UpdateJumpRefsOnFolderRename(rOld.displayName.c_str(),
                                              newFolder.c_str(), inifilename);
            }
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            // See the session branch above — cm_RereadSource only for rename.
            if (Move) {
                HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
                if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
            }
            return FS_FILE_OK;
        }

        // --- 3. Server-side rename (file / directory inside a session) ---
        // Two different sessions cannot be joined by a server-side rename. Say
        // so with the code the API reserves for it: on NOTSUPPORTED, Total
        // Commander copies the file itself, downloading to a temp file and
        // uploading from there. Any other answer, NOTFOUND included, reads as
        // plain failure and the copy stops. The comparison is by session name
        // rather than by resolved pointer, since a session open only in
        // another thread resolves to nothing here and two of those would look
        // like one and the same.
        const PathResolution rOldFile = ResolvePathKindW(OldName);
        const PathResolution rNewFile = ResolvePathKindW(NewName);
        SFTP_LOG("ENTRY", "FsRenMovFileW file branch: oldSession='%s' newSession='%s'",
                 rOldFile.displayName.c_str(), rNewFile.displayName.c_str());

        // Two different sessions: no server-side rename can join them, and
        // Total Commander does not step in either — answering NOTSUPPORTED
        // just ends the copy with an error, which is what this used to do. So
        // the plugin carries the file itself, down from one session and up to
        // the other. It goes through a local temporary file rather than
        // straight from socket to socket: the data has to pass through this
        // machine either way, and the existing transfer paths already handle
        // progress, cancellation, resume and every transport the plugin
        // speaks.
        if (_stricmp(rOldFile.displayName.c_str(), rNewFile.displayName.c_str()) != 0)
            return CopyBetweenSessions(OldName, NewName, !!Move, !!OverWrite, ri);

        std::wstring olddir(wdirtypemax, L'\0');
        std::wstring newdir(wdirtypemax, L'\0');
        pConnectSettings serverid1 = ResolveTransferSession(OldName, olddir.data(), olddir.size() - 1);
        pConnectSettings serverid2 = ResolveTransferSession(NewName, newdir.data(), newdir.size() - 1);
        olddir.resize(wcslen(olddir.data()));
        newdir.resize(wcslen(newdir.data()));

        if (serverid1 == nullptr || serverid1 != serverid2)
            return FS_FILE_NOTFOUND;

        ResetLastPercent(serverid1);
        SessionContextGuard _sessionGuard(serverid1);

        const bool isdir = ri && (ri->Attr & FILE_ATTRIBUTE_DIRECTORY);

        // A copy inside one session cannot be a rename: that would take the
        // file away from where it was. Shell-only servers have `cp` for it;
        // SFTP and the PHP agent have no server-side copy, so the file makes
        // the same round trip as between two sessions; LAN Pair has neither
        // and refuses.
        if (!Move) {
            if (IsLanPairTransport(serverid1))
                return FS_FILE_NOTSUPPORTED;
            if (!serverid1->scponly)
                return CopyBetweenSessions(OldName, NewName, false, !!OverWrite, ri);
        }

        // LAN Pair rename.
        if (IsLanPairTransport(serverid1)) {
            if (!serverid1->lanSession || !serverid1->lanSession->isConnected()) return FS_FILE_WRITEERROR;
            const std::string oldUtf8 = LanRemotePathToUtf8(olddir.data());
            const std::string newUtf8 = LanRemotePathToUtf8(newdir.data());
            bool exists = false;
            if (serverid1->lanSession->rename(oldUtf8, newUtf8, !!OverWrite, &exists))
                return FS_FILE_OK;
            return exists ? FS_FILE_EXISTS : FS_FILE_WRITEERROR;
        }

        int rc = SftpRenameMoveFileW(serverid1, olddir.data(), newdir.data(), !!Move, !!OverWrite, isdir);
        switch (rc) {
        case SFTP_OK:
            return FS_FILE_OK;
        case SFTP_EXISTS:
            return FS_FILE_EXISTS;
        default:
            return FS_FILE_WRITEERROR;
        }
    });
}

int WINAPI FsRenMovFile(LPCSTR OldName, LPCSTR NewName, BOOL Move, BOOL OverWrite, RemoteInfoStruct * ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        std::array<WCHAR, wdirtypemax> oldNameW{};
        std::array<WCHAR, wdirtypemax> newNameW{};
        return FsRenMovFileW(awlcopy(oldNameW.data(), OldName, oldNameW.size() - 1), awlcopy(newNameW.data(), NewName, newNameW.size() - 1), Move, OverWrite, ri);
    });
}

static bool FileExistsT(LPCWSTR LocalName)
{
    WIN32_FIND_DATAW s;
    HANDLE findhandle = FindFirstFileT(LocalName, &s);
    if (!findhandle || findhandle == INVALID_HANDLE_VALUE)
        return false;
    FindClose(findhandle);
    return true;
}

static void SanitizeLocalFileNameW(LPWSTR localPath) noexcept
{
    if (!localPath || !localPath[0])
        return;
    const std::wstring_view pathView(localPath);
    const size_t slashPos = pathView.find_last_of(L"\\/");
    if (slashPos == std::wstring_view::npos || slashPos + 1 >= pathView.size())
        return;
    wchar_t* filePart = localPath + slashPos + 1;
    while (*filePart) {
        if (static_cast<unsigned>(*filePart) < 32u) {
            *filePart = L' ';
        } else if (*filePart == L':' || *filePart == L'|' || *filePart == L'*' || *filePart == L'?' ||
                   *filePart == L'\\' || *filePart == L'/' || *filePart == L'"') {
            *filePart = L'_';
        }
        ++filePart;
    }
}

static int CreateHelpFileLocalW(LPCWSTR localName, bool overwrite)
{
    const DWORD disposition = overwrite ? CREATE_ALWAYS : CREATE_NEW;
    handle_util::FileHandle outFile(CreateFileT(
        localName,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        disposition,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr));

    if (!outFile) {
        const DWORD gle = GetLastError();
        if (gle == ERROR_ALREADY_EXISTS || gle == ERROR_FILE_EXISTS)
            return FS_FILE_EXISTS;
        return FS_FILE_WRITEERROR;
    }

    // Through LngStrU8, so the block is written in the plugin's current
    // language: LoadString would always hand back the compiled English
    // resource and the translations in the .lng files would never show.
    // That makes the file UTF-8, hence the BOM below — without it a viewer
    // reads the bytes as the system codepage and non-Latin text arrives as
    // mojibake.
    std::string body("\xEF\xBB\xBF");
    body += LngStrU8(IDS_HELPTEXT, "Plugin help:");

    // Trailer with the exact build so a user reporting an issue can copy
    // it verbatim. Values fall back to `local` when no CI-generated
    // build_info_gen.h is present (developer local build).
    body.append("\r\n\r\n--- Build ---\r\n");
    body.append("Tag:   ").append(SFTP_BUILD_TAG).append("\r\n");
    body.append("SHA:   ").append(SFTP_BUILD_SHA).append("\r\n");
    body.append("Date:  ").append(SFTP_BUILD_DATE).append("\r\n");

    DWORD written = 0;
    const BOOL ok = WriteFile(outFile.get(), body.data(),
                              static_cast<DWORD>(body.size()), &written, nullptr);
    return ok ? FS_FILE_OK : FS_FILE_WRITEERROR;
}

// A download that is really a move has to take the remote file away itself —
// Total Commander removes the local side of a move, never the plugin's side.
// Failing to remove it leaves the file in both places, so the reason is shown;
// the download itself has succeeded by then and stays reported as such.
// A download the user resumed keeps the source: part of the result was there
// before this transfer started, and nothing vouches that it matches.
static int FinishDownloadMove(pConnectSettings serverid, LPCWSTR remoteRelative,
                              bool Move, bool resumed)
{
    if (!Move || !serverid)
        return FS_FILE_OK;
    if (resumed) {
        SFTP_LOG("ENTRY", "FsGetFileW move: resumed, source kept");
        ShowStatusId(IDS_MOVE_KEPT_RESUMED, nullptr, true);
        return FS_FILE_OK;
    }

    // LAN Pair has no SFTP session to delete through; its peer does it.
    int rc = SFTP_FAILED;
    if (IsLanPairTransport(serverid)) {
        if (serverid->lanSession && serverid->lanSession->isConnected() &&
            serverid->lanSession->remove(LanRemotePathToUtf8(remoteRelative)))
            rc = SFTP_OK;
    } else {
        rc = SftpDeleteFileW(serverid, remoteRelative, false);
    }
    SFTP_LOG("ENTRY", "FsGetFileW move: deleting the source rc=%d", rc);
    if (rc != SFTP_OK)
        ShowStatusId(IDS_ERR_DELETE, nullptr, true);
    return FS_FILE_OK;
}

int WINAPI FsGetFileW(LPCWSTR RemoteName, LPWSTR LocalName, int CopyFlags, RemoteInfoStruct * ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_READERROR, [&]() -> int {
        const bool OverWrite = !!(CopyFlags & FS_COPYFLAGS_OVERWRITE);
        bool Resume = !!(CopyFlags & FS_COPYFLAGS_RESUME);
        // What the user asked for, kept apart from `Resume`, which the
        // auto-resume loop below also sets after a dropped connection: that
        // continues this very transfer and does not make a move unsafe.
        const bool resumeAsked = Resume;
        const bool Move = !!(CopyFlags & FS_COPYFLAGS_MOVE);
        SFTP_LOG("ENTRY", "FsGetFileW start flags=0x%x overwrite=%d resume=%d move=%d shift=%d",
                 CopyFlags, OverWrite ? 1 : 0, Resume ? 1 : 0, Move ? 1 : 0,
                 (GetAsyncKeyState(VK_SHIFT) & 0x8000) ? 1 : 0);

        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};
        if (remoteView.size() < 3 || !LocalName || !ri)
            return FS_FILE_NOTFOUND;

        // Virtual sessions under \[Imports]\ are exported as INI-format
        // text files: user F5/F6 to a real filesystem path yields a
        // human-readable snippet with the connect fields we cached. Pseudo
        // rows and the [Manage custom locations] sub-tree have no useful
        // download representation and refuse silently.
        {
            std::string sourceId, subPath;
            const ImportsPathKind kind = ClassifyImportsPath(RemoteName,
                &sourceId, &subPath);
            if (kind != ImportsPathKind::NotImports) {
                if (kind != ImportsPathKind::SourceSubPath)
                    return FS_FILE_NOTSUPPORTED;
                // Pseudo rows and manage-locations entries have no INI
                // section to export. FS_FILE_USERABORT isn't silent in the
                // FsGetFile path (TC still pops "Error downloading file"),
                // so mirror the [Active Sessions] / F7-help pattern: write a
                // short explanatory stub note and return OK. TC opens its
                // viewer on the stub file, and the user sees a description
                // of what the entry does instead of a scary error.
                const std::string managePrefix =
                    std::string(kManageCustomFolder) + "/";
                auto writeStub = [&](const std::string& note) -> int {
                    HANDLE h = CreateFileW(LocalName, GENERIC_WRITE, 0,
                        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (h == INVALID_HANDLE_VALUE) return FS_FILE_WRITEERROR;
                    DWORD written = 0;
                    WriteFile(h, note.data(),
                              static_cast<DWORD>(note.size()),
                              &written, nullptr);
                    CloseHandle(h);
                    return FS_FILE_OK;
                };

                if (subPath == kRefreshEntry) {
                    return writeStub(
                        "This is the [Refresh] action.\r\n"
                        "Press Enter here to re-scan every configured channel "
                        "(standard location plus any custom paths).\r\n");
                }
                if (subPath == kAddCustomEntry) {
                    return writeStub(
                        "This is the [Add custom location...] action.\r\n"
                        "Press Enter here to open a folder-picker dialog "
                        "and enroll a custom import location.\r\n");
                }
                if (subPath == kManageCustomFolder) {
                    return writeStub(
                        "This is the [Manage custom locations] sub-folder.\r\n"
                        "Enter it to see and remove configured custom paths.\r\n");
                }
                if (subPath.size() > managePrefix.size() &&
                    subPath.compare(0, managePrefix.size(), managePrefix) == 0)
                {
                    std::string customPath = subPath.substr(managePrefix.size());
                    std::replace(customPath.begin(), customPath.end(), '/', '\\');
                    std::string note = "Custom import path for source: ";
                    note.append(sourceId).append("\r\n");
                    note.append("Path: ").append(customPath).append("\r\n\r\n");
                    note.append("Press F8 to remove this custom location. "
                                "Cached sessions with this path as their "
                                "source will be pruned.\r\n");
                    return writeStub(note);
                }
                if (subPath.find(" not currently detected") != std::string::npos) {
                    std::string note = "The standard location for source '";
                    note.append(sourceId);
                    note.append("' is not currently detected on this system.\r\n"
                                "Cached sessions remain visible. Use "
                                "[Add custom location...] to enroll a "
                                "portable folder as the source.\r\n");
                    return writeStub(note);
                }

                // Must be a real cached session — confirm via
                // ImportCache::ListSource so folder segments (dron, my,
                // ...) also refuse cleanly instead of yielding an empty
                // file.
                const auto sessions =
                    sftp::GetImportCache().ListSource(sourceId);
                bool matched = false;
                for (const auto& s : sessions) {
                    if (_stricmp(s.displayName.c_str(), subPath.c_str()) == 0) {
                        matched = true;
                        break;
                    }
                }
                if (!matched)
                    return FS_FILE_NOTSUPPORTED;

                const std::string cacheSection =
                    sftp::GetImportCache().SectionNameForConnect(sourceId, subPath);
                const std::string& cachePath =
                    sftp::GetImportCache().CacheFilePath();
                if (cacheSection.empty() || cachePath.empty())
                    return FS_FILE_NOTFOUND;

                // F3 comes through here as well as F5, so the export is not
                // refused: the snippet carries a proxy the plugin speaks, and
                // names any other route, which makes importing it back refuse.
                const sftp::SessionDependency dep =
                    sftp::ImportCache::ReadDependency(cacheSection, cachePath);

                std::string header = "Imported session from [Imports]\\[";
                header.append(sourceId).append("]\\").append(subPath);
                return ExportSessionAsIniFile(cacheSection.c_str(),
                    cachePath.c_str(), subPath.c_str(),
                    header.c_str(), LocalName, OverWrite, &dep);
            }
        }

        // Both pseudo rows in the plugin root stand for "open a new
        // connection", so F3 on either shows the plugin help. Without the
        // second one TC tries to download the row from the server and
        // reports "Error downloading file!".
        if (remoteView.substr(1) == std::wstring_view(s_f7newconnectionW.data()) ||
            remoteView.substr(1) == std::wstring_view(s_quickconnectW.data())) {
            return CreateHelpFileLocalW(LocalName, OverWrite);
        }

        // F3/F4/F5 on a row inside the [Active Sessions] magic folder →
        // write a one-line stub note into the temp file and return OK.
        // Without this TC tries to download the row from the server and
        // pops "Error downloading file" because none of these paths exist.
        {
            std::string entry;
            if (IsActiveSessionsPath(RemoteName, &entry) && !entry.empty()) {
                std::string note;
                if (_stricmp(entry.c_str(), kDisconnectAllEntry) == 0)
                    note = "Press F8 here to disconnect every active session.\r\n";
                else
                    note = "Press F8 here to disconnect session '" + entry + "'.\r\n";
                HANDLE hStub = CreateFileW(LocalName, GENERIC_WRITE, 0, nullptr,
                                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hStub != INVALID_HANDLE_VALUE) {
                    DWORD written = 0;
                    WriteFile(hStub, note.data(), static_cast<DWORD>(note.size()), &written, nullptr);
                    CloseHandle(hStub);
                }
                return FS_FILE_OK;
            }
        }

        // F3/F4/F5 on a saved session (root-level or nested in a folder)
        // → export the session's INI section into the download target as a
        // human-readable INI snippet. Symmetric with the reverse-import
        // path in FsPutFileW, and with the virtual-session export above.
        //
        // TC's WFX API routes F3 (view), F4 (edit) and F5 (copy) through
        // the same FsGetFile entry point with no reliable "intent" hint.
        // All three gestures export the session's raw INI content — F3/F5
        // work naturally; F4 opens an editor on the snapshot but saving
        // does NOT round-trip back to sftpplug.ini. Alt+Enter (a separate
        // FsExecuteFile path) still opens the editable Configure dialog.
        {
            const PathResolution r = ResolvePathKindW(RemoteName);
            if (r.kind == PathKind::SessionLeaf &&
                _stricmp(r.displayName.c_str(), s_f7newconnection) != 0 &&
                _stricmp(r.displayName.c_str(), s_quickconnect)    != 0)
            {
                std::string header = "Session '";
                header.append(r.displayName).append("' from sftpplug.ini");
                return ExportSessionAsIniFile(r.displayName.c_str(),
                    inifilename, r.displayName.c_str(),
                    header.c_str(), LocalName, OverWrite);
            }
        }

        SanitizeLocalFileNameW(LocalName);

        std::wstring remotedir(wdirtypemax, L'\0');
        pConnectSettings serverid = ResolveTransferSession(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return FS_FILE_READERROR;

        // Prefix all ShowStatus output in this thread with "[<session>] ".
        SessionContextGuard _sessionGuard(serverid);

        int startPct = 0;
        if (Resume && ri && ri->Size64 > 0) {
            HANDLE h = CreateFileW(LocalName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER li{};
                if (GetFileSizeEx(h, &li) && li.QuadPart > 0)
                    startPct = (int)std::clamp((li.QuadPart * 100LL) / ri->Size64, 0LL, 100LL);
                CloseHandle(h);
            }
        }

        serverid->lastpercent = startPct;

        int err = ProgressProcT(PluginNumber, RemoteName, LocalName, startPct);
        if (err)
            return FS_FILE_USERABORT;
        if (!OverWrite && !Resume && FileExistsT(LocalName)) {
            // Converted text cannot be resumed (offsets differ on each side),
            // so TC is told to offer overwrite only.
            const bool textMode = (serverid->unixlinebreaks == 1) && SftpDetermineTransferModeW(RemoteName);
            return textMode ? FS_FILE_EXISTS : FS_FILE_EXISTSRESUMEALLOWED;
        }
        if (OverWrite) {
            DeleteFileT(LocalName);
        }

        // PHP Agent TAR batch download: queue single file instead of downloading individually.
        if (ri && !(ri->Attr & FILE_ATTRIBUTE_DIRECTORY) &&
            IsPhpAgentTransport(serverid) && serverid->php_tar &&
            TarDownloadSessionIsActive(serverid))
        {
            if (TarDownloadSessionQueue(serverid, LocalName, remotedir.data())) {
                // The file arrives only when the batch runs, after this call
                // has returned, so a move inside a TAR batch stays a copy.
                if (Move)
                    SFTP_LOG("TAR", "FsGetFileW move queued as a copy; source kept");
                return FS_FILE_OK;
            }
        }

        // PHP Agent TAR directory download.
        if (ri && (ri->Attr & FILE_ATTRIBUTE_DIRECTORY) &&
            IsPhpAgentTransport(serverid) && serverid->php_tar)
        {
            CreateDirectoryW(LocalName, nullptr);
            const int rc = PhpAgentDownloadDirAsTar(serverid, remotedir.data(), LocalName, OverWrite);
            if (rc == SFTP_OK)    return FS_FILE_OK;
            if (rc == SFTP_ABORT) return FS_FILE_USERABORT;
            // On any error fall through to TC-managed recursion.
            return FS_FILE_NOTSUPPORTED;
        }

        // LAN Pair download.
        if (IsLanPairTransport(serverid)) {
            if (!serverid->lanSession || !serverid->lanSession->isConnected())
                return FS_FILE_READERROR;
            const std::string remoteUtf8 = LanRemotePathToUtf8(remotedir.data());
            int fsResult = FS_FILE_READERROR;
            serverid->lanSession->getFile(remoteUtf8, LocalName,
                                          ri ? ri->Size64 : 0,
                                          ri ? &ri->LastWriteTime : nullptr,
                                          OverWrite, Resume, &fsResult);
            if (fsResult == FS_FILE_READERROR)
                return download_batch::ResolveReadError(RemoteName, LocalName, Move, resumeAsked);
            return (fsResult == FS_FILE_OK)
                ? FinishDownloadMove(serverid, remotedir.data(), Move, resumeAsked)
                : fsResult;
        }

        // A dropped connection leaves part of the file; the loop picks it up
        // from there. It goes on only while each round adds to the file — an
        // error that keeps striking at the same offset would otherwise spin
        // here for good.
        // A file that cannot be read may be skipped when it is one of many.
        const auto readError = [&] {
            return download_batch::ResolveReadError(RemoteName, LocalName, Move, resumeAsked);
        };
        int64_t partialSize = -1;
        for (;;) {  // auto-resume loop
            const int rc = SftpDownloadFileW(serverid, remotedir.data(), LocalName, true, ri->Size64, &ri->LastWriteTime, Resume);
            SFTP_LOG("ENTRY", "FsGetFileW SftpDownloadFileW rc=%d", rc);
            switch (rc) {
                case SFTP_OK:          return FinishDownloadMove(serverid, remotedir.data(), Move, resumeAsked);
                case SFTP_EXISTS:      return FS_FILE_EXISTS;
                case SFTP_WRITEFAILED: return FS_FILE_WRITEERROR;
                case SFTP_ABORT:       return FS_FILE_USERABORT;
                case SFTP_PARTIAL: {
                    WIN32_FILE_ATTRIBUTE_DATA fad{};
                    const int64_t now = GetFileAttributesExW(LocalName, GetFileExInfoStandard, &fad)
                        ? (static_cast<int64_t>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow
                        : -1;
                    if (now <= partialSize) {
                        SFTP_LOG("ENTRY", "FsGetFileW auto-resume made no progress at %lld",
                                 static_cast<long long>(now));
                        return readError();
                    }
                    partialSize = now;
                    Resume = true;
                    break;
                }
                default:               return readError(); // SFTP_READFAILED among them
            }
        }
    });
}

int WINAPI FsGetFile(LPCSTR RemoteName, LPSTR LocalName, int CopyFlags, RemoteInfoStruct* ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_READERROR, [&]() -> int {
        if (!RemoteName || !LocalName || !ri)
            return FS_FILE_NOTFOUND;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        std::array<WCHAR, wdirtypemax> localNameW{};
        return FsGetFileW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), awlcopy(localNameW.data(), LocalName, localNameW.size() - 1), CopyFlags, ri);
    });
}

int WINAPI FsPutFileW(LPCWSTR LocalName, LPCWSTR RemoteName, int CopyFlags)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        const bool OverWrite = !!(CopyFlags & FS_COPYFLAGS_OVERWRITE);
        const bool Resume = !!(CopyFlags & FS_COPYFLAGS_RESUME);
        const bool Move = !!(CopyFlags & FS_COPYFLAGS_MOVE);
        SFTP_LOG("ENTRY", "FsPutFileW start flags=0x%x overwrite=%d resume=%d move=%d shift=%d",
                 CopyFlags, OverWrite ? 1 : 0, Resume ? 1 : 0, Move ? 1 : 0,
                 (GetAsyncKeyState(VK_SHIFT) & 0x8000) ? 1 : 0);

        const std::wstring_view localView = LocalName ? std::wstring_view(LocalName) : std::wstring_view{};
        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};

        // Auto-overwrites files -> return error if file exists
        if ((CopyFlags & (FS_COPYFLAGS_EXISTS_SAMECASE | FS_COPYFLAGS_EXISTS_DIFFERENTCASE)) != 0) {
            if (!OverWrite && !Resume) {
                return FS_FILE_EXISTSRESUMEALLOWED;
            }
        }

        if (remoteView.size() < 3 || localView.empty())
            return FS_FILE_WRITEERROR;

        // \[Imports]\ is read-only from outside: no user-driven upload
        // ever lands there. FS_FILE_USERABORT is documented as "user
        // pressed abort in progress dialog"; TC pops "Error uploading
        // file" for it when no dialog was involved. Return FS_FILE_OK
        // instead — the plugin discards the incoming bytes, TC thinks
        // the upload succeeded, and the user gets no error. Matches the
        // silent-no-op UX pattern the regular-session F4 write-back path
        // uses. Real-disk → panel session-INI import lives on the else
        // branch below.
        if (IsImportsPath(RemoteName))
            return FS_FILE_OK;

        // Reverse of the [Imports] INI-export path: when the destination
        // path does NOT resolve to any existing session, treat the upload
        // as an attempt to import a session-INI file. The helper handles
        // validation, user-visible error dialogs and the actual section
        // copy; nullopt means "not our target — carry on with the normal
        // upload".
        if (const auto rc = TryImportSessionFromUpload(LocalName, RemoteName, OverWrite))
            return *rc;

        int err = ProgressProcT(PluginNumber, LocalName, RemoteName, 0);
        if (err)
            return FS_FILE_USERABORT;

        std::array<WCHAR, wdirtypemax> remotedir{};

        pConnectSettings serverid = ResolveTransferSession(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return FS_FILE_READERROR;
        ResetLastPercent(serverid);

        // Prefix all ShowStatus output in this thread with "[<session>] ".
        SessionContextGuard _sessionGuard(serverid);

        // LAN Pair upload.
        if (IsLanPairTransport(serverid)) {
            if (!serverid->lanSession || !serverid->lanSession->isConnected())
                return FS_FILE_WRITEERROR;
            const std::string remoteUtf8 = LanRemotePathToUtf8(remotedir.data());
            int fsResult = FS_FILE_WRITEERROR;
            serverid->lanSession->putFile(LocalName, remoteUtf8, OverWrite, Resume, &fsResult);
            // A move takes the local file away here too, under the same rule
            // as the other transports: never after a resumed transfer.
            if (fsResult == FS_FILE_OK && Move) {
                if (Resume) {
                    ShowStatusId(IDS_MOVE_KEPT_RESUMED, nullptr, true);
                } else if (!DeleteFileW(LocalName)) {
                    SFTP_LOG("ENTRY", "FsPutFileW LAN move: could not delete '%S' (%lu)",
                             LocalName, GetLastError());
                    ShowStatusId(IDS_ERR_DELETE, nullptr, true);
                }
            }
            return fsResult;
        }

        // PHP Agent TAR batch upload: queue file into session, send all as one TAR at FsStatusInfo END.
        if (IsPhpAgentTransport(serverid) && serverid->php_tar && TarUploadSessionIsActive()) {
            // Fill in cs on first file if session was started without one (PUT_MULTI_THREAD).
            if (!TarUploadSessionIsActive(serverid))
                TarUploadSessionBegin(serverid);
            const std::string remoteRelA = unicode_util::wstring_to_utf8(remotedir.data());
            // A file the batch would not take goes up on its own below rather
            // than being reported as sent. One it took is sent only when the
            // batch runs, after this call has returned, so a move stays a copy.
            if (TarUploadSessionQueue(serverid, LocalName, remoteRelA.c_str())) {
                SFTP_LOG("TAR", "FsPutFileW queued '%S' -> '%s'%s", LocalName, remoteRelA.c_str(),
                         Move ? " (move kept as a copy)" : "");
                return FS_FILE_OK;
            }
            SFTP_LOG("TAR", "FsPutFileW not queued '%S'; uploading it alone", LocalName);
        }
        SFTP_LOG("TAR", "FsPutFileW TAR skip: isPhpAgent=%d php_tar=%d tarActive=%d",
                 IsPhpAgentTransport(serverid) ? 1 : 0,
                 serverid->php_tar ? 1 : 0,
                 TarUploadSessionIsActive() ? 1 : 0);

        // Without FS_COPYFLAGS_OVERWRITE an existing file must be reported,
        // not replaced: Total Commander then asks and calls again. It sets
        // the EXISTS flags only when its own listing knows (handled above);
        // otherwise - a subfolder it never listed, a background copy - the
        // upload, which truncates, would overwrite without asking.
        if (!OverWrite && !Resume && RemoteFileExists(serverid, remotedir.data()))
            return SftpSupportsResume(serverid) ? FS_FILE_EXISTSRESUMEALLOWED : FS_FILE_EXISTS;

        const bool setattr = !!(CopyFlags & FS_COPYFLAGS_EXISTS_SAMECASE);
        int rc = SftpUploadFileW(serverid, LocalName, remotedir.data(), Resume, setattr);
        SFTP_LOG("ENTRY", "FsPutFileW SftpUploadFileW rc=%d", rc);
        switch (rc) {
            case SFTP_OK:
                // The mirror of a download that is a move: here it is the
                // local file that has to go, and the plugin is the one asked
                // to remove it. Total Commander only takes away the side it
                // owns, which for an upload is the remote one. A resumed
                // upload keeps it, as a resumed download keeps the remote.
                if (Move && Resume) {
                    SFTP_LOG("ENTRY", "FsPutFileW move: resumed, source kept");
                    ShowStatusId(IDS_MOVE_KEPT_RESUMED, nullptr, true);
                } else if (Move && !DeleteFileW(LocalName)) {
                    SFTP_LOG("ENTRY", "FsPutFileW move: could not delete '%S' (%lu)",
                             LocalName, GetLastError());
                    ShowStatusId(IDS_ERR_DELETE, nullptr, true);
                }
                return FS_FILE_OK;
            case SFTP_EXISTS:      return SftpSupportsResume(serverid) ? FS_FILE_EXISTSRESUMEALLOWED : FS_FILE_EXISTS;
            case SFTP_READFAILED:  return FS_FILE_READERROR;
            case SFTP_WRITEFAILED: return FS_FILE_WRITEERROR;
            case SFTP_ABORT:       return FS_FILE_USERABORT;
            default:               return FS_FILE_WRITEERROR;
        }
        return FS_FILE_WRITEERROR;
    });
}

int WINAPI FsPutFile(LPCSTR LocalName, LPCSTR RemoteName, int CopyFlags)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        if (!LocalName || !RemoteName)
            return FS_FILE_WRITEERROR;
        std::array<WCHAR, wdirtypemax> localNameW{};
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsPutFileW(awlcopy(localNameW.data(), LocalName, localNameW.size() - 1), awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), CopyFlags);
    });
}

BOOL WINAPI FsDeleteFileW(LPCWSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};
        if (remoteView.size() < 2)
            return false;

        // F8 inside \[Imports]\ has two paths:
        //   1. On a row inside [Manage custom locations]\  → remove that
        //      custom path from the INI and prune its cached sessions.
        //   2. Anywhere else under \[Imports]\  → silently refused (virtual
        //      entries mirror source-program state; deleting them from TC
        //      would wipe cache sections without affecting the source).
        {
            std::string importsSource, importsSub;
            if (IsImportsPath(RemoteName, &importsSource, &importsSub)) {
                const std::string managePrefix =
                    std::string(kManageCustomFolder) + "/";
                if (!importsSource.empty() &&
                    importsSub.size() > managePrefix.size() &&
                    _strnicmp(importsSub.c_str(), managePrefix.c_str(),
                              managePrefix.size()) == 0)
                {
                    // Extract the custom path portion and reverse the '/'
                    // normalisation that IsImportsPath applied so we match
                    // the Windows-style entry stored in `[Imports]`.
                    std::string customPath = importsSub.substr(managePrefix.size());
                    std::replace(customPath.begin(), customPath.end(), '/', '\\');
                    if (customPath.empty())
                        return false;
                    if (!RemoveImportCustomPath(importsSource.c_str(),
                            customPath.c_str(), inifilename))
                    {
                        return false;
                    }
                    sftp::GetImportCache().PruneChannel(importsSource, customPath);
                    HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
                    if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
                    return true;
                }
                return false;  // any other F8 under Imports is refused
            }
        }

        // F8 on a row inside the [Active Sessions] magic folder → disconnect
        // that session (not delete it from INI). Resolved before the path
        // resolver because none of these paths correspond to a saved session.
        // F8 on a row inside [Proxies] removes that record. Sessions still
        // pointing at it block the removal and are named, the same rule the
        // connection dialog applies — with no session of its own to excuse,
        // since the folder is not editing one.
        {
            std::string proxyEntry;
            if (IsProxiesPath(RemoteName, &proxyEntry) && !proxyEntry.empty()) {
                const int proxynr = ProxyNrFromRowName(proxyEntry);
                if (proxynr <= 0)
                    return FS_FILE_NOTSUPPORTED;

                std::string inUse = LngStrU8(IDS_ERROR_INUSE, "Proxy is in use by connection:");
                inUse.append("\r\n");
                inUse.resize(1024, '\0');
                if (DeleteProxy(proxynr, "", inifilename, inUse.data(), inUse.size() - 1))
                    return FS_FILE_OK;

                const std::wstring message = unicode_util::utf8_to_wstring(inUse.c_str());
                if (RequestProcW) {
                    RequestProcW(PluginNumber, RT_MsgOK, L"SFTP",
                                 const_cast<WCHAR*>(message.c_str()), nullptr, 0);
                } else {
                    MessageBoxW(FindWindowA("TTOTAL_CMD", nullptr),
                                message.c_str(), L"SFTP", MB_OK | MB_ICONSTOP);
                }
                return FS_FILE_NOTSUPPORTED;
            }
        }

        {
            std::string entry;
            if (IsActiveSessionsPath(RemoteName, &entry) && !entry.empty()) {
                if (_stricmp(entry.c_str(), kDisconnectAllEntry) == 0) {
                    // Snapshot active sessions first, then walk and disconnect —
                    // FsDisconnect mutates g_servers, so we can't iterate it
                    // live.
                    std::vector<std::string> active;
                    {
                        std::array<char, wdirtypemax> nameBuf{};
                        SERVERHANDLE hdl = FindFirstServer(nameBuf.data(), nameBuf.size() - 1);
                        while (hdl) {
                            if (GetServerIdFromName(nameBuf.data(), GetCurrentThreadId()) != nullptr) {
                                active.emplace_back(nameBuf.data());
                            }
                            nameBuf[0] = 0;
                            hdl = FindNextServer(hdl, nameBuf.data(), nameBuf.size() - 1);
                        }
                    }
                    for (const auto& name : active) {
                        std::string disconnPath;
                        disconnPath.reserve(name.size() + 1);
                        disconnPath.append("\\").append(name);
                        FsDisconnect(disconnPath.c_str());
                    }
                } else {
                    std::string disconnPath;
                    disconnPath.reserve(entry.size() + 1);
                    disconnPath.append("\\").append(entry);
                    FsDisconnect(disconnPath.c_str());
                }
                HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
                if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
                return true;
            }
        }

        const PathResolution r = ResolvePathKindW(RemoteName);

        // Real file inside a session → server-side delete.
        if (r.kind == PathKind::SessionWithSubpath) {
            std::wstring remotedir(wdirtypemax, L'\0');
            pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
            remotedir.resize(wcslen(remotedir.data()));
            if (serverid == nullptr)
                return false;
            ResetLastPercent(serverid);
            SessionContextGuard _sessionGuard(serverid);
            if (IsLanPairTransport(serverid)) {
                if (!serverid->lanSession || !serverid->lanSession->isConnected()) return false;
                return serverid->lanSession->remove(LanRemotePathToUtf8(remotedir.data()));
            }
            int rc = SftpDeleteFileW(serverid, remotedir.data(), false);
            return (rc == SFTP_OK) ? true : false;
        }

        // Saved-session entry (root-level OR nested in a folder) → drop the
        // INI section. Refuse the pseudo helper entries which are not real
        // sessions and don't have an INI section to remove.
        if (r.kind == PathKind::SessionLeaf) {
            if (_stricmp(r.displayName.c_str(), s_f7newconnection) == 0 ||
                _stricmp(r.displayName.c_str(), s_quickconnect) == 0)
                return false;
            // Disconnect any active connection under this name first so the
            // registry doesn't preserve a ghost entry (LoadServersFromIniW
            // keeps entries with a non-null serverid even after the INI
            // section is gone, which would leave the deleted session
            // visible in subsequent listings).
            {
                std::string disconnPath;
                disconnPath.reserve(r.displayName.size() + 1);
                disconnPath.append("\\").append(r.displayName);
                FsDisconnect(disconnPath.c_str());
            }
            if (DeleteServerFromIniW(r.displayName.c_str(), inifilenameW)) {
                if (CryptProc)
                    CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_DELETE_PASSWORD,
                              const_cast<char*>(r.displayName.c_str()), nullptr, 0);
                // Clear any jump-host references that pointed at the deleted
                // session so the by-reference picker doesn't surface them as
                // "[!] (missing)" markers afterwards.
                UpdateJumpRefsOnSessionRename(r.displayName.c_str(), nullptr, inifilename);
                LoadServersFromIniW(inifilenameW, s_quickconnect);
                HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
                if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
                return true;
            }
        }
        return false;
    });
}

BOOL WINAPI FsDeleteFile(LPCSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsDeleteFileW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1));
    });
}

BOOL WINAPI FsRemoveDirW(LPCWSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        const PathResolution r = ResolvePathKindW(RemoteName);

        // Real directory inside a session → server-side rmdir.
        if (r.kind == PathKind::SessionWithSubpath) {
            std::wstring remotedir(wdirtypemax, L'\0');
            pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
            remotedir.resize(wcslen(remotedir.data()));
            if (serverid == nullptr)
                return false;
            ResetLastPercent(serverid);
            SessionContextGuard _sessionGuard(serverid);
            if (IsLanPairTransport(serverid)) {
                if (!serverid->lanSession || !serverid->lanSession->isConnected()) return false;
                return serverid->lanSession->remove(LanRemotePathToUtf8(remotedir.data()));
            }
            int rc = SftpDeleteFileW(serverid, remotedir.data(), true);
            return (rc == SFTP_OK) ? true : false;
        }

        // Folder grouping → wipe every saved session whose name lives under
        // this folder (recursively — nested subfolders are caught by the same
        // prefix match). TC has already shown the "delete non-empty folder?"
        // confirmation by the time it calls us, so we just do the work.
        if (r.kind == PathKind::Folder && !r.displayName.empty()) {
            // Collect matching section names first; mutating the INI mid-
            // enumeration would shift the underlying buffer.
            const std::vector<std::string> toDelete =
                CollectSessionsUnderFolder(r.displayName, inifilenameW);
            if (toDelete.empty())
                return false;

            for (const auto& name : toDelete) {
                // Same disconnect-before-delete dance as the single-session
                // path: avoid leaving a ghost entry in the registry.
                std::string disconnPath;
                disconnPath.reserve(name.size() + 1);
                disconnPath.append("\\").append(name);
                FsDisconnect(disconnPath.c_str());
                DeleteServerFromIniW(name.c_str(), inifilenameW);
                if (CryptProc)
                    CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_DELETE_PASSWORD,
                              const_cast<char*>(name.c_str()), nullptr, 0);
                UpdateJumpRefsOnSessionRename(name.c_str(), nullptr, inifilename);
            }

            LoadServersFromIniW(inifilenameW, s_quickconnect);
            HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
            if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
            return true;
        }

        return false;
    });
}

BOOL WINAPI FsRemoveDir(LPCSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsRemoveDirW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1));
    });
}

// ANSI attribute API used by TC in this plugin ABI.

BOOL WINAPI FsSetAttrW(LPCWSTR RemoteName, int NewAttr)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        // Use std::wstring instead of std::array<WCHAR, wdirtypemax>
        std::wstring remotedirW(wdirtypemax, L'\0');
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedirW.data(), remotedirW.size() - 1);
        remotedirW.resize(wcslen(remotedirW.data()));
        if (serverid == nullptr)
            return false;
        ResetLastPercent(serverid);
        SessionContextGuard _sessionGuard(serverid);
        // Use std::string instead of std::array<char, wdirtypemax>
        std::string remotedirA(wdirtypemax, '\0');
        walcopy(remotedirA.data(), remotedirW.data(), remotedirA.size() - 1);
        remotedirA.resize(strlen(remotedirA.data()));
        int rc = SftpSetAttr(serverid, remotedirA.data(), NewAttr);
        return (rc == SFTP_OK) ? true : false;
    });
}

BOOL WINAPI FsSetAttr(LPCSTR RemoteName, int NewAttr)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<char, wdirtypemax> remotedir{};
        pConnectSettings serverid = GetServerIdAndRelativePathFromPath(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return false;
        ResetLastPercent(serverid);
        int rc = SftpSetAttr(serverid, remotedir.data(), NewAttr);
        return (rc == SFTP_OK) ? true : false;
    });
}

BOOL WINAPI FsSetTimeW(LPCWSTR RemoteName, LPFILETIME /*CreationTime*/, LPFILETIME /*LastAccessTime*/, LPFILETIME LastWriteTime)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};
        if (remoteView.size() < 3 || !LastWriteTime)
            return false;

        // Use std::wstring instead of std::array<WCHAR, wdirtypemax>
        std::wstring remotedir(wdirtypemax, L'\0');
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        remotedir.resize(wcslen(remotedir.data()));
        if (serverid == nullptr)
            return false;
        ResetLastPercent(serverid);
        int rc = SftpSetDateTimeW(serverid, remotedir.data(), LastWriteTime);
        return (rc == SFTP_OK) ? true : false;
    });
}

BOOL WINAPI FsSetTime(LPCSTR RemoteName, LPFILETIME CreationTime, LPFILETIME LastAccessTime, LPFILETIME LastWriteTime)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsSetTimeW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), CreationTime, LastAccessTime, LastWriteTime);
    });
}

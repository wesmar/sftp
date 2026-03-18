#include "global.h"
#include <windows.h>
#include <shellapi.h>
#include <array>
#include <string>
#include <vector>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "WindowsUserFeedback.h"
#include "res/resource.h"
#include "CoreUtils.h"

#pragma comment(lib, "version.lib")

// Reads FileVersion from own VERSIONINFO resource, returns e.g. "1.0.0.10"
// Returns empty string on failure.
std::wstring GetPluginVersionW()
{
    std::array<wchar_t, MAX_PATH> path{};
    if (!GetModuleFileNameW(hinst, path.data(), static_cast<DWORD>(path.size())))
        return {};

    DWORD dummy{};
    const DWORD size = GetFileVersionInfoSizeW(path.data(), &dummy);
    if (!size)
        return {};

    std::vector<BYTE> buf(size);
    if (!GetFileVersionInfoW(path.data(), 0, size, buf.data()))
        return {};

    VS_FIXEDFILEINFO* pvi{};
    UINT len{};
    if (!VerQueryValueW(buf.data(), L"\\", reinterpret_cast<void**>(&pvi), &len) || !pvi)
        return {};

    wchar_t ver[32]{};
    swprintf_s(ver, L"%u.%u.%u.%u",
        HIWORD(pvi->dwFileVersionMS),
        LOWORD(pvi->dwFileVersionMS),
        HIWORD(pvi->dwFileVersionLS),
        LOWORD(pvi->dwFileVersionLS));
    return ver;
}

bool GetPluginDirectoryA(std::string& outDir)
{
    outDir.clear();
    std::array<char, MAX_PATH> dllPath{};
    DWORD n = GetModuleFileNameA(hinst, dllPath.data(), static_cast<DWORD>(dllPath.size()));
    if (n == 0 || n >= dllPath.size())
        return false;
    char* slash = strrchr(dllPath.data(), '\\');
    if (!slash)
        return false;
    *slash = 0;
    outDir.assign(dllPath.data());
    return !outDir.empty();
}

void OpenPluginHelp(HWND hWnd)
{
    std::string pluginDir;
    WindowsUserFeedback feedback(hWnd);
    if (!GetPluginDirectoryA(pluginDir)) {
        feedback.ShowError(LngStrU8(IDS_ERR_NO_PLUGIN_DIR, "Cannot locate plugin directory."), "Help");
        return;
    }

    // Build title with version: "SFTP Plugin v1.0.0.10"
    std::wstring helpTitle = L"SFTP Plugin";
    const std::wstring ver = GetPluginVersionW();
    if (!ver.empty())
        helpTitle += L" v" + ver;

    std::string chmPath = pluginDir + "\\sftpplug.chm";
    DWORD attrs = GetFileAttributesA(chmPath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        HINSTANCE openRc = ShellExecuteA(hWnd, "open", chmPath.c_str(), nullptr, pluginDir.c_str(), SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(openRc) > 32)
            return;
    }

    std::array<WCHAR, 8192> shortHelpW{};
    LoadStringW(hinst, IDS_HELPTEXT, shortHelpW.data(), static_cast<int>(shortHelpW.size() - 1));
    std::wstring msgW = L"CHM help file not found or failed to open.\n\nExpected location:\n";
    msgW += std::wstring(chmPath.begin(), chmPath.end());
    msgW += L"\n\n";
    msgW += shortHelpW.data();
    int needed = WideCharToMultiByte(CP_ACP, 0, msgW.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string msg(needed > 0 ? needed - 1 : 0, '\0');
    if (needed > 0)
        WideCharToMultiByte(CP_ACP, 0, msgW.c_str(), -1, msg.data(), needed, nullptr, nullptr);
    int titleNeeded = WideCharToMultiByte(CP_ACP, 0, helpTitle.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string title(titleNeeded > 0 ? titleNeeded - 1 : 0, '\0');
    if (titleNeeded > 0)
        WideCharToMultiByte(CP_ACP, 0, helpTitle.c_str(), -1, title.data(), titleNeeded, nullptr, nullptr);
    feedback.ShowError(msg, title);
}

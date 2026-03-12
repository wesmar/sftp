#include "global.h"
#include <windows.h>
#include <shellapi.h>
#include <array>
#include <string>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "WindowsUserFeedback.h"
#include "res/resource.h"

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
        feedback.ShowError("Cannot locate plugin directory.", "Help");
        return;
    }

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
    feedback.ShowError(msg, "Help");
}

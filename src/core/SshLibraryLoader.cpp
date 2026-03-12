#include "global.h"
#include <windows.h>
#include <array>
#include <string>
#include "CoreUtils.h"
#include "SshLibraryLoader.h"
#include "WindowsUserFeedback.h"

#ifndef SFTP_ALLINONE
HINSTANCE sshlib = nullptr;
#endif

bool loadOK = false;
bool loadAgent = false;

#ifdef SFTP_ALLINONE

bool LoadSSHLib() noexcept
{
    loadOK = true;
    loadAgent = true;
    return true;
}

#else

static FARPROC GetProcAddress2(HMODULE hModule, LPCSTR lpProcName) noexcept
{
    FARPROC retval = GetProcAddress(hModule, lpProcName);
    if (!retval)
        loadOK = false;
    return retval;
}

static FARPROC GetProcAddressAgent(HMODULE hModule, LPCSTR lpProcName) noexcept
{
    FARPROC retval = GetProcAddress(hModule, lpProcName);
    if (!retval)
        loadAgent = false;
    return retval;
}

#define FUNCDEF(r, f, p) typedef r (*t##f) p;
#define FUNCDEF2(r, f, p) typedef r (*t##f) p;
#include "SshDynFunctions.h"
#undef FUNCDEF2
#undef FUNCDEF

#define FUNCDEF(r, f, p) t##f f = nullptr;
#define FUNCDEF2(r, f, p) t##f f = nullptr;
#include "SshDynFunctions.h"
#undef FUNCDEF2
#undef FUNCDEF

static HINSTANCE LoadDllAdv(LPCSTR path, LPCSTR subdir, LPCSTR name, DWORD flags = 0) noexcept
{
    HMODULE lib = nullptr;
    std::string dllname = path;
    if (subdir && subdir[0])
        dllname += std::string(subdir) + "\\";
    dllname += name;
    if (flags) {
        lib = LoadLibraryExA(dllname.c_str(), nullptr, flags);
    } else {
        // Ensure dependencies are resolved relative to the DLL directory first.
        lib = LoadLibraryExA(dllname.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!lib)
            lib = LoadLibraryA(dllname.c_str());
    }
    return static_cast<HINSTANCE>(lib);
}

static HINSTANCE LoadAllLibs(LPCSTR dllpath) noexcept
{
    HMODULE lib = nullptr;
#ifdef _WIN64
    lib = LoadDllAdv(dllpath, "64", "libssh2.dll");
    if (!lib)
        lib = LoadDllAdv(dllpath, "x64", "libssh2.dll");
#endif
    if (!lib)
        lib = LoadDllAdv(dllpath, "", "libssh2.dll");
    return static_cast<HINSTANCE>(lib);
}

bool LoadSSHLib() noexcept
{
    if (sshlib)
        return loadOK;

    LogProc(PluginNumber, MSGTYPE_DETAILS, "Loading SSH Library");
    int olderrormode = SetErrorMode(0x8001);
    std::array<char, MAX_PATH> dllname{};
    dllname[0] = 0;

    // First, try the plugin DLL directory.
    GetModuleFileName(hinst, dllname.data(), static_cast<DWORD>(dllname.size() - 10));
    LPSTR p = strrchr(dllname.data(), '\\');
    p = p ? p + 1 : dllname.data();
    p[0] = 0;
    sshlib = LoadAllLibs(dllname.data());

    if (!sshlib) {
        GetModuleFileName(nullptr, dllname.data(), static_cast<DWORD>(dllname.size() - 10));
        LPSTR p2 = strrchr(dllname.data(), '\\');
        p2 = p2 ? p2 + 1 : dllname.data();
        p2[0] = 0;
        sshlib = LoadAllLibs(dllname.data());
    }
    if (!sshlib) {
        // Then try the Total Commander directory and PATH.
        sshlib = static_cast<HINSTANCE>(LoadLibraryA("libssh2.dll"));
    }
    if (!sshlib) {
        LPCSTR txt = "Please put the libssh2.dll either\n"
                     "- in the same directory as the plugin, or\n"
                     "- in the Total Commander dir, or\n"
#ifdef _WIN64
                     "- in subdir \"64\" of the plugin or TC directory, or\n"
#endif
                     "- somewhere in your PATH!";

        WindowsUserFeedback tempFeedback;
        tempFeedback.ShowError(txt, "Error");
        return false;
    }

    SetErrorMode(olderrormode);
    loadOK = true;
    loadAgent = true;

#define FUNCDEF(r, f, p) f = (t##f)GetProcAddress2(sshlib, #f)
#define FUNCDEF2(r, f, p) f = (t##f)GetProcAddressAgent(sshlib, #f)
#include "SshDynFunctions.h"
#undef FUNCDEF2
#undef FUNCDEF

    return loadOK;
}

#endif

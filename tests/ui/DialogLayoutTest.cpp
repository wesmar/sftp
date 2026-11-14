// Renders every plugin dialog in every language through the plugin's own
// layout code and checks the result: no clipped text, no overlapping
// controls, nothing outside the dialog. A PNG of each run is written for
// review.
//
//   dialog_layout_test <language-dir> <output-dir>

#define NOMINMAX
#include <windows.h>
#include <gdiplus.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "DialogLayout.h"
#include "DialogStrings.h"

#pragma comment(lib, "gdiplus.lib")

namespace {

using StringMap = std::unordered_map<UINT, std::wstring>;

struct Language {
    std::wstring code;
    StringMap strings;
};

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty())
        return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty())
        return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

// Same format LngLoader reads: "ID=text", '#' comments, \r \n \t \\ escapes.
Language LoadLanguage(const std::filesystem::path& file)
{
    Language lang{file.stem().wstring(), {}};
    std::ifstream in(file, std::ios::binary);
    std::string line;
    bool first = true;
    while (std::getline(in, line)) {
        if (first && line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF)
            line.erase(0, 3);
        first = false;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty() || line[0] == '#')
            continue;
        const size_t eq = line.find('=');
        if (eq == std::string::npos)
            continue;
        std::string text;
        for (size_t i = eq + 1; i < line.size(); ++i) {
            if (line[i] == '\\' && i + 1 < line.size()) {
                const char e = line[++i];
                text += e == 'n' ? '\n' : e == 'r' ? '\r' : e == 't' ? '\t' : e;
            } else {
                text += line[i];
            }
        }
        lang.strings[static_cast<UINT>(std::strtoul(line.substr(0, eq).c_str(), nullptr, 10))] = Utf8ToWide(text);
    }
    return lang;
}

std::wstring StringFor(const Language& lang, UINT id)
{
    if (const auto it = lang.strings.find(id); it != lang.strings.end())
        return it->second;
    wchar_t buf[1024] = {};
    const int n = LoadStringW(GetModuleHandleW(nullptr), id, buf, 1023);
    return std::wstring(buf, static_cast<size_t>(n > 0 ? n : 0));
}

enum class Variant { Ssh, Php, Lan };

struct DialogCase {
    const char* name;
    int id;
    UINT caption;
    std::span<const DialogString> strings;
    void (*layout)(HWND);
    Variant variant;
};

struct Run {
    const Language* lang;
    const DialogCase* dialog;
};

void ShowLanControls(HWND h, const Language& lang)
{
    for (int id : {IDC_LANPAIR_GROUP, IDC_LAN_TIMEOUT_LABEL, IDC_LAN_TIMEOUT, IDC_LAN_TIMEOUT_HINT, IDC_LAN_TI})
        ShowWindow(GetDlgItem(h, id), SW_SHOW);
    for (int id : {IDC_PERMISSIONS_GROUP, IDC_FILEMOD_LABEL, IDC_FILEMOD, IDC_DIRMOD_LABEL, IDC_DIRMOD, IDC_PHP_TAR})
        ShowWindow(GetDlgItem(h, id), SW_HIDE);
    SetDlgItemTextW(h, IDC_PHPSHELL, StringFor(lang, IDS_BUTTON_PAIR).c_str());
}

INT_PTR CALLBACK DialogProc(HWND h, UINT msg, WPARAM, LPARAM lParam)
{
    if (msg != WM_INITDIALOG)
        return FALSE;
    const auto* run = reinterpret_cast<const Run*>(lParam);
    SetWindowTextW(h, StringFor(*run->lang, run->dialog->caption).c_str());
    for (const auto& s : run->dialog->strings) {
        const std::wstring text = StringFor(*run->lang, s.string);
        if (!text.empty())
            SetDlgItemTextW(h, s.control, text.c_str());
    }
    if (run->dialog->id == IDD_DOWNLOAD_ERROR)
        SetDlgItemTextW(h, IDC_DOWNLOAD_ERROR_PATH, L"/var/log/remote/example-archive.tar.gz");
    DlgLayout::OnInitDialog(h);
    run->dialog->layout(h);
    // What UpdateScpOnlyDependentControls does when the mode is set.
    if (run->dialog->id == IDD_CONNECTION) {
        if (run->dialog->variant == Variant::Lan) {
            ShowLanControls(h, *run->lang);
        } else {
            for (int id : {IDC_LANPAIR_GROUP, IDC_LAN_TIMEOUT_LABEL, IDC_LAN_TIMEOUT, IDC_LAN_TIMEOUT_HINT, IDC_LAN_TI})
                ShowWindow(GetDlgItem(h, id), SW_HIDE);
        }
        run->dialog->layout(h);
    }
    return TRUE;
}

struct ControlInfo {
    HWND hwnd;
    int id;
    RECT rect;
    std::wstring text;
    bool groupBox;
};

std::vector<ControlInfo> VisibleControls(HWND h)
{
    std::vector<ControlInfo> out;
    for (HWND c = GetWindow(h, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
        if (!(GetWindowLongW(c, GWL_STYLE) & WS_VISIBLE))
            continue;
        RECT r{};
        GetWindowRect(c, &r);
        MapWindowPoints(nullptr, h, reinterpret_cast<POINT*>(&r), 2);
        wchar_t text[512] = {};
        GetWindowTextW(c, text, 511);
        wchar_t cls[32] = {};
        GetClassNameW(c, cls, 32);
        const bool groupBox = _wcsicmp(cls, L"Button") == 0 && (GetWindowLongW(c, GWL_STYLE) & BS_TYPEMASK) == BS_GROUPBOX;
        out.push_back({c, GetDlgCtrlID(c), r, text, groupBox});
    }
    return out;
}

int Check(HWND h, std::vector<std::string>& report)
{
    int failures = 0;
    RECT client{};
    GetClientRect(h, &client);
    const int tolerance = DlgLayout::Scale(h, 2);
    const auto controls = VisibleControls(h);
    for (const auto& c : controls) {
        const int need = DlgLayout::RequiredWidth(c.hwnd);
        const int have = c.rect.right - c.rect.left;
        if (need > have + tolerance) {
            const bool ellipsis = (GetWindowLongW(c.hwnd, GWL_STYLE) & SS_ENDELLIPSIS) != 0;
            report.push_back(std::string(ellipsis ? "  ellipsis " : "  CLIPPED  ") + "id " + std::to_string(c.id) +
                             " needs " + std::to_string(need) + " has " + std::to_string(have) + ": " + WideToUtf8(c.text));
            if (!ellipsis)
                ++failures;
        }
        if (c.rect.left < 0 || c.rect.right > client.right || c.rect.bottom > client.bottom) {
            report.push_back("  OUTSIDE  id " + std::to_string(c.id) + ": " + WideToUtf8(c.text));
            ++failures;
        }
    }
    for (size_t i = 0; i < controls.size(); ++i) {
        for (size_t j = i + 1; j < controls.size(); ++j) {
            if (controls[i].groupBox || controls[j].groupBox)
                continue;
            RECT x{};
            if (IntersectRect(&x, &controls[i].rect, &controls[j].rect) && (x.right - x.left) > 1 && (x.bottom - x.top) > 1) {
                report.push_back("  OVERLAP  id " + std::to_string(controls[i].id) + " / id " + std::to_string(controls[j].id) +
                                 ": " + WideToUtf8(controls[i].text) + " | " + WideToUtf8(controls[j].text));
                ++failures;
            }
        }
    }
    return failures;
}

int PngEncoder(CLSID* clsid)
{
    UINT count = 0, size = 0;
    Gdiplus::GetImageEncodersSize(&count, &size);
    std::vector<BYTE> buf(size);
    auto* encoders = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buf.data());
    Gdiplus::GetImageEncoders(count, size, encoders);
    for (UINT i = 0; i < count; ++i) {
        if (wcscmp(encoders[i].MimeType, L"image/png") == 0) {
            *clsid = encoders[i].Clsid;
            return 0;
        }
    }
    return -1;
}

void SaveScreenshot(HWND h, const std::filesystem::path& file)
{
    RECT r{};
    GetWindowRect(h, &r);
    const int w = r.right - r.left;
    const int hgt = r.bottom - r.top;
    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, w, hgt);
    HGDIOBJ old = SelectObject(mem, bmp);
    PrintWindow(h, mem, 2 /* PW_RENDERFULLCONTENT */);
    SelectObject(mem, old);
    {
        Gdiplus::Bitmap image(bmp, nullptr);
        CLSID png{};
        if (PngEncoder(&png) == 0)
            image.Save(file.wstring().c_str(), &png, nullptr);
    }
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
}

void Pump()
{
    MSG m;
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    if (argc < 3) {
        std::printf("usage: dialog_layout_test <language-dir> <output-dir>\n");
        return 2;
    }
    const std::filesystem::path langDir = argv[1];
    const std::filesystem::path outDir = argv[2];
    std::filesystem::create_directories(outDir);

    Gdiplus::GdiplusStartupInput gdiInput;
    ULONG_PTR gdiToken = 0;
    Gdiplus::GdiplusStartup(&gdiToken, &gdiInput, nullptr);

    std::vector<Language> languages{{L"en", {}}};
    for (const auto& f : std::filesystem::directory_iterator(langDir))
        if (f.path().extension() == L".lng")
            languages.push_back(LoadLanguage(f.path()));

    const DialogCase cases[] = {
        {"connection-ssh", IDD_CONNECTION, kConnectionDialogCaption, kConnectionDialogStrings, DlgLayout::LayoutConnectionDialog, Variant::Ssh},
        {"connection-php", IDD_CONNECTION, kConnectionDialogCaption, kConnectionDialogStrings, DlgLayout::LayoutConnectionDialog, Variant::Php},
        {"connection-lan", IDD_CONNECTION, kConnectionDialogCaption, kConnectionDialogStrings, DlgLayout::LayoutConnectionDialog, Variant::Lan},
        {"jumphost", IDD_JUMPHOST, kJumpHostDialogCaption, kJumpHostDialogStrings, DlgLayout::LayoutJumpHostDialog, Variant::Ssh},
        {"proxy", IDD_PROXY, kProxyDialogCaption, kProxyDialogStrings, DlgLayout::LayoutProxyDialog, Variant::Ssh},
        {"properties", IDD_PROPERTIES, kPropertiesDialogCaption, kPropertiesDialogStrings, DlgLayout::LayoutPropertiesDialog, Variant::Ssh},
        {"download-error", IDD_DOWNLOAD_ERROR, kDownloadErrorDialogCaption, kDownloadErrorDialogStrings, DlgLayout::LayoutDownloadErrorDialog, Variant::Ssh},
    };

    int failures = 0;
    for (const auto& lang : languages) {
        for (const auto& dc : cases) {
            Run run{&lang, &dc};
            HWND h = nullptr;
            {
                DlgLayout::PerMonitorDpiScope dpi;
                h = CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(dc.id), nullptr, DialogProc,
                                       reinterpret_cast<LPARAM>(&run));
            }
            if (!h) {
                std::printf("FAIL %s/%s: dialog not created (%lu)\n", WideToUtf8(lang.code).c_str(), dc.name, GetLastError());
                ++failures;
                continue;
            }
            SetWindowPos(h, nullptr, 40, 40, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_SHOWWINDOW | SWP_NOACTIVATE);
            UpdateWindow(h);
            Pump();

            std::vector<std::string> report;
            const int bad = Check(h, report);
            RECT r{};
            GetWindowRect(h, &r);
            std::printf("%s %-6s %-15s %4ldx%-4ld dpi %u%s\n", bad ? "FAIL" : "ok  ", WideToUtf8(lang.code).c_str(), dc.name,
                        r.right - r.left, r.bottom - r.top, DlgLayout::DpiOf(h), report.empty() ? "" : ":");
            for (const auto& line : report)
                std::printf("%s\n", line.c_str());
            failures += bad;
            SaveScreenshot(h, outDir / (lang.code + L"-" + Utf8ToWide(dc.name) + L".png"));
            DestroyWindow(h);
            Pump();
        }
    }

    Gdiplus::GdiplusShutdown(gdiToken);
    std::printf("%d layout problem(s)\n", failures);
    return failures == 0 ? 0 : 1;
}

// Connection dialog/UI extracted from SftpConnection.cpp
#include "global.h"
#include <windows.h>
#include <commdlg.h>
#include <array>
#include <map>
#include <mutex>
#include <new>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <cstring>
#include <format>
#include <string_view>
#include <stdio.h>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "UtfConversion.h"
#include "UnicodeHelpers.h"
#include "FtpDirectoryParser.h"
#include "SftpInternal.h"
#include "WindowsUserFeedback.h"
#include "SessionImport.h"
#include "PhpAgentClient.h"
#include "PhpShellConsole.h"
#include "ConnectionDialog.h"
#include "LanPair.h"
#include "JumpHostConnection.h"
#include "ProfileSettings.h"

extern bool serverfieldchangedbyuser;

struct ProxyDialogContext {
    int proxynr = 0;
    int focusset = 0;
    pConnectSettings ownerConnectResults = nullptr;
    LPCSTR iniFileName = nullptr;
    tConnectSettings connectData{};
};

// Context for the Jump Host settings dialog.
struct JumpDialogContext {
    pConnectSettings cs    = nullptr;   // main connection settings (in/out)
    LPCSTR iniFileName     = nullptr;
    bool   hasCryptProc    = false;
};

// Helper: open a file browser for key file selection in jump dialog.
static void BrowseJumpKeyFile(HWND hWnd, int editCtrl)
{
    OPENFILENAMEA ofn{};
    std::array<char, MAX_PATH> path{};
    GetDlgItemTextA(hWnd, editCtrl, path.data(), static_cast<int>(path.size()) - 1);
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = hWnd;
    ofn.lpstrFilter  = "Key files\0*.pub;*.pem;*.ppk;*.key\0All files\0*.*\0\0";
    ofn.lpstrFile    = path.data();
    ofn.nMaxFile     = static_cast<DWORD>(path.size()) - 1;
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileNameA(&ofn))
        SetDlgItemTextA(hWnd, editCtrl, path.data());
}

// Enable/disable jump host controls based on the checkbox state.
static void UpdateJumpControlStates(HWND hWnd)
{
    const bool enabled = IsDlgButtonChecked(hWnd, IDC_JUMP_ENABLE) == BST_CHECKED;
    for (int id : { IDC_JUMP_HOST, IDC_JUMP_PORT, IDC_JUMP_USER,
                    IDC_JUMP_PASSWORD, IDC_JUMP_PUBKEY, IDC_JUMP_PRIVKEY,
                    IDC_JUMP_USEAGENT, IDC_JUMP_LOADPUBKEY, IDC_JUMP_LOADPRIVKEY,
                    IDC_JUMP_CRYPTPASS }) {
        EnableWindow(GetDlgItem(hWnd, id), enabled);
    }
}

static void UpdateMainJumpControlStates(HWND hWnd, bool sshMode)
{
    const bool jumpChecked = IsDlgButtonChecked(hWnd, IDC_JUMP_ENABLE) == BST_CHECKED;
    EnableWindow(GetDlgItem(hWnd, IDC_JUMP_ENABLE), sshMode ? TRUE : FALSE);
    EnableWindow(GetDlgItem(hWnd, IDC_JUMP_BUTTON), (sshMode && jumpChecked) ? TRUE : FALSE);
}

static void LocalizeDlgControls(HWND hWnd, UINT captionStrId,
    std::initializer_list<std::pair<int, UINT>> controls);

// Jump Host settings dialog procedure.
static INT_PTR CALLBACK JumpHostDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    auto* ctx = reinterpret_cast<JumpDialogContext*>(GetWindowLongPtr(hWnd, DWLP_USER));

    switch (msg) {
    case WM_INITDIALOG: {
        ctx = reinterpret_cast<JumpDialogContext*>(lParam);
        SetWindowLongPtr(hWnd, DWLP_USER, lParam);
        if (!ctx || !ctx->cs) { EndDialog(hWnd, IDCANCEL); return 1; }

        pConnectSettings cs = ctx->cs;

        LocalizeDlgControls(hWnd, IDS_JUMP_DLG_CAPTION, {
            { IDC_JUMP_GROUP,        IDS_JUMP_DLG_GROUP    },
            { IDC_JUMP_ENABLE,       IDS_JUMP_DLG_USE      },
            { IDC_JUMP_LABEL_HOST,   IDS_JUMP_DLG_HOST     },
            { IDC_JUMP_LABEL_PORT,   IDS_JUMP_DLG_PORT     },
            { IDC_JUMP_LABEL_USER,   IDS_JUMP_DLG_USER     },
            { IDC_JUMP_LABEL_PASS,   IDS_JUMP_DLG_PASS     },
            { IDC_JUMP_LABEL_PUBKEY, IDS_JUMP_DLG_PUBKEY   },
            { IDC_JUMP_LABEL_PRIVKEY,IDS_JUMP_DLG_PRIVKEY  },
            { IDC_JUMP_USEAGENT,     IDS_JUMP_DLG_USEAGENT },
            { IDC_JUMP_CRYPTPASS,    IDS_DLG_CRYPTPASS     },
            { IDC_JUMP_EDITPASS,     IDS_DLG_CHANGEPASS    },
        });

        CheckDlgButton(hWnd, IDC_JUMP_ENABLE, cs->use_jump_host ? BST_CHECKED : BST_UNCHECKED);
        SetDlgItemTextA(hWnd, IDC_JUMP_HOST, cs->jump_host.c_str());
        SetDlgItemInt(hWnd, IDC_JUMP_PORT, cs->jump_port ? cs->jump_port : 22, FALSE);
        SetDlgItemTextA(hWnd, IDC_JUMP_USER, cs->jump_user.c_str());
        SetDlgItemTextA(hWnd, IDC_JUMP_PASSWORD, cs->jump_password.c_str());
        SetDlgItemTextA(hWnd, IDC_JUMP_PUBKEY, cs->jump_pubkeyfile.c_str());
        SetDlgItemTextA(hWnd, IDC_JUMP_PRIVKEY, cs->jump_privkeyfile.c_str());
        CheckDlgButton(hWnd, IDC_JUMP_USEAGENT, cs->jump_useagent ? BST_CHECKED : BST_UNCHECKED);

        if (!ctx->hasCryptProc)
            EnableWindow(GetDlgItem(hWnd, IDC_JUMP_CRYPTPASS), FALSE);

        UpdateJumpControlStates(hWnd);

        // Center dialog over parent.
        RECT r1{}, r2{};
        if (GetWindowRect(hWnd, &r1) && GetWindowRect(GetParent(hWnd), &r2)) {
            int w = r2.right - r2.left, h = r2.bottom - r2.top;
            int dw = r1.right - r1.left, dh = r1.bottom - r1.top;
            SetWindowPos(hWnd, nullptr,
                r2.left + (w - dw) / 2, r2.top + (h - dh) / 2,
                0, 0, SWP_NOZORDER | SWP_NOSIZE);
        }
        return 1;
    }

    case WM_COMMAND:
        if (!ctx) break;
        switch (LOWORD(wParam)) {
        case IDOK: {
            pConnectSettings cs = ctx->cs;
            cs->use_jump_host   = IsDlgButtonChecked(hWnd, IDC_JUMP_ENABLE) == BST_CHECKED;

            std::array<char, MAX_PATH> buf{};
            GetDlgItemTextA(hWnd, IDC_JUMP_HOST, buf.data(), static_cast<int>(buf.size()) - 1);
            cs->jump_host = buf.data();

            BOOL portOk = FALSE;
            UINT port = GetDlgItemInt(hWnd, IDC_JUMP_PORT, &portOk, FALSE);
            cs->jump_port = (portOk && port > 0 && port < 65536)
                ? static_cast<unsigned short>(port) : 22;

            GetDlgItemTextA(hWnd, IDC_JUMP_USER, buf.data(), static_cast<int>(buf.size()) - 1);
            cs->jump_user = buf.data();

            GetDlgItemTextA(hWnd, IDC_JUMP_PASSWORD, buf.data(), static_cast<int>(buf.size()) - 1);
            cs->jump_password = buf.data();

            GetDlgItemTextA(hWnd, IDC_JUMP_PUBKEY, buf.data(), static_cast<int>(buf.size()) - 1);
            cs->jump_pubkeyfile = buf.data();

            GetDlgItemTextA(hWnd, IDC_JUMP_PRIVKEY, buf.data(), static_cast<int>(buf.size()) - 1);
            cs->jump_privkeyfile = buf.data();

            cs->jump_useagent = IsDlgButtonChecked(hWnd, IDC_JUMP_USEAGENT) == BST_CHECKED;

            // Persist jump host settings to INI.
            if (ctx->iniFileName && cs->DisplayName[0]) {
                LPCSTR sec = cs->DisplayName.c_str();
                LPCSTR ini = ctx->iniFileName;
                WritePrivateProfileString(sec, "usejumphost",  cs->use_jump_host ? "1" : "0", ini);
                WritePrivateProfileString(sec, "jumphost",     cs->jump_host.c_str(), ini);
                std::array<char, 16> portBuf{};
                _itoa_s(cs->jump_port, portBuf.data(), portBuf.size(), 10);
                WritePrivateProfileString(sec, "jumpport",     portBuf.data(), ini);
                WritePrivateProfileString(sec, "jumpuser",     cs->jump_user.c_str(), ini);
                WritePrivateProfileString(sec, "jumppubkeyfile",  cs->jump_pubkeyfile.c_str(), ini);
                WritePrivateProfileString(sec, "jumpprivkeyfile", cs->jump_privkeyfile.c_str(), ini);
                WritePrivateProfileString(sec, "jumpuseagent", cs->jump_useagent ? "1" : "0", ini);
                // Password: encrypt like main password.
                if (!cs->jump_password.empty()) {
                    std::array<char, 1024> enc{};
                    EncryptString(cs->jump_password.c_str(), enc.data(), static_cast<UINT>(enc.size()));
                    WritePrivateProfileString(sec, "jumppassword", enc.data(), ini);
                } else {
                    WritePrivateProfileString(sec, "jumppassword", "", ini);
                }
            }

            EndDialog(hWnd, IDOK);
            return 1;
        }
        case IDCANCEL:
            EndDialog(hWnd, IDCANCEL);
            return 1;
        case IDC_JUMP_ENABLE:
            UpdateJumpControlStates(hWnd);
            break;
        case IDC_JUMP_LOADPUBKEY:
            BrowseJumpKeyFile(hWnd, IDC_JUMP_PUBKEY);
            break;
        case IDC_JUMP_LOADPRIVKEY:
            BrowseJumpKeyFile(hWnd, IDC_JUMP_PRIVKEY);
            break;
        }
        break;
    }
    return 0;
}

struct ConnectDialogContext {
    pConnectSettings connectResults = nullptr;
    LPCSTR displayName = nullptr;
    LPCSTR iniFileName = nullptr;
    int focusset = 0;
    int lastTransferMode = 0;
    std::string defaultSystemLabel;
    std::string defaultEncodingLabel;
    std::wstring defaultPasswordLabel;
    std::unique_ptr<lanpair::DiscoveryService> lanDiscovery;
    std::unique_ptr<lanpair::PairServer> lanServer;
    std::unordered_map<std::string, lanpair::PeerAnnouncement> lanPeers;
    std::vector<std::string> lanPeerOrder;
    std::string lanPeerId;
    std::wstring lanDisplayName;
    bool lanDiscoveryRunning = false;
    bool lanServerRunning = false;
    bool lanRolePromptShown = false;
};

// Forward declaration so GetConnectDialogContext can return context via the class.
class ConnectionDialog;

namespace {
constexpr int TC_DIALOG_STATIC_ID = -1;
}

static ConnectDialogContext* GetConnectDialogContext(HWND hWnd);

// ============================================================================
// ConnectionDialog class definition
// ============================================================================

class ConnectionDialog {
public:
    ConnectionDialog(HWND hWnd, ConnectDialogContext* ctx);
    ~ConnectionDialog() = default;
    INT_PTR HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    ConnectDialogContext* GetContext() const noexcept { return m_ctx; }
private:
    INT_PTR OnInitDialog(LPARAM lParam);
    INT_PTR OnShowWindow(BOOL fShow);
    INT_PTR OnCommand(WPARAM wParam, LPARAM lParam);
    void    OnDestroy();
    INT_PTR OnLanPeerMessage(WPARAM wParam, LPARAM lParam);
    void    OnOk();
    void    OnCancel();
    void    OnSessionChanged();
    void    OnTransferModeChanged();
    void    OnPhpShellBtn();
    void    OnBrowseKeyFile(bool isPublicKey);
    void    OnPrivateKeyChanged();
    void    OnUseAgentChanged();
    void    OnJumpEnableChanged();
    void    OnJumpButton();
    void    OnProxyButton();
    void    OnProxyComboChanged();
    void    OnDeleteLastProxy();
    void    OnImportSessions();
    void    OnPluginHelp();
    void    OnCertHelp();
    void    OnPasswordHelp();
    void    OnUtf8Help();
    void    OnEditPass();
    void    OnConnectToChanged();

    HWND                  m_hWnd;
    ConnectDialogContext*  m_ctx;
    pConnectSettings       m_settings;
    bool                   m_initialized;
};

static BOOL SetDlgItemText(HWND hWnd, int nIDDlgItem, const std::string& text)
{
    return ::SetDlgItemTextA(hWnd, nIDDlgItem, text.c_str());
}

static UINT GetDlgItemText(HWND hWnd, int nIDDlgItem, std::string& out, size_t capacity = MAX_PATH)
{
    if (capacity == 0)
        capacity = 1;
    out.assign(capacity, '\0');
    const UINT len = ::GetDlgItemTextA(hWnd, nIDDlgItem, out.data(), static_cast<int>(capacity));
    out.resize(len);
    return len;
}

static BOOL WritePrivateProfileString(const char* section, const char* key, const std::string& value, const char* fileName)
{
    return ::WritePrivateProfileStringA(section, key, value.c_str(), fileName);
}

static BOOL WritePrivateProfileString(const std::string& section, const char* key, const char* value, const std::string& fileName)
{
    return ::WritePrivateProfileStringA(section.c_str(), key, value, fileName.c_str());
}

static BOOL WritePrivateProfileString(const std::string& section, const char* key, const std::string& value, const std::string& fileName)
{
    return ::WritePrivateProfileStringA(section.c_str(), key, value.c_str(), fileName.c_str());
}

static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) {
        return {};
    }
    const int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(), len, nullptr, nullptr);
    return out;
}

static std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) {
        return {};
    }
    const int len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(), -1, nullptr, 0);
    if (len <= 0) {
        return {};
    }
    std::wstring out(static_cast<size_t>(len - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(), -1, out.data(), len);
    return out;
}

static std::wstring LoadResStringW(UINT id)
{
    const char* lngStr = LngGetString(id);
    if (lngStr)
        return Utf8ToWide(std::string(lngStr));
    std::array<wchar_t, 1024> buf{};
    const int n = LoadStringW(hinst, id, buf.data(), static_cast<int>(buf.size() - 1));
    if (n <= 0)
        return {};
    return std::wstring(buf.data(), static_cast<size_t>(n));
}

// Sets a dialog control's text from LNG/RC. No-op if no translation is found.
static void LocalizeDlgControl(HWND hWnd, int ctrlId, UINT strId)
{
    std::wstring s = LoadResStringW(strId);
    if (!s.empty())
        SetDlgItemTextW(hWnd, ctrlId, s.c_str());
}

// Translates all named controls in a dialog from LNG/RC string table.
// Call from WM_INITDIALOG after the dialog is fully initialized.
static void LocalizeDlgControls(HWND hWnd, UINT captionStrId,
    std::initializer_list<std::pair<int, UINT>> controls)
{
    std::wstring caption = LoadResStringW(captionStrId);
    if (!caption.empty())
        SetWindowTextW(hWnd, caption.c_str());
    for (const auto& [ctrlId, strId] : controls)
        LocalizeDlgControl(hWnd, ctrlId, strId);
}

// Repositions label + checkbox + button on one row based on actual text widths.
// Prevents translated text from overlapping or leaving excessive gaps.
static void ArrangeInlineRow(HWND hWnd, int labelId, int checkId, int btnId)
{
    HWND hLabel = GetDlgItem(hWnd, labelId);
    HWND hCheck = GetDlgItem(hWnd, checkId);
    HWND hBtn   = GetDlgItem(hWnd, btnId);
    if (!hLabel || !hCheck || !hBtn)
        return;

    HDC hdc = GetDC(hWnd);
    HFONT hFont    = reinterpret_cast<HFONT>(SendMessage(hWnd, WM_GETFONT, 0, 0));
    HFONT hOldFont = reinterpret_cast<HFONT>(SelectObject(hdc, hFont));

    wchar_t buf[256] = {};
    SIZE szLabel{}, szCheck{};
    GetWindowTextW(hLabel, buf, 255);
    GetTextExtentPoint32W(hdc, buf, static_cast<int>(wcslen(buf)), &szLabel);
    GetWindowTextW(hCheck, buf, 255);
    GetTextExtentPoint32W(hdc, buf, static_cast<int>(wcslen(buf)), &szCheck);

    SelectObject(hdc, hOldFont);
    ReleaseDC(hWnd, hdc);

    RECT rLabel{}, rCheck{}, rBtn{}, rDlg{};
    GetWindowRect(hLabel, &rLabel); MapWindowPoints(nullptr, hWnd, reinterpret_cast<POINT*>(&rLabel), 2);
    GetWindowRect(hCheck, &rCheck); MapWindowPoints(nullptr, hWnd, reinterpret_cast<POINT*>(&rCheck), 2);
    GetWindowRect(hBtn,   &rBtn);   MapWindowPoints(nullptr, hWnd, reinterpret_cast<POINT*>(&rBtn),   2);
    GetClientRect(hWnd, &rDlg);

    constexpr int kGap   = 4;   // pixels between controls
    constexpr int kBoxW  = 16;  // checkbox square

    const int labelX = rLabel.left;
    const int labelW = szLabel.cx + kGap;
    const int checkX = labelX + labelW + kGap;
    const int btnW   = rBtn.right  - rBtn.left;
    const int btnH   = rBtn.bottom - rBtn.top;

    // Button positioned right after checkbox text, clamped to dialog right edge.
    const int rawBtnX   = checkX + kBoxW + static_cast<int>(szCheck.cx) + kGap * 2;
    const int finalBtnX = (std::min)(rawBtnX, static_cast<int>(rDlg.right) - btnW - kGap);

    // Checkbox: fill the space between its start and the button.
    const int checkW = (std::max)(finalBtnX - kGap - checkX, kBoxW + 4);

    SetWindowPos(hLabel, nullptr, labelX,    rLabel.top, labelW, rLabel.bottom - rLabel.top, SWP_NOZORDER);
    SetWindowPos(hCheck, nullptr, checkX,    rCheck.top, checkW, rCheck.bottom - rCheck.top, SWP_NOZORDER);
    SetWindowPos(hBtn,   nullptr, finalBtnX, rBtn.top,   btnW,   btnH,                       SWP_NOZORDER);
}

static std::wstring FormatBracesW(std::wstring templ, std::initializer_list<std::wstring_view> args)
{
    size_t pos = 0;
    for (const auto& arg : args) {
        const size_t at = templ.find(L"{}", pos);
        if (at == std::wstring::npos) {
            break;
        }
        templ.replace(at, 2, arg.data(), arg.size());
        pos = at + arg.size();
    }
    return templ;
}

static std::wstring GetSessionDisplayNameW(HWND hWnd)
{
    std::array<wchar_t, MAX_PATH> sessionW{};
    GetDlgItemTextW(hWnd, IDC_SESSIONCOMBO, sessionW.data(), static_cast<int>(sessionW.size() - 1));
    std::wstring value = sessionW.data();
    while (!value.empty() && (value.back() == L' ' || value.back() == L'\t')) {
        value.pop_back();
    }
    size_t lead = 0;
    while (lead < value.size() && (value[lead] == L' ' || value[lead] == L'\t')) {
        ++lead;
    }
    if (lead > 0) {
        value.erase(0, lead);
    }
    return value;
}

static void SetDialogLabelTextAndRedraw(HWND hWnd, int ctrlId, const wchar_t* textW)
{
    HWND hCtrl = GetDlgItem(hWnd, ctrlId);
    if (!hCtrl) {
        return;
    }

    RECT rcScreen{};
    if (GetWindowRect(hCtrl, &rcScreen)) {
        POINT tl{ rcScreen.left, rcScreen.top };
        POINT br{ rcScreen.right, rcScreen.bottom };
        ScreenToClient(hWnd, &tl);
        ScreenToClient(hWnd, &br);
        RECT rcClient{ tl.x, tl.y, br.x, br.y };
        InvalidateRect(hWnd, &rcClient, TRUE);
    }

    SetWindowTextW(hCtrl, textW ? textW : L"");
    RedrawWindow(hCtrl, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW | RDW_FRAME);
    RedrawWindow(hWnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW | RDW_ALLCHILDREN);
}

static void SetDialogLabelTextAndRedrawA(HWND hWnd, int ctrlId, const char* textA)
{
    std::wstring w = Utf8ToWide(textA ? std::string(textA) : std::string{});
    if (w.empty() && textA && textA[0]) {
        const int lenAcp = MultiByteToWideChar(CP_ACP, 0, textA, -1, nullptr, 0);
        if (lenAcp > 0) {
            w.assign(static_cast<size_t>(lenAcp - 1), L'\0');
            MultiByteToWideChar(CP_ACP, 0, textA, -1, w.data(), lenAcp);
        }
    }
    SetDialogLabelTextAndRedraw(hWnd, ctrlId, w.c_str());
}


static int PhpChunkValueToComboIndex(int chunkMb) noexcept
{
    switch (chunkMb) {
    case 2: return 1;
    case 4: return 2;
    case 8: return 3;
    case 16: return 4;
    case 32: return 5;
    case 64: return 6;
    case 1: return 0; // legacy value: treat as Auto
    default: return 0;
    }
}

static int PhpChunkComboIndexToValue(int idx) noexcept
{
    switch (idx) {
    case 1: return 2;
    case 2: return 4;
    case 3: return 8;
    case 4: return 16;
    case 5: return 32;
    case 6: return 64;
    default: return 0;
    }
}

static std::wstring TrimWhitespaceW(std::wstring text)
{
    while (!text.empty() && iswspace(text.front()))
        text.erase(text.begin());
    while (!text.empty() && iswspace(text.back()))
        text.pop_back();
    return text;
}

static void SplitLanTimeoutText(std::wstring& label, std::wstring& suffix)
{
    const std::wstring full = LoadResStringW(IDS_LAN_SESSION_TIMEOUT);
    const size_t open = full.find(L'[');
    const size_t close = open == std::wstring::npos ? std::wstring::npos : full.find(L']', open + 1);
    if (open == std::wstring::npos || close == std::wstring::npos || close <= open) {
        label = TrimWhitespaceW(full);
        suffix.clear();
        return;
    }

    label = TrimWhitespaceW(full.substr(0, open));
    suffix = TrimWhitespaceW(full.substr(close + 1));
}

static int ReadLanTimeoutMinutes(HWND hWnd)
{
    std::array<char, 32> buf{};
    GetDlgItemTextA(hWnd, IDC_LAN_TIMEOUT, buf.data(), static_cast<int>(buf.size() - 1));
    const long value = strtol(buf.data(), nullptr, 10);
    return value > 0 ? static_cast<int>(value) : 0;
}

static void SetLanTimeoutMinutes(HWND hWnd, int minutes)
{
    std::array<char, 16> buf{};
    _itoa_s(max(0, minutes), buf.data(), static_cast<int>(buf.size()), 10);
    SetDlgItemTextA(hWnd, IDC_LAN_TIMEOUT, buf.data());
}

static void GetPhpOptionLabels(std::string& methodLabel, std::string& chunkLabel) noexcept
{
    const WORD lang = PRIMARYLANGID(GetConfiguredUiLanguageId());
    switch (lang) {
    case LANG_POLISH:
        methodLabel = "Metoda:";
        chunkLabel = "Fragmenty:";
        break;
    case LANG_GERMAN:
        methodLabel = "Methode:";
        chunkLabel = "Fragmente:";
        break;
    case LANG_FRENCH:
        methodLabel = "Methode:";
        chunkLabel = "Fragments:";
        break;
    case LANG_SPANISH:
        methodLabel = "Metodo:";
        chunkLabel = "Fragmentos:";
        break;
    case LANG_ITALIAN:
        methodLabel = "Metodo:";
        chunkLabel = "Frammenti:";
        break;
    default:
        methodLabel = "Method:";
        chunkLabel = "Chunks:";
        break;
    }
}

constexpr UINT WM_APP_LAN_PEER = WM_APP + 77;

static int LanRoleComboToValue(int idx) noexcept
{
    if (idx < 0 || idx > 2) {
        return 0;
    }
    return idx;
}

static std::string MakeLanPeerId() noexcept
{
    char host[256] = {};
    gethostname(host, static_cast<int>(sizeof(host) - 1));
    return std::string(host); // hostname only — stable across TC restarts
}

static void StopLanPairing(ConnectDialogContext* dlgCtx)
{
    if (!dlgCtx) {
        return;
    }
    if (dlgCtx->lanServer) {
        dlgCtx->lanServer->stop();
        dlgCtx->lanServerRunning = false;
    }
    if (dlgCtx->lanDiscovery) {
        dlgCtx->lanDiscovery->stop();
        dlgCtx->lanDiscoveryRunning = false;
    }
}

static void RefreshLanPeerCombo(HWND hWnd, ConnectDialogContext* dlgCtx, const std::string& selectedPeerId)
{
    if (!dlgCtx) {
        return;
    }
    std::string effectiveSelectedPeerId = selectedPeerId;
    if (effectiveSelectedPeerId.empty()) {
        const int curSel = (int)SendDlgItemMessage(hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0);
        if (curSel > 0 && curSel <= (int)dlgCtx->lanPeerOrder.size()) {
            effectiveSelectedPeerId = dlgCtx->lanPeerOrder[curSel - 1];
        }
    }
    SendDlgItemMessage(hWnd, IDC_UTF8, CB_RESETCONTENT, 0, 0);
    const std::wstring autoDiscovery = LoadResStringW(IDS_LAN_PEER_AUTODISC);
    SendDlgItemMessageW(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)(autoDiscovery.empty() ? L"Auto-discovery" : autoDiscovery.c_str()));
    dlgCtx->lanPeerOrder.clear();

    int selectedIndex = 0;
    int nextIndex = 1;
    std::wstring peerFallback = LoadResStringW(IDS_LAN_PEER_LABEL);
    if (peerFallback.empty()) {
        peerFallback = L"Peer";
    } else if (!peerFallback.empty() && peerFallback.back() == L':') {
        peerFallback.pop_back();
    }
    for (const auto& [peerId, ann] : dlgCtx->lanPeers) {
        const std::string nameU8 = ann.displayName.empty() ? ann.peerId : ann.displayName;
        const std::wstring nameW = Utf8ToWide(nameU8);
        const std::wstring ipW = Utf8ToWide(ann.ip);
        const std::wstring displayW = std::format(L"{} ({}:{})", nameW.empty() ? peerFallback : nameW, ipW, ann.tcpPort);
        SendDlgItemMessageW(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)displayW.c_str());
        dlgCtx->lanPeerOrder.push_back(peerId);
        if (!effectiveSelectedPeerId.empty() && effectiveSelectedPeerId == peerId) {
            selectedIndex = nextIndex;
        }
        ++nextIndex;
    }
    SendDlgItemMessage(hWnd, IDC_UTF8, CB_SETCURSEL, selectedIndex, 0);
    SendDlgItemMessage(hWnd, IDC_UTF8, CB_SETDROPPEDWIDTH, 240, 0);
}

static void EnsureLanDiscoveryRunning(HWND hWnd, ConnectDialogContext* dlgCtx, pConnectSettings s)
{
    if (!dlgCtx || dlgCtx->lanDiscoveryRunning) {
        return;
    }

    const std::wstring sessionName = GetSessionDisplayNameW(hWnd);
    if (!sessionName.empty() && _wcsicmp(sessionName.c_str(), L"Quick connect") != 0 && _wcsicmp(sessionName.c_str(), L"Szybkie połączenie") != 0) {
        dlgCtx->lanDisplayName = sessionName;
    }

    if (!dlgCtx->lanDiscovery) {
        dlgCtx->lanDiscovery = std::make_unique<lanpair::DiscoveryService>();
    }
    if (dlgCtx->lanPeerId.empty()) {
        dlgCtx->lanPeerId = MakeLanPeerId();
    }
    if (dlgCtx->lanDisplayName.empty()) {
        // Prefer system hostname for Unicode-safe LAN announce, independent of ACP session names.
        wchar_t host[256] = {};
        DWORD hostLen = static_cast<DWORD>(std::size(host));
        if (GetComputerNameW(host, &hostLen) && host[0]) {
            dlgCtx->lanDisplayName = host;
        } else {
            dlgCtx->lanDisplayName = L"SFTPplug";
        }
    }

    lanpair::DiscoveryConfig cfg{};
    cfg.tcpPort = 45846;
    lanpair::PairError err{};
    const bool ok = dlgCtx->lanDiscovery->start(
        cfg,
        dlgCtx->lanPeerId,
        WideToUtf8(dlgCtx->lanDisplayName),
        lanpair::PairRole::Dual,
        [hWnd](const lanpair::PeerAnnouncement& ann) {
            auto* copy = new lanpair::PeerAnnouncement(ann);
            PostMessage(hWnd, WM_APP_LAN_PEER, 0, reinterpret_cast<LPARAM>(copy));
        },
        &err);

    if (ok) {
        dlgCtx->lanDiscoveryRunning = true;
    } else {
        ShowStatus(std::format("LAN discovery start failed: {}", err.message).c_str());
    }
}

static void HandleLanPairAction(HWND hWnd, ConnectDialogContext* dlgCtx, pConnectSettings s)
{
    if (!dlgCtx || !s) {
        return;
    }

    EnsureLanDiscoveryRunning(hWnd, dlgCtx, s);

    std::array<wchar_t, MAX_PATH> passW{};
    GetDlgItemTextW(hWnd, IDC_PASSWORD, passW.data(), static_cast<int>(passW.size() - 1));
    // Empty password is allowed in TOFU mode (trust-on-first-use).

    const int roleIdx = (int)SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0);
    int role = LanRoleComboToValue(roleIdx);

    auto startReceiver = [&](bool allowStopToggle) -> bool {
        if (!dlgCtx->lanServer) {
            dlgCtx->lanServer = std::make_unique<lanpair::PairServer>();
        }
        if (dlgCtx->lanServerRunning) {
            if (allowStopToggle) {
                dlgCtx->lanServer->stop();
                dlgCtx->lanServerRunning = false;
                const std::wstring s = LoadResStringW(IDS_LAN_MSG_RECEIVER_STOPPED);
                ShowStatusW(s.empty() ? L"LAN Pair receiver stopped." : s.c_str());
            } else {
                const std::wstring s = LoadResStringW(IDS_LAN_MSG_RECEIVER_RUNNING);
                ShowStatusW(s.empty() ? L"LAN Pair receiver already running." : s.c_str());
            }
            return true;
        }

        lanpair::PairServerConfig cfg{};
        cfg.port = 45846;
        cfg.peerId = dlgCtx->lanPeerId;
        cfg.displayName = WideToUtf8(dlgCtx->lanDisplayName);
        cfg.role = lanpair::PairRole::Receiver;
        cfg.password = WideToUtf8(passW.data());
        lanpair::PairError err{};
        const std::wstring acceptedTempl = LoadResStringW(IDS_LAN_MSG_ACCEPTED);
        const bool ok = dlgCtx->lanServer->start(
            cfg,
            [acceptedTempl](const lanpair::PairSessionInfo& info) {
                std::wstring peerW(info.remotePeerId.begin(), info.remotePeerId.end());
                std::wstring ipW(info.remoteIp.begin(), info.remoteIp.end());
                const std::wstring msg = acceptedTempl.empty()
                    ? L"LAN Pair accepted: " + peerW + L" (" + ipW + L")"
                    : FormatBracesW(acceptedTempl, { std::wstring_view(peerW), std::wstring_view(ipW) });
                ShowStatusW(msg.c_str());
            },
            &err);
        if (!ok) {
            WindowsUserFeedback tempFeedback(hWnd);
            std::wstring msgTemplW = LoadResStringW(IDS_LAN_ERR_RECEIVER_START);
            if (msgTemplW.empty()) msgTemplW = L"Receiver start failed: {}";
            std::wstring errW(err.message.begin(), err.message.end());
            const std::wstring msgW = FormatBracesW(msgTemplW, { std::wstring_view(errW) });
            const std::wstring titleW = LoadResStringW(IDS_LAN_TITLE);
            tempFeedback.ShowError(WideToUtf8(msgW), titleW.empty() ? "LAN Pair" : WideToUtf8(titleW));
            return false;
        }
        dlgCtx->lanServerRunning = true;
        {
            const std::wstring s = LoadResStringW(IDS_LAN_MSG_RECEIVER_STARTED);
            ShowStatusW(s.empty() ? L"LAN Pair receiver started." : s.c_str());
        }
        return true;
    };

    if (role == 0) {
        startReceiver(false);
        const std::wstring s = LoadResStringW(IDS_LAN_MSG_AUTO_LISTEN);
        ShowStatusW(s.empty() ? L"LAN Pair: listening. Role dialog will appear when peer is detected." : s.c_str());
        return;
    }

    if (role == 1) {
        startReceiver(true);
        return;
    }

    int peerIdx = (int)SendDlgItemMessage(hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0);
    if (peerIdx <= 0 || peerIdx > (int)dlgCtx->lanPeerOrder.size()) {
        WindowsUserFeedback tempFeedback(hWnd);
        const std::wstring msgW = LoadResStringW(IDS_LAN_ERR_SELECT_PEER);
        const std::wstring titleW = LoadResStringW(IDS_LAN_TITLE);
        tempFeedback.ShowError(msgW.empty() ? "Select discovered peer first in Peer list." : WideToUtf8(msgW),
                               titleW.empty() ? "LAN Pair" : WideToUtf8(titleW));
        return;
    }
    const std::string& peerId = dlgCtx->lanPeerOrder[peerIdx - 1];
    auto it = dlgCtx->lanPeers.find(peerId);
    if (it == dlgCtx->lanPeers.end()) {
        WindowsUserFeedback tempFeedback(hWnd);
        const std::wstring msgW = LoadResStringW(IDS_LAN_ERR_PEER_UNAVAILABLE);
        const std::wstring titleW = LoadResStringW(IDS_LAN_TITLE);
        tempFeedback.ShowError(msgW.empty() ? "Selected peer is no longer available." : WideToUtf8(msgW),
                               titleW.empty() ? "LAN Pair" : WideToUtf8(titleW));
        return;
    }

    lanpair::PairClient client;
    lanpair::PairClientConfig cfg{};
    cfg.peerId = dlgCtx->lanPeerId;
    cfg.targetIp = it->second.ip;
    cfg.targetPort = it->second.tcpPort;
    cfg.password = WideToUtf8(passW.data());

    lanpair::PairSessionInfo info{};
    lanpair::PairError err{};
    const bool ok = client.connectAndAuthenticate(cfg, &info, &err);
    if (!ok) {
        WindowsUserFeedback tempFeedback(hWnd);
        std::wstring msgTemplW = LoadResStringW(IDS_LAN_ERR_PAIR_FAILED);
        if (msgTemplW.empty()) msgTemplW = L"Pairing failed: {}";
        std::wstring errW(err.message.begin(), err.message.end());
        const std::wstring msgW = FormatBracesW(msgTemplW, { std::wstring_view(errW) });
        const std::wstring titleW = LoadResStringW(IDS_LAN_TITLE);
        tempFeedback.ShowError(WideToUtf8(msgW), titleW.empty() ? "LAN Pair" : WideToUtf8(titleW));
        return;
    }

    s->lan_pair_peer = peerId;
    WindowsUserFeedback tempFeedback(hWnd);
    std::wstring msgTemplW = LoadResStringW(IDS_LAN_MSG_PAIR_OK);
    if (msgTemplW.empty()) msgTemplW = L"Pairing OK with {} ({})";
    std::wstring peerW(info.remotePeerId.begin(), info.remotePeerId.end());
    std::wstring ipW(info.remoteIp.begin(), info.remoteIp.end());
    const std::wstring msgW = FormatBracesW(msgTemplW, { std::wstring_view(peerW), std::wstring_view(ipW) });
    const std::wstring titleW = LoadResStringW(IDS_LAN_TITLE);
    tempFeedback.ShowMessage(WideToUtf8(msgW), titleW.empty() ? "LAN Pair" : WideToUtf8(titleW));
}

// ============================================================================
// WM_COMMAND handlers - refactored to separate functions
// ============================================================================

static void OnBrowseKeyFileCommand(HWND hWnd, bool isPublicKey)
{
    OPENFILENAME ofn{};
    std::string szFileName(MAX_PATH, '\0');
    
    ofn.lStructSize = sizeof(OPENFILENAME);
    ofn.hwndOwner = hWnd;
    ofn.nFilterIndex = 1;
    ofn.lpstrFile = szFileName.data();
    ofn.nMaxFile = static_cast<DWORD>(szFileName.size());
    
    if (isPublicKey) {
        lstrcpy(szFileName.data(), TEXT("*.pub"));
        ofn.lpstrFilter = TEXT("Public key files (*.pub)\0*.pub\0All Files\0*.*\0");
        ofn.lpstrTitle = TEXT("Select public key file");
    } else {
        lstrcpy(szFileName.data(), TEXT("*.pem"));
        ofn.lpstrFilter = TEXT("Private key files (*.pem;*.ppk)\0*.pem;*.ppk\0OpenSSH private key (*.pem)\0*.pem\0PuTTY private key (*.ppk)\0*.ppk\0All Files\0*.*\0");
        ofn.lpstrTitle = TEXT("Select private key file");
    }
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    
    if (GetOpenFileName(&ofn)) {
        szFileName.resize(strlen(szFileName.data()));
        SetDlgItemText(hWnd, isPublicKey ? IDC_PUBKEY : IDC_PRIVKEY, szFileName.data());
        if (!isPublicKey)
            UpdateKeyControlsForPrivateKey(hWnd);
    }
}

static void OnPhpShellCommand(HWND hWnd, ConnectDialogContext* dlgCtx, pConnectSettings dlgConnectResults)
{
    int transferMode = (int)SendDlgItemMessage(hWnd, IDC_TRANSFERMODE, CB_GETCURSEL, 0, 0);
    if (transferMode == static_cast<int>(sftp::TransferMode::smb_lan)) {
        HandleLanPairAction(hWnd, dlgCtx, dlgConnectResults);
        return;
    }
    if (transferMode == static_cast<int>(sftp::TransferMode::php_agent)) {
        SendDlgItemMessage(hWnd, IDC_TRANSFERMODE, CB_SETCURSEL, (WPARAM)static_cast<int>(sftp::TransferMode::php_shell), 0);
        UpdateScpOnlyDependentControls(hWnd);
        transferMode = static_cast<int>(sftp::TransferMode::php_shell);
    }
    if (transferMode != static_cast<int>(sftp::TransferMode::php_shell)) {
        WindowsUserFeedback tempFeedback(hWnd);
        tempFeedback.ShowMessage("Select Transfer = PHP Shell (HTTP).", "PHP Shell");
        return;
    }
    tConnectSettings shellSettings{};
    shellSettings.sock = INVALID_SOCKET;
    
    // Use std::string instead of std::array for modern C++ style
    std::string server, user, password;
    server.resize(MAX_PATH);
    user.resize(MAX_PATH);
    password.resize(MAX_PATH);
    
    const UINT serverLen = GetDlgItemTextA(hWnd, IDC_CONNECTTO, server.data(), static_cast<int>(server.size()));
    const UINT userLen = GetDlgItemTextA(hWnd, IDC_USERNAME, user.data(), static_cast<int>(user.size()));
    const UINT passLen = GetDlgItemTextA(hWnd, IDC_PASSWORD, password.data(), static_cast<int>(password.size()));
    
    server.resize(serverLen);
    user.resize(userLen);
    password.resize(passLen);
    
    shellSettings.server = std::move(server);
    shellSettings.user = std::move(user);
    shellSettings.password = std::move(password);
    
    std::string authError;
    if (PhpAgentValidateAuth(&shellSettings, authError) != SFTP_OK) {
        std::string localPhpPath;
        std::string pluginDir;
        if (GetPluginDirectoryA(pluginDir)) {
            localPhpPath = pluginDir;
            localPhpPath += "\\sftp.php";
        }
        std::string msg = authError.empty() ? "Wrong credentials for PHP Agent." : authError;
        if (!localPhpPath.empty()) {
            msg += "\n\nPlease copy your plugin script from:\n";
            msg += localPhpPath;
            msg += "\nand upload it to your server URL path.";
        } else {
            msg += "\n\nPlease check URL syntax, file name, and sftp.php deployment path on server.";
        }
        WindowsUserFeedback tempFeedback(hWnd);
        tempFeedback.ShowError(msg, "PHP Shell");
        return;
    }
    ShowPhpShellConsole(hWnd, std::move(shellSettings));
}

static void RebuildSystemAndEncodingCombos(HWND hWnd, ConnectDialogContext* dlgCtx, pConnectSettings s)
{
    const int transferMode = (int)SendDlgItemMessage(hWnd, IDC_TRANSFERMODE, CB_GETCURSEL, 0, 0);
    const bool phpMode = transferMode != static_cast<int>(sftp::TransferMode::ssh_auto);
    const bool smbMode = transferMode == static_cast<int>(sftp::TransferMode::smb_lan);

    SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_RESETCONTENT, 0, 0);
    SendDlgItemMessage(hWnd, IDC_UTF8, CB_RESETCONTENT, 0, 0);

    if (!smbMode && dlgCtx) {
        if (dlgCtx->lanServerRunning || dlgCtx->lanDiscoveryRunning) {
            StopLanPairing(dlgCtx);
        }
    }

    if (smbMode) {
        const std::wstring roleLabel = LoadResStringW(IDS_LAN_ROLE_LABEL);
        const std::wstring peerLabel = LoadResStringW(IDS_LAN_PEER_LABEL);
        const std::wstring roleAuto = LoadResStringW(IDS_LAN_ROLE_AUTO);
        const std::wstring roleReceiver = LoadResStringW(IDS_LAN_ROLE_RECEIVER);
        const std::wstring roleDonor = LoadResStringW(IDS_LAN_ROLE_DONOR);
        SetDialogLabelTextAndRedraw(hWnd, IDC_SYSTEMLABEL, roleLabel.empty() ? L"Pair role:" : roleLabel.c_str());
        SetDialogLabelTextAndRedraw(hWnd, IDC_CODEPAGELABEL, peerLabel.empty() ? L"Peer:" : peerLabel.c_str());
        {
            const std::wstring passLabel = LoadResStringW(IDS_LAN_PASSWORD_LABEL);
            SetDialogLabelTextAndRedraw(hWnd, IDC_PASSLABEL, passLabel.empty() ? L"Pairing password:" : passLabel.c_str());
        }
        {
            std::wstring timeoutLabel, timeoutHint;
            SplitLanTimeoutText(timeoutLabel, timeoutHint);
            if (!timeoutLabel.empty())
                SetDialogLabelTextAndRedraw(hWnd, IDC_LAN_TIMEOUT_LABEL, timeoutLabel.c_str());
            if (!timeoutHint.empty())
                SetDialogLabelTextAndRedraw(hWnd, IDC_LAN_TIMEOUT_HINT, timeoutHint.c_str());
        }
        const std::wstring pairBtn = LoadResStringW(IDS_BUTTON_PAIR);
        SetDlgItemTextW(hWnd, IDC_PHPSHELL, pairBtn.empty() ? L"Pair..." : pairBtn.c_str());

        SendDlgItemMessageW(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)(roleAuto.empty() ? L"Auto" : roleAuto.c_str()));
        SendDlgItemMessageW(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)(roleReceiver.empty() ? L"Receiver" : roleReceiver.c_str()));
        SendDlgItemMessageW(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)(roleDonor.empty() ? L"Donor" : roleDonor.c_str()));
        SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_SETCURSEL, max(0, min(2, s->lan_pair_role)), 0);
        RefreshLanPeerCombo(hWnd, dlgCtx, s->lan_pair_peer);
        EnsureLanDiscoveryRunning(hWnd, dlgCtx, s);
        return;
    }

    if (phpMode) {
        std::string methodLabel;
        std::string chunkLabel;
        GetPhpOptionLabels(methodLabel, chunkLabel);
        SetDialogLabelTextAndRedrawA(hWnd, IDC_SYSTEMLABEL, methodLabel.c_str());
        SetDialogLabelTextAndRedrawA(hWnd, IDC_CODEPAGELABEL, chunkLabel.c_str());
        if (dlgCtx && !dlgCtx->defaultPasswordLabel.empty())
            SetDialogLabelTextAndRedraw(hWnd, IDC_PASSLABEL, dlgCtx->defaultPasswordLabel.c_str());
        const std::wstring shellBtn = LoadResStringW(IDS_BUTTON_SHELL);
        SetDlgItemTextW(hWnd, IDC_PHPSHELL, shellBtn.empty() ? L"Shell..." : shellBtn.c_str());

        SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)"Auto");
        SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)"POST");
        SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)"PUT");
        SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_SETCURSEL, max(0, min(2, s->php_http_mode)), 0);

        SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)"Auto");
        SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)"2 MB");
        SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)"4 MB");
        SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)"8 MB");
        SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)"16 MB");
        SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)"32 MB");
        SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)"64 MB");
        SendDlgItemMessage(hWnd, IDC_UTF8, CB_SETCURSEL, PhpChunkValueToComboIndex(s->php_chunk_mib), 0);
        SendDlgItemMessage(hWnd, IDC_UTF8, CB_SETDROPPEDWIDTH, 120, 0);
        return;
    }

    if (dlgCtx) {
        if (!dlgCtx->defaultSystemLabel.empty())
            SetDialogLabelTextAndRedrawA(hWnd, IDC_SYSTEMLABEL, dlgCtx->defaultSystemLabel.c_str());
        if (!dlgCtx->defaultEncodingLabel.empty())
            SetDialogLabelTextAndRedrawA(hWnd, IDC_CODEPAGELABEL, dlgCtx->defaultEncodingLabel.c_str());
        if (!dlgCtx->defaultPasswordLabel.empty())
            SetDialogLabelTextAndRedraw(hWnd, IDC_PASSLABEL, dlgCtx->defaultPasswordLabel.c_str());
    }
    const std::wstring shellBtn = LoadResStringW(IDS_BUTTON_SHELL);
    SetDlgItemTextW(hWnd, IDC_PHPSHELL, shellBtn.empty() ? L"Shell..." : shellBtn.c_str());

    std::array<char, MAX_PATH> strbuf{};
    LoadString(hinst, IDS_AUTO, strbuf.data(), static_cast<int>(strbuf.size()));
    SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)strbuf.data());
    strlcpy(strbuf.data(), "Windows (CR/LF)", strbuf.size() - 1);
    SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)strbuf.data());
    strlcpy(strbuf.data(), "Unix (LF)", strbuf.size() - 1);
    SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)strbuf.data());
    SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_SETCURSEL, max(0, min(2, s->unixlinebreaks + 1)), 0);

    LoadString(hinst, IDS_AUTO, strbuf.data(), static_cast<int>(strbuf.size()));
    SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)strbuf.data());
    for (int i = IDS_UTF8; i <= IDS_OTHER; i++) {
        LoadString(hinst, i, strbuf.data(), static_cast<int>(strbuf.size()));
        SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)strbuf.data());
    }

    int cbline = 0;
    int cp = s->codepage;
    switch (s->utf8names) {
    case -1: cbline = 0; break;
    case 1: cbline = 1; break;
    default:
        cbline = 0;
        for (int i = 0; i < kCodepageListCount; i++) {
            if (cp == codepagelist[i]) {
                cbline = i;
                break;
            }
        }
        if (cp > 0 && cbline == 0) {
            _itoa_s(cp, strbuf.data(), strbuf.size(), 10);
            SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)strbuf.data());
            cbline = kCodepageListCount - 1;
        }
        break;
    }
    SendDlgItemMessage(hWnd, IDC_UTF8, CB_SETCURSEL, cbline, 0);
    SendDlgItemMessage(hWnd, IDC_UTF8, CB_SETDROPPEDWIDTH, 220, 0);
}

static INT_PTR ShowLocalizedDialogBoxParam(int dialogId, HWND parent, DLGPROC dlgProc, LPARAM dlgParam) noexcept
{
    const LANGID langId = GetConfiguredUiLanguageId();
    if (langId != 0) {
        WORD bestLang = langId;
        HRSRC hrsrc = FindResourceEx(hinst, RT_DIALOG, MAKEINTRESOURCE(dialogId), bestLang);
        if (!hrsrc) {
            // Try a neutral sublanguage.
            bestLang = MAKELANGID(PRIMARYLANGID(langId), SUBLANG_NEUTRAL);
            hrsrc = FindResourceEx(hinst, RT_DIALOG, MAKEINTRESOURCE(dialogId), bestLang);
        }
        if (!hrsrc) {
            // Fallback: enumerate available languages and pick the first match for the primary language.
            bestLang = langId;
            EnumResourceLanguages(hinst, RT_DIALOG, MAKEINTRESOURCE(dialogId),
                [](HMODULE /*h*/, LPCTSTR /*t*/, LPCTSTR /*n*/, WORD l, LONG_PTR p) -> BOOL {
                    WORD* targetLang = reinterpret_cast<WORD*>(p);
                    if (PRIMARYLANGID(l) == PRIMARYLANGID(*targetLang)) {
                        *targetLang = l;
                        return FALSE; // Stop enumerating
                    }
                    return TRUE;
                }, reinterpret_cast<LONG_PTR>(&bestLang));
            
            hrsrc = FindResourceEx(hinst, RT_DIALOG, MAKEINTRESOURCE(dialogId), bestLang);
        }

        if (hrsrc) {
            HGLOBAL hglob = LoadResource(hinst, hrsrc);
            if (hglob) {
                const DLGTEMPLATE* tpl = static_cast<const DLGTEMPLATE*>(LockResource(hglob));
                if (tpl) {
                    return DialogBoxIndirectParam(hinst, tpl, parent, dlgProc, dlgParam);
                }
            }
        }
    }
    return DialogBoxParam(hinst, MAKEINTRESOURCE(dialogId), parent, dlgProc, dlgParam);
}

static ProxyDialogContext* GetProxyDialogContext(HWND hWnd)
{
    return reinterpret_cast<ProxyDialogContext*>(GetWindowLongPtr(hWnd, DWLP_USER));
}

static ConnectDialogContext* GetConnectDialogContext(HWND hWnd)
{
    const auto* dlg = reinterpret_cast<const ConnectionDialog*>(GetWindowLongPtr(hWnd, DWLP_USER));
    return dlg ? dlg->GetContext() : nullptr;
}

static tConnectSettings g_proxyDialogDummyData{};
static std::mutex g_connectDialogMutex;

static bool IsPpkPath(LPCSTR path) noexcept
{
    if (!path || !path[0])
        return false;

    const char* end = path + strlen(path);
    while (end > path && std::isspace(static_cast<unsigned char>(end[-1])))
        --end;
    while (path < end && std::isspace(static_cast<unsigned char>(*path)))
        ++path;
    if (end - path >= 2 && path[0] == '"' && end[-1] == '"') {
        ++path;
        --end;
    }

    const char* dot = nullptr;
    for (const char* p = end; p > path; --p) {
        if (p[-1] == '.') {
            dot = p - 1;
            break;
        }
        if (p[-1] == '\\' || p[-1] == '/')
            break;
    }
    return dot && _stricmp(dot, ".ppk") == 0;
}

// Enable or disable every control in the client-certificate groupbox.
static void EnableCertSection(HWND hWnd, bool enable)
{
    static const int kCertIds[] = {
        IDC_CERTFRAME, IDC_STATICPUB, IDC_STATICPEM,
        IDC_PUBKEY, IDC_PRIVKEY, IDC_LOADPUBKEY, IDC_LOADPRIVKEY,
        IDC_CERTHELP, IDC_CERTHELPPRIV
    };
    for (int id : kCertIds)
        EnableWindow(GetDlgItem(hWnd, id), enable ? TRUE : FALSE);
}

// Single authoritative function: sets the cert section state for the current
// transfer mode, Pageant checkbox, and private-key path.
//   SSH + no Pageant + non-.ppk priv key → all enabled, pub key enabled
//   SSH + no Pageant + .ppk priv key     → all enabled, pub key disabled
//   SSH + Pageant                        → all disabled
//   PHP Agent / PHP Shell / LAN Pair     → all disabled
static void UpdateCertSectionState(HWND hWnd)
{
    const int transferMode = (int)SendDlgItemMessage(hWnd, IDC_TRANSFERMODE, CB_GETCURSEL, 0, 0);
    const bool sshMode = (transferMode == static_cast<int>(sftp::TransferMode::ssh_auto));

    if (!sshMode) {
        EnableCertSection(hWnd, false);
        return;
    }

    const bool useAgent = IsDlgButtonChecked(hWnd, IDC_USEAGENT) == BST_CHECKED;
    EnableCertSection(hWnd, !useAgent);
    if (useAgent) return;

    // Without Pageant: pub key only needed when priv key is NOT a .ppk
    std::array<char, MAX_PATH> privKeyPath{};
    GetDlgItemText(hWnd, IDC_PRIVKEY, privKeyPath.data(), static_cast<int>(privKeyPath.size() - 1));
    const bool pubKeyNeeded = !IsPpkPath(privKeyPath.data());
    EnableWindow(GetDlgItem(hWnd, IDC_STATICPUB), pubKeyNeeded ? TRUE : FALSE);
    EnableWindow(GetDlgItem(hWnd, IDC_PUBKEY),    pubKeyNeeded ? TRUE : FALSE);
    EnableWindow(GetDlgItem(hWnd, IDC_LOADPUBKEY), pubKeyNeeded ? TRUE : FALSE);
}

// Keep thin public wrappers for the header declaration (no external callers remain,
// but they preserve ABI if needed in the future).
void EnableControlsPageant(HWND hWnd, bool enable) { EnableCertSection(hWnd, enable); }
void UpdateKeyControlsForPrivateKey(HWND hWnd)      { UpdateCertSectionState(hWnd); }

void UpdateScpOnlyDependentControls(HWND hWnd)
{
    const int transferMode = (int)SendDlgItemMessage(hWnd, IDC_TRANSFERMODE, CB_GETCURSEL, 0, 0);
    const bool smbMode = transferMode == static_cast<int>(sftp::TransferMode::smb_lan);
    const bool phpMode = transferMode != static_cast<int>(sftp::TransferMode::ssh_auto);
    const bool phpShellMode = transferMode == static_cast<int>(sftp::TransferMode::php_shell);
    const bool scpOnly = IsDlgButtonChecked(hWnd, IDC_SCP_ALL) == BST_CHECKED;
    HWND scpData = GetDlgItem(hWnd, IDC_SCP_DATA);
    HWND shellTransfer = GetDlgItem(hWnd, IDC_SHELLTRANSFER);
    HWND scpAll = GetDlgItem(hWnd, IDC_SCP_ALL);
    HWND systemCombo = GetDlgItem(hWnd, IDC_SYSTEM);
    HWND useAgent = GetDlgItem(hWnd, IDC_USEAGENT);
    HWND compress = GetDlgItem(hWnd, IDC_COMPRESS);
    HWND detailedLog = GetDlgItem(hWnd, IDC_DETAILED_LOG);
    HWND utf8Combo = GetDlgItem(hWnd, IDC_UTF8);
    HWND utf8Help = GetDlgItem(hWnd, IDC_UTF8HELP);
    HWND protoAuto = GetDlgItem(hWnd, IDC_PROTOAUTO);
    HWND protoV4 = GetDlgItem(hWnd, IDC_PROTOV4);
    HWND protoV6 = GetDlgItem(hWnd, IDC_PROTOV6);
    HWND username = GetDlgItem(hWnd, IDC_USERNAME);
    HWND fileMod = GetDlgItem(hWnd, IDC_FILEMOD);
    HWND dirMod = GetDlgItem(hWnd, IDC_DIRMOD);
    HWND certHelp = GetDlgItem(hWnd, IDC_CERTHELP);
    HWND certHelpPriv = GetDlgItem(hWnd, IDC_CERTHELPPRIV);
    HWND phpShellBtn = GetDlgItem(hWnd, IDC_PHPSHELL);
    if (smbMode) {
        CheckDlgButton(hWnd, IDC_SCP_DATA, BST_UNCHECKED);
        CheckDlgButton(hWnd, IDC_SCP_ALL, BST_UNCHECKED);
        CheckDlgButton(hWnd, IDC_SHELLTRANSFER, BST_UNCHECKED);
        CheckDlgButton(hWnd, IDC_USEAGENT, BST_UNCHECKED);
        EnableWindow(scpData, FALSE);
        EnableWindow(shellTransfer, FALSE);
        EnableWindow(scpAll, FALSE);
        EnableWindow(systemCombo, TRUE);
        EnableWindow(useAgent, FALSE);
        EnableWindow(compress, FALSE);
        EnableWindow(detailedLog, FALSE);
        EnableWindow(utf8Combo, TRUE);
        EnableWindow(utf8Help, FALSE);
        EnableWindow(protoAuto, FALSE);
        EnableWindow(protoV4, FALSE);
        EnableWindow(protoV6, FALSE);
        EnableWindow(username, FALSE);
        EnableWindow(fileMod, FALSE);
        EnableWindow(dirMod, FALSE);
        EnableWindow(certHelp, FALSE);
        EnableWindow(certHelpPriv, FALSE);
        EnableWindow(phpShellBtn, TRUE);
        const std::wstring pairBtn = LoadResStringW(IDS_BUTTON_PAIR);
        SetWindowTextW(phpShellBtn, pairBtn.empty() ? L"Pair..." : pairBtn.c_str());
        UpdateCertSectionState(hWnd);
        UpdateMainJumpControlStates(hWnd, false);
        ShowWindow(GetDlgItem(hWnd, IDC_LANPAIR_GROUP),     SW_SHOW);
        ShowWindow(GetDlgItem(hWnd, IDC_LAN_TIMEOUT_LABEL), SW_SHOW);
        ShowWindow(GetDlgItem(hWnd, IDC_LAN_TIMEOUT),       SW_SHOW);
        ShowWindow(GetDlgItem(hWnd, IDC_LAN_TIMEOUT_HINT),  SW_SHOW);
        ShowWindow(GetDlgItem(hWnd, IDC_PERMISSIONS_GROUP), SW_HIDE);
        ShowWindow(GetDlgItem(hWnd, IDC_FILEMOD_LABEL),     SW_HIDE);
        ShowWindow(GetDlgItem(hWnd, IDC_FILEMOD),           SW_HIDE);
        ShowWindow(GetDlgItem(hWnd, IDC_DIRMOD_LABEL),      SW_HIDE);
        ShowWindow(GetDlgItem(hWnd, IDC_DIRMOD),            SW_HIDE);
        return;
    }

    ShowWindow(GetDlgItem(hWnd, IDC_LANPAIR_GROUP),     SW_HIDE);
    ShowWindow(GetDlgItem(hWnd, IDC_LAN_TIMEOUT_LABEL), SW_HIDE);
    ShowWindow(GetDlgItem(hWnd, IDC_LAN_TIMEOUT),       SW_HIDE);
    ShowWindow(GetDlgItem(hWnd, IDC_LAN_TIMEOUT_HINT),  SW_HIDE);
    ShowWindow(GetDlgItem(hWnd, IDC_PERMISSIONS_GROUP), SW_SHOW);
    ShowWindow(GetDlgItem(hWnd, IDC_FILEMOD_LABEL),     SW_SHOW);
    ShowWindow(GetDlgItem(hWnd, IDC_FILEMOD),           SW_SHOW);
    ShowWindow(GetDlgItem(hWnd, IDC_DIRMOD_LABEL),      SW_SHOW);
    ShowWindow(GetDlgItem(hWnd, IDC_DIRMOD),            SW_SHOW);

    if (phpMode) {
        CheckDlgButton(hWnd, IDC_SCP_DATA, BST_UNCHECKED);
        CheckDlgButton(hWnd, IDC_SCP_ALL, BST_UNCHECKED);
        CheckDlgButton(hWnd, IDC_SHELLTRANSFER, BST_UNCHECKED);
        CheckDlgButton(hWnd, IDC_USEAGENT, BST_UNCHECKED);
        EnableWindow(scpData, FALSE);
        EnableWindow(shellTransfer, FALSE);
        EnableWindow(scpAll, FALSE);
        EnableWindow(systemCombo, TRUE);
        EnableWindow(useAgent, FALSE);
        EnableWindow(compress, FALSE);
        EnableWindow(detailedLog, FALSE);
        EnableWindow(utf8Combo, TRUE);
        EnableWindow(utf8Help, FALSE);
        EnableWindow(protoAuto, FALSE);
        EnableWindow(protoV4, FALSE);
        EnableWindow(protoV6, FALSE);
        EnableWindow(username, FALSE);
        EnableWindow(fileMod, FALSE);
        EnableWindow(dirMod, FALSE);
        EnableWindow(certHelp, FALSE);
        EnableWindow(certHelpPriv, FALSE);
        EnableWindow(phpShellBtn, phpShellMode ? TRUE : FALSE);
        const std::wstring shellBtn = LoadResStringW(IDS_BUTTON_SHELL);
        SetWindowTextW(phpShellBtn, shellBtn.empty() ? L"Shell..." : shellBtn.c_str());
        UpdateCertSectionState(hWnd);
        UpdateMainJumpControlStates(hWnd, false);
        return;
    }

    EnableWindow(scpAll, TRUE);
    EnableWindow(systemCombo, TRUE);
    EnableWindow(useAgent, TRUE);
    EnableWindow(compress, TRUE);
    EnableWindow(detailedLog, TRUE);
    EnableWindow(utf8Combo, TRUE);
    EnableWindow(utf8Help, TRUE);
    EnableWindow(protoAuto, TRUE);
    EnableWindow(protoV4, TRUE);
    EnableWindow(protoV6, TRUE);
    EnableWindow(username, TRUE);
    EnableWindow(fileMod, TRUE);
    EnableWindow(dirMod, TRUE);
    EnableWindow(certHelp, TRUE);
    EnableWindow(certHelpPriv, TRUE);
    EnableWindow(phpShellBtn, FALSE);
    const std::wstring shellBtn = LoadResStringW(IDS_BUTTON_SHELL);
    SetWindowTextW(phpShellBtn, shellBtn.empty() ? L"Shell..." : shellBtn.c_str());
    UpdateCertSectionState(hWnd);
    UpdateMainJumpControlStates(hWnd, true);

    EnableWindow(scpData, !scpOnly);
    EnableWindow(shellTransfer, scpOnly);
    if (!scpOnly)
        CheckDlgButton(hWnd, IDC_SHELLTRANSFER, BST_UNCHECKED);
}

static void TrimSessionName(char* s) noexcept
{
    if (!s)
        return;
    size_t len = strlen(s);
    size_t start = 0;
    while (start < len && (s[start] == ' ' || s[start] == '\t'))
        ++start;
    size_t end = len;
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t'))
        --end;
    if (start > 0)
        memmove(s, s + start, end - start);
    s[end - start] = 0;
}

static void FillSessionCombo(HWND hWnd, LPCSTR currentSession)
{
    SendDlgItemMessage(hWnd, IDC_SESSIONCOMBO, CB_RESETCONTENT, 0, 0);
    std::array<char, wdirtypemax> name{};
    SERVERHANDLE hdl = FindFirstServer(name.data(), name.size() - 1);
    while (hdl) {
        if (_stricmp(name.data(), s_quickconnect) != 0)
            SendDlgItemMessage(hWnd, IDC_SESSIONCOMBO, CB_ADDSTRING, 0, (LPARAM)name.data());
        hdl = FindNextServer(hdl, name.data(), name.size() - 1);
    }
    if (currentSession && currentSession[0])
        SetDlgItemText(hWnd, IDC_SESSIONCOMBO, currentSession);
    else
        SetDlgItemText(hWnd, IDC_SESSIONCOMBO, "");
}

static void ApplyLoadedSessionToDialog(HWND hWnd, pConnectSettings s, LPCSTR iniFileName)
{
    if (!s || !iniFileName)
        return;
    ConnectDialogContext* dlgCtx = GetConnectDialogContext(hWnd);
    SetDlgItemText(hWnd, IDC_CONNECTTO, s->server);
    SetDlgItemText(hWnd, IDC_USERNAME, s->user);
    SetDlgItemText(hWnd, IDC_PUBKEY, s->pubkeyfile);
    SetDlgItemText(hWnd, IDC_PRIVKEY, s->privkeyfile);
    SetDlgItemText(hWnd, IDC_PASSWORD, s->password);

    switch (s->protocoltype) {
    case 1:  CheckRadioButton(hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOV4); break;
    case 2:  CheckRadioButton(hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOV6); break;
    default: CheckRadioButton(hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOAUTO); break;
    }

    CheckDlgButton(hWnd, IDC_USEAGENT, s->useagent ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hWnd, IDC_DETAILED_LOG, s->detailedlog ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hWnd, IDC_COMPRESS, s->compressed ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hWnd, IDC_SCP_DATA, s->scpfordata ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hWnd, IDC_SCP_ALL, s->scponly ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hWnd, IDC_SHELLTRANSFER, (s->shell_transfer_dd && s->shell_transfer_force) ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hWnd, IDC_JUMP_ENABLE, s->use_jump_host ? BST_CHECKED : BST_UNCHECKED);
    SendDlgItemMessage(hWnd, IDC_TRANSFERMODE, CB_SETCURSEL, max(0, min(3, s->transfermode)), 0);
    RebuildSystemAndEncodingCombos(hWnd, dlgCtx, s);
    if (dlgCtx)
        dlgCtx->lastTransferMode = max(0, min(3, s->transfermode));
    UpdateScpOnlyDependentControls(hWnd);
    SetLanTimeoutMinutes(hWnd, s->lan_pair_timeout_min);

    std::array<char, 32> modbuf{};
    _itoa_s(s->filemod, modbuf.data(), modbuf.size(), 8);
    SetDlgItemText(hWnd, IDC_FILEMOD, modbuf.data());
    _itoa_s(s->dirmod, modbuf.data(), modbuf.size(), 8);
    SetDlgItemText(hWnd, IDC_DIRMOD, modbuf.data());

    fillProxyCombobox(hWnd, s->proxynr, iniFileName);
}

INT_PTR WINAPI ProxyDlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
    RECT rt1, rt2;
    int w, h, DlgWidth, DlgHeight, NewPosX, NewPosY;
    ProxyDialogContext* ctx = GetProxyDialogContext(hWnd);
    tConnectSettings& ConnectData = ctx ? ctx->connectData : g_proxyDialogDummyData;

    switch (Message) {
    case WM_INITDIALOG: {
        ctx = reinterpret_cast<ProxyDialogContext*>(lParam);
        if (!ctx || !ctx->iniFileName) {
            EndDialog(hWnd, IDCANCEL);
            return 1;
        }
        SetWindowLongPtr(hWnd, DWLP_USER, lParam);
        LocalizeDlgControls(hWnd, IDS_PROXY_DLG_CAPTION, {
            { IDC_PROXY_GROUP,      IDS_PROXY_DLG_GROUP },
            { IDC_PROXY_LABEL_HOST, IDS_PROXY_DLG_HOST  },
            { IDC_PROXY_LABEL_USER, IDS_PROXY_DLG_USER  },
            { IDC_PROXY_LABEL_PASS, IDS_PROXY_DLG_PASS  },
            { IDC_CRYPTPASS,        IDS_DLG_CRYPTPASS   },
            { IDC_EDITPASS,         IDS_DLG_CHANGEPASS  },
        });
        LoadProxySettingsFromNr(ctx->proxynr, &ctx->connectData, ctx->iniFileName);

        switch (ConnectData.proxytype) {
        case sftp::Proxy::http:   ctx->focusset = IDC_OTHERPROXY; break;
        case sftp::Proxy::socks4: ctx->focusset = IDC_SOCKS4APROXY; break;
        case sftp::Proxy::socks5: ctx->focusset = IDC_SOCKS5PROXY; break;
        default: ctx->focusset = IDC_NOPROXY;
        }
        CheckRadioButton(hWnd, IDC_NOPROXY, IDC_SOCKS5PROXY, ctx->focusset);

        BOOL showProxySettings = (ConnectData.proxytype != sftp::Proxy::notused);
        EnableWindow(GetDlgItem(hWnd, IDC_PROXYSERVER), showProxySettings);
        EnableWindow(GetDlgItem(hWnd, IDC_PROXYUSERNAME), showProxySettings);
        EnableWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), showProxySettings);
        SetDlgItemText(hWnd, IDC_PROXYSERVER, ConnectData.proxyserver);
        SetDlgItemText(hWnd, IDC_PROXYUSERNAME, ConnectData.proxyuser);

        if (ConnectData.proxypassword == "\001" && CryptProc) {
            std::array<char, 64> proxyentry{};
            if (ctx->proxynr > 1)
                strlcpy(proxyentry.data(), std::format("proxy{}", ctx->proxynr), proxyentry.size() - 1);
            else
                strlcpy(proxyentry.data(), "proxy", proxyentry.size()-1);

            strlcat(proxyentry.data(), "$$pass", proxyentry.size()-1);

            std::array<char, MAX_PATH> proxyPassword{};
            if (CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD_NO_UI, proxyentry.data(), proxyPassword.data(), static_cast<int>(proxyPassword.size() - 1)) == FS_FILE_OK) {
                ConnectData.proxypassword = proxyPassword.data();
                SetDlgItemText(hWnd, IDC_PROXYPASSWORD, ConnectData.proxypassword);
                CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
            } else {
                ShowWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_EDITPASS), SW_SHOW);
            }
        } else {
            SetDlgItemText(hWnd, IDC_PROXYPASSWORD, ConnectData.proxypassword);
            if (!CryptProc)
                EnableWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), false);
            else if (ConnectData.proxypassword.empty() && CryptCheckPass)
                CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
        }
        

        // Center the dialog relative to its parent window.
        if (GetWindowRect(hWnd, &rt1) && GetWindowRect(GetParent(hWnd), &rt2)) {
            w = rt2.right  - rt2.left;
            h = rt2.bottom - rt2.top;
            DlgWidth   = rt1.right - rt1.left;
            DlgHeight  = rt1.bottom - rt1.top;
            NewPosX    = rt2.left + (w - DlgWidth)/2;
            NewPosY    = rt2.top + (h - DlgHeight)/2;
            SetWindowPos(hWnd, 0, NewPosX, NewPosY, 0, 0, SWP_NOZORDER | SWP_NOSIZE);
        }
        return 1;
    }
    case WM_SHOWWINDOW: {
        if (ctx && ctx->focusset)
            SetFocus(GetDlgItem(hWnd, ctx->focusset));
        break;
    }
    case WM_COMMAND: {
        if (!ctx)
            break;
        switch (LOWORD(wParam)) {
        case IDOK: {
            ConnectData.proxytype = sftp::Proxy::notused;
            if (IsDlgButtonChecked(hWnd, IDC_OTHERPROXY))
                ConnectData.proxytype = sftp::Proxy::http;
            else if (IsDlgButtonChecked(hWnd, IDC_SOCKS4APROXY))
                ConnectData.proxytype = sftp::Proxy::socks4;
            else if (IsDlgButtonChecked(hWnd, IDC_SOCKS5PROXY))
                ConnectData.proxytype = sftp::Proxy::socks5;

            GetDlgItemText(hWnd, IDC_PROXYSERVER, ConnectData.proxyserver);
            GetDlgItemText(hWnd, IDC_PROXYUSERNAME, ConnectData.proxyuser);
            GetDlgItemText(hWnd, IDC_PROXYPASSWORD, ConnectData.proxypassword);

            std::array<char, 64> proxyentry{};
            if (ctx->proxynr > 1)
                strlcpy(proxyentry.data(), std::format("proxy{}", ctx->proxynr), proxyentry.size() - 1);
            else
                strlcpy(proxyentry.data(), "proxy", proxyentry.size()-1);

            WritePrivateProfileString(proxyentry.data(), "proxyserver", ConnectData.proxyserver, ctx->iniFileName);
            WritePrivateProfileString(proxyentry.data(), "proxyuser", ConnectData.proxyuser, ctx->iniFileName);
            std::array<char, 64> buf{};
            _itoa_s((int)ConnectData.proxytype, buf.data(), buf.size(), 10);
            LPSTR proxy_str = (ConnectData.proxytype == sftp::Proxy::notused) ? nullptr : buf.data();
            WritePrivateProfileString(proxyentry.data(), "proxytype", proxy_str, ctx->iniFileName);

            std::array<char, 1024> szEncryptedPassword{};
            if (!IsWindowVisible(GetDlgItem(hWnd, IDC_EDITPASS))) {  // Edit button is hidden.
                if (ConnectData.proxypassword.empty()) {
                    WritePrivateProfileString(proxyentry.data(), "proxypassword", nullptr, ctx->iniFileName);
                } else if (CryptProc && IsDlgButtonChecked(hWnd, IDC_CRYPTPASS)) {
                    std::array<char, 64> proxyentry2{};
                    strlcpy(proxyentry2.data(), proxyentry.data(), proxyentry2.size()-1);
                    strlcat(proxyentry2.data(), "$$pass", proxyentry2.size()-1);
                    bool ok = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD, proxyentry2.data(), const_cast<char*>(ConnectData.proxypassword.c_str()), 0) == FS_FILE_OK;
                    WritePrivateProfileString(proxyentry.data(), "proxypassword", ok? "!" : nullptr, ctx->iniFileName);
                    CryptCheckPass = true;
                } else {
                    EncryptString(ConnectData.proxypassword.c_str(), szEncryptedPassword.data(), static_cast<UINT>(szEncryptedPassword.size()));
                    WritePrivateProfileString(proxyentry.data(), "proxypassword", szEncryptedPassword.data(), ctx->iniFileName);
                }
            }
            
            EndDialog(hWnd, IDOK);
            return 1;
        }
        case IDCANCEL:
        {
            EndDialog(hWnd, IDCANCEL);
            return 1;
        }
        case IDC_OTHERPROXY:
        case IDC_SOCKS4APROXY:
        case IDC_SOCKS5PROXY:
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYSERVER), true);
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYUSERNAME), true);
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), true);
            SetFocus(GetDlgItem(hWnd, IDC_PROXYSERVER));
            break;
        case IDC_NOPROXY:
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYSERVER), false);
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYUSERNAME), false);
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), false);
            break;
        case IDC_PROXYHELP:
        {
            std::array<WCHAR, 100> szCaption{};
            LoadStringW(hinst, IDS_HELP_CAPTION, szCaption.data(), static_cast<int>(szCaption.size()));
            std::array<WCHAR, 1024> szBuffer{};
            LoadStringW(hinst, IDS_HELP_PROXY, szBuffer.data(), static_cast<int>(szBuffer.size()));
            if (RequestProcW)
                RequestProcW(PluginNumber, RT_MsgOK, szCaption.data(), szBuffer.data(), nullptr, 0);
            else
                MessageBoxW(hWnd, szBuffer.data(), szCaption.data(), MB_OK | MB_ICONINFORMATION);
            break;
        }
        case IDC_EDITPASS:
        {   
            bool doshow = true;
            int err;
            std::array<char, 64> proxyentry{};
            if (ctx->proxynr > 1)
                strlcpy(proxyentry.data(), std::format("proxy{}", ctx->proxynr), proxyentry.size() - 1);
            else
                strlcpy(proxyentry.data(), "proxy", proxyentry.size()-1);

            strlcat(proxyentry.data(), "$$pass", proxyentry.size()-1);

            std::array<char, MAX_PATH> proxyPassword{};
            err = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, proxyentry.data(), proxyPassword.data(), static_cast<int>(proxyPassword.size() - 1));
            if (err == FS_FILE_OK) {
                ConnectData.proxypassword = proxyPassword.data();
                SetDlgItemText(hWnd, IDC_PROXYPASSWORD, ConnectData.proxypassword);
            } else if (err == FS_FILE_READERROR) {         // No password stored.
                SetDlgItemText(hWnd, IDC_PROXYPASSWORD, "");
            } else {
                doshow = false;
            }
            if (doshow) {
                ShowWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_EDITPASS), SW_HIDE);
                if (ctx->ownerConnectResults && !ctx->ownerConnectResults->password.empty())
                    CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
            }
        }
        } /* switch */
    }
    } /* switch */
    return 0;
}

// Returns the real proxy number stored in CB_SETITEMDATA for the currently
// selected combo item (0 = no proxy, >0 = proxy slot number).
static int GetProxyNrFromCombo(HWND hWnd)
{
    const int idx = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
    if (idx < 0) return 0;
    const LRESULT data = SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETITEMDATA, idx, 0);
    return (data == CB_ERR || data < 0) ? 0 : static_cast<int>(data);
}

void fillProxyCombobox(HWND hWnd, int defproxynr, LPCSTR iniFileName)
{
    SendDlgItemMessageW(hWnd, IDC_PROXYCOMBO, CB_RESETCONTENT, 0, 0);
    std::array<WCHAR, 100> noproxy{};
    std::array<WCHAR, 100> addproxy{};
    std::array<WCHAR, 100> httpproxy{};
    std::array<WCHAR, 256> buf{};
    LoadStringW(hinst, IDS_NO_PROXY,   noproxy.data(),   static_cast<int>(noproxy.size()));
    LoadStringW(hinst, IDS_HTTP_PROXY, httpproxy.data(), static_cast<int>(httpproxy.size()));
    LoadStringW(hinst, IDS_ADD_PROXY,  addproxy.data(),  static_cast<int>(addproxy.size()));

    // Item 0: "No proxy" — itemdata=0
    LRESULT i0 = SendDlgItemMessageW(hWnd, IDC_PROXYCOMBO, CB_ADDSTRING, 0, (LPARAM)noproxy.data());
    SendDlgItemMessageW(hWnd, IDC_PROXYCOMBO, CB_SETITEMDATA, i0, 0);

    tConnectSettings connectData;
    int proxynr = 1;
    while (LoadProxySettingsFromNr(proxynr, &connectData, iniFileName)) {
        // Skip "notused" slots — they appear as duplicate "No proxy" and confuse users.
        if (connectData.proxytype != sftp::Proxy::notused) {
            wcslcpy(buf.data(), std::format(L"{}: ", proxynr).c_str(), buf.size() - 1);
            switch (connectData.proxytype) {
            case sftp::Proxy::http:
                wcslcat(buf.data(), httpproxy.data(), buf.size()-1);
                break;
            case sftp::Proxy::socks4:
                wcslcat(buf.data(), L"SOCKS4a: ", buf.size()-1);
                break;
            case sftp::Proxy::socks5:
                wcslcat(buf.data(), L"SOCKS5: ", buf.size()-1);
                break;
            default:
                break;
            }
            std::array<WCHAR, 256> proxyW{};
            awlcopy(proxyW.data(), connectData.proxyserver.c_str(), proxyW.size() - 1);
            wcslcat(buf.data(), proxyW.data(), buf.size()-1);
            LRESULT iN = SendDlgItemMessageW(hWnd, IDC_PROXYCOMBO, CB_ADDSTRING, 0, (LPARAM)buf.data());
            SendDlgItemMessageW(hWnd, IDC_PROXYCOMBO, CB_SETITEMDATA, iN, proxynr);
        }
        proxynr++;
    }

    // Last item: "Add new proxy" — itemdata=-1 (sentinel, not a real proxy slot)
    LRESULT iLast = SendDlgItemMessageW(hWnd, IDC_PROXYCOMBO, CB_ADDSTRING, 0, (LPARAM)addproxy.data());
    SendDlgItemMessageW(hWnd, IDC_PROXYCOMBO, CB_SETITEMDATA, iLast, -1);

    // Select the item whose stored proxynr matches defproxynr (fall back to 0).
    const int count = (int)SendDlgItemMessageW(hWnd, IDC_PROXYCOMBO, CB_GETCOUNT, 0, 0);
    bool found = false;
    for (int i = 0; i < count; ++i) {
        if ((int)SendDlgItemMessageW(hWnd, IDC_PROXYCOMBO, CB_GETITEMDATA, i, 0) == defproxynr) {
            SendDlgItemMessageW(hWnd, IDC_PROXYCOMBO, CB_SETCURSEL, i, 0);
            found = true;
            break;
        }
    }
    if (!found)
        SendDlgItemMessageW(hWnd, IDC_PROXYCOMBO, CB_SETCURSEL, 0, 0);
}

bool DeleteLastProxy(int proxynrtodelete, LPCSTR ServerToSkip, LPCSTR iniFileName, LPSTR AppendToList, size_t maxlen)
{
    if (proxynrtodelete <= 1)
        return false;

    bool CanDelete = true;
    bool AlreadyAdded = false;
    std::array<char, wdirtypemax> name{};
    SERVERHANDLE hdl = FindFirstServer(name.data(), name.size() - 1);
    while (hdl) {
        if (_stricmp(name.data(), ServerToSkip) != 0) {
            int proxynr = GetPrivateProfileInt(name.data(), "proxynr", 0, iniFileName);
            if (proxynr == proxynrtodelete) {
                CanDelete = false;
                if (AlreadyAdded)
                    strlcat(AppendToList, ", ", maxlen);
                strlcat(AppendToList, name.data(), maxlen);
                AlreadyAdded = true;
            }
        }
        hdl = FindNextServer(hdl, name.data(), name.size() - 1);
    }
    if (CanDelete) {
        std::array<char, 64> proxyentry{};
        strlcpy(proxyentry.data(), std::format("proxy{}", proxynrtodelete), proxyentry.size() - 1);
        WritePrivateProfileString(proxyentry.data(), nullptr, nullptr, iniFileName);
    }
    return CanDelete;
}

static void ShowHelpDialog(HWND hWnd, UINT bodyStringId)
{
    std::array<WCHAR, 100> szCaption{};
    LoadStringW(hinst, IDS_HELP_CAPTION, szCaption.data(), static_cast<int>(szCaption.size()));
    std::array<WCHAR, 1024> szBuffer{};
    LoadStringW(hinst, bodyStringId, szBuffer.data(), static_cast<int>(szBuffer.size()));
    if (RequestProcW)
        RequestProcW(PluginNumber, RT_MsgOK, szCaption.data(), szBuffer.data(), nullptr, 0);
    else
        MessageBoxW(hWnd, szBuffer.data(), szCaption.data(), MB_OK | MB_ICONINFORMATION);
}

// ============================================================================
// WM_COMMAND handlers - additional refactored functions
// ============================================================================

static void OnDeleteLastProxyCommand(HWND hWnd, pConnectSettings dlgConnectResults, LPCSTR dlgIniFileName)
{
    // Get the proxynr stored in the last real proxy item (before "Add new proxy").
    const int count = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCOUNT, 0, 0);
    const int lastRealIdx = count - 2;
    int proxynr = (lastRealIdx > 0)
        ? (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETITEMDATA, lastRealIdx, 0)
        : 0;
    if (proxynr >= 2) {
        std::string errorstr(1024, '\0');
        LoadStringA(hinst, IDS_ERROR_INUSE, errorstr.data(), static_cast<int>(errorstr.size()));
        errorstr.resize(strlen(errorstr.data()));
        errorstr += "\n";

        if (DeleteLastProxy(proxynr, dlgConnectResults->DisplayName.c_str(), dlgIniFileName, errorstr.data(), errorstr.size() - 1)) {
            int proxynrSel = GetProxyNrFromCombo(hWnd);
            fillProxyCombobox(hWnd, proxynrSel, dlgIniFileName);
        } else {
            std::wstring werrorstr(1024, L'\0');
            const int len = MultiByteToWideChar(CP_ACP, 0, errorstr.data(), -1, werrorstr.data(), static_cast<int>(werrorstr.size()));
            werrorstr.resize(len > 0 ? len - 1 : 0);
            
            if (RequestProcW)
                RequestProcW(PluginNumber, RT_MsgOK, L"SFTP", werrorstr.data(), nullptr, 0);
            else
                MessageBoxW(hWnd, werrorstr.data(), L"SFTP", MB_OK | MB_ICONSTOP);
        }
    } else {
        MessageBeep(MB_ICONSTOP);
    }
}

static void OnImportSessionsCommand(HWND hWnd, pConnectSettings dlgConnectResults, ConnectDialogContext* dlgCtx)
{
    pConnectSettings importApplyTarget = dlgConnectResults->dialogforconnection ? nullptr : dlgConnectResults;
    std::string importedSession(wdirtypemax, '\0');
    
    int importedCount = sftp::ShowExternalSessionImportMenu(
        hWnd, dlgCtx->iniFileName, importApplyTarget, importedSession.data(), static_cast<int>(importedSession.size()));
    
    LoadServersFromIni(dlgCtx->iniFileName, s_quickconnect);
    
    std::string currentSession(wdirtypemax, '\0');
    const UINT curLen = GetDlgItemTextA(hWnd, IDC_SESSIONCOMBO, currentSession.data(), static_cast<int>(currentSession.size()));
    currentSession.resize(curLen);
    
    if (importedCount > 0 && importedSession[0]) {
        importedSession.resize(strlen(importedSession.data()));
        FillSessionCombo(hWnd, importedSession.data());
        tConnectSettings loaded{};
        if (LoadServerSettings(importedSession.data(), &loaded, dlgCtx->iniFileName))
            ApplyLoadedSessionToDialog(hWnd, &loaded, dlgCtx->iniFileName);
    } else {
        FillSessionCombo(hWnd, currentSession.data());
    }
    fillProxyCombobox(hWnd, dlgConnectResults->proxynr, dlgCtx->iniFileName);
}

static void OnSessionChangedCommand(HWND hWnd, ConnectDialogContext* dlgCtx, LPCSTR dlgIniFileName)
{
    std::string sessionName(wdirtypemax, '\0');
    const UINT len = GetDlgItemTextA(hWnd, IDC_SESSIONCOMBO, sessionName.data(), static_cast<int>(sessionName.size()));
    sessionName.resize(len);
    
    TrimSessionName(sessionName.data());
    
    if (sessionName[0] && _stricmp(sessionName.data(), s_quickconnect) != 0) {
        tConnectSettings loaded{};
        if (LoadServerSettings(sessionName.data(), &loaded, dlgIniFileName))
            ApplyLoadedSessionToDialog(hWnd, &loaded, dlgIniFileName);
    }
}

static void OnProxyButtonCommand(HWND hWnd, pConnectSettings dlgConnectResults, ConnectDialogContext* dlgCtx)
{
    int proxynr = GetProxyNrFromCombo(hWnd);
    if (proxynr > 0) {
        ProxyDialogContext proxyCtx;
        proxyCtx.proxynr = proxynr;
        proxyCtx.ownerConnectResults = dlgConnectResults;
        proxyCtx.iniFileName = dlgCtx->iniFileName;
        
        if (IDOK == ShowLocalizedDialogBoxParam(IDD_PROXY, GetActiveWindow(), ProxyDlgProc, (LPARAM)&proxyCtx))
            fillProxyCombobox(hWnd, proxynr, dlgCtx->iniFileName);
    }
}

static void OnJumpButtonCommand(HWND hWnd, pConnectSettings dlgConnectResults, LPCSTR dlgDisplayName, LPCSTR dlgIniFileName)
{
    if (!dlgConnectResults) return;
    
    JumpDialogContext jumpCtx;
    jumpCtx.cs = dlgConnectResults;
    jumpCtx.iniFileName = dlgIniFileName;
    jumpCtx.hasCryptProc = (CryptProc != nullptr);
    
    if (dlgDisplayName)
        dlgConnectResults->DisplayName = dlgDisplayName;
    
    ShowLocalizedDialogBoxParam(IDD_JUMPHOST, hWnd, JumpHostDlgProc, (LPARAM)&jumpCtx);
    
    CheckDlgButton(hWnd, IDC_JUMP_ENABLE,
        dlgConnectResults->use_jump_host ? BST_CHECKED : BST_UNCHECKED);
}

// ============================================================================
// SR: 09.07.2005 — ConnectDlgProc now delegates to ConnectionDialog class
// ============================================================================

INT_PTR WINAPI ConnectDlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
    auto* dlg = reinterpret_cast<ConnectionDialog*>(GetWindowLongPtr(hWnd, DWLP_USER));

    switch (Message) {
    case WM_INITDIALOG: {
        auto* dlgCtx = reinterpret_cast<ConnectDialogContext*>(lParam);
        if (!dlgCtx || !dlgCtx->connectResults || !dlgCtx->displayName || !dlgCtx->iniFileName) {
            EndDialog(hWnd, IDCANCEL);
            return 1;
        }
        dlg = new ConnectionDialog(hWnd, dlgCtx);
        SetWindowLongPtr(hWnd, DWLP_USER, reinterpret_cast<LONG_PTR>(dlg));
        return dlg->HandleMessage(Message, wParam, lParam);
    }
    case WM_DESTROY: {
        const INT_PTR result = dlg ? dlg->HandleMessage(Message, wParam, lParam) : 0;
        delete dlg;
        SetWindowLongPtr(hWnd, DWLP_USER, 0);
        return result;
    }
    default:
        return dlg ? dlg->HandleMessage(Message, wParam, lParam) : 0;
    }
}

// ============================================================================
// ConnectionDialog method implementations
// ============================================================================

ConnectionDialog::ConnectionDialog(HWND hWnd, ConnectDialogContext* ctx)
    : m_hWnd(hWnd)
    , m_ctx(ctx)
    , m_settings(ctx ? ctx->connectResults : nullptr)
    , m_initialized(false)
{
}

INT_PTR ConnectionDialog::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG:   return OnInitDialog(lParam);
    case WM_SHOWWINDOW:   return OnShowWindow(LOWORD(wParam));
    case WM_COMMAND:      return OnCommand(wParam, lParam);
    case WM_APP_LAN_PEER: return OnLanPeerMessage(wParam, lParam);
    case WM_DESTROY:      OnDestroy(); return 0;
    }
    return 0;
}

INT_PTR ConnectionDialog::OnInitDialog(LPARAM /*lParam*/)
{
    // ConnectDlgProc already validated dlgCtx and stored the ConnectionDialog*
    // in DWLP_USER before routing here, so no null-check or SetWindowLongPtr needed.
    LPCSTR dlgDisplayName = m_ctx->displayName;
    LPCSTR dlgIniFileName = m_ctx->iniFileName;
    int* dlgFocusset = &m_ctx->focusset;

    LocalizeDlgControls(m_hWnd, IDS_DLG_CAPTION, {
        { IDC_LABEL_CONNECTTO,    IDS_DLG_CONNECTTO         },
        { IDC_LABEL_USERNAME,     IDS_DLG_USERNAME          },
        { IDC_PASSLABEL,          IDS_JUMP_DLG_PASS         },
        { IDC_USEAGENT,           IDS_DLG_USEAGENT          },
        { IDC_EDITPASS,           IDS_DLG_CHANGEPASS        },
        { IDC_CRYPTPASS,          IDS_DLG_CRYPTPASS         },
        { IDC_LABEL_CERTGROUP,    IDS_DLG_CERTGROUP         },
        { IDC_STATICPUB,          IDS_DLG_PUBKEY            },
        { IDC_STATICPEM,          IDS_DLG_PRIVKEY           },
        { IDC_COMPRESS,           IDS_DLG_COMPRESS          },
        { IDC_DETAILED_LOG,       IDS_DLG_DETAILED_LOG      },
        { IDC_SHELLTRANSFER,      IDS_DLG_SHELLTRANSFER     },
        { IDC_SCP_DATA,           IDS_DLG_SCP_DATA          },
        { IDC_SCP_ALL,            IDS_DLG_SCP_ALL           },
        { IDC_LABEL_TRANSFER,     IDS_DLG_TRANSFER          },
        { IDC_CODEPAGELABEL,      IDS_DLG_ENCODING          },
        { IDC_PERMISSIONS_GROUP,  IDS_DLG_PERMISSIONS_GROUP },
        { IDC_FILEMOD_LABEL,      IDS_DLG_FILEMOD           },
        { IDC_DIRMOD_LABEL,       IDS_DLG_DIRMOD            },
        { IDC_LABEL_SESSION,      IDS_DLG_SESSION           },
        { IDC_LABEL_JUMPHOST_GRP, IDS_DLG_JUMPHOST_GRP      },
        { IDC_JUMP_ENABLE,        IDS_DLG_USE_JUMPHOST      },
        { IDC_LABEL_PROXY_SETTINGS, IDS_DLG_PROXY_SETTINGS  },
        { IDC_DELETELAST,         IDS_DLG_DELETELAST        },
        { IDC_IMPORTSESSIONS,     IDS_DLG_IMPORT            },
    });

    ArrangeInlineRow(m_hWnd, IDC_LABEL_JUMPHOST_GRP, IDC_JUMP_ENABLE, IDC_JUMP_BUTTON);

    if (m_ctx->lanPeerId.empty())
        m_ctx->lanPeerId = MakeLanPeerId();
    if (m_ctx->lanDisplayName.empty()) {
        std::array<wchar_t, MAX_COMPUTERNAME_LENGTH + 1> host{};
        DWORD hostLen = static_cast<DWORD>(host.size() - 1);
        if (GetComputerNameW(host.data(), &hostLen) && host[0])
            m_ctx->lanDisplayName = host.data();
        else
            m_ctx->lanDisplayName = L"SFTPplug";
    }

    std::array<char, 32> modbuf{};
    RECT rt1, rt2;
    int w, h, DlgWidth, DlgHeight, NewPosX, NewPosY;

    SendDlgItemMessage(m_hWnd, IDC_DEFAULTCOMBO, CB_SETCURSEL, 0, 0);
    LoadServersFromIni(dlgIniFileName, s_quickconnect);
    FillSessionCombo(m_hWnd, strcmp(dlgDisplayName, s_quickconnect) != 0 ? dlgDisplayName : "");
    serverfieldchangedbyuser = false;

    SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_ADDSTRING, 0, (LPARAM)"SSH (SFTP/SCP)");
    SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_ADDSTRING, 0, (LPARAM)"PHP Agent (HTTP)");
    SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_ADDSTRING, 0, (LPARAM)"PHP Shell (HTTP)");
    {
        const std::wstring lanMode = LoadResStringW(IDS_TRANSFERMODE_LANPAIR);
        SendDlgItemMessageW(m_hWnd, IDC_TRANSFERMODE, CB_ADDSTRING, 0,
            (LPARAM)(lanMode.empty() ? L"LAN Pair (SMB-like)" : lanMode.c_str()));
    }

    {
        std::array<char, 128> labelBuf{};
        GetDlgItemText(m_hWnd, IDC_SYSTEMLABEL, labelBuf.data(), static_cast<int>(labelBuf.size() - 1));
        m_ctx->defaultSystemLabel = labelBuf.data();
        labelBuf.fill('\0');
        GetDlgItemText(m_hWnd, IDC_CODEPAGELABEL, labelBuf.data(), static_cast<int>(labelBuf.size() - 1));
        m_ctx->defaultEncodingLabel = labelBuf.data();
    }
    {
        std::array<WCHAR, 128> wlabelBuf{};
        GetDlgItemTextW(m_hWnd, IDC_PASSLABEL, wlabelBuf.data(), static_cast<int>(wlabelBuf.size() - 1));
        m_ctx->defaultPasswordLabel = wlabelBuf.data();
    }

    if (strcmp(dlgDisplayName, s_quickconnect) != 0) {
        SetDlgItemText(m_hWnd, IDC_CONNECTTO, m_settings->server);
        if (!m_settings->server.empty())
            serverfieldchangedbyuser = true;

        switch (m_settings->protocoltype) {
        case 1:  CheckRadioButton(m_hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOV4); break;
        case 2:  CheckRadioButton(m_hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOV6); break;
        default: CheckRadioButton(m_hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOAUTO); break;
        }

        SetDlgItemText(m_hWnd, IDC_USERNAME, m_settings->user);

        if (m_settings->useagent)
            CheckDlgButton(m_hWnd, IDC_USEAGENT, BST_CHECKED);
        if (m_settings->detailedlog)
            CheckDlgButton(m_hWnd, IDC_DETAILED_LOG, BST_CHECKED);
        if (m_settings->compressed)
            CheckDlgButton(m_hWnd, IDC_COMPRESS, BST_CHECKED);
        if (m_settings->scpfordata)
            CheckDlgButton(m_hWnd, IDC_SCP_DATA, BST_CHECKED);
        if (m_settings->scponly)
            CheckDlgButton(m_hWnd, IDC_SCP_ALL, BST_CHECKED);
        if (m_settings->shell_transfer_dd && m_settings->shell_transfer_force)
            CheckDlgButton(m_hWnd, IDC_SHELLTRANSFER, BST_CHECKED);
        if (m_settings->use_jump_host)
            CheckDlgButton(m_hWnd, IDC_JUMP_ENABLE, BST_CHECKED);

        SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_SETCURSEL, max(0, min(3, m_settings->transfermode)), 0);

        if (m_settings->password == "\001" && CryptProc) {
            std::array<char, MAX_PATH> sessionPassword{};
            if (CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD_NO_UI, dlgDisplayName,
                          sessionPassword.data(), static_cast<int>(sessionPassword.size() - 1)) == FS_FILE_OK) {
                m_settings->password = sessionPassword.data();
                SetDlgItemText(m_hWnd, IDC_PASSWORD, m_settings->password);
                CheckDlgButton(m_hWnd, IDC_CRYPTPASS, BST_CHECKED);
            } else {
                ShowWindow(GetDlgItem(m_hWnd, IDC_PASSWORD), SW_HIDE);
                ShowWindow(GetDlgItem(m_hWnd, IDC_CRYPTPASS), SW_HIDE);
                ShowWindow(GetDlgItem(m_hWnd, IDC_EDITPASS), SW_SHOW);
            }
        } else {
            SetDlgItemText(m_hWnd, IDC_PASSWORD, m_settings->password);
            if (!CryptProc)
                EnableWindow(GetDlgItem(m_hWnd, IDC_CRYPTPASS), false);
            else {
                std::array<char, MAX_PATH> storedPasswordRaw{};
                GetPrivateProfileString(dlgDisplayName, "password", "",
                                        storedPasswordRaw.data(),
                                        storedPasswordRaw.size() - 1,
                                        dlgIniFileName);
                CheckDlgButton(m_hWnd, IDC_CRYPTPASS,
                               strcmp(storedPasswordRaw.data(), "!") == 0 ? BST_CHECKED : BST_UNCHECKED);
            }
        }

        SetDlgItemText(m_hWnd, IDC_PUBKEY, m_settings->pubkeyfile);
        SetDlgItemText(m_hWnd, IDC_PRIVKEY, m_settings->privkeyfile);

        _itoa_s(m_settings->filemod, modbuf.data(), modbuf.size(), 8);
        SetDlgItemText(m_hWnd, IDC_FILEMOD, modbuf.data());
        _itoa_s(m_settings->dirmod, modbuf.data(), modbuf.size(), 8);
        SetDlgItemText(m_hWnd, IDC_DIRMOD, modbuf.data());

        fillProxyCombobox(m_hWnd, m_settings->proxynr, dlgIniFileName);
    } else {
        CheckRadioButton(m_hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOAUTO);
        SetDlgItemText(m_hWnd, IDC_FILEMOD, "644");
        SetDlgItemText(m_hWnd, IDC_DIRMOD, "755");
        CheckDlgButton(m_hWnd, IDC_SHELLTRANSFER, BST_UNCHECKED);
        SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_SETCURSEL, 0, 0);
        fillProxyCombobox(m_hWnd, 0, dlgIniFileName);
    }
    RebuildSystemAndEncodingCombos(m_hWnd, m_ctx, m_settings);
    SetLanTimeoutMinutes(m_hWnd, m_settings->lan_pair_timeout_min);
    m_ctx->lastTransferMode = (int)SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_GETCURSEL, 0, 0);
    UpdateScpOnlyDependentControls(m_hWnd);

    if (strcmp(dlgDisplayName, s_quickconnect) != 0) {
        if (m_settings->server.empty())
            *dlgFocusset = IDC_CONNECTTO;
        else if (m_settings->user.empty())
            *dlgFocusset = IDC_USERNAME;
        else
            *dlgFocusset = IDC_PASSWORD;
    } else {
        *dlgFocusset = IDC_CONNECTTO;
    }

    if (GetWindowRect(m_hWnd, &rt1) && GetWindowRect(GetParent(m_hWnd), &rt2)) {
        w = rt2.right  - rt2.left;
        h = rt2.bottom - rt2.top;
        DlgWidth   = rt1.right - rt1.left;
        DlgHeight  = rt1.bottom - rt1.top;
        NewPosX    = rt2.left + (w - DlgWidth) / 2;
        NewPosY    = rt2.top  + (h - DlgHeight) / 2;
        SetWindowPos(m_hWnd, 0, NewPosX, NewPosY, 0, 0, SWP_NOZORDER | SWP_NOSIZE);
    }

    // SR: 11.07.2005
    serverfieldchangedbyuser = false;
    return 1;
}

INT_PTR ConnectionDialog::OnShowWindow(BOOL /*fShow*/)
{
    if (m_ctx && m_ctx->focusset)
        SetFocus(GetDlgItem(m_hWnd, m_ctx->focusset));
    return 0;
}

INT_PTR ConnectionDialog::OnCommand(WPARAM wParam, LPARAM /*lParam*/)
{
    switch (LOWORD(wParam)) {
    case IDOK:
        OnOk();
        return 1;
    case IDCANCEL:
        OnCancel();
        return 1;
    case IDC_SESSIONCOMBO:
        if (HIWORD(wParam) == CBN_SELCHANGE)
            OnSessionChanged();
        break;
    case IDC_TRANSFERMODE:
        if (HIWORD(wParam) == CBN_SELCHANGE)
            OnTransferModeChanged();
        break;
    case IDC_PHPSHELL:
        OnPhpShellBtn();
        break;
    case IDC_LOADPUBKEY:
    case IDC_LOADPRIVKEY:
        OnBrowseKeyFile(LOWORD(wParam) == IDC_LOADPUBKEY);
        break;
    case IDC_PRIVKEY:
        if (HIWORD(wParam) == EN_CHANGE)
            OnPrivateKeyChanged();
        break;
    case IDC_USEAGENT:
        OnUseAgentChanged();
        break;
    case IDC_JUMP_ENABLE:
        OnJumpEnableChanged();
        break;
    case IDC_JUMP_BUTTON:
        OnJumpButton();
        break;
    case IDC_PROXYBUTTON:
        OnProxyButton();
        break;
    case IDC_PROXYCOMBO:
        if (HIWORD(wParam) == CBN_SELCHANGE)
            OnProxyComboChanged();
        break;
    case IDC_DELETELAST:
        OnDeleteLastProxy();
        break;
    case IDC_IMPORTSESSIONS:
        OnImportSessions();
        break;
    case IDC_PLUGINHELP:
        OnPluginHelp();
        break;
    case IDC_CERTHELP:
    case IDC_CERTHELPPRIV:
        OnCertHelp();
        break;
    case IDC_PASSWORDHELP:
        OnPasswordHelp();
        break;
    case IDC_UTF8HELP:
        OnUtf8Help();
        break;
    case IDC_EDITPASS:
        OnEditPass();
        break;
    case IDC_CONNECTTO:
        if (HIWORD(wParam) == EN_CHANGE)
            OnConnectToChanged();
        break;
    case IDC_SCP_ALL:
        UpdateScpOnlyDependentControls(m_hWnd);
        break;
    }
    return 0;
}

void ConnectionDialog::OnDestroy()
{
    StopLanPairing(m_ctx);
}

INT_PTR ConnectionDialog::OnLanPeerMessage(WPARAM /*wParam*/, LPARAM lParam)
{
    auto* ann = reinterpret_cast<lanpair::PeerAnnouncement*>(lParam);
    if (m_ctx && ann) {
        const bool peerWasNew = m_ctx->lanPeers.find(ann->peerId) == m_ctx->lanPeers.end();
        const std::string newPeerId = ann->peerId;
        m_ctx->lanPeers[ann->peerId] = *ann;
        delete ann;

        const int transferMode = (int)SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_GETCURSEL, 0, 0);
        if (transferMode == static_cast<int>(sftp::TransferMode::smb_lan)) {
            const BOOL dropped = (BOOL)SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_GETDROPPEDSTATE, 0, 0);
            if (!dropped)
                RefreshLanPeerCombo(m_hWnd, m_ctx, m_settings ? m_settings->lan_pair_peer : std::string{});

            const int roleSel = (int)SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0);
            if (peerWasNew && roleSel == 0 && !m_ctx->lanRolePromptShown) {
                m_ctx->lanRolePromptShown = true;
                const std::wstring titleW = LoadResStringW(IDS_LAN_TITLE);
                const std::wstring msgW   = LoadResStringW(IDS_LAN_ROLE_PROMPT);
                const int choice = MessageBoxW(
                    m_hWnd,
                    msgW.empty() ? L"Znaleziono peera LAN Pair.\nWybierz rolę:\n\nTak = Dawca\nNie = Biorca\nAnuluj = bez zmian" : msgW.c_str(),
                    titleW.empty() ? L"LAN Pair" : titleW.c_str(),
                    MB_ICONQUESTION | MB_YESNOCANCEL | MB_DEFBUTTON1);
                if (choice == IDYES || choice == IDNO) {
                    const int newRole = (choice == IDYES) ? 2 : 1;
                    SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_SETCURSEL, newRole, 0);
                    if (choice == IDYES) {
                        for (size_t i = 0; i < m_ctx->lanPeerOrder.size(); ++i) {
                            if (m_ctx->lanPeerOrder[i] == newPeerId) {
                                SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_SETCURSEL, static_cast<WPARAM>(i + 1), 0);
                                break;
                            }
                        }
                    }
                    HandleLanPairAction(m_hWnd, m_ctx, m_settings);
                }
                m_ctx->lanRolePromptShown = false;
            }
        }
        return 1;
    }
    delete ann;
    return 1;
}

void ConnectionDialog::OnOk()
{
    StopLanPairing(m_ctx);

    LPCSTR dlgDisplayName = m_ctx->displayName;
    LPCSTR dlgIniFileName = m_ctx->iniFileName;
    std::array<char, 32> modbuf{};
    std::array<char, MAX_PATH> strbuf{};
    int cp = 0, cbline = 0;

    GetDlgItemText(m_hWnd, IDC_CONNECTTO, m_settings->server);
    GetDlgItemText(m_hWnd, IDC_USERNAME,  m_settings->user);
    GetDlgItemText(m_hWnd, IDC_PASSWORD,  m_settings->password);
    if (IsDlgButtonChecked(m_hWnd, IDC_PROTOV4))
        m_settings->protocoltype = 1;
    else if (IsDlgButtonChecked(m_hWnd, IDC_PROTOV6))
        m_settings->protocoltype = 2;
    else
        m_settings->protocoltype = 0;
    m_settings->transfermode = (int)SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_GETCURSEL, 0, 0);
    if (m_settings->transfermode < 0 || m_settings->transfermode > 3)
        m_settings->transfermode = 0;
    const bool smbMode = m_settings->transfermode == static_cast<int>(sftp::TransferMode::smb_lan);
    const bool phpMode = m_settings->transfermode != static_cast<int>(sftp::TransferMode::ssh_auto);
    if (phpMode && !smbMode) {
        m_settings->php_http_mode = (int)SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0);
        if (m_settings->php_http_mode < 0 || m_settings->php_http_mode > 2)
            m_settings->php_http_mode = 0;
        m_settings->php_chunk_mib = PhpChunkComboIndexToValue(
            (int)SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0));
    } else if (smbMode) {
        m_settings->lan_pair_role = LanRoleComboToValue(
            (int)SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0));
        const int peerIdx = (int)SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0);
        if (peerIdx > 0 && peerIdx <= (int)m_ctx->lanPeerOrder.size())
            m_settings->lan_pair_peer = m_ctx->lanPeerOrder[peerIdx - 1];
        else
            m_settings->lan_pair_peer.clear();
        m_settings->lan_pair_timeout_min = ReadLanTimeoutMinutes(m_hWnd);
    }

    GetDlgItemText(m_hWnd, IDC_PUBKEY, m_settings->pubkeyfile);
    GetDlgItemText(m_hWnd, IDC_PRIVKEY, m_settings->privkeyfile);
    m_settings->useagent      = IsDlgButtonChecked(m_hWnd, IDC_USEAGENT)     == BST_CHECKED;
    m_settings->use_jump_host = IsDlgButtonChecked(m_hWnd, IDC_JUMP_ENABLE)  == BST_CHECKED;
    m_settings->detailedlog   = IsDlgButtonChecked(m_hWnd, IDC_DETAILED_LOG) == BST_CHECKED;
    m_settings->compressed    = IsDlgButtonChecked(m_hWnd, IDC_COMPRESS)     == BST_CHECKED;
    m_settings->scpfordata    = IsDlgButtonChecked(m_hWnd, IDC_SCP_DATA)     == BST_CHECKED;
    m_settings->scponly       = IsDlgButtonChecked(m_hWnd, IDC_SCP_ALL)      == BST_CHECKED;
    if (m_settings->scponly)
        m_settings->scpfordata = true;
    const bool shellTransferChecked = IsDlgButtonChecked(m_hWnd, IDC_SHELLTRANSFER) == BST_CHECKED;
    m_settings->shell_transfer_dd    = shellTransferChecked;
    m_settings->shell_transfer_force = shellTransferChecked;

    if (!phpMode || smbMode) {
        if (smbMode) {
            m_settings->utf8names      = -1;
            m_settings->unixlinebreaks = -1;
            m_settings->codepage       = 0;
        } else {
            cp = 0;
            cbline = (char)SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0);
            switch (cbline) {
            case 0: m_settings->utf8names = -1; break;
            case 1: m_settings->utf8names =  1; break;
            default:
                m_settings->utf8names = 0;
                if (cbline >= 0 && cbline < kCodepageListCount) {
                    cp = codepagelist[cbline];
                    if (cp == -3) {
                        if (RequestProc(PluginNumber, RT_Other, "Code page", "Code page (e.g. 28591):",
                                        strbuf.data(), strbuf.size() - 1))
                            cp = atoi(strbuf.data());
                    } else if (cp == -4) {
                        cp = m_settings->codepage;
                    }
                }
            }
            m_settings->codepage       = cp;
            m_settings->unixlinebreaks = (char)SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0) - 1;
        }
    }

    GetDlgItemText(m_hWnd, IDC_FILEMOD, modbuf.data(), modbuf.size() - 1);
    m_settings->filemod = modbuf[0] == 0 ? 0644 : strtol(modbuf.data(), nullptr, 8);
    GetDlgItemText(m_hWnd, IDC_DIRMOD, modbuf.data(), modbuf.size() - 1);
    m_settings->dirmod  = modbuf[0] == 0 ? 0755 : strtol(modbuf.data(), nullptr, 8);

    m_settings->proxynr = GetProxyNrFromCombo(m_hWnd);

    std::array<char, wdirtypemax> targetProfile{};
    std::array<char, wdirtypemax> enteredProfile{};
    targetProfile[0] = 0;
    enteredProfile[0] = 0;

    GetDlgItemText(m_hWnd, IDC_SESSIONCOMBO, enteredProfile.data(), enteredProfile.size() - 1);
    TrimSessionName(enteredProfile.data());
    if (enteredProfile[0] && _stricmp(enteredProfile.data(), s_quickconnect) != 0) {
        strlcpy(targetProfile.data(), enteredProfile.data(), targetProfile.size() - 1);
    } else if (strcmp(dlgDisplayName, s_quickconnect) != 0) {
        strlcpy(targetProfile.data(), dlgDisplayName, targetProfile.size() - 1);
    }

    if (targetProfile[0]) {
        if (smbMode && m_settings->server.empty()) {
            if (!m_settings->lan_pair_peer.empty())
                m_settings->server = std::format("lanpair://peer/{}", m_settings->lan_pair_peer);
            else
                m_settings->server = "lanpair://local";
        }

        if (strcmp(dlgDisplayName, s_quickconnect) != 0 &&
            _stricmp(targetProfile.data(), dlgDisplayName) != 0) {
            int moveRc = CopyMoveServerInIni(dlgDisplayName, targetProfile.data(), true, false, dlgIniFileName);
            if (moveRc == FS_FILE_EXISTS) {
                MessageBoxA(m_hWnd,
                            "Session with this name already exists.\nChoose a different session name.",
                            "SFTP", MB_OK | MB_ICONWARNING);
                return;
            }
        }

        m_settings->DisplayName = targetProfile.data();
        if (m_settings->dialogforconnection && strcmp(dlgDisplayName, s_quickconnect) == 0)
            m_settings->saveonlyprofile = true;
        std::array<char, 16> buf{};
        WritePrivateProfileString(targetProfile.data(), "server",   m_settings->server.c_str(),  dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "user",     m_settings->user.c_str(),    dlgIniFileName);
        _itoa_s(m_settings->protocoltype, buf.data(), buf.size(), 10);
        WritePrivateProfileString(targetProfile.data(), "protocol", m_settings->protocoltype == 0 ? nullptr : buf.data(), dlgIniFileName);
        _itoa_s(max(0, min(3, m_settings->transfermode)), buf.data(), buf.size(), 10);
        WritePrivateProfileString(targetProfile.data(), "transfermode", buf.data(), dlgIniFileName);
        _itoa_s(max(0, min(2, m_settings->php_http_mode)), buf.data(), buf.size(), 10);
        WritePrivateProfileString(targetProfile.data(), "phphttpmode", m_settings->php_http_mode == 0 ? nullptr : buf.data(), dlgIniFileName);
        _itoa_s(m_settings->php_chunk_mib, buf.data(), buf.size(), 10);
        WritePrivateProfileString(targetProfile.data(), "phpchunkmb", m_settings->php_chunk_mib == 0 ? nullptr : buf.data(), dlgIniFileName);
        _itoa_s(max(0, min(2, m_settings->lan_pair_role)), buf.data(), buf.size(), 10);
        WritePrivateProfileString(targetProfile.data(), "lanpairrole", m_settings->lan_pair_role == 0 ? nullptr : buf.data(), dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "lanpairpeer", m_settings->lan_pair_peer.empty() ? nullptr : m_settings->lan_pair_peer.c_str(), dlgIniFileName);
        _itoa_s(max(0, m_settings->lan_pair_timeout_min), buf.data(), buf.size(), 10);
        WritePrivateProfileString(targetProfile.data(), "lanpairtimeout", m_settings->lan_pair_timeout_min == 0 ? nullptr : buf.data(), dlgIniFileName);
        if (m_settings->transfermode == static_cast<int>(sftp::TransferMode::smb_lan) &&
            !m_settings->password.empty() && !m_settings->lan_pair_peer.empty()) {
            const std::string localId = MakeLanPeerId();
            PrepareLanPairTrustKeys(localId, m_settings->lan_pair_peer, m_settings->password);
        }
        WritePrivateProfileString(targetProfile.data(), "detailedlog", m_settings->detailedlog ? "1" : nullptr, dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "utf8",        m_settings->utf8names == -1 ? nullptr : m_settings->utf8names == 1 ? "1" : "0", dlgIniFileName);
        _itoa_s(m_settings->codepage, buf.data(), buf.size(), 10);
        WritePrivateProfileString(targetProfile.data(), "codepage",    buf.data(), dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "unixlinebreaks", m_settings->unixlinebreaks == -1 ? nullptr : m_settings->unixlinebreaks == 1 ? "1" : "0", dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "largefilesupport", m_settings->scpserver64bit == -1 ? nullptr : m_settings->scpserver64bit == 1 ? "1" : "0", dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "compression",     m_settings->compressed          ? "1" : nullptr, dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "scpfordata",      m_settings->scpfordata           ? "1" : nullptr, dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "scponly",         m_settings->scponly              ? "1" : nullptr, dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "shelltransfer",   m_settings->shell_transfer_dd    ? "1" : nullptr, dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "shelltransferforce", m_settings->shell_transfer_force ? "1" : nullptr, dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "pubkeyfile",   m_settings->pubkeyfile.empty()   ? nullptr : m_settings->pubkeyfile.c_str(),   dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "privkeyfile",  m_settings->privkeyfile.empty()  ? nullptr : m_settings->privkeyfile.c_str(),  dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "useagent",     m_settings->useagent             ? "1" : nullptr, dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "usejumphost",  m_settings->use_jump_host        ? "1" : nullptr, dlgIniFileName);
        if (!m_settings->jump_host.empty())
            WritePrivateProfileString(targetProfile.data(), "jumphost", m_settings->jump_host.c_str(), dlgIniFileName);
        if (m_settings->jump_port && m_settings->jump_port != 22) {
            std::array<char, 16> portBuf{};
            _itoa_s(m_settings->jump_port, portBuf.data(), portBuf.size(), 10);
            WritePrivateProfileString(targetProfile.data(), "jumpport", portBuf.data(), dlgIniFileName);
        }
        if (!m_settings->jump_user.empty())
            WritePrivateProfileString(targetProfile.data(), "jumpuser", m_settings->jump_user.c_str(), dlgIniFileName);
        if (!m_settings->jump_pubkeyfile.empty())
            WritePrivateProfileString(targetProfile.data(), "jumppubkeyfile", m_settings->jump_pubkeyfile.c_str(), dlgIniFileName);
        if (!m_settings->jump_privkeyfile.empty())
            WritePrivateProfileString(targetProfile.data(), "jumpprivkeyfile", m_settings->jump_privkeyfile.c_str(), dlgIniFileName);
        WritePrivateProfileString(targetProfile.data(), "jumpuseagent", m_settings->jump_useagent ? "1" : nullptr, dlgIniFileName);
        if (!m_settings->jump_password.empty()) {
            std::array<char, 1024> jumpEnc{};
            EncryptString(m_settings->jump_password.c_str(), jumpEnc.data(), static_cast<UINT>(jumpEnc.size()));
            WritePrivateProfileString(targetProfile.data(), "jumppassword", jumpEnc.data(), dlgIniFileName);
        }
        _itoa_s(m_settings->filemod, modbuf.data(), modbuf.size(), 8);
        WritePrivateProfileString(targetProfile.data(), "filemod", m_settings->filemod == 0644 ? nullptr : modbuf.data(), dlgIniFileName);
        _itoa_s(m_settings->dirmod, modbuf.data(), modbuf.size(), 8);
        WritePrivateProfileString(targetProfile.data(), "dirmod", m_settings->dirmod == 0755 ? nullptr : modbuf.data(), dlgIniFileName);
        _itoa_s(m_settings->proxynr, buf.data(), buf.size(), 10);
        WritePrivateProfileString(targetProfile.data(), TEXT("proxynr"), buf.data(), dlgIniFileName);

        std::array<char, 1024> szEncryptedPassword{};
        if (!IsWindowVisible(GetDlgItem(m_hWnd, IDC_EDITPASS))) {
            if (m_settings->password.empty()) {
                WritePrivateProfileString(targetProfile.data(), "password", nullptr, dlgIniFileName);
            } else if (CryptProc && IsDlgButtonChecked(m_hWnd, IDC_CRYPTPASS)) {
                bool ok = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD,
                                    targetProfile.data(),
                                    const_cast<char*>(m_settings->password.c_str()), 0) == FS_FILE_OK;
                WritePrivateProfileString(targetProfile.data(), "password", ok ? "!" : nullptr, dlgIniFileName);
                CryptCheckPass = true;
            } else {
                EncryptString(m_settings->password.c_str(), szEncryptedPassword.data(),
                              static_cast<UINT>(szEncryptedPassword.size()));
                WritePrivateProfileString(targetProfile.data(), "password", szEncryptedPassword.data(), dlgIniFileName);
            }
        }
    }

    const int transferMode = max(0, min(3, m_settings->transfermode));
    if (transferMode == static_cast<int>(sftp::TransferMode::php_agent) ||
        transferMode == static_cast<int>(sftp::TransferMode::php_shell)) {
        if (!UpdateLocalPhpAgentScriptWithPassword(m_settings->password.c_str())) {
            SFTP_LOG("PHP", "Local sftp.php update skipped: file missing or not writable in plugin directory.");
            ShowStatus("PHP Agent: local sftp.php update skipped (missing or read-only file).");
        }
    }
    m_settings->customport = 0;  // will be set later by the connection logic
    EndDialog(m_hWnd, IDOK);
}

void ConnectionDialog::OnCancel()
{
    StopLanPairing(m_ctx);
    EndDialog(m_hWnd, IDCANCEL);
}

void ConnectionDialog::OnSessionChanged()
{
    std::array<char, wdirtypemax> sessionName{};
    GetDlgItemText(m_hWnd, IDC_SESSIONCOMBO, sessionName.data(), sessionName.size() - 1);
    TrimSessionName(sessionName.data());
    if (sessionName[0] && _stricmp(sessionName.data(), s_quickconnect) != 0) {
        tConnectSettings loaded{};
        if (LoadServerSettings(sessionName.data(), &loaded, m_ctx->iniFileName))
            ApplyLoadedSessionToDialog(m_hWnd, &loaded, m_ctx->iniFileName);
    }
}

void ConnectionDialog::OnTransferModeChanged()
{
    if (m_ctx) {
        if (m_ctx->lastTransferMode == static_cast<int>(sftp::TransferMode::ssh_auto)) {
            m_settings->unixlinebreaks = (char)SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0) - 1;
            const int encSel = (int)SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0);
            if (encSel == 0)
                m_settings->utf8names = -1;
            else if (encSel == 1)
                m_settings->utf8names = 1;
            else if (encSel >= 0 && encSel < kCodepageListCount) {
                m_settings->utf8names = 0;
                const int cp = codepagelist[encSel];
                if (cp > 0)
                    m_settings->codepage = cp;
            }
        } else if (m_ctx->lastTransferMode == static_cast<int>(sftp::TransferMode::php_agent) ||
                   m_ctx->lastTransferMode == static_cast<int>(sftp::TransferMode::php_shell)) {
            m_settings->php_http_mode = (int)SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0);
            if (m_settings->php_http_mode < 0 || m_settings->php_http_mode > 2)
                m_settings->php_http_mode = 0;
            m_settings->php_chunk_mib = PhpChunkComboIndexToValue(
                (int)SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0));
        } else if (m_ctx->lastTransferMode == static_cast<int>(sftp::TransferMode::smb_lan)) {
            m_settings->lan_pair_role = LanRoleComboToValue(
                (int)SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0));
            const int peerIdx = (int)SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0);
            if (peerIdx > 0 && peerIdx <= (int)m_ctx->lanPeerOrder.size())
                m_settings->lan_pair_peer = m_ctx->lanPeerOrder[peerIdx - 1];
            else
                m_settings->lan_pair_peer.clear();
            m_settings->lan_pair_timeout_min = ReadLanTimeoutMinutes(m_hWnd);
        }
    }
    RebuildSystemAndEncodingCombos(m_hWnd, m_ctx, m_settings);
    if (m_ctx)
        m_ctx->lastTransferMode = (int)SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_GETCURSEL, 0, 0);
    UpdateScpOnlyDependentControls(m_hWnd);
}

void ConnectionDialog::OnPhpShellBtn()
{
    OnPhpShellCommand(m_hWnd, m_ctx, m_settings);
}

void ConnectionDialog::OnBrowseKeyFile(bool isPublicKey)
{
    OnBrowseKeyFileCommand(m_hWnd, isPublicKey);
}

void ConnectionDialog::OnPrivateKeyChanged()
{
    UpdateCertSectionState(m_hWnd);
}

void ConnectionDialog::OnUseAgentChanged()
{
    UpdateCertSectionState(m_hWnd);
}

void ConnectionDialog::OnJumpEnableChanged()
{
    const bool checked = IsDlgButtonChecked(m_hWnd, IDC_JUMP_ENABLE) == BST_CHECKED;
    if (m_settings)
        m_settings->use_jump_host = checked;
    EnableWindow(GetDlgItem(m_hWnd, IDC_JUMP_BUTTON), checked ? TRUE : FALSE);
}

void ConnectionDialog::OnJumpButton()
{
    OnJumpButtonCommand(m_hWnd, m_settings, m_ctx->displayName, m_ctx->iniFileName);
    CheckDlgButton(m_hWnd, IDC_JUMP_ENABLE,
        m_settings->use_jump_host ? BST_CHECKED : BST_UNCHECKED);
}

void ConnectionDialog::OnProxyButton()
{
    OnProxyButtonCommand(m_hWnd, m_settings, m_ctx);
}

void ConnectionDialog::OnProxyComboChanged()
{
    if ((int)SendDlgItemMessage(m_hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0) ==
        (int)SendDlgItemMessage(m_hWnd, IDC_PROXYCOMBO, CB_GETCOUNT, 0, 0) - 1)
        PostMessage(m_hWnd, WM_COMMAND, IDC_PROXYBUTTON, 0);
}

void ConnectionDialog::OnDeleteLastProxy()
{
    OnDeleteLastProxyCommand(m_hWnd, m_settings, m_ctx->iniFileName);
}

void ConnectionDialog::OnImportSessions()
{
    OnImportSessionsCommand(m_hWnd, m_settings, m_ctx);
}

void ConnectionDialog::OnPluginHelp()
{
    OpenPluginHelp(m_hWnd);
}

void ConnectionDialog::OnCertHelp()
{
    ShowHelpDialog(m_hWnd, IDS_HELP_CERT);
}

void ConnectionDialog::OnPasswordHelp()
{
    ShowHelpDialog(m_hWnd, IDS_HELP_PASSWORD);
}

void ConnectionDialog::OnUtf8Help()
{
    ShowHelpDialog(m_hWnd, IDS_HELP_UTF8);
}

void ConnectionDialog::OnEditPass()
{
    bool doshow = true;
    std::array<char, MAX_PATH> sessionPassword{};
    int err = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD,
                        m_ctx->displayName, sessionPassword.data(),
                        static_cast<int>(sessionPassword.size() - 1));
    if (err == FS_FILE_OK) {
        m_settings->password = sessionPassword.data();
        SetDlgItemText(m_hWnd, IDC_PASSWORD, m_settings->password);
    } else if (err == FS_FILE_READERROR) {
        SetDlgItemText(m_hWnd, IDC_PASSWORD, std::string{});
    } else {
        doshow = false;
    }
    if (doshow) {
        ShowWindow(GetDlgItem(m_hWnd, IDC_PASSWORD),  SW_SHOW);
        ShowWindow(GetDlgItem(m_hWnd, IDC_CRYPTPASS), SW_SHOW);
        ShowWindow(GetDlgItem(m_hWnd, IDC_EDITPASS),  SW_HIDE);
        if (!m_settings->password.empty())
            CheckDlgButton(m_hWnd, IDC_CRYPTPASS, BST_CHECKED);
    }
}

void ConnectionDialog::OnConnectToChanged()
{
    serverfieldchangedbyuser = true;
}

bool ShowConnectDialog(pConnectSettings ConnectSettings, LPCSTR DisplayName, LPCSTR inifilename)
{
    std::lock_guard<std::mutex> lock(g_connectDialogMutex);
    // Ensure this UI thread uses language selected in Total Commander.
    ApplyConfiguredUiLanguageForCurrentThread();
    LoadServerSettings(DisplayName, ConnectSettings, inifilename);

    if (ConnectSettings->dialogforconnection && !ConnectSettings->server.empty()) {
        if ((ConnectSettings->user.empty() ||
             !ConnectSettings->password.empty()) &&        // password saved
            (ConnectSettings->proxyuser.empty() ||   // no proxy auth is required
             !ConnectSettings->proxypassword.empty()))     // or proxy pass saved
            return true;
        else {
            std::array<char, 256> title{};
            // A proxy user name was given,  but no proxy password -> ask for proxy password
            if (!ConnectSettings->proxyuser.empty() &&       // no proxy auth is required
                ConnectSettings->proxypassword.empty()) {
                LoadString(hinst, IDS_PROXY_PASS_TITLE, title.data(), title.size());
                strlcat(title.data(), ConnectSettings->proxyuser, title.size()-1);
                std::array<char, MAX_PATH> proxyPassword{};
                if (!RequestProc(PluginNumber, RT_PasswordFirewall, title.data(), title.data(), proxyPassword.data(), static_cast<int>(proxyPassword.size() - 1)))
                    return false;
                ConnectSettings->proxypassword = proxyPassword.data();
            }
            return true;
        }
    } else {
        ConnectDialogContext dlgCtx;
        dlgCtx.connectResults = ConnectSettings;
        dlgCtx.displayName = DisplayName;
        dlgCtx.iniFileName = inifilename;
        return (IDOK == ShowLocalizedDialogBoxParam(IDD_WEBDAV, GetActiveWindow(), ConnectDlgProc, (LPARAM)&dlgCtx));
    }
}

#ifndef HWND_MESSAGE
#define HWND_MESSAGE ((HWND)(-3))
#endif

pConnectSettings SftpConnectToServer(LPCSTR DisplayName, LPCSTR inifilename, LPCSTR overridepass)
{
    tConnectSettings ConnectSettings{};
    ConnectSettings.sock = INVALID_SOCKET; // Zabezpieczenie przed zamykaniem gniazda 0 przez PHP Agent
    ConnectSettings.feedback = std::make_unique<WindowsUserFeedback>();
    ConnectSettings.dialogforconnection = true;
    ConnectSettings.saveonlyprofile = false;

    // Get connection settings here
    if (ShowConnectDialog(&ConnectSettings, DisplayName, inifilename)) {
        if (ConnectSettings.saveonlyprofile) {
            return nullptr;  // unique_ptr destructor releases feedback
        }
        // LanPair mode: skip traditional SFTP/SCP connection flow
        if (ConnectSettings.transfermode == static_cast<int>(sftp::TransferMode::smb_lan)) {
            // LanPair will handle connection via separate pairing mechanism
            // For now, allow the flow to continue but mark for LanPair handling
            ConnectSettings.passSaveMode = sftp::PassSaveMode::empty;
        }
        if (overridepass)
            ConnectSettings.password = overridepass;
        if (ConnectSettings.useagent || ConnectSettings.password.empty()) {
            ConnectSettings.passSaveMode = sftp::PassSaveMode::empty;
        } else {
            ConnectSettings.passSaveMode = sftp::PassSaveMode::plain;
        }
        if (CryptProc && ConnectSettings.password == "\001") {
            ConnectSettings.passSaveMode = sftp::PassSaveMode::crypt;
            std::array<char, MAX_PATH> passwordBuf{};
            int rc = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, DisplayName, passwordBuf.data(), static_cast<int>(passwordBuf.size() - 1));
            if (rc != FS_FILE_OK) {
                ConnectSettings.feedback->ShowError("Failed to load password!");
                return nullptr;
            }
            ConnectSettings.password = passwordBuf.data();
        }
        if (CryptProc && ConnectSettings.proxypassword == "\001") {
            std::array<char, 64> proxyentry{};
            if (ConnectSettings.proxynr > 1)
                strlcpy(proxyentry.data(), std::format("proxy{}", ConnectSettings.proxynr), proxyentry.size() - 1);
            else
                strlcpy(proxyentry.data(), "proxy", proxyentry.size()-1);

            strlcat(proxyentry.data(), "$$pass", proxyentry.size()-1);
            std::array<char, MAX_PATH> proxyPasswordBuf{};
            int rc = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, proxyentry.data(), proxyPasswordBuf.data(), static_cast<int>(proxyPasswordBuf.size() - 1));
            if (rc != FS_FILE_OK) {
                ConnectSettings.feedback->ShowError("Failed to load proxy password!");
                return nullptr;
            }
            ConnectSettings.proxypassword = proxyPasswordBuf.data();
        }
        // Clear proxy credentials when proxy type is disabled.
        if (ConnectSettings.proxytype == sftp::Proxy::notused) {
            ConnectSettings.proxyuser.clear();
            ConnectSettings.proxypassword.clear();
        }
        if (!IsPhpAgentTransport(&ConnectSettings) && !IsLanPairTransport(&ConnectSettings)) {
            // split server name into server/path
            std::array<char, MAX_PATH> serverBuf{};
            strlcpy(serverBuf.data(), ConnectSettings.server, serverBuf.size() - 1);
            ReplaceBackslashBySlash(serverBuf.data());
            // Remove trailing sftp://
            if (_strnicmp(serverBuf.data(), "sftp://", 7) == 0)
                memmove(serverBuf.data(), serverBuf.data() + 7, strlen(serverBuf.data()) - 6);
            char* p = strchr(serverBuf.data(), '/');
            ConnectSettings.lastactivepath[0] = 0;
            if (p) {
                awlcopy(ConnectSettings.lastactivepath, p, countof(ConnectSettings.lastactivepath)-1);
                p[0] = 0;
                // Remove trailing slash, including the root edge case.
            }
            // look for address and port
            p = strchr(serverBuf.data(), ':');
            if (!ParseAddress(serverBuf.data(), serverBuf.data(), &ConnectSettings.customport, 22)) {
                ConnectSettings.feedback->ShowError("Invalid server address.");
                return nullptr;
            }
            ConnectSettings.server = serverBuf.data();
        }

        if (ProgressProc(PluginNumber, DisplayName, "temp", 0)) {
            return nullptr;
        }

        if (SftpConnect(&ConnectSettings) != SFTP_OK) {
            return nullptr;
        }
        {
            // This will show ftp toolbar
            std::array<char, MAX_PATH> connbuf{};
            strlcpy(connbuf.data(), "CONNECT \\", connbuf.size() - 1);
            strlcat(connbuf.data(), DisplayName, connbuf.size() - 1);
            LogProc(PluginNumber, MSGTYPE_CONNECT, connbuf.data());

            // Move the connected settings to the heap ? unique_ptrs transfer ownership.
            try {
                return new tConnectSettings(std::move(ConnectSettings));
            } catch (const std::bad_alloc&) {
                if (ConnectSettings.feedback) {
                    ConnectSettings.feedback->ShowError("Out of memory while creating connection settings.");
                }
                return nullptr;
            }
        }
    }
    return nullptr;
}

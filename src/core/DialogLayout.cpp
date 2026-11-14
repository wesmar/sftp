#include "DialogLayout.h"

#include <dwmapi.h>

#include <algorithm>
#include <array>
#include <climits>
#include <string>
#include <vector>

#include "../res/resource.h"

namespace DlgLayout {

namespace {

// ---------------------------------------------------------------------------
// DPI APIs, looked up at run time: the plugin still loads on systems that
// predate them (they fall back to the system DPI there).
// ---------------------------------------------------------------------------
struct DpiApi {
    UINT (WINAPI* getDpiForWindow)(HWND) = nullptr;
    int (WINAPI* getSystemMetricsForDpi)(int, UINT) = nullptr;
    HANDLE (WINAPI* setThreadDpiAwarenessContext)(HANDLE) = nullptr;

    DpiApi()
    {
        if (HMODULE user32 = GetModuleHandleW(L"user32.dll")) {
            getDpiForWindow = reinterpret_cast<decltype(getDpiForWindow)>(GetProcAddress(user32, "GetDpiForWindow"));
            getSystemMetricsForDpi = reinterpret_cast<decltype(getSystemMetricsForDpi)>(GetProcAddress(user32, "GetSystemMetricsForDpi"));
            setThreadDpiAwarenessContext =
                reinterpret_cast<decltype(setThreadDpiAwarenessContext)>(GetProcAddress(user32, "SetThreadDpiAwarenessContext"));
        }
    }
};

const DpiApi& Api()
{
    static const DpiApi api;
    return api;
}

// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, spelled out so the header
// version the project targets does not matter.
const HANDLE kPerMonitorAwareV2 = reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-4));

thread_local PerMonitorDpiScope* t_dpiScope = nullptr;

// ---------------------------------------------------------------------------
// Control helpers
// ---------------------------------------------------------------------------
struct Item {
    HWND hwnd;
    RECT rect; // dialog client coordinates
};

int Width(const RECT& r) { return r.right - r.left; }
int Height(const RECT& r) { return r.bottom - r.top; }

RECT RectInParent(HWND parent, HWND child)
{
    RECT r{};
    GetWindowRect(child, &r);
    MapWindowPoints(nullptr, parent, reinterpret_cast<POINT*>(&r), 2);
    return r;
}

bool IsClass(HWND hwnd, const wchar_t* name)
{
    wchar_t cls[32] = {};
    GetClassNameW(hwnd, cls, 32);
    return _wcsicmp(cls, name) == 0;
}

bool IsGroupBox(HWND hwnd)
{
    return IsClass(hwnd, L"Button") && (GetWindowLongW(hwnd, GWL_STYLE) & BS_TYPEMASK) == BS_GROUPBOX;
}

// Edits and combo boxes take whatever width they are given.
bool IsStretchable(HWND hwnd)
{
    return IsClass(hwnd, L"Edit") || IsClass(hwnd, L"ComboBox");
}

std::wstring TextOf(HWND hwnd)
{
    const int len = GetWindowTextLengthW(hwnd);
    std::wstring s(static_cast<size_t>(len) + 1, L'\0');
    GetWindowTextW(hwnd, s.data(), len + 1);
    s.resize(static_cast<size_t>(len));
    return s;
}

int TextExtent(HWND hwnd, const std::wstring& text, UINT extraFlags)
{
    if (text.empty())
        return 0;
    HDC dc = GetDC(hwnd);
    HFONT font = reinterpret_cast<HFONT>(SendMessageW(hwnd, WM_GETFONT, 0, 0));
    HGDIOBJ old = font ? SelectObject(dc, font) : nullptr;
    RECT r{0, 0, 0, 0};
    DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &r, DT_CALCRECT | DT_SINGLELINE | extraFlags);
    if (old)
        SelectObject(dc, old);
    ReleaseDC(hwnd, dc);
    return Width(r);
}

int LineHeight(HWND hwnd)
{
    HDC dc = GetDC(hwnd);
    HFONT font = reinterpret_cast<HFONT>(SendMessageW(hwnd, WM_GETFONT, 0, 0));
    HGDIOBJ old = font ? SelectObject(dc, font) : nullptr;
    TEXTMETRICW tm{};
    GetTextMetricsW(dc, &tm);
    if (old)
        SelectObject(dc, old);
    ReleaseDC(hwnd, dc);
    return tm.tmHeight;
}

int GlyphWidth(HWND hwnd)
{
    const UINT dpi = DpiOf(hwnd);
    if (Api().getSystemMetricsForDpi)
        return Api().getSystemMetricsForDpi(SM_CXMENUCHECK, dpi);
    return MulDiv(GetSystemMetrics(SM_CXMENUCHECK), static_cast<int>(dpi), 96);
}

// Moves/resizes a control. A combo box is sized by its dropped-down extent,
// so its height must not be taken from its (closed) window rectangle.
void SetBounds(HWND parent, HWND hwnd, int x, int y, int w)
{
    RECT r = RectInParent(parent, hwnd);
    int h = Height(r);
    if (IsClass(hwnd, L"ComboBox")) {
        RECT dropped{};
        if (SendMessageW(hwnd, CB_GETDROPPEDCONTROLRECT, 0, reinterpret_cast<LPARAM>(&dropped)))
            h = (std::max)(h, Height(dropped));
    }
    SetWindowPos(hwnd, nullptr, x, y, (std::max)(w, 1), h, SWP_NOZORDER | SWP_NOACTIVATE);
}

std::vector<Item> Children(HWND hDlg, bool visibleOnly)
{
    std::vector<Item> items;
    for (HWND c = GetWindow(hDlg, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
        if (visibleOnly && !(GetWindowLongW(c, GWL_STYLE) & WS_VISIBLE))
            continue;
        items.push_back({c, RectInParent(hDlg, c)});
    }
    return items;
}

// Visible controls grouped into rows by vertical overlap; group boxes, which
// span many rows, are left out.
std::vector<std::vector<Item>> Rows(HWND hDlg)
{
    std::vector<Item> items;
    for (const auto& it : Children(hDlg, true))
        if (!IsGroupBox(it.hwnd))
            items.push_back(it);
    std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) { return a.rect.top < b.rect.top; });

    std::vector<std::vector<Item>> rows;
    std::vector<RECT> spans;
    for (const auto& it : items) {
        bool placed = false;
        for (size_t r = 0; r < rows.size() && !placed; ++r) {
            const int overlap = (std::min)(spans[r].bottom, it.rect.bottom) - (std::max)(spans[r].top, it.rect.top);
            if (overlap * 2 >= (std::min)(Height(spans[r]), Height(it.rect))) {
                rows[r].push_back(it);
                spans[r].top = (std::min)(spans[r].top, it.rect.top);
                spans[r].bottom = (std::max)(spans[r].bottom, it.rect.bottom);
                placed = true;
            }
        }
        if (!placed) {
            rows.push_back({it});
            spans.push_back(it.rect);
        }
    }
    for (auto& row : rows)
        std::sort(row.begin(), row.end(), [](const Item& a, const Item& b) { return a.rect.left < b.rect.left; });
    return rows;
}

int LeftMargin(HWND hDlg)
{
    int margin = INT_MAX;
    for (const auto& it : Children(hDlg, true))
        margin = (std::min)(margin, static_cast<int>(it.rect.left));
    return margin == INT_MAX ? Gap(hDlg) : (std::max)(margin, 0);
}

// Right edge a control may extend to: inside its group box, or the dialog's.
int RightLimit(HWND hDlg, const RECT& r, int dialogLimit)
{
    for (const auto& g : Children(hDlg, true)) {
        if (!IsGroupBox(g.hwnd))
            continue;
        if (r.left >= g.rect.left && r.right <= g.rect.right && r.top >= g.rect.top && r.bottom <= g.rect.bottom)
            return g.rect.right - Scale(hDlg, 6);
    }
    return dialogLimit;
}

} // namespace

// ---------------------------------------------------------------------------
// Public primitives
// ---------------------------------------------------------------------------
UINT DpiOf(HWND hwnd)
{
    if (Api().getDpiForWindow && hwnd) {
        if (const UINT dpi = Api().getDpiForWindow(hwnd))
            return dpi;
    }
    HDC dc = GetDC(nullptr);
    const int dpi = GetDeviceCaps(dc, LOGPIXELSX);
    ReleaseDC(nullptr, dc);
    return dpi > 0 ? static_cast<UINT>(dpi) : 96u;
}

int Scale(HWND hwnd, int value96) { return MulDiv(value96, static_cast<int>(DpiOf(hwnd)), 96); }
int Gap(HWND hwnd) { return Scale(hwnd, 4); }

int MeasureText(HWND /*hDlg*/, HWND hCtrl)
{
    const bool noPrefix = IsClass(hCtrl, L"Static") && (GetWindowLongW(hCtrl, GWL_STYLE) & SS_NOPREFIX);
    return TextExtent(hCtrl, TextOf(hCtrl), noPrefix ? DT_NOPREFIX : 0);
}

int RequiredWidth(HWND hCtrl)
{
    RECT r{};
    GetWindowRect(hCtrl, &r);
    const int current = Width(r);
    const LONG style = GetWindowLongW(hCtrl, GWL_STYLE);
    const std::wstring text = TextOf(hCtrl);
    if (text.empty())
        return current;

    if (IsClass(hCtrl, L"Static")) {
        const LONG type = style & SS_TYPEMASK;
        if (type != SS_LEFT && type != SS_SIMPLE && type != SS_LEFTNOWORDWRAP && type != SS_CENTER && type != SS_RIGHT)
            return current; // icons, frames, bitmaps
        // A static two or more lines tall wraps; its width is the layout's choice.
        if (type != SS_SIMPLE && type != SS_LEFTNOWORDWRAP && Height(r) >= 2 * LineHeight(hCtrl))
            return current;
        return TextExtent(hCtrl, text, (style & SS_NOPREFIX) ? DT_NOPREFIX : 0) + Scale(hCtrl, 2);
    }
    if (IsClass(hCtrl, L"Button")) {
        const int textW = TextExtent(hCtrl, text, 0);
        switch (style & BS_TYPEMASK) {
        case BS_CHECKBOX: case BS_AUTOCHECKBOX: case BS_3STATE: case BS_AUTO3STATE:
        case BS_RADIOBUTTON: case BS_AUTORADIOBUTTON:
            return GlyphWidth(hCtrl) + Scale(hCtrl, 6) + textW;
        case BS_GROUPBOX:
            return textW + Scale(hCtrl, 16);
        default:
            return textW + Scale(hCtrl, 10);
        }
    }
    return current;
}

RECT GetRect(HWND hDlg, int ctrlId)
{
    HWND h = GetDlgItem(hDlg, ctrlId);
    return h ? RectInParent(hDlg, h) : RECT{};
}

void Move(HWND hDlg, int ctrlId, int x, int y, int w, int h)
{
    if (HWND hw = GetDlgItem(hDlg, ctrlId)) {
        if (IsClass(hw, L"ComboBox"))
            SetBounds(hDlg, hw, x, y, w);
        else
            SetWindowPos(hw, nullptr, x, y, (std::max)(w, 1), h, SWP_NOZORDER | SWP_NOACTIVATE);
    }
}

// ---------------------------------------------------------------------------
// Fitting
// ---------------------------------------------------------------------------
int FitToText(HWND hDlg)
{
    RECT client{};
    GetClientRect(hDlg, &client);
    const int width = client.right;
    const int margin = LeftMargin(hDlg);
    const int gap = Gap(hDlg);
    const int minStretch = Scale(hDlg, 40);

    int need = 0;
    for (const auto& row : Rows(hDlg)) {
        int sum = row.front().rect.left;
        for (size_t i = 0; i < row.size(); ++i) {
            const int w = Width(row[i].rect);
            if (i > 0)
                sum += gap;
            sum += IsStretchable(row[i].hwnd) ? (std::min)(w, minStretch) : (std::max)(w, RequiredWidth(row[i].hwnd));
        }
        need = (std::max)(need, sum + margin - width);
    }
    for (const auto& g : Children(hDlg, true))
        if (IsGroupBox(g.hwnd))
            need = (std::max)(need, RequiredWidth(g.hwnd) - Width(g.rect));
    if (need <= 0)
        return 0;

    RECT window{};
    GetWindowRect(hDlg, &window);
    MONITORINFO mi{sizeof(mi)};
    GetMonitorInfoW(MonitorFromWindow(hDlg, MONITOR_DEFAULTTONEAREST), &mi);
    const int maxGrow = Width(mi.rcWork) - Width(window);
    const int delta = (std::min)(need, (std::max)(maxGrow, 0));
    if (delta <= 0)
        return 0;

    const int mid = width / 2;
    for (const auto& it : Children(hDlg, false)) {
        if (it.rect.left >= mid)
            SetBounds(hDlg, it.hwnd, it.rect.left + delta, it.rect.top, Width(it.rect));
        else if (it.rect.right > mid)
            SetBounds(hDlg, it.hwnd, it.rect.left, it.rect.top, Width(it.rect) + delta);
    }
    // Keep the dialog where it was centred, inside the work area.
    int left = window.left - delta / 2;
    left = (std::max)(static_cast<int>(mi.rcWork.left), (std::min)(left, static_cast<int>(mi.rcWork.right) - Width(window) - delta));
    SetWindowPos(hDlg, nullptr, left, window.top, Width(window) + delta, Height(window), SWP_NOZORDER | SWP_NOACTIVATE);
    return delta;
}

void FixClippedRows(HWND hDlg)
{
    RECT client{};
    GetClientRect(hDlg, &client);
    const int dialogLimit = client.right - LeftMargin(hDlg);
    const int gap = Gap(hDlg);
    const int minStretch = Scale(hDlg, 40);

    for (auto row : Rows(hDlg)) {
        for (size_t i = 0; i < row.size(); ++i) {
            const int req = RequiredWidth(row[i].hwnd);
            int need = req - Width(row[i].rect);
            if (need <= 0)
                continue;

            const int limit = (i + 1 < row.size()) ? row[i + 1].rect.left - gap : RightLimit(hDlg, row[i].rect, dialogLimit);
            const int take = (std::min)(need, (std::max)(0, limit - static_cast<int>(row[i].rect.right)));
            row[i].rect.right += take;
            need -= take;

            for (size_t j = i + 1; need > 0 && j < row.size(); ++j) {
                if (!IsStretchable(row[j].hwnd))
                    continue;
                const int give = (std::min)(need, Width(row[j].rect) - minStretch);
                if (give <= 0)
                    break;
                for (size_t k = i + 1; k < j; ++k) {
                    row[k].rect.left += give;
                    row[k].rect.right += give;
                }
                row[j].rect.left += give;
                row[i].rect.right += give;
                need -= give;
                for (size_t k = i + 1; k <= j; ++k)
                    SetBounds(hDlg, row[k].hwnd, row[k].rect.left, row[k].rect.top, Width(row[k].rect));
                break;
            }
            SetBounds(hDlg, row[i].hwnd, row[i].rect.left, row[i].rect.top, Width(row[i].rect));

            if (need > 0 && IsClass(row[i].hwnd, L"Static")) {
                const LONG_PTR style = GetWindowLongPtrW(row[i].hwnd, GWL_STYLE);
                if (!(style & SS_ENDELLIPSIS))
                    SetWindowLongPtrW(row[i].hwnd, GWL_STYLE, style | SS_ENDELLIPSIS);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chrome and DPI context
// ---------------------------------------------------------------------------
void ApplyWindowChrome(HWND hDlg)
{
    // DWMWA_WINDOW_CORNER_PREFERENCE = 33 / DWMWCP_ROUND = 2 and
    // DWMWA_SYSTEMBACKDROP_TYPE = 38 / DWMSBT_MAINWINDOW = 2 (Mica): Windows 11
    // builds that do not know an attribute reject it, which is harmless.
    const DWORD round = 2;
    DwmSetWindowAttribute(hDlg, 33, &round, sizeof(round));
    const DWORD mica = 2;
    DwmSetWindowAttribute(hDlg, 38, &mica, sizeof(mica));
}

PerMonitorDpiScope::PerMonitorDpiScope() noexcept
{
    if (Api().setThreadDpiAwarenessContext) {
        previous_ = Api().setThreadDpiAwarenessContext(kPerMonitorAwareV2);
        active_ = previous_ != nullptr; // NULL: PMv2 unknown before Windows 10 1703
    }
    outer_ = t_dpiScope;
    t_dpiScope = this;
}

PerMonitorDpiScope::~PerMonitorDpiScope()
{
    Restore();
    t_dpiScope = outer_;
}

void PerMonitorDpiScope::Restore() noexcept
{
    if (active_) {
        Api().setThreadDpiAwarenessContext(previous_);
        active_ = false;
    }
}

void PerMonitorDpiScope::ReleaseEarly() noexcept
{
    if (t_dpiScope)
        t_dpiScope->Restore();
}

void OnInitDialog(HWND hDlg)
{
    PerMonitorDpiScope::ReleaseEarly();
    ApplyWindowChrome(hDlg);
}

// ---------------------------------------------------------------------------
// Dialog-specific arrangements
// ---------------------------------------------------------------------------
namespace {

// Controls packed against the right edge in the order given, each as wide as
// its text but no narrower than `minWidth96`, `gap96` apart (96-DPI pixels).
void PackRight(HWND hDlg, std::initializer_list<int> ids, int minWidth96, int gap96)
{
    RECT client{};
    GetClientRect(hDlg, &client);
    const int gap = Scale(hDlg, gap96);
    const int minWidth = Scale(hDlg, minWidth96);
    int right = client.right - LeftMargin(hDlg);
    for (auto id = std::rbegin(ids); id != std::rend(ids); ++id) {
        HWND hw = GetDlgItem(hDlg, *id);
        if (!hw)
            continue;
        const RECT r = RectInParent(hDlg, hw);
        const int w = (std::max)(RequiredWidth(hw), minWidth);
        right -= w;
        SetWindowPos(hw, nullptr, right, r.top, w, Height(r), SWP_NOZORDER | SWP_NOACTIVATE);
        right -= gap;
    }
}

// Protocol radios packed against the right edge, each as wide as its text.
void ArrangeProtocolButtons(HWND hDlg)
{
    PackRight(hDlg, {IDC_PROTOAUTO, IDC_PROTOV4, IDC_PROTOV6}, 0, 4);
}

// LAN Pair row: timeout label, its edit, the hint, then the TrustedInstaller
// box from the column of the System combo to the right edge.
void ArrangeLanTimeoutRow(HWND hDlg)
{
    HWND hLabel = GetDlgItem(hDlg, IDC_LAN_TIMEOUT_LABEL);
    HWND hHint = GetDlgItem(hDlg, IDC_LAN_TIMEOUT_HINT);
    if (!hLabel || !hHint || !GetDlgItem(hDlg, IDC_LAN_TIMEOUT) || !GetDlgItem(hDlg, IDC_LAN_TI) || !GetDlgItem(hDlg, IDC_SYSTEM))
        return;
    const RECT rLabel = GetRect(hDlg, IDC_LAN_TIMEOUT_LABEL);
    const RECT rEdit = GetRect(hDlg, IDC_LAN_TIMEOUT);
    const RECT rHint = GetRect(hDlg, IDC_LAN_TIMEOUT_HINT);
    const RECT rTi = GetRect(hDlg, IDC_LAN_TI);
    const RECT rSystem = GetRect(hDlg, IDC_SYSTEM);
    const RECT rGroup = GetRect(hDlg, IDC_LANPAIR_GROUP);
    const int gap = Gap(hDlg);

    const int labelW = RequiredWidth(hLabel);
    Move(hDlg, IDC_LAN_TIMEOUT_LABEL, rLabel.left, rLabel.top, labelW, Height(rLabel));
    const int editX = rLabel.left + labelW + gap;
    Move(hDlg, IDC_LAN_TIMEOUT, editX, rEdit.top, Width(rEdit), Height(rEdit));
    const int hintX = editX + Width(rEdit) + gap;
    Move(hDlg, IDC_LAN_TIMEOUT_HINT, hintX, rHint.top, RequiredWidth(hHint), Height(rHint));
    // The checkbox lines up with the System combo's column, unless that
    // leaves it too little room; it never starts before the hint ends.
    const int tiRight = rGroup.right - Scale(hDlg, 6);
    const int tiNeed = RequiredWidth(GetDlgItem(hDlg, IDC_LAN_TI));
    const int tiX = (std::max)(hintX + RequiredWidth(hHint) + gap,
                               (std::min)(static_cast<int>(rSystem.left), tiRight - tiNeed));
    if (tiRight > tiX)
        Move(hDlg, IDC_LAN_TI, tiX, rTi.top, tiRight - tiX, Height(rTi));
}

// Label/field forms: every field of the group starts at one column, just
// right of the longest label (never left of where the template put it), and
// keeps its right edge. Pairs with a missing control are skipped.
void AlignLabelColumn(HWND hDlg, std::initializer_list<std::pair<int, int>> pairs)
{
    const int gap = Gap(hDlg);
    int column = 0;
    for (const auto& [labelId, fieldId] : pairs) {
        HWND label = GetDlgItem(hDlg, labelId);
        if (!label || !GetDlgItem(hDlg, fieldId))
            continue;
        const RECT rl = GetRect(hDlg, labelId);
        const RECT rf = GetRect(hDlg, fieldId);
        column = (std::max)(column, (std::max)(static_cast<int>(rl.left) + RequiredWidth(label) + gap, static_cast<int>(rf.left)));
    }
    for (const auto& [labelId, fieldId] : pairs) {
        HWND field = GetDlgItem(hDlg, fieldId);
        if (!GetDlgItem(hDlg, labelId) || !field)
            continue;
        const RECT rl = GetRect(hDlg, labelId);
        const RECT rf = GetRect(hDlg, fieldId);
        Move(hDlg, labelId, rl.left, rl.top, column - gap - rl.left, Height(rl));
        if (rf.right > column)
            SetBounds(hDlg, field, column, rf.top, rf.right - column);
    }
}

// Group boxes that span the dialog end where the widest one does.
void AlignGroupRightEdges(HWND hDlg, int referenceId, std::initializer_list<int> groupIds)
{
    const RECT ref = GetRect(hDlg, referenceId);
    for (int id : groupIds) {
        if (!GetDlgItem(hDlg, id))
            continue;
        const RECT r = GetRect(hDlg, id);
        if (ref.right > r.right)
            Move(hDlg, id, r.left, r.top, ref.right - r.left, Height(r));
    }
}

// PHP TAR checkbox follows the permissions row to the group box edge.
void ArrangePhpTarCheckbox(HWND hDlg)
{
    if (!GetDlgItem(hDlg, IDC_PHP_TAR) || !GetDlgItem(hDlg, IDC_DIRMOD))
        return;
    const RECT rTar = GetRect(hDlg, IDC_PHP_TAR);
    const RECT rDirmod = GetRect(hDlg, IDC_DIRMOD);
    const RECT rGroup = GetRect(hDlg, IDC_PERMISSIONS_GROUP);
    const int x = rDirmod.right + Gap(hDlg) * 3;
    const int right = rGroup.right - Scale(hDlg, 6);
    if (right > x)
        Move(hDlg, IDC_PHP_TAR, x, rTar.top, right - x, Height(rTar));
}

} // namespace

void LayoutConnectionDialog(HWND hDlg)
{
    FitToText(hDlg);
    AlignGroupRightEdges(hDlg, IDC_LABEL_CERTGROUP, {IDC_PERMISSIONS_GROUP, IDC_LANPAIR_GROUP});
    ArrangeProtocolButtons(hDlg);
    ArrangeExpandLabel(hDlg, IDC_LABEL_CONNECTTO, IDC_PROTOAUTO);
    ArrangePasswordRow(hDlg, IDC_PASSLABEL, IDC_PASSWORDHELP, IDC_USEAGENT);
    ArrangePermissionsRow(hDlg, IDC_FILEMOD_LABEL, IDC_FILEMOD, IDC_DIRMOD_LABEL, IDC_DIRMOD, IDC_PERMISSIONS_GROUP);
    ArrangePhpTarCheckbox(hDlg);
    ArrangeLanTimeoutRow(hDlg);
    ArrangeExpandLabel(hDlg, IDC_CODEPAGELABEL, IDC_UTF8HELP);
    ArrangeExpandLabel(hDlg, IDC_LABEL_TRANSFER, IDC_TRANSFERMODE);
    ArrangeExpandLabel(hDlg, IDC_SYSTEMLABEL, IDC_SYSTEM);
    ArrangeLabelFillButton(hDlg, IDC_LABEL_SESSION, IDC_SESSIONNAME, IDC_PHPSHELL);
    ArrangeInlineRow(hDlg, IDC_LABEL_JUMPHOST_GRP, IDC_JUMP_ENABLE, IDC_JUMP_BUTTON, IDC_JUMP_SESSION_PICK);
    FixClippedRows(hDlg);
    InvalidateRect(hDlg, nullptr, TRUE);
}

void LayoutJumpHostDialog(HWND hDlg)
{
    FitToText(hDlg);
    AlignLabelColumn(hDlg, {{IDC_JUMP_LABEL_HOST, IDC_JUMP_HOST},
                            {IDC_JUMP_LABEL_USER, IDC_JUMP_USER},
                            {IDC_JUMP_LABEL_PASS, IDC_JUMP_PASSWORD},
                            {IDC_JUMP_LABEL_PASS, IDC_JUMP_EDITPASS}});
    FixClippedRows(hDlg);
    InvalidateRect(hDlg, nullptr, TRUE);
}

void LayoutProxyDialog(HWND hDlg)
{
    FitToText(hDlg);
    AlignLabelColumn(hDlg, {{IDC_PROXY_LABEL_HOST, IDC_PROXYSERVER},
                            {IDC_PROXY_LABEL_USER, IDC_PROXYUSERNAME},
                            {IDC_PROXY_LABEL_PASS, IDC_PROXYPASSWORD},
                            {IDC_PROXY_LABEL_PASS, IDC_EDITPASS}});
    FixClippedRows(hDlg);
    InvalidateRect(hDlg, nullptr, TRUE);
}

void LayoutPropertiesDialog(HWND hDlg)
{
    FitToText(hDlg);
    AlignLabelColumn(hDlg, {{IDC_PROP_LBL_NAME, IDC_PROP_NAME},
                            {IDC_PROP_LBL_OWNER, IDC_PROP_OWNER},
                            {IDC_PROP_LBL_GROUP, IDC_PROP_GROUP},
                            {IDC_PROP_LBL_PERMS, IDC_PROP_PERMISSIONS},
                            {IDC_PROP_LBL_SIZE, IDC_PROP_SIZE},
                            {IDC_PROP_LBL_MODIFIED, IDC_PROP_MODIFIED}});
    FixClippedRows(hDlg);
    InvalidateRect(hDlg, nullptr, TRUE);
}

void LayoutDownloadErrorDialog(HWND hDlg)
{
    FitToText(hDlg);
    // Command buttons: at least the standard 75 pixels, the default first.
    PackRight(hDlg, {IDC_DOWNLOAD_SKIP, IDC_DOWNLOAD_SKIP_ALL, IDCANCEL}, 75, 6);
    FixClippedRows(hDlg);
    InvalidateRect(hDlg, nullptr, TRUE);
}

} // namespace DlgLayout

// ---------------------------------------------------------------------------
// Row arrangements
// ---------------------------------------------------------------------------
using DlgLayout::Gap;
using DlgLayout::GetRect;
using DlgLayout::Move;
using DlgLayout::RequiredWidth;

void ArrangeInlineRow(HWND hDlg, int labelId, int checkId, int btnId, int comboId)
{
    HWND hLabel = GetDlgItem(hDlg, labelId);
    HWND hCheck = GetDlgItem(hDlg, checkId);
    HWND hBtn = GetDlgItem(hDlg, btnId);
    if (!hLabel || !hCheck || !hBtn)
        return;

    const RECT rLabel = GetRect(hDlg, labelId);
    const RECT rCheck = GetRect(hDlg, checkId);
    const RECT rBtn = GetRect(hDlg, btnId);
    RECT client{};
    GetClientRect(hDlg, &client);
    const int gap = Gap(hDlg);

    // Reading order: what the jump host is taken from, whether it is used,
    // how to inspect it. The button stays at the right edge, the checkbox sits
    // just left of it at its own width, and the dropdown - session names, the
    // part that really varies - gets everything between label and checkbox.
    const int labelW = RequiredWidth(hLabel);
    const int checkW = RequiredWidth(hCheck);
    const int btnW = (std::max)(static_cast<int>(rBtn.right - rBtn.left), RequiredWidth(hBtn));
    const int btnX = client.right - btnW - rLabel.left;
    const int checkX = btnX - gap - checkW;

    Move(hDlg, labelId, rLabel.left, rLabel.top, labelW, rLabel.bottom - rLabel.top);
    Move(hDlg, checkId, checkX, rCheck.top, checkW, rCheck.bottom - rCheck.top);
    Move(hDlg, btnId, btnX, rBtn.top, btnW, rBtn.bottom - rBtn.top);

    if (comboId) {
        const RECT rCombo = GetRect(hDlg, comboId);
        const int comboX = rLabel.left + labelW + gap;
        const int comboW = checkX - gap - comboX;
        // Narrower than this the dropdown is unusable; it then keeps its place.
        if (comboW >= DlgLayout::Scale(hDlg, 40))
            Move(hDlg, comboId, comboX, rCombo.top, comboW, rCombo.bottom - rCombo.top);
    }
}

void ArrangePasswordRow(HWND hDlg, int labelId, int helpBtnId, int checkId)
{
    HWND hLabel = GetDlgItem(hDlg, labelId);
    HWND hCheck = GetDlgItem(hDlg, checkId);
    if (!hLabel || !GetDlgItem(hDlg, helpBtnId) || !hCheck)
        return;

    const RECT rLabel = GetRect(hDlg, labelId);
    const RECT rHelp = GetRect(hDlg, helpBtnId);
    const RECT rCheck = GetRect(hDlg, checkId);
    RECT client{};
    GetClientRect(hDlg, &client);
    const int gap = Gap(hDlg);

    const int labelW = RequiredWidth(hLabel);
    const int helpX = rLabel.left + labelW + gap;
    const int checkW = RequiredWidth(hCheck);
    const int checkX = (std::max)(helpX + static_cast<int>(rHelp.right - rHelp.left) + gap,
                                  static_cast<int>(client.right) - static_cast<int>(rLabel.left) - checkW);

    Move(hDlg, labelId, rLabel.left, rLabel.top, labelW, rLabel.bottom - rLabel.top);
    Move(hDlg, helpBtnId, helpX, rHelp.top, rHelp.right - rHelp.left, rHelp.bottom - rHelp.top);
    Move(hDlg, checkId, checkX, rCheck.top, checkW, rCheck.bottom - rCheck.top);
}

void ArrangePermissionsRow(HWND hDlg, int leftLabelId, int leftEditId, int rightLabelId, int rightEditId, int groupId)
{
    HWND hLL = GetDlgItem(hDlg, leftLabelId);
    HWND hRL = GetDlgItem(hDlg, rightLabelId);
    if (!hLL || !GetDlgItem(hDlg, leftEditId) || !hRL || !GetDlgItem(hDlg, rightEditId) || !GetDlgItem(hDlg, groupId))
        return;

    const RECT rLL = GetRect(hDlg, leftLabelId);
    const RECT rLE = GetRect(hDlg, leftEditId);
    const RECT rRL = GetRect(hDlg, rightLabelId);
    const RECT rRE = GetRect(hDlg, rightEditId);
    const int gap = Gap(hDlg);
    const int editW = rLE.right - rLE.left;
    const int editH = rLE.bottom - rLE.top;
    const int labelH = rLL.bottom - rLL.top;

    // leftLabel -> leftEdit -> rightLabel -> rightEdit, each label as wide as its text.
    const int llW = RequiredWidth(hLL);
    const int leX = rLL.left + llW + gap;
    const int rlX = leX + editW + gap * 3;
    const int rlW = RequiredWidth(hRL);
    const int reX = rlX + rlW + gap;

    Move(hDlg, leftLabelId, rLL.left, rLL.top, llW, labelH);
    Move(hDlg, leftEditId, leX, rLE.top, editW, editH);
    Move(hDlg, rightLabelId, rlX, rRL.top, rlW, labelH);
    Move(hDlg, rightEditId, reX, rRE.top, editW, editH);
}

void ArrangeExpandLabel(HWND hDlg, int labelId, int fixedNextId)
{
    HWND hLabel = GetDlgItem(hDlg, labelId);
    if (!hLabel || !GetDlgItem(hDlg, fixedNextId))
        return;

    const RECT rLabel = GetRect(hDlg, labelId);
    const RECT rNext = GetRect(hDlg, fixedNextId);
    const int newW = rNext.left - rLabel.left - Gap(hDlg);
    if (newW <= 0)
        return;
    Move(hDlg, labelId, rLabel.left, rLabel.top, newW, rLabel.bottom - rLabel.top);

    if (RequiredWidth(hLabel) > newW) {
        // "Connect to: (server/path or server:port/path)": the explanation in
        // parentheses goes first, then whatever still overflows ends in "...".
        if (labelId == IDC_LABEL_CONNECTTO) {
            std::array<wchar_t, 256> buf{};
            GetWindowTextW(hLabel, buf.data(), static_cast<int>(buf.size()) - 1);
            std::wstring s(buf.data());
            const size_t pos = s.find(L" (");
            if (pos != std::wstring::npos)
                SetWindowTextW(hLabel, s.substr(0, pos).c_str());
        }
        const LONG_PTR style = GetWindowLongPtrW(hLabel, GWL_STYLE);
        if (!(style & SS_ENDELLIPSIS))
            SetWindowLongPtrW(hLabel, GWL_STYLE, style | SS_ENDELLIPSIS);
    }
}

void ArrangeLabelFillButton(HWND hDlg, int labelId, int fillId, int btnId)
{
    HWND hLabel = GetDlgItem(hDlg, labelId);
    HWND hBtn = GetDlgItem(hDlg, btnId);
    if (!hLabel || !GetDlgItem(hDlg, fillId) || !hBtn)
        return;

    const RECT rLabel = GetRect(hDlg, labelId);
    const RECT rFill = GetRect(hDlg, fillId);
    const RECT rBtn = GetRect(hDlg, btnId);
    const int gap = Gap(hDlg);

    // The button keeps its right edge and widens leftwards for a longer label
    // ("Shell..." becomes "Pair..." in LAN mode, and both are translated).
    const int btnW = (std::max)(static_cast<int>(rBtn.right - rBtn.left), RequiredWidth(hBtn));
    const int btnX = rBtn.right - btnW;
    const int labelW = RequiredWidth(hLabel);
    const int fillX = rLabel.left + labelW + gap;
    const int fillW = btnX - gap - fillX;

    Move(hDlg, labelId, rLabel.left, rLabel.top, labelW, rLabel.bottom - rLabel.top);
    Move(hDlg, btnId, btnX, rBtn.top, btnW, rBtn.bottom - rBtn.top);
    if (fillW > 0)
        Move(hDlg, fillId, fillX, rFill.top, fillW, rFill.bottom - rFill.top);
}

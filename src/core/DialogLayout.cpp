#include "DialogLayout.h"
#include <algorithm>
#include <string>
#include <array>
#include "../res/resource.h"

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

int DlgLayout::MeasureText(HWND hDlg, HWND hCtrl)
{
    wchar_t buf[256] = {};
    GetWindowTextW(hCtrl, buf, 255);
    HDC   hdc  = GetDC(hDlg);
    HFONT hOld = reinterpret_cast<HFONT>(
        SelectObject(hdc, reinterpret_cast<HFONT>(SendMessage(hDlg, WM_GETFONT, 0, 0))));
    SIZE sz{};
    GetTextExtentPoint32W(hdc, buf, static_cast<int>(wcslen(buf)), &sz);
    SelectObject(hdc, hOld);
    ReleaseDC(hDlg, hdc);
    return sz.cx;
}

RECT DlgLayout::GetRect(HWND hDlg, int ctrlId)
{
    RECT r{};
    HWND h = GetDlgItem(hDlg, ctrlId);
    if (h) {
        GetWindowRect(h, &r);
        MapWindowPoints(nullptr, hDlg, reinterpret_cast<POINT*>(&r), 2);
    }
    return r;
}

void DlgLayout::Move(HWND hDlg, int ctrlId, int x, int y, int w, int h)
{
    HWND hw = GetDlgItem(hDlg, ctrlId);
    if (hw)
        SetWindowPos(hw, nullptr, x, y, w, h, SWP_NOZORDER);
}

// ---------------------------------------------------------------------------
// Arrangements
// ---------------------------------------------------------------------------

void ArrangeInlineRow(HWND hDlg, int labelId, int checkId, int btnId)
{
    HWND hLabel = GetDlgItem(hDlg, labelId);
    HWND hCheck = GetDlgItem(hDlg, checkId);
    HWND hBtn   = GetDlgItem(hDlg, btnId);
    if (!hLabel || !hCheck || !hBtn)
        return;

    const int  szLabel = DlgLayout::MeasureText(hDlg, hLabel);
    const int  szCheck = DlgLayout::MeasureText(hDlg, hCheck);
    const RECT rLabel  = DlgLayout::GetRect(hDlg, labelId);
    const RECT rCheck  = DlgLayout::GetRect(hDlg, checkId);
    const RECT rBtn    = DlgLayout::GetRect(hDlg, btnId);
    RECT rDlg{};
    GetClientRect(hDlg, &rDlg);

    const int scaledBoxW = rCheck.bottom - rCheck.top;

    const int labelX    = rLabel.left;
    const int labelW    = szLabel + DlgLayout::kGap;
    const int checkX    = labelX + labelW + DlgLayout::kGap;
    const int btnW      = rBtn.right  - rBtn.left;
    const int btnH      = rBtn.bottom - rBtn.top;
    const int rawBtnX   = checkX + scaledBoxW + szCheck + DlgLayout::kGap * 2;
    const int finalBtnX = (std::min)(rawBtnX, (int)rDlg.right - btnW - DlgLayout::kGap);
    const int checkW    = (std::max)(finalBtnX - DlgLayout::kGap - checkX, scaledBoxW + 4);

    DlgLayout::Move(hDlg, labelId, labelX,    rLabel.top, labelW, rLabel.bottom - rLabel.top);
    DlgLayout::Move(hDlg, checkId, checkX,    rCheck.top, checkW, rCheck.bottom - rCheck.top);
    DlgLayout::Move(hDlg, btnId,   finalBtnX, rBtn.top,   btnW,   btnH);
}

void ArrangePasswordRow(HWND hDlg, int labelId, int helpBtnId, int checkId)
{
    HWND hLabel = GetDlgItem(hDlg, labelId);
    HWND hHelp  = GetDlgItem(hDlg, helpBtnId);
    HWND hCheck = GetDlgItem(hDlg, checkId);
    if (!hLabel || !hHelp || !hCheck)
        return;

    const int  szLabel = DlgLayout::MeasureText(hDlg, hLabel);
    const RECT rLabel  = DlgLayout::GetRect(hDlg, labelId);
    const RECT rHelp   = DlgLayout::GetRect(hDlg, helpBtnId);
    const RECT rCheck  = DlgLayout::GetRect(hDlg, checkId);
    RECT rDlg{};
    GetClientRect(hDlg, &rDlg);

    const int  szCheck = DlgLayout::MeasureText(hDlg, hCheck);
    const int labelX = rLabel.left;
    const int labelW = szLabel + DlgLayout::kGap;
    const int helpX  = labelX + labelW;
    const int helpW  = rHelp.right  - rHelp.left;
    const int helpH  = rHelp.bottom - rHelp.top;

    // Checkbox right-anchored: text measured, placed at dialog right edge.
    const int checkW = DlgLayout::kBoxW + szCheck + DlgLayout::kGap * 2;
    const int checkX = rDlg.right - checkW - DlgLayout::kGap;

    DlgLayout::Move(hDlg, labelId,   labelX, rLabel.top,  labelW, rLabel.bottom - rLabel.top);
    DlgLayout::Move(hDlg, helpBtnId, helpX,  rHelp.top,   helpW,  helpH);
    DlgLayout::Move(hDlg, checkId,   checkX, rCheck.top,  checkW, rCheck.bottom - rCheck.top);
}

void ArrangePermissionsRow(HWND hDlg,
    int leftLabelId, int leftEditId,
    int rightLabelId, int rightEditId,
    int groupId)
{
    HWND hLL  = GetDlgItem(hDlg, leftLabelId);
    HWND hLE  = GetDlgItem(hDlg, leftEditId);
    HWND hRL  = GetDlgItem(hDlg, rightLabelId);
    HWND hRE  = GetDlgItem(hDlg, rightEditId);
    HWND hGrp = GetDlgItem(hDlg, groupId);
    if (!hLL || !hLE || !hRL || !hRE || !hGrp)
        return;

    const int  szLL  = DlgLayout::MeasureText(hDlg, hLL);
    const int  szRL  = DlgLayout::MeasureText(hDlg, hRL);
    const RECT rLL   = DlgLayout::GetRect(hDlg, leftLabelId);
    const RECT rLE   = DlgLayout::GetRect(hDlg, leftEditId);
    const RECT rRL   = DlgLayout::GetRect(hDlg, rightLabelId);
    const RECT rRE   = DlgLayout::GetRect(hDlg, rightEditId);
    const RECT rGrp  = DlgLayout::GetRect(hDlg, groupId);

    const int editW  = rLE.right  - rLE.left;
    const int editH  = rLE.bottom - rLE.top;
    const int labelH = rLL.bottom - rLL.top;

    // Left-to-right flow: leftLabel → leftEdit → rightLabel → rightEdit
    const int llX = rLL.left;
    const int llW = szLL + DlgLayout::kGap;
    const int leX = llX + llW + DlgLayout::kGap;
    const int rlX = leX + editW + DlgLayout::kGap * 3;
    const int rlW = szRL + DlgLayout::kGap;
    const int reX = rlX + rlW + DlgLayout::kGap;

    DlgLayout::Move(hDlg, leftLabelId,  llX, rLL.top, llW,   labelH);
    DlgLayout::Move(hDlg, leftEditId,   leX, rLE.top, editW, editH);
    DlgLayout::Move(hDlg, rightLabelId, rlX, rRL.top, rlW,   labelH);
    DlgLayout::Move(hDlg, rightEditId,  reX, rRE.top, editW, editH);
}

void ArrangeExpandLabel(HWND hDlg, int labelId, int fixedNextId)
{
    HWND hLabel = GetDlgItem(hDlg, labelId);
    if (!hLabel) return;

    const RECT rLabel = DlgLayout::GetRect(hDlg, labelId);
    const RECT rNext  = DlgLayout::GetRect(hDlg, fixedNextId);
    const int  newW   = rNext.left - rLabel.left - DlgLayout::kGap;
    
    if (newW > 0) {
        DlgLayout::Move(hDlg, labelId,
            rLabel.left, rLabel.top, newW, rLabel.bottom - rLabel.top);

        int textW = DlgLayout::MeasureText(hDlg, hLabel);
        if (textW > newW) {
            if (labelId == IDC_LABEL_CONNECTTO) {
                std::array<wchar_t, 256> buf{};
                GetWindowTextW(hLabel, buf.data(), static_cast<int>(buf.size()) - 1);
                std::wstring s(buf.data());
                size_t pos = s.find(L" (");
                if (pos != std::wstring::npos) {
                    s = s.substr(0, pos);
                    SetWindowTextW(hLabel, s.c_str());
                }
            }
            
            // Add SS_ENDELLIPSIS so any remaining overflow is gracefully dotted
            LONG_PTR style = GetWindowLongPtr(hLabel, GWL_STYLE);
            if (!(style & SS_ENDELLIPSIS)) {
                SetWindowLongPtr(hLabel, GWL_STYLE, style | SS_ENDELLIPSIS);
            }
        }
    }
}

void ArrangeLabelFillButton(HWND hDlg, int labelId, int fillId, int btnId)
{
    HWND hLabel = GetDlgItem(hDlg, labelId);
    if (!hLabel)
        return;

    const int  szLabel = DlgLayout::MeasureText(hDlg, hLabel);
    const RECT rLabel  = DlgLayout::GetRect(hDlg, labelId);
    const RECT rFill   = DlgLayout::GetRect(hDlg, fillId);
    const RECT rBtn    = DlgLayout::GetRect(hDlg, btnId);

    const int labelX = rLabel.left;
    const int labelW = szLabel + DlgLayout::kGap;
    const int fillX  = labelX + labelW + DlgLayout::kGap;
    const int fillW  = rBtn.left - DlgLayout::kGap - fillX;

    DlgLayout::Move(hDlg, labelId, labelX, rLabel.top, labelW, rLabel.bottom - rLabel.top);
    if (fillW > 0)
        DlgLayout::Move(hDlg, fillId, fillX, rFill.top, fillW, rFill.bottom - rFill.top);
}

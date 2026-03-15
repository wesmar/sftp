#pragma once
#include <windows.h>

// Low-level primitives — used by the Arrange* functions below.
namespace DlgLayout {
    constexpr int kGap  = 4;   // pixels between adjacent controls
    constexpr int kBoxW = 16;  // checkbox square width in pixels

    int  MeasureText(HWND hDlg, HWND hCtrl);
    RECT GetRect    (HWND hDlg, int  ctrlId);
    void Move       (HWND hDlg, int  ctrlId, int x, int y, int w, int h);
}

// label(text-sized) → checkbox(fill) → button(after checkbox text, clamped right)
void ArrangeInlineRow(HWND hDlg, int labelId, int checkId, int btnId);

// label(text-sized) → helpBtn(fixed) → checkbox(fill to right edge)
void ArrangePasswordRow(HWND hDlg, int labelId, int helpBtnId, int checkId);

// leftLabel(text) leftEdit | rightLabel(text) rightEdit(right-anchored to groupbox)
void ArrangePermissionsRow(HWND hDlg,
    int leftLabelId, int leftEditId,
    int rightLabelId, int rightEditId,
    int groupId);

// Expand label width to fill the available space before fixedNextId.
void ArrangeExpandLabel(HWND hDlg, int labelId, int fixedNextId);

// label(text-sized) → fill-ctrl(stretch to button) → button(stays at current position)
void ArrangeLabelFillButton(HWND hDlg, int labelId, int fillId, int btnId);

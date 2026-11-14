#pragma once
#include <windows.h>

// Layout of the plugin's dialogs: per-monitor DPI, widths driven by the text
// of whichever language is loaded, and the Windows 11 caption.
//
// Order of work for a dialog:
//   1. its texts are set (LocalizeDlgControls);
//   2. Layout<Dialog>() widens the dialog until every text fits, runs the
//      row arrangements that express how each row is meant to read, and
//      finally gives any control that still clips room from a stretchable
//      neighbour;
//   3. after a change of DPI, visibility or text, the same call runs again.
namespace DlgLayout {

// Posted to a dialog after WM_DPICHANGED, once the system has rescaled it.
constexpr UINT kRelayoutMessage = WM_APP + 78;
// WM_DPICHANGED; the project's WINVER predates the SDK declaring it.
constexpr UINT kDpiChangedMessage = 0x02E0;

// Effective DPI of a window (the system DPI before Windows 10 1607).
UINT DpiOf(HWND hwnd);
// `value96` pixels at 96 DPI, scaled to the window's DPI.
int Scale(HWND hwnd, int value96);
// Gap between adjacent controls at the window's DPI.
int Gap(HWND hwnd);

// Width of the control's text alone, in its own font, mnemonics excluded.
int  MeasureText(HWND hDlg, HWND hCtrl);
// Width the control needs to show all of its text: text plus the check box
// or radio glyph, or a button's padding. Controls whose width is not
// text-driven (edits, combo boxes, wrapping statics) report their width.
int  RequiredWidth(HWND hCtrl);
RECT GetRect(HWND hDlg, int ctrlId);
void Move(HWND hDlg, int ctrlId, int x, int y, int w, int h);

// Widens the dialog, within its monitor's work area, until every row of
// visible controls can hold its texts. Controls right of the dialog's middle
// move with the new edge; controls across the middle stretch.
// Returns the pixels added (never shrinks).
int FitToText(HWND hDlg);

// Grows every visible control that still clips its text, into free space or
// into room taken from the nearest edit or combo box to its right. A static
// that cannot get enough room ends in an ellipsis.
void FixClippedRows(HWND hDlg);

// Rounded corners and a Mica caption on Windows 11; no effect elsewhere.
void ApplyWindowChrome(HWND hDlg);

// Total Commander runs system-DPI aware, so its own windows are stretched by
// the system on monitors with another scale. The plugin's dialogs are
// created per-monitor aware (V2) instead and stay sharp on every monitor.
// Wrap the DialogBox* call; WM_INITDIALOG then calls ReleaseEarly(), so
// windows the modal loop creates afterwards (Total Commander's own prompts)
// get the host's mode again.
class PerMonitorDpiScope {
public:
    PerMonitorDpiScope() noexcept;
    ~PerMonitorDpiScope();
    PerMonitorDpiScope(const PerMonitorDpiScope&) = delete;
    PerMonitorDpiScope& operator=(const PerMonitorDpiScope&) = delete;
    static void ReleaseEarly() noexcept;

private:
    void Restore() noexcept;
    HANDLE previous_ = nullptr;
    bool active_ = false;
    PerMonitorDpiScope* outer_ = nullptr;
};

// Common WM_INITDIALOG work: releases the DPI scope and applies the chrome.
void OnInitDialog(HWND hDlg);

// Complete layouts of the plugin's dialogs (FitToText, the row arrangements,
// FixClippedRows). Safe to call again at any time.
void LayoutConnectionDialog(HWND hDlg);
void LayoutJumpHostDialog(HWND hDlg);
void LayoutProxyDialog(HWND hDlg);
void LayoutPropertiesDialog(HWND hDlg);
void LayoutDownloadErrorDialog(HWND hDlg);

} // namespace DlgLayout

// Row arrangements, DPI aware. Each places one row the way it is meant to
// read; the controls outside the row are not touched.

// label(text-sized) -> optional combo(fill) -> checkbox(text-sized) -> button(right-anchored)
void ArrangeInlineRow(HWND hDlg, int labelId, int checkId, int btnId, int comboId = 0);
// label(text-sized) -> helpBtn(fixed) ... checkbox(right-anchored)
void ArrangePasswordRow(HWND hDlg, int labelId, int helpBtnId, int checkId);
// leftLabel(text) leftEdit | rightLabel(text) rightEdit
void ArrangePermissionsRow(HWND hDlg, int leftLabelId, int leftEditId, int rightLabelId, int rightEditId, int groupId);
// label grows into the space before fixedNextId; an overflow ends in "..."
void ArrangeExpandLabel(HWND hDlg, int labelId, int fixedNextId);
// label(text-sized) -> fill-ctrl(stretch) -> button(right edge kept, widened for its text)
void ArrangeLabelFillButton(HWND hDlg, int labelId, int fillId, int btnId);

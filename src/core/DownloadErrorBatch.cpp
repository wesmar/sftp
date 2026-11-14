#include "global.h"
#include <windows.h>
#include <string>
#include "DownloadErrorBatch.h"
#include "DialogLayout.h"
#include "DialogStrings.h"
#include "DialogText.h"
#include "PluginEntryPoints.h"
#include "res/resource.h"

namespace {

thread_local unsigned t_batchDepth = 0;
thread_local bool t_skipAll = false;

INT_PTR CALLBACK DownloadErrorDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case DlgLayout::kDpiChangedMessage:
        PostMessageW(hDlg, DlgLayout::kRelayoutMessage, 0, 0);
        return FALSE;
    case DlgLayout::kRelayoutMessage:
        DlgLayout::LayoutDownloadErrorDialog(hDlg);
        return TRUE;
    case WM_INITDIALOG:
        LocalizeDlgControls(hDlg, kDownloadErrorDialogCaption, kDownloadErrorDialogStrings);
        SetDlgItemTextW(hDlg, IDC_DOWNLOAD_ERROR_PATH, reinterpret_cast<LPCWSTR>(lParam));
        DlgLayout::OnInitDialog(hDlg);
        DlgLayout::LayoutDownloadErrorDialog(hDlg);
        // Focus on Skip, so the read-only path does not open selected.
        SetFocus(GetDlgItem(hDlg, IDC_DOWNLOAD_SKIP));
        return FALSE;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_DOWNLOAD_SKIP:
        case IDC_DOWNLOAD_SKIP_ALL:
        case IDCANCEL:
            EndDialog(hDlg, LOWORD(wParam));
            return TRUE;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return FALSE;
}

// The window the question belongs to: the transfer's own progress window when
// this thread has one, Total Commander's main window otherwise.
HWND QuestionOwner() noexcept
{
    if (HWND active = GetActiveWindow())
        return GetAncestor(active, GA_ROOTOWNER);
    return FindWindowW(L"TTOTAL_CMD", nullptr);
}

INT_PTR AskUser(LPCWSTR remoteName)
{
    DlgLayout::PerMonitorDpiScope dpiScope;
    return DialogBoxParamW(hinst, MAKEINTRESOURCEW(IDD_DOWNLOAD_ERROR), QuestionOwner(),
                           DownloadErrorDlgProc, reinterpret_cast<LPARAM>(remoteName ? remoteName : L""));
}

void LogSkipped(LPCWSTR remoteName)
{
    std::wstring line = LoadResStringW(IDS_LOG_DOWNLOAD_SKIPPED);
    if (line.empty())
        line = L"Skipped after a download error:";
    line += L' ';
    line += remoteName ? remoteName : L"";
    if (LogProcW) {
        LogProcW(PluginNumber, MSGTYPE_IMPORTANTERROR, line.data());
    } else if (LogProc) {
        const int n = WideCharToMultiByte(CP_ACP, 0, line.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (n > 0) {
            std::string ansi(static_cast<size_t>(n), '\0');
            WideCharToMultiByte(CP_ACP, 0, line.c_str(), -1, ansi.data(), n, nullptr, nullptr);
            LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, ansi.data());
        }
    }
}

} // namespace

namespace download_batch {

void Begin() noexcept
{
    if (t_batchDepth++ == 0)
        t_skipAll = false;
}

void End() noexcept
{
    if (t_batchDepth > 0 && --t_batchDepth == 0)
        t_skipAll = false;
}

int ResolveReadError(LPCWSTR remoteName, LPCWSTR localName, bool move, bool resume)
{
    if (move || resume || t_batchDepth == 0)
        return FS_FILE_READERROR;

    if (!t_skipAll) {
        switch (AskUser(remoteName)) {
        case IDC_DOWNLOAD_SKIP:
            break;
        case IDC_DOWNLOAD_SKIP_ALL:
            t_skipAll = true;
            break;
        case IDCANCEL:
            return FS_FILE_USERABORT;
        default: // the question could not be shown: the plain error stands
            return FS_FILE_READERROR;
        }
    }

    // A skipped file leaves nothing behind that could pass for a download.
    if (localName && localName[0] && !DeleteFileW(localName)) {
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
            return FS_FILE_WRITEERROR;
    }
    LogSkipped(remoteName);
    return FS_FILE_OK;
}

} // namespace download_batch

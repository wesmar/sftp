#include "global.h"
#include <windows.h>
#include <span>
#include <string>
#include "DialogText.h"
#include "LngLoader.h"
#include "PluginEntryPoints.h"

std::wstring LoadResStringW(UINT id)
{
    return LngLoadString(hinst, id);
}

void LocalizeDlgControls(HWND hDlg, UINT captionId, std::span<const DialogString> controls)
{
    if (const std::wstring caption = LoadResStringW(captionId); !caption.empty())
        SetWindowTextW(hDlg, caption.c_str());
    for (const auto& c : controls) {
        if (const std::wstring text = LoadResStringW(c.string); !text.empty())
            SetDlgItemTextW(hDlg, c.control, text.c_str());
    }
}

#pragma once

#include <windows.h>
#include <span>
#include <string>
#include "DialogStrings.h"

// Text of the plugin's windows in the loaded language: the .lng translation
// first, the English string table otherwise; empty when neither has it.
std::wstring LoadResStringW(UINT id);

// Sets a dialog's caption and the listed controls from LoadResStringW. A
// string with no text leaves what the dialog template says.
void LocalizeDlgControls(HWND hDlg, UINT captionId, std::span<const DialogString> controls);

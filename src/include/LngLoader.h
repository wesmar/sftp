#pragma once

#include <windows.h>
#include <string>

// Load a lang_XX.lng file matching langId from the directory that contains
// the plugin DLL.  Call this once in FsInitW after the language is resolved.
// The loaded strings are held in an in-process map.
void LngLoadForLanguage(LANGID langId, HINSTANCE hPluginInst) noexcept;

// Return the translated string for id, or nullptr if no .lng override exists.
// The returned pointer is valid for the lifetime of the process.
const char* LngGetString(UINT id) noexcept;

#pragma once

#include <windows.h>
#include <string>

// Load a lang_XX.lng file matching langId from the directory that contains
// the plugin DLL.  Call this once in FsInitW after the language is resolved.
// The loaded strings are held in an in-process map.
void LngLoadForLanguage(LANGID langId, HINSTANCE hPluginInst) noexcept;

// Load a .lng file by explicit filename stem (e.g. "fin" loads language\fin.lng).
// Used for custom/unsupported languages specified via Language= in sftpplug.ini.
void LngLoadByCode(const char* code, HINSTANCE hPluginInst) noexcept;

// Return the translated string for id, or nullptr if no .lng override exists.
// The returned pointer is valid for the lifetime of the process.
const char* LngGetString(UINT id) noexcept;

// Load a wide string: tries .lng (UTF-8) first, falls back to LoadStringW.
bool LngLoadStringW(HINSTANCE hInst, UINT id, WCHAR* buf, int bufLen) noexcept;

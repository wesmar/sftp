#pragma once
// ============================================================
//  Single source of truth for plugin version.
//  Used by both sftpplug.rc (VERSIONINFO) and C++ code.
// ============================================================

#define VER_MAJOR       1
#define VER_MINOR       0
#define VER_PATCH       0
#define VER_BUILD       14

// Comma-separated form for FILEVERSION / PRODUCTVERSION
#define VER_FILEVERSION         VER_MAJOR, VER_MINOR, VER_PATCH, VER_BUILD

// Dot-separated strings for StringFileInfo VALUE fields
#define VER_FILEVERSION_STR     "1.0.0.15"
#define VER_PRODUCTVERSION_STR  "1.0.0.15"

// Wide-string variant for C++ runtime use (optional)
#define VER_FILEVERSION_WSTR    L"1.0.0.15"

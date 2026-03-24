#pragma once
// ============================================================
//  Single source of truth for plugin version.
//  Used by both sftpplug.rc (VERSIONINFO) and C++ code.
// ============================================================

#define VER_MAJOR       10
#define VER_MINOR       0
#define VER_PATCH       0
#define VER_BUILD       17

// Comma-separated form for FILEVERSION / PRODUCTVERSION
#define VER_FILEVERSION         VER_MAJOR, VER_MINOR, VER_PATCH, VER_BUILD

// Dot-separated strings for StringFileInfo VALUE fields
#define VER_FILEVERSION_STR     "10.0.0.17"
#define VER_PRODUCTVERSION_STR  "10.0.0.17"

// Wide-string variant for C++ runtime use (optional)
#define VER_FILEVERSION_WSTR    L"10.0.0.17"

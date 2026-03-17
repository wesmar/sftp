#pragma once
#include <string>

// Ensures kitty-decryptpassword.exe is present in the KiTTY Portable folder.
// If already there, returns the path immediately.
// Otherwise: adds a Windows Defender path exclusion via WMI/COM for the
// KiTTY root folder, then extracts the exe from the embedded CAB resource.
// Returns the full path to the exe, or empty string on failure.
std::string EnsureKittyDecryptExe(const std::string& sessionFilePath);

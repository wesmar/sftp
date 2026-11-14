#pragma once

#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "IExternalSessionSource.h"

namespace sftp {

// Return true if `iniPath` holds a section named `section` with a non-empty
// `server` or `user` key. Used to detect collision when materialising a
// virtual/imported session into the plugin's own sftpplug.ini, and to answer
// the same "does this saved session exist?" question for adapters whose
// import flow needs to pick a unique name.
bool IniSectionExists(const std::string& section, LPCSTR iniPath) noexcept;

// Callback invoked once per regular file discovered under `root`.
//   fullPath  absolute path (backslash-joined).
//   relPath   path relative to `root`, joined with '/', without the file
//             extension — ready to use as a DisplayName segment (e.g.
//             "team/aws/prod").
// Return `true` to continue walking, `false` to stop.
using WalkFileCallback = std::function<bool(const std::wstring& fullPath,
                                             const std::string& relPath)>;

// Recursively enumerate `root`. Every regular file whose extension matches
// `ext` (case-insensitive, without a leading dot; empty ⇒ any) is passed to
// `onFile`. Symlinks and directories are traversed but never reported.
void WalkDirectoryFiles(const std::wstring& root,
                        const std::wstring& ext,
                        WalkFileCallback     onFile);

// Change stamps for IExternalSessionSource::ChangeStamp: names joined with
// their last-write times, so an edit, an addition or a removal changes the
// string. A path that does not exist contributes a marker of its own, so
// its appearing later changes the stamp too.
std::string FileChangeStamp(const std::vector<std::wstring>& files);
// Every file under `root`, at any depth.
std::string FolderChangeStamp(const std::wstring& root);
// A key under HKEY_CURRENT_USER and each of its direct subkeys. A subkey's
// time moves when one of its values is written, which is how PuTTY and
// WinSCP store an edited session.
std::string RegistryChangeStamp(const char* subKey);
// A user-supplied path as the pickers deliver it (ANSI), widened.
std::wstring AnsiPathToWide(const std::string& path);

// Modern shell folder picker. `title` and `initialPath` are ANSI (CP_ACP);
// the returned `outPath` is ANSI. Returns false if the user cancelled or the
// selection could not be resolved to a filesystem path (e.g. namespace-only).
bool BrowseForFolder(HWND               owner,
                     const char*        title,
                     const char*        initialPath,
                     std::string&       outPath);

// Single-file picker via GetOpenFileNameW. `filter` is a NUL-separated Win32
// filter string ("Session files\0*.reg\0All files\0*.*\0"); the terminating
// double-NUL is required. `initialPath` may be a full file path (splits into
// directory + name) or a bare directory. Returns false on cancel.
bool BrowseForFile(HWND               owner,
                   const char*        title,
                   const char*        filter,
                   const char*        initialPath,
                   std::string&       outPath);

// Parse a PuTTY-style `LineCodePage` value ("UTF-8", "KOI8-R", "ISO-8859-2",
// "CP1251", "WIN-1252", "Windows-1250", …) into the two-field representation
// the plugin's INI uses: `outUtf8` is 0 or 1 (feeds `utf8=` INI key), and
// `outCodepage` is a numeric Windows codepage (feeds `codepage=`). Returns
// false with (0, 0) on empty / unrecognised input — caller leaves existing
// settings untouched. `outUtf8=1` implies `outCodepage=0`; mutually
// exclusive by contract.
bool ParseLineCodePage(const std::string& raw,
                       int& outUtf8, int& outCodepage) noexcept;

// Fills the proxy part of `dep` — type, address, user — so the session can
// be copied with its proxy. The port is spelled out only when it differs
// from the one the plugin assumes for that type; 0 means the source gave
// none. An empty host leaves `dep` alone.
void DescribeProxy(Proxy type, const std::string& host, DWORD port,
                   const std::string& user, SessionDependency& dep);

// PuTTY's proxy numbering, which KiTTY and WinSCP share: `ProxyMethod` 1 is
// SOCKS4, 2 SOCKS5, 3 HTTP. For those it fills the proxy part of `dep` —
// type, address, user — so the session can be copied with its proxy.
// Telnet (4), a local command (5) and an SSH jump host (6) are left alone:
// they are not proxies the plugin can rebuild, and stay a refusal.
// `port` 0 means the source stored none; PuTTY then uses 80.
void DescribePuttyProxy(DWORD method, const std::string& host, DWORD port,
                        const std::string& user, SessionDependency& dep);

// Route an imported key-file path into the right slot of the plugin's
// connect settings. `.pub` → public-key sidecar; anything else →
// private key (covers `.ppk`, `.pem`, and bare OpenSSH paths without
// an extension). `outPriv` / `outPub` are the connect-settings string
// fields; only the matching one is written, the other is left alone.
// Empty `path` is a no-op.
void AssignImportedKeyFile(const std::string& path,
                            std::string& outPriv,
                            std::string& outPub);

// Percent-decoder for the PuTTY-style on-disk name scheme. Malformed
// `%XX` runs pass through untouched.
std::string PuttyUrlDecode(const std::string& encoded);

// Percent-encoder for the PuTTY-style scheme. Escapes any byte < 0x20 or
// > 0x7E, plus space / `%` / `\` / `*` / `?`, plus a leading `.`.
std::string PuttyUrlEncode(const std::string& raw);

// Hex nibble to int. Returns -1 on non-hex input.
int  HexNibble(char c) noexcept;

// REG_SZ / REG_EXPAND_SZ reader that trims trailing NULs. Returns false
// when the value is absent, wrong-typed, or empty.
bool ReadRegString(HKEY key, const char* valueName, std::string& out);

// REG_DWORD reader. Returns false when the value is absent or wrong-typed.
bool ReadRegDword(HKEY key, const char* valueName, DWORD& out) noexcept;

// ExpandEnvironmentStrings wrapper that returns the input unchanged if
// expansion fails or the input is empty.
std::string ExpandEnvA(const std::string& raw);

// FNV-1a 32-bit hash. Used for channel-tag hashing in the import cache and
// for the virtual-session alias suffix.
uint32_t Fnv1aHash(std::string_view s) noexcept;

// Overwrite a buffer that held a decrypted password before it returns to the
// allocator, so the plaintext does not linger in freed memory, a crash dump or
// the hibernation file. Best effort by nature: it reaches the copy we own, not
// whatever the decoder kept inside itself.
void SecureWipe(std::string& s) noexcept;
void SecureWipe(std::vector<char>& v) noexcept;

// Wipes on the way out, whichever way out that is. Declare it after the
// string it guards, so it runs while that string is still alive. Functions
// holding a secret usually grow an early return sooner or later, and this
// keeps the next one from quietly skipping the wipe.
class ScopedWipe {
public:
    explicit ScopedWipe(std::string& s) noexcept : s_(&s) {}
    ~ScopedWipe() noexcept { if (s_) SecureWipe(*s_); }
    ScopedWipe(const ScopedWipe&)            = delete;
    ScopedWipe& operator=(const ScopedWipe&) = delete;
private:
    std::string* s_;
};

}  // namespace sftp

#pragma once

#include "IExternalSessionSource.h"

namespace sftp {

// KiTTY session source — https://www.9bis.net/kitty/
//
// KiTTY does not use the registry: every session lives as a plain-text
// `Key\Value\` file under `<install-dir>\Sessions\<url-encoded name>`.
// The install directory is wherever the user unpacked the ZIP — there
// is no canonical Program Files layout.
//
// Standard channel: probe a handful of common install locations
//   %APPDATA%\KiTTY\Sessions\
//   %LOCALAPPDATA%\KiTTY\Sessions\
//   %USERPROFILE%\KiTTY\Sessions\
// If none of them holds sessions, fall back to HKCR\.kitty — KiTTY
// installers usually register a file association for `.kitty`
// scripts, whose handler command line points at the KiTTY exe.
// Portable ZIP extracts skip the registration; those users reach the
// source via the custom-path channel.
//
// Custom channel: user picks a folder. If it is already a `Sessions`
// directory we use it verbatim; if it is the KiTTY install root
// (contains `kitty.exe` and a `Sessions\` sibling) we descend one
// level automatically. Both flows are documented so users do not
// have to know which folder to point at.
//
// Field mapping (KiTTY → tConnectSettings):
//   HostName / PortNumber / UserName        → server / server-suffix / user
//   Protocol=ssh                             → accepted (others skipped)
//   PublicKeyFile                            → private / public key (shared
//                                              AssignImportedKeyFile — routes
//                                              `.pub` to pubkeyfile, all
//                                              other paths to privkeyfile)
//   AgentFwd / AuthAgent                     → useagent
//   LineCodePage                             → utf8 / codepage (shared
//                                              ParseLineCodePage)
//   EnterSendsCrLf                           → unixlinebreaks
//   Password + TerminalType                  → password (KiTTY's own
//                                              reversible obfuscation is
//                                              decoded by our built-in
//                                              KittyDecrypt, then re-wrapped
//                                              with EncryptString so the
//                                              cache stores the same DPAPI
//                                              format sftpplug.ini uses)
//
// Password import is on for KiTTY — the KiTTY `Save password` box is an
// explicit user gesture, so carrying the value forward matches user intent.
// Decoded via the native KittyDecrypt module and re-wrapped with the
// plugin's own EncryptString before it lands in the cache.
class KittyAdapter final : public IExternalSessionSource {
public:
    const char* SourceId()   const noexcept override { return "kitty";  }
    const char* FolderName() const noexcept override { return "[KiTTY]"; }

    bool DetectStandard() const noexcept override;
    // Every file in the standard Sessions folder.
    std::string ChangeStamp() const override;
    std::string CustomPathStamp(const std::string& path) const override;

    EnumerationResult EnumerateStandard() override;
    EnumerationResult EnumerateCustomPath(const std::string& path) override;

    bool LoadSettings(const ExternalSessionEntry& entry,
                      pConnectSettings out,
                      SessionDependency* dependency) override;

    // KiTTY sessions live in a directory of per-session files.
    CustomPathPickerKind CustomPathPicker() const noexcept override
    { return CustomPathPickerKind::Folder; }
};

}  // namespace sftp

#pragma once

#include "IExternalSessionSource.h"

namespace sftp {

// SecureCRT / SecureFX session source.
//
// Standard channel: %APPDATA%\VanDyke\Config\Sessions\.
// Detection marker: presence of Default.ini in that folder (created by
// SecureCRT on first launch; a bare Sessions\ folder can survive an
// uninstall and give a false-positive).
//
// Session files use VanDyke's custom `<type>:"<key>"=<value>` INI variant
// (see VanDykeIniParser). Directory structure under Sessions\ is the folder
// hierarchy; every folder appears as-is in the DisplayName (no name is
// reserved — a user folder called `__main__` shows as `__main__`).
//
// Field mapping (VanDyke → tConnectSettings):
//   S:"Hostname"                              → server (host part)
//   D:"[SSH2] Port"                           → server (":<port>" suffix when != 22)
//   S:"Username"                              → user
//   S:"Identity Filename V2"                  → privkeyfile
//   S:"Output Transformer Name" = "UTF-8"     → utf8names = 1
//   S:"Protocol Name" != "SSH2"               → session skipped
//   S:"Password V2"                           → intentionally not read;
//                                               plugin surfaces the standard
//                                               interactive password prompt
// Firewall / proxy / jump-host fields are not surfaced by this adapter;
// materialised sessions inherit no proxy settings and can be edited via the
// standard Configure dialog if needed.
class SecureCrtAdapter final : public IExternalSessionSource {
public:
    const char* SourceId()    const noexcept override { return "securecrt";  }
    const char* FolderName()  const noexcept override { return "[SecureCRT]"; }

    bool DetectStandard() const noexcept override;
    // The Sessions tree and the Firewalls folder beside it.
    std::string ChangeStamp() const override;
    std::string CustomPathStamp(const std::string& path) const override;

    EnumerationResult EnumerateStandard() override;
    EnumerationResult EnumerateCustomPath(const std::string& path) override;

    bool LoadSettings(const ExternalSessionEntry& entry,
                      pConnectSettings out,
                      SessionDependency* dependency) override;

    // SecureCRT sessions live in a directory tree
    // (%APPDATA%\VanDyke\Config\Sessions\ or any portable copy of it).
    CustomPathPickerKind CustomPathPicker() const noexcept override
    { return CustomPathPickerKind::Folder; }
};

}  // namespace sftp

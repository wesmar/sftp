#pragma once

#include "IExternalSessionSource.h"

namespace sftp {

// PuTTY session source.
//
// Standard channel: HKCU\Software\SimonTatham\PuTTY\Sessions — the
// registry key PuTTY and every drop-in fork (ExtraPuTTY, PuTTY CAC,
// PuTTY Portable that wraps official PuTTY) write into. Tabbed
// runners like mtPuTTY and SuperPuTTY delegate storage here too.
//
// Detection: RegOpenKeyEx on the sessions root. Absent key → adapter
// treats source as unreachable; present-but-empty is a valid state.
//
// Field mapping (PuTTY registry value → tConnectSettings):
//   HostName          (REG_SZ)    → server (URL-decoded; :<port> when port != 22)
//   PortNumber        (REG_DWORD) → server ":<port>" suffix
//   UserName          (REG_SZ)    → user (URL-decoded)
//   PublicKeyFile     (REG_SZ)    → privkeyfile / pubkeyfile via
//                                   AssignImportedKeyFile (env vars expanded)
//   AgentFwd / AuthAgent (REG_DWORD) → useagent = 1 when non-zero
//   LineCodePage      (REG_SZ)    → utf8names / codepage via ParseLineCodePage
//   EnterSendsCrLf    (REG_DWORD) → unixlinebreaks
//
// Password is not handled — PuTTY does not store one on disk.
//
// Custom channel: `putty.reg` file exported from PuTTY Portable
// (Windows Registry Editor Version 5.00, UTF-16 LE with BOM). Users
// pick the file via [Add custom location...]; the adapter parses
// its SessionSubKey entries and merges them with the registry channel.
class PuttyAdapter final : public IExternalSessionSource {
public:
    const char* SourceId()    const noexcept override { return "putty";   }
    const char* FolderName()  const noexcept override { return "[PuTTY]"; }

    bool DetectStandard() const noexcept override;
    // The Sessions registry key and each session key under it.
    std::string ChangeStamp() const override;
    std::string CustomPathStamp(const std::string& path) const override;

    EnumerationResult EnumerateStandard() override;
    EnumerationResult EnumerateCustomPath(const std::string& path) override;

    bool LoadSettings(const ExternalSessionEntry& entry,
                      pConnectSettings out,
                      SessionDependency* dependency) override;

    CustomPathPickerKind CustomPathPicker() const noexcept override
    { return CustomPathPickerKind::File; }

    const char* CustomPathFileFilter() const noexcept override
    {
        // NUL-separated Win32 filter: label\0pattern\0label\0pattern\0
        // Double-NUL termination happens automatically because the
        // string literal ends with an implicit '\0' after "*.*".
        return "PuTTY registry export (*.reg)\0*.reg\0All files (*.*)\0*.*\0";
    }
};

}  // namespace sftp

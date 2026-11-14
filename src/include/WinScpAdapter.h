#pragma once

#include "IExternalSessionSource.h"

namespace sftp {

// WinSCP session source.
//
// Standard channel: HKCU\Software\Martin Prikryl\WinSCP 2\Sessions —
// the registry key WinSCP itself writes to on install-mode setups.
// Detection: RegOpenKeyEx on the sessions root; a portable-only
// install leaves it absent.
//
// Custom channel: portable `WinSCP.ini` — user picks the file via
// [Add custom location...], sessions live under [Sessions\<name>]
// sections. Same URL-encoded key names as the registry variant.
//
// Field mapping (WinSCP → tConnectSettings):
//   HostName        (REG_SZ / INI)  → server (URL-decoded)
//   PortNumber      (REG_DWORD)     → server ":<port>" suffix
//   UserName        (REG_SZ)        → user (URL-decoded)
//   PublicKeyFile   (REG_SZ)        → privkeyfile when .ppk / .pem,
//                                     pubkeyfile when .pub
//   AgentFwd / AuthAgent            → useagent = 1 when non-zero
//   FSProtocol == 0                 → default SFTP flow
//   FSProtocol == 1                 → scponly = 1, scpfordata = 1,
//                                     unixlinebreaks = 1 (WinSCP SCP)
//   FSProtocol != 0 && != 1         → session skipped (FTP / WebDAV / S3)
//
// Password is not carried across. On first connect the plugin's own
// interactive prompt kicks in, or the user can save one via the
// Configure dialog.
class WinScpAdapter final : public IExternalSessionSource {
public:
    const char* SourceId()    const noexcept override { return "winscp";  }
    const char* FolderName()  const noexcept override { return "[WinSCP]"; }

    bool DetectStandard() const noexcept override;
    // The Sessions registry key and each session key under it.
    std::string ChangeStamp() const override;
    std::string CustomPathStamp(const std::string& path) const override;

    EnumerationResult EnumerateStandard() override;
    EnumerationResult EnumerateCustomPath(const std::string& path) override;

    bool LoadSettings(const ExternalSessionEntry& entry,
                      pConnectSettings out,
                      SessionDependency* dependency) override;

    // WinSCP portable ships a `WinSCP.ini` file; pick that with a
    // file dialog.
    CustomPathPickerKind CustomPathPicker() const noexcept override
    { return CustomPathPickerKind::File; }

    const char* CustomPathFileFilter() const noexcept override
    {
        return "WinSCP portable configuration (WinSCP.ini)\0WinSCP.ini\0"
               "INI files (*.ini)\0*.ini\0"
               "All files (*.*)\0*.*\0";
    }
};

}  // namespace sftp

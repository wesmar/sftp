#pragma once

#include "IExternalSessionSource.h"

namespace sftp {

// OpenSSH client config source (`~/.ssh/config`).
//
// Standard channel: %USERPROFILE%\.ssh\config — where OpenSSH for Windows
// keeps it. Custom channel: any config file the user picks.
//
// Every concrete `Host` name becomes a session; patterns (`*`, `?`, `!`)
// are not listed but apply to the hosts they match. Values resolve the
// way `ssh` resolves them: the first value obtained for a keyword wins, so
// a `Host *` block at the end only fills gaps. `Include` is followed;
// `Match` blocks are skipped.
//
// Field mapping (config → tConnectSettings):
//   HostName      → server (the alias itself when absent; %h expanded)
//   Port          → server ":<port>" suffix (omitted for 22)
//   User          → user (the local user name when absent, as `ssh` does)
//   IdentityFile  → privkeyfile / pubkeyfile (first one; ~ and %d %u %h %r
//                   expanded)
//   ProxyJump     → jump_* for a single hop, resolved through the jump
//                   host's own `Host` entry; a chain refuses
//   ProxyCommand  → refuses
//   (always)      → utf8 and Unix line endings, so no probes run on connect
//
// No password is ever stored in the file, so none comes across.
class OpenSshAdapter final : public IExternalSessionSource {
public:
    const char* SourceId()   const noexcept override { return "openssh";   }
    const char* FolderName() const noexcept override { return "[OpenSSH]"; }

    bool DetectStandard() const noexcept override;

    EnumerationResult EnumerateStandard() override;
    EnumerationResult EnumerateCustomPath(const std::string& path) override;

    bool LoadSettings(const ExternalSessionEntry& entry,
                      pConnectSettings out,
                      SessionDependency* dependency) override;

    // The standard config and every file it includes, with their times, so
    // an edit anywhere among them re-scans the folder on the next visit.
    std::string ChangeStamp() const override;
    std::string CustomPathStamp(const std::string& path) const override;

    CustomPathPickerKind CustomPathPicker() const noexcept override
    { return CustomPathPickerKind::File; }

    const char* CustomPathFileFilter() const noexcept override
    {
        return "OpenSSH config (config)\0config\0"
               "All files (*.*)\0*.*\0";
    }
};

}  // namespace sftp

#pragma once

#include "IExternalSessionSource.h"

namespace sftp {

// FileZilla session source.
//
// Standard channel: %APPDATA%\FileZilla\sitemanager.xml — the single
// XML file the FileZilla client writes on install-mode setups. There
// is no per-user registry entry to probe, so detection is a plain
// file-exists check on that path.
//
// Custom channel: portable sitemanager.xml — user picks the file via
// [Add custom location...]. Same format as the standard one.
//
// FileZilla sitemanager.xml layout (relevant subset):
//
//   <FileZilla3 ...>
//     <Servers>
//       <Server>
//         <Host>example.com</Host>
//         <Port>22</Port>
//         <Protocol>1</Protocol>        (1 = SFTP; others skipped)
//         <User>root</User>
//         <Logontype>4</Logontype>      (4 = key file)
//         <Keyfile>C:\keys\id_rsa</Keyfile>
//         <EncodingType>Auto</EncodingType>
//         <CustomEncoding>UTF-8</CustomEncoding>
//         my_session_name              (text node of the Server element)
//       </Server>
//       <Folder expanded="1">
//         Team                          (folder display name — text node)
//         <Server>...</Server>
//       </Folder>
//     </Servers>
//   </FileZilla3>
//
// Sessions can be nested arbitrarily under `<Folder>` elements; the
// adapter flattens the tree to a `/`-joined DisplayName
// ("Team/prod/host1"), which the panel resolver renders as nested
// subfolders.
//
// Field mapping (FileZilla → tConnectSettings):
//   <Host>          → server (host part)
//   <Port>          → server ":<port>" suffix (omitted for 22)
//   <User>          → user
//   <Protocol> == 1 → SFTP flow accepted
//   <Protocol> != 1 → session skipped (FTP / FTPS / WebDAV / S3 / …)
//   <Keyfile>       → pubkeyfile when .pub, privkeyfile otherwise
//                     (FileZilla stores OpenSSH-style paths without an
//                      extension like id_rsa / id_ed25519 because its
//                      fzsftp back-end reads OpenSSH PEM directly.)
//   <EncodingType>  → utf8names / codepage via ParseLineCodePage
//                     ("Auto" → leave defaults; "UTF-8" → utf8=1;
//                      "Custom" → look at <CustomEncoding>)
//
// Password import:
//   <Pass encoding="base64">    → decoded, re-wrapped with EncryptString
//                                 (matches the "Save password" radio in
//                                 the FileZilla Site Manager)
//   <Pass encoding="crypt">     → skipped; needs the FileZilla master
//                                 password (Argon2 + AES-GCM), the plugin
//                                 falls back to its interactive prompt
class FileZillaAdapter final : public IExternalSessionSource {
public:
    const char* SourceId()   const noexcept override { return "filezilla";  }
    const char* FolderName() const noexcept override { return "[FileZilla]"; }

    bool DetectStandard() const noexcept override;
    // sitemanager.xml, and filezilla.xml beside it for the global proxy.
    std::string ChangeStamp() const override;
    std::string CustomPathStamp(const std::string& path) const override;

    EnumerationResult EnumerateStandard() override;
    EnumerationResult EnumerateCustomPath(const std::string& path) override;

    bool LoadSettings(const ExternalSessionEntry& entry,
                      pConnectSettings out,
                      SessionDependency* dependency) override;

    // Portable channel points at a `sitemanager.xml` file directly.
    CustomPathPickerKind CustomPathPicker() const noexcept override
    { return CustomPathPickerKind::File; }

    const char* CustomPathFileFilter() const noexcept override
    {
        return "FileZilla site manager (sitemanager.xml)\0sitemanager.xml\0"
               "XML files (*.xml)\0*.xml\0"
               "All files (*.*)\0*.*\0";
    }
};

}  // namespace sftp

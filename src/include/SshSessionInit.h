#pragma once

#include <memory>
#include "SftpClient.h"

struct ISshBackend;

int InitializeSshSession(
    pConnectSettings ConnectSettings,
    int& progress,
    int& loop,
    SYSTICKS& lasttime,
    std::unique_ptr<ISshBackend>& backend);

int VerifyServerFingerprint(pConnectSettings ConnectSettings);

// A host key's fingerprint in both forms a profile may hold: SHA256 as
// OpenSSH prints it ("SHA256:" + unpadded base64), and the MD5 hex pairs
// that earlier versions stored.
struct HostKeyFingerprint {
    std::string sha256;
    std::string md5;
};

HostKeyFingerprint ReadHostKeyFingerprint(ISshSession* session);

// Whether a stored fingerprint names this key. A stored MD5 still matches,
// so profiles saved by earlier versions keep connecting; the caller then
// rewrites it in the SHA256 form.
bool FingerprintMatches(const std::string& stored, const HostKeyFingerprint& fp);

// The form written to the profile: SHA256 when the library gave one.
const std::string& FingerprintToStore(const HostKeyFingerprint& fp);

// Both forms, one per line, for the confirmation prompt.
std::string FingerprintForPrompt(const HostKeyFingerprint& fp);

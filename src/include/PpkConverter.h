#pragma once

#include <string_view>
#include "SecureMemory.h"

// PuTTY private key files (.ppk, formats 2 and 3) decoded into an unencrypted
// PKCS#8 PEM that stays in wiped-on-free memory and is handed to
// libssh2_userauth_publickey_frommemory. Nothing decrypted is written to disk.
//
// Every step is verified rather than trusted: the file MAC is checked (also
// for unencrypted keys), the key is rebuilt through OpenSSL and passes its
// pairwise consistency check, and the rebuilt public key must equal the
// public blob stored in the file.

enum class PpkConvertError : int {
    ok = 0,
    io_error,
    unsupported_version,
    unsupported_algorithm,
    unsupported_encryption,
    unsupported_kdf,
    kdf_limits_exceeded,
    kdf_unavailable,
    passphrase_required,
    bad_passphrase_or_mac,
    invalid_format,
    inconsistent_key,
    crypto_error,
    internal_error,
};

// Converts the .ppk at `ppkPath` (ANSI path, as stored in the session).
// `passphrase` may be null or empty for an unencrypted key.
PpkConvertError ConvertPpkFileToPem(const char* ppkPath, const char* passphrase, SecureChars& outPem) noexcept;

// Converts .ppk file content already in memory.
PpkConvertError ConvertPpkToPem(std::string_view fileContent, const char* passphrase, SecureChars& outPem) noexcept;

// Upper bounds on the Argon2 parameters a .ppk may request. A key file is
// untrusted input: without limits a crafted header could ask for gigabytes of
// memory or hours of work before the MAC check can reject it.
inline constexpr uint32_t kPpkArgon2MaxMemoryKiB = 1024u * 1024u;        // 1 GiB
inline constexpr uint64_t kPpkArgon2MaxWorkKiB   = 16ull * 1024u * 1024u; // memory x passes <= 16 GiB
inline constexpr uint32_t kPpkArgon2MaxLanes     = 64;

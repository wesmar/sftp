#pragma once
#include <windows.h>
#include <stddef.h>

// Native PuTTY PPK -> temporary PEM converter for libssh2_userauth_publickey_fromfile.
// Supports PPK v2 and v3.
// Output: traditional PEM for RSA/ECDSA keys.

enum class PpkConvertError : int {
    ok = 0,
    io_error,
    unsupported_version,
    unsupported_algorithm,
    unsupported_encryption,
    unsupported_kdf,
    kdf_unavailable,
    passphrase_required,
    bad_passphrase_or_mac,
    invalid_format,
    crypto_error,
    internal_error,
};

// Converts a PPK file to a temporary PEM private key file.
// passphrase: passphrase for encrypted keys (null/empty for unencrypted keys).
// outPemPath: caller buffer for temp output path.
// outError: optional detailed status.
// On success caller must delete output file with DeleteFileA.
bool ConvertPpkToOpenSsh(const char* ppkPath, const char* passphrase,
                         char* outPemPath, size_t outPemPathLen,
                         PpkConvertError* outError) noexcept;

// Backward-compatible wrapper.
bool ConvertPpkV2ToOpenSsh(const char* ppkPath, const char* passphrase,
                           char* outPemPath, size_t outPemPathLen) noexcept;

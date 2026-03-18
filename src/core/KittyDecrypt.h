#pragma once
#include <string>

// Try to decrypt a KiTTY base64 password using both key derivation modes.
// Returns true and fills `out` with plaintext on success.
[[nodiscard]] bool DecryptKittyPassword(const std::string& enc,
                                   const std::string& host,
                                   const std::string& term,
                                   std::string&       out);

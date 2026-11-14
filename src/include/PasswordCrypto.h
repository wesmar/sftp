#pragma once

#include <string>
#include <string_view>

// Passwords as stored in the profile ini.
//
//   dpapi:<base64>  DPAPI, bound to the current Windows user (written)
//   plain:<text>    stored in the clear on purpose (read only)
//   <digits>        legacy XOR obfuscation of older releases (read only;
//                   written only when DPAPI itself fails)
//
// A profile may also hold "!": the password is kept by Total Commander's
// password manager. That is for the caller to resolve, not this module.
namespace password_crypto {

// Marker a profile carries in place of a password kept by Total Commander.
inline constexpr std::string_view kMasterPasswordMarker = "\001";

// Stored form of `plain`; empty for an empty password.
[[nodiscard]] std::string Protect(std::string_view plain);

// The password behind a stored form; empty when it cannot be recovered.
[[nodiscard]] std::string Unprotect(std::string_view stored);

} // namespace password_crypto

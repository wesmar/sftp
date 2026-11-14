#include "Test.h"
#include "LanPairInternal.h"

#include <openssl/evp.h>

#include <array>
#include <string>
#include <vector>

using lanpair_internal::deriveKeyPbkdf2;
using lanpair_internal::derivePairKey;
using lanpair_internal::kDerivedKeySize;
using lanpair_internal::kPbkdf2Iterations;

namespace {

std::vector<uint8_t> OpenSslPbkdf2(const std::string& password, const uint8_t* salt, size_t saltLen)
{
    std::vector<uint8_t> out(kDerivedKeySize);
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt, static_cast<int>(saltLen),
                      static_cast<int>(kPbkdf2Iterations), EVP_sha256(), static_cast<int>(out.size()), out.data());
    return out;
}

} // namespace

TEST_CASE("lanpair: BCrypt PBKDF2 equals OpenSSL's")
{
    const std::array<uint8_t, 16> salt = { 's', 'a', 'l', 't', 's', 'a', 'l', 't',
                                           0x00, 0x7F, 0x80, 0xFF, 1, 2, 3, 4 };
    const auto key = deriveKeyPbkdf2("pass\xC4\x85word", salt, kDerivedKeySize);
    CHECK(key.has_value());
    CHECK(*key == OpenSslPbkdf2("pass\xC4\x85word", salt.data(), salt.size()));
    CHECK(!deriveKeyPbkdf2("", salt, kDerivedKeySize).has_value());
}

TEST_CASE("lanpair: pair key matches the earlier releases' derivation")
{
    // Earlier releases: salt = first 16 bytes of HMAC-SHA256(key "LANPAIR",
    // "<lower id><><higher id>"), then PBKDF2. Peers paired by them keep working.
    const std::string ids = "alpha-peer<>bravo-peer";
    std::array<uint8_t, EVP_MAX_MD_SIZE> mac{};
    size_t macLen = 0;
    EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, "LANPAIR", 7,
              reinterpret_cast<const unsigned char*>(ids.data()), ids.size(), mac.data(), mac.size(), &macLen);
    CHECK_EQ(macLen, size_t{32});
    const auto expected = OpenSslPbkdf2("shared secret", mac.data(), 16);

    const auto forward = derivePairKey("shared secret", "alpha-peer", "bravo-peer");
    const auto reverse = derivePairKey("shared secret", "bravo-peer", "alpha-peer");
    CHECK(forward.has_value() && reverse.has_value());
    CHECK(*forward == expected);
    CHECK(*reverse == expected);
}

#include "Test.h"
#include "PasswordCrypto.h"

#include <string>

using password_crypto::Protect;
using password_crypto::Unprotect;

TEST_CASE("password: DPAPI round trip, UTF-8 and long values")
{
    for (const std::string plain : { std::string("secret"), std::string("p\xC3\xA4ss w\xC3\xB6rd \xC4\x85\xC4\x99"),
                                     std::string(3000, 'x') }) {
        const std::string stored = Protect(plain);
        CHECK(stored.starts_with("dpapi:"));
        CHECK(stored.find(plain) == std::string::npos);
        CHECK_BYTES(Unprotect(stored), plain);
    }
}

TEST_CASE("password: empty stays empty")
{
    CHECK_BYTES(Protect(""), "");
    CHECK_BYTES(Unprotect(""), "");
}

TEST_CASE("password: legacy XOR format of older releases still reads")
{
    // Worked by hand from the published key "unpz...": the key is read from
    // offset (length mod key length), each byte written as three digits.
    CHECK_BYTES(Unprotect("015"), "a");       // 'a' ^ 'n' = 15
    CHECK_BYTES(Unprotect("017024"), "ab");   // 'a' ^ 'p' = 17, 'b' ^ 'z' = 24
}

TEST_CASE("password: plain prefix and malformed values")
{
    CHECK_BYTES(Unprotect("plain:abc def"), "abc def");
    CHECK_BYTES(Unprotect("dpapi:not base64 !!"), "");
    CHECK_BYTES(Unprotect("dpapi:AAAA"), "");  // valid base64, not a DPAPI blob
    CHECK_BYTES(Unprotect("12"), "");          // not whole triplets
    CHECK_BYTES(Unprotect("999"), "");         // a triplet above 255
    CHECK_BYTES(Unprotect("01a"), "");
    CHECK_BYTES(Unprotect("!"), "");           // TC's password manager: the caller's business
}

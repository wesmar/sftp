#include "Test.h"
#include "PpkConverter.h"

#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace {

const char* const kAlgorithms[] = {"rsa2048", "ecdsa256", "ecdsa384", "ecdsa521", "ed25519"};
const char* const kVariants[] = {"v3-none", "v2-none", "v3-enc", "v2-enc"};

std::string FixtureDir()
{
    char* dir = nullptr;
    size_t len = 0;
    std::string value;
    if (_dupenv_s(&dir, &len, "SFTP_TEST_FIXTURES") == 0 && dir) {
        value = dir;
        std::free(dir);
    }
    if (value.empty())
        test::Fail(__FILE__, __LINE__, "SFTP_TEST_FIXTURES is not set (run tests through run-unit-tests.ps1)");
    return value + "\\ppk\\";
}

std::string ReadText(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        test::Fail(__FILE__, __LINE__, "cannot read " + path);
    std::ostringstream s;
    s << in.rdbuf();
    return s.str();
}

std::string Passphrase() { return ReadText(FixtureDir() + "passphrase.txt"); }

std::vector<uint8_t> Base64(const std::string& text)
{
    std::vector<uint8_t> out(text.size());
    std::unique_ptr<EVP_ENCODE_CTX, decltype(&EVP_ENCODE_CTX_free)> ctx(EVP_ENCODE_CTX_new(), EVP_ENCODE_CTX_free);
    int n = 0;
    int tail = 0;
    EVP_DecodeInit(ctx.get());
    EVP_DecodeUpdate(ctx.get(), out.data(), &n, reinterpret_cast<const unsigned char*>(text.data()), static_cast<int>(text.size()));
    EVP_DecodeFinal(ctx.get(), out.data() + n, &tail);
    out.resize(static_cast<size_t>(n + tail));
    return out;
}

// The public blob puttygen printed: "<algorithm> <base64> <comment>".
std::vector<uint8_t> ExpectedPublicBlob(const char* algorithm)
{
    std::istringstream line(ReadText(FixtureDir() + algorithm + ".pub"));
    std::string type;
    std::string blob;
    line >> type >> blob;
    return Base64(blob);
}

void PutString(std::vector<uint8_t>& out, const void* data, size_t len)
{
    const auto n = static_cast<uint32_t>(len);
    const uint8_t prefix[4] = {static_cast<uint8_t>(n >> 24), static_cast<uint8_t>(n >> 16),
                               static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n)};
    out.insert(out.end(), prefix, prefix + 4);
    const auto* p = static_cast<const uint8_t*>(data);
    out.insert(out.end(), p, p + len);
}

void PutString(std::vector<uint8_t>& out, const std::string& s) { PutString(out, s.data(), s.size()); }

void PutMpint(std::vector<uint8_t>& out, const BIGNUM* bn)
{
    std::vector<uint8_t> bytes(static_cast<size_t>(BN_num_bytes(bn)));
    BN_bn2bin(bn, bytes.data());
    if (!bytes.empty() && (bytes[0] & 0x80))
        bytes.insert(bytes.begin(), 0);
    PutString(out, bytes.data(), bytes.size());
}

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

PkeyPtr LoadPem(const SecureChars& pem)
{
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    return PkeyPtr(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
}

// Rebuilds the SSH public blob from a loaded private key, independently of
// the converter, so the comparison with puttygen's output is end to end.
std::vector<uint8_t> PublicBlobOf(EVP_PKEY* key)
{
    std::vector<uint8_t> blob;
    if (EVP_PKEY_is_a(key, "RSA")) {
        BIGNUM* n = nullptr;
        BIGNUM* e = nullptr;
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e);
        PutString(blob, std::string("ssh-rsa"));
        PutMpint(blob, e);
        PutMpint(blob, n);
        BN_free(n);
        BN_free(e);
    } else if (EVP_PKEY_is_a(key, "EC")) {
        char group[32] = {};
        EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), nullptr);
        // OpenSSL reports its canonical names (prime256v1, secp384r1, ...).
        const std::string g(group);
        std::string curve;
        if (g == "prime256v1" || g == "P-256") curve = "nistp256";
        else if (g == "secp384r1" || g == "P-384") curve = "nistp384";
        else if (g == "secp521r1" || g == "P-521") curve = "nistp521";
        else test::Fail(__FILE__, __LINE__, "unexpected EC group " + g);
        uint8_t point[200] = {};
        size_t pointLen = 0;
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point), &pointLen);
        PutString(blob, "ecdsa-sha2-" + curve);
        PutString(blob, curve);
        PutString(blob, point, pointLen);
    } else if (EVP_PKEY_is_a(key, "ED25519")) {
        uint8_t pk[32] = {};
        size_t pkLen = sizeof(pk);
        EVP_PKEY_get_raw_public_key(key, pk, &pkLen);
        PutString(blob, std::string("ssh-ed25519"));
        PutString(blob, pk, pkLen);
    }
    return blob;
}

PpkConvertError Convert(const std::string& content, const std::string& pass, SecureChars& pem)
{
    return ConvertPpkToPem(content, pass.empty() ? nullptr : pass.c_str(), pem);
}

std::string ReplaceLine(const std::string& content, const std::string& prefix, const std::string& replacement)
{
    const size_t start = content.find(prefix);
    if (start == std::string::npos)
        test::Fail(__FILE__, __LINE__, "fixture has no line starting with " + prefix);
    const size_t end = content.find('\n', start);
    return content.substr(0, start) + replacement + (end == std::string::npos ? "" : content.substr(end));
}

const char* ErrorName(PpkConvertError e)
{
    switch (e) {
    case PpkConvertError::ok: return "ok";
    case PpkConvertError::io_error: return "io_error";
    case PpkConvertError::unsupported_version: return "unsupported_version";
    case PpkConvertError::unsupported_algorithm: return "unsupported_algorithm";
    case PpkConvertError::unsupported_encryption: return "unsupported_encryption";
    case PpkConvertError::unsupported_kdf: return "unsupported_kdf";
    case PpkConvertError::kdf_limits_exceeded: return "kdf_limits_exceeded";
    case PpkConvertError::kdf_unavailable: return "kdf_unavailable";
    case PpkConvertError::passphrase_required: return "passphrase_required";
    case PpkConvertError::bad_passphrase_or_mac: return "bad_passphrase_or_mac";
    case PpkConvertError::invalid_format: return "invalid_format";
    case PpkConvertError::inconsistent_key: return "inconsistent_key";
    case PpkConvertError::crypto_error: return "crypto_error";
    case PpkConvertError::internal_error: return "internal_error";
    }
    return "?";
}

#define CHECK_PPK(actual, expected)                                                                   \
    do {                                                                                              \
        ++test::CheckCount();                                                                         \
        const PpkConvertError test_a_ = (actual);                                                     \
        if (test_a_ != (expected))                                                                    \
            test::Fail(__FILE__, __LINE__, std::string("got ") + ErrorName(test_a_) + ", expected " + \
                                               ErrorName(expected));                                  \
    } while (0)

} // namespace

TEST_CASE("PPK: every puttygen fixture converts to the key puttygen describes")
{
    const std::string pass = Passphrase();
    for (const char* alg : kAlgorithms) {
        const std::vector<uint8_t> expected = ExpectedPublicBlob(alg);
        for (const char* variant : kVariants) {
            const std::string name = std::string(alg) + "-" + variant;
            const bool encrypted = std::string(variant).find("enc") != std::string::npos;
            SecureChars pem;
            const PpkConvertError e = Convert(ReadText(FixtureDir() + name + ".ppk"), encrypted ? pass : "", pem);
            if (e != PpkConvertError::ok)
                test::Fail(__FILE__, __LINE__, name + ": " + ErrorName(e));
            CHECK(std::string(pem.begin(), pem.end()).rfind("-----BEGIN PRIVATE KEY-----", 0) == 0);
            PkeyPtr key = LoadPem(pem);
            if (!key)
                test::Fail(__FILE__, __LINE__, name + ": OpenSSL cannot read the produced PEM");
            if (PublicBlobOf(key.get()) != expected)
                test::Fail(__FILE__, __LINE__, name + ": public key differs from puttygen's");
        }
    }
}

TEST_CASE("PPK: encrypted keys need the right passphrase")
{
    for (const char* alg : kAlgorithms) {
        for (const char* variant : {"v3-enc", "v2-enc"}) {
            const std::string content = ReadText(FixtureDir() + alg + "-" + variant + ".ppk");
            SecureChars pem;
            CHECK_PPK(Convert(content, "", pem), PpkConvertError::passphrase_required);
            CHECK_PPK(Convert(content, "wrong passphrase", pem), PpkConvertError::bad_passphrase_or_mac);
            CHECK(pem.empty());
        }
    }
}

TEST_CASE("PPK: the MAC protects unencrypted keys of both formats")
{
    for (const char* variant : {"v3-none", "v2-none"}) {
        const std::string original = ReadText(FixtureDir() + "ed25519-" + variant + ".ppk");
        SecureChars pem;
        CHECK_PPK(Convert(ReplaceLine(original, "Comment:", "Comment: edited"), "", pem),
                  PpkConvertError::bad_passphrase_or_mac);

        // Swap one base64 character of the public blob for another valid one.
        std::string tampered = original;
        const size_t pub = tampered.find('\n', tampered.find("Public-Lines:")) + 9;
        tampered[pub] = tampered[pub] == 'A' ? 'B' : 'A';
        CHECK_PPK(Convert(tampered, "", pem), PpkConvertError::bad_passphrase_or_mac);
    }
}

TEST_CASE("PPK: Argon2 limits are enforced before any derivation runs")
{
    const std::string original = ReadText(FixtureDir() + "rsa2048-v3-enc.ppk");
    const std::string pass = Passphrase();
    SecureChars pem;
    CHECK_PPK(Convert(ReplaceLine(original, "Argon2-Memory:", "Argon2-Memory: 4194304"), pass, pem),
              PpkConvertError::kdf_limits_exceeded);
    CHECK_PPK(Convert(ReplaceLine(original, "Argon2-Passes:", "Argon2-Passes: 100000"), pass, pem),
              PpkConvertError::kdf_limits_exceeded);
    CHECK_PPK(Convert(ReplaceLine(original, "Argon2-Parallelism:", "Argon2-Parallelism: 0"), pass, pem),
              PpkConvertError::kdf_limits_exceeded);
    CHECK_PPK(Convert(ReplaceLine(original, "Argon2-Parallelism:", "Argon2-Parallelism: 2000"), pass, pem),
              PpkConvertError::kdf_limits_exceeded);
    CHECK_PPK(Convert(ReplaceLine(original, "Key-Derivation:", "Key-Derivation: scrypt"), pass, pem),
              PpkConvertError::unsupported_kdf);
}

TEST_CASE("PPK: unsupported versions, ciphers and algorithms are named as such")
{
    const std::string original = ReadText(FixtureDir() + "ed25519-v3-none.ppk");
    SecureChars pem;
    CHECK_PPK(Convert(ReplaceLine(original, "PuTTY-User-Key-File-", "PuTTY-User-Key-File-4: ssh-ed25519"), "", pem),
              PpkConvertError::unsupported_version);
    CHECK_PPK(Convert(ReplaceLine(original, "Encryption:", "Encryption: aes128-cbc"), "", pem),
              PpkConvertError::unsupported_encryption);
    CHECK_PPK(Convert(ReplaceLine(original, "PuTTY-User-Key-File-", "PuTTY-User-Key-File-3: ssh-dss"), "", pem),
              PpkConvertError::unsupported_algorithm);
    CHECK_PPK(Convert("", "", pem), PpkConvertError::invalid_format);
    CHECK_PPK(Convert("-----BEGIN OPENSSH PRIVATE KEY-----\n", "", pem), PpkConvertError::invalid_format);
}

TEST_CASE("property: every truncation of a key file is rejected without harm")
{
    const std::string original = ReadText(FixtureDir() + "ecdsa256-v3-none.ppk");
    for (size_t cut = 0; cut + 1 < original.size(); ++cut) {
        // A cut inside the trailing newline still leaves a complete file.
        if (original.find_first_not_of("\r\n", cut) == std::string::npos)
            break;
        SecureChars pem;
        CHECK(Convert(original.substr(0, cut), "", pem) != PpkConvertError::ok);
        CHECK(pem.empty());
    }
}

TEST_CASE("property: a corrupted key file never yields a different key")
{
    const std::string original = ReadText(FixtureDir() + "ed25519-v3-none.ppk");
    const std::vector<uint8_t> expected = ExpectedPublicBlob("ed25519");
    test::Rng rng(0xFEEDull);
    for (int i = 0; i < 3000; ++i) {
        std::string mutated = original;
        const int flips = 1 + static_cast<int>(rng.Below(3));
        for (int k = 0; k < flips; ++k)
            mutated[rng.Below(mutated.size())] = static_cast<char>(rng.Below(256));
        SecureChars pem;
        if (Convert(mutated, "", pem) == PpkConvertError::ok) {
            PkeyPtr key = LoadPem(pem);
            CHECK(key && PublicBlobOf(key.get()) == expected);
        }
    }
}

TEST_CASE("PPK: an Ed25519 secret stored in fewer than 32 bytes is zero-extended")
{
    // PuTTY writes the secret with put_mp_le_unsigned, so a secret whose most
    // significant (last) byte is zero is stored as 31 bytes. Build such a file
    // by hand: unencrypted format 3, whose MAC key is the empty string.
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i)
        seed[i] = static_cast<uint8_t>(0x11 * (i + 1));
    seed[31] = 0;
    PkeyPtr key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed, sizeof(seed)), EVP_PKEY_free);
    uint8_t pk[32] = {};
    size_t pkLen = sizeof(pk);
    EVP_PKEY_get_raw_public_key(key.get(), pk, &pkLen);

    std::vector<uint8_t> publicBlob;
    PutString(publicBlob, std::string("ssh-ed25519"));
    PutString(publicBlob, pk, 32);
    std::vector<uint8_t> privateBlob;
    PutString(privateBlob, seed, 31);
    while (privateBlob.size() % 16)
        privateBlob.push_back(0);

    const std::string comment = "short secret";
    std::vector<uint8_t> macData;
    PutString(macData, std::string("ssh-ed25519"));
    PutString(macData, std::string("none"));
    PutString(macData, comment);
    PutString(macData, publicBlob.data(), publicBlob.size());
    PutString(macData, privateBlob.data(), privateBlob.size());
    static const uint8_t kEmpty = 0;
    uint8_t mac[32] = {};
    size_t macLen = 0;
    EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, &kEmpty, 0, macData.data(), macData.size(), mac, sizeof(mac), &macLen);

    auto b64 = [](const std::vector<uint8_t>& v) {
        std::string out(4 * ((v.size() + 2) / 3) + 1, '\0');
        out.resize(static_cast<size_t>(EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), v.data(), static_cast<int>(v.size()))));
        return out;
    };
    std::string hex;
    for (size_t i = 0; i < macLen; ++i) {
        static const char digits[] = "0123456789abcdef";
        hex += digits[mac[i] >> 4];
        hex += digits[mac[i] & 15];
    }
    const std::string file = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: " + comment +
                             "\nPublic-Lines: 1\n" + b64(publicBlob) + "\nPrivate-Lines: 1\n" + b64(privateBlob) +
                             "\nPrivate-MAC: " + hex + "\n";
    SecureChars pem;
    CHECK_PPK(Convert(file, "", pem), PpkConvertError::ok);
    PkeyPtr loaded = LoadPem(pem);
    CHECK(loaded && PublicBlobOf(loaded.get()) == publicBlob);
}

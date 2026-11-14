// PuTTY private key files (.ppk) decoded on OpenSSL.
//
// Format reference: PuTTY's sshpubk.c and the "PPK file format" appendix of
// the PuTTY manual. Both supported formats share one layout:
//
//   PuTTY-User-Key-File-<2|3>: <algorithm>
//   Encryption: none | aes256-cbc
//   Comment: <text>
//   Public-Lines: <n>          followed by n lines of base64
//   Key-Derivation: Argon2id   (format 3, encrypted only; then Argon2-Memory,
//   ...                         -Passes, -Parallelism and -Salt)
//   Private-Lines: <n>         followed by n lines of base64
//   Private-MAC: <hex>
//
// Format 2 derives the AES key from SHA-1 and MACs with HMAC-SHA-1; format 3
// derives AES key, IV and MAC key from Argon2 and MACs with HMAC-SHA-256. In
// both, the MAC covers algorithm, encryption, comment, public blob and the
// *decrypted* private blob, and is present for unencrypted keys as well.

#include "PpkConverter.h"

#include <windows.h>
#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/pem.h>

namespace {

using Error = PpkConvertError;

// ---------------------------------------------------------------------------
// OpenSSL ownership
// ---------------------------------------------------------------------------
struct OsslDelete {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
    void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); }
    void operator()(EVP_ENCODE_CTX* p) const noexcept { EVP_ENCODE_CTX_free(p); }
    void operator()(EVP_KDF* p) const noexcept { EVP_KDF_free(p); }
    void operator()(EVP_KDF_CTX* p) const noexcept { EVP_KDF_CTX_free(p); }
    void operator()(BIGNUM* p) const noexcept { BN_clear_free(p); }
    void operator()(BN_CTX* p) const noexcept { BN_CTX_free(p); }
    void operator()(OSSL_PARAM_BLD* p) const noexcept { OSSL_PARAM_BLD_free(p); }
    void operator()(OSSL_PARAM* p) const noexcept { OSSL_PARAM_clear_free(p); }
    void operator()(BIO* p) const noexcept { BIO_free(p); }
};
template <class T> using Owned = std::unique_ptr<T, OsslDelete>;

// Leaves OpenSSL's per-thread error queue empty, so libssh2 (which inspects it
// after a failed key load) never sees errors that belong to this module.
struct ErrorQueueGuard {
    ErrorQueueGuard() noexcept { ERR_clear_error(); }
    ~ErrorQueueGuard() { ERR_clear_error(); }
};

constexpr size_t kMaxFileSize = 512 * 1024;
constexpr size_t kMaxLines = 4096;
constexpr size_t kMaxMpintBytes = 2049; // 16384-bit modulus plus a sign byte

// ---------------------------------------------------------------------------
// SSH wire format
// ---------------------------------------------------------------------------
class WireReader {
public:
    WireReader(const uint8_t* data, size_t size) noexcept : p_(data), end_(data + size) {}

    bool String(const uint8_t*& data, size_t& len) noexcept
    {
        if (static_cast<size_t>(end_ - p_) < 4)
            return false;
        const size_t n = (static_cast<size_t>(p_[0]) << 24) | (static_cast<size_t>(p_[1]) << 16) |
                         (static_cast<size_t>(p_[2]) << 8) | static_cast<size_t>(p_[3]);
        p_ += 4;
        if (static_cast<size_t>(end_ - p_) < n)
            return false;
        data = p_;
        len = n;
        p_ += n;
        return true;
    }

    bool StringEquals(std::string_view expected) noexcept
    {
        const uint8_t* d = nullptr;
        size_t n = 0;
        return String(d, n) && n == expected.size() && std::memcmp(d, expected.data(), n) == 0;
    }

    // SSH mpint: big-endian two's complement. Key components are never
    // negative, so a set sign bit is malformed input.
    Owned<BIGNUM> Mpint() noexcept
    {
        const uint8_t* d = nullptr;
        size_t n = 0;
        if (!String(d, n) || n > kMaxMpintBytes || (n > 0 && (d[0] & 0x80)))
            return nullptr;
        Owned<BIGNUM> bn(BN_secure_new());
        if (!bn || !BN_bin2bn(d, static_cast<int>(n), bn.get()))
            return nullptr;
        return bn;
    }

    bool AtEnd() const noexcept { return p_ == end_; }

private:
    const uint8_t* p_;
    const uint8_t* end_;
};

template <class Container>
void PutString(Container& out, const void* data, size_t len)
{
    const auto n = static_cast<uint32_t>(len);
    const uint8_t prefix[4] = {static_cast<uint8_t>(n >> 24), static_cast<uint8_t>(n >> 16),
                               static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n)};
    out.insert(out.end(), prefix, prefix + 4);
    const auto* p = static_cast<const uint8_t*>(data);
    out.insert(out.end(), p, p + len);
}

// ---------------------------------------------------------------------------
// Text layer
// ---------------------------------------------------------------------------
struct PpkFile {
    int version = 0;
    std::string algorithm;
    std::string encryption;
    std::string comment;
    std::string kdf;
    uint32_t argonMemory = 0;
    uint32_t argonPasses = 0;
    uint32_t argonLanes = 0;
    std::vector<uint8_t> argonSalt;
    std::vector<uint8_t> publicBlob;
    SecureBytes privateBlob;
    std::vector<uint8_t> mac;
};

class LineReader {
public:
    explicit LineReader(std::string_view text) noexcept : text_(text) {}

    bool Next(std::string_view& line) noexcept
    {
        if (pos_ >= text_.size())
            return false;
        size_t end = text_.find('\n', pos_);
        if (end == std::string_view::npos)
            end = text_.size();
        line = text_.substr(pos_, end - pos_);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        pos_ = end + 1;
        return true;
    }

    // "Key: value". PuTTY writes exactly one space after the colon.
    bool Field(std::string_view key, std::string_view& value) noexcept
    {
        std::string_view line;
        if (!Next(line) || line.size() < key.size() + 1 || line.substr(0, key.size()) != key || line[key.size()] != ':')
            return false;
        value = line.substr(key.size() + 1);
        if (!value.empty() && value.front() == ' ')
            value.remove_prefix(1);
        return true;
    }

private:
    std::string_view text_;
    size_t pos_ = 0;
};

bool ParseU32(std::string_view s, uint32_t& out) noexcept
{
    if (s.empty() || s.size() > 10)
        return false;
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9')
            return false;
        v = v * 10 + static_cast<uint64_t>(c - '0');
    }
    if (v > 0xFFFFFFFFull)
        return false;
    out = static_cast<uint32_t>(v);
    return true;
}

bool DecodeHex(std::string_view hex, std::vector<uint8_t>& out)
{
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (hex.empty() || hex.size() % 2)
        return false;
    out.resize(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        const int hi = nibble(hex[2 * i]);
        const int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

template <class Container>
bool DecodeBase64(std::string_view text, Container& out)
{
    Owned<EVP_ENCODE_CTX> ctx(EVP_ENCODE_CTX_new());
    if (!ctx || text.empty() || text.size() > kMaxFileSize)
        return false;
    out.resize(text.size());
    int produced = 0;
    int tail = 0;
    EVP_DecodeInit(ctx.get());
    if (EVP_DecodeUpdate(ctx.get(), out.data(), &produced,
                         reinterpret_cast<const unsigned char*>(text.data()), static_cast<int>(text.size())) < 0 ||
        EVP_DecodeFinal(ctx.get(), out.data() + produced, &tail) < 0)
        return false;
    out.resize(static_cast<size_t>(produced) + static_cast<size_t>(tail));
    return !out.empty();
}

template <class Container>
bool ReadBase64Lines(LineReader& lines, std::string_view countText, Container& out)
{
    uint32_t count = 0;
    if (!ParseU32(countText, count) || count == 0 || count > kMaxLines)
        return false;
    SecureChars joined;
    for (uint32_t i = 0; i < count; ++i) {
        std::string_view line;
        if (!lines.Next(line))
            return false;
        joined.insert(joined.end(), line.begin(), line.end());
    }
    return DecodeBase64(std::string_view(joined.data(), joined.size()), out);
}

Error ParsePpk(std::string_view text, PpkFile& f)
{
    LineReader lines(text);
    std::string_view line;
    if (!lines.Next(line))
        return Error::invalid_format;

    constexpr std::string_view kMagic = "PuTTY-User-Key-File-";
    if (line.substr(0, kMagic.size()) != kMagic)
        return Error::invalid_format;
    const std::string_view rest = line.substr(kMagic.size());
    const size_t colon = rest.find(':');
    if (colon == std::string_view::npos)
        return Error::invalid_format;
    const std::string_view versionText = rest.substr(0, colon);
    if (versionText == "2")
        f.version = 2;
    else if (versionText == "3")
        f.version = 3;
    else
        return Error::unsupported_version;
    std::string_view alg = rest.substr(colon + 1);
    if (!alg.empty() && alg.front() == ' ')
        alg.remove_prefix(1);
    f.algorithm.assign(alg);

    std::string_view value;
    if (!lines.Field("Encryption", value))
        return Error::invalid_format;
    f.encryption.assign(value);
    if (f.encryption != "none" && f.encryption != "aes256-cbc")
        return Error::unsupported_encryption;

    if (!lines.Field("Comment", value))
        return Error::invalid_format;
    f.comment.assign(value);

    if (!lines.Field("Public-Lines", value) || !ReadBase64Lines(lines, value, f.publicBlob))
        return Error::invalid_format;

    if (f.version == 3 && f.encryption != "none") {
        if (!lines.Field("Key-Derivation", value))
            return Error::invalid_format;
        f.kdf.assign(value);
        if (!lines.Field("Argon2-Memory", value) || !ParseU32(value, f.argonMemory) ||
            !lines.Field("Argon2-Passes", value) || !ParseU32(value, f.argonPasses) ||
            !lines.Field("Argon2-Parallelism", value) || !ParseU32(value, f.argonLanes) ||
            !lines.Field("Argon2-Salt", value) || !DecodeHex(value, f.argonSalt))
            return Error::invalid_format;
    }

    if (!lines.Field("Private-Lines", value) || !ReadBase64Lines(lines, value, f.privateBlob))
        return Error::invalid_format;

    if (!lines.Field("Private-MAC", value) || !DecodeHex(value, f.mac))
        return Error::invalid_format;
    return Error::ok;
}

// ---------------------------------------------------------------------------
// Key derivation, decryption, MAC
// ---------------------------------------------------------------------------
bool Sha1(std::initializer_list<std::string_view> parts, uint8_t out[20])
{
    Owned<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestInit_ex2(ctx.get(), EVP_sha1(), nullptr) != 1)
        return false;
    for (auto part : parts) {
        if (EVP_DigestUpdate(ctx.get(), part.data(), part.size()) != 1)
            return false;
    }
    unsigned int len = 0;
    return EVP_DigestFinal_ex(ctx.get(), out, &len) == 1 && len == 20;
}

struct DerivedKeys {
    std::array<uint8_t, 32> cipherKey{};
    std::array<uint8_t, 16> cipherIv{};
    SecureBytes macKey;
    ~DerivedKeys()
    {
        SecureZeroMemory(cipherKey.data(), cipherKey.size());
        SecureZeroMemory(cipherIv.data(), cipherIv.size());
    }
};

Error DeriveV2(std::string_view passphrase, DerivedKeys& k)
{
    static constexpr char kZero[4] = {0, 0, 0, 0};
    static constexpr char kOne[4] = {0, 0, 0, 1};
    std::array<uint8_t, 40> material{};
    std::array<uint8_t, 20> mac{};
    const bool ok = Sha1({std::string_view(kZero, 4), passphrase}, material.data()) &&
                    Sha1({std::string_view(kOne, 4), passphrase}, material.data() + 20) &&
                    Sha1({"putty-private-key-file-mac-key", passphrase}, mac.data());
    if (ok) {
        std::memcpy(k.cipherKey.data(), material.data(), 32);
        k.macKey.assign(mac.begin(), mac.end());
    }
    SecureZeroMemory(material.data(), material.size());
    SecureZeroMemory(mac.data(), mac.size());
    return ok ? Error::ok : Error::crypto_error;
}

Error DeriveV3(const PpkFile& f, std::string_view passphrase, DerivedKeys& k)
{
    const char* kdfName = nullptr;
    if (f.kdf == "Argon2id")
        kdfName = "ARGON2ID";
    else if (f.kdf == "Argon2i")
        kdfName = "ARGON2I";
    else if (f.kdf == "Argon2d")
        kdfName = "ARGON2D";
    else
        return Error::unsupported_kdf;

    // Argon2 itself requires memory >= 8 KiB per lane.
    if (f.argonLanes == 0 || f.argonLanes > kPpkArgon2MaxLanes || f.argonPasses == 0 ||
        f.argonMemory < 8ull * f.argonLanes || f.argonMemory > kPpkArgon2MaxMemoryKiB ||
        static_cast<uint64_t>(f.argonMemory) * f.argonPasses > kPpkArgon2MaxWorkKiB ||
        f.argonSalt.empty() || f.argonSalt.size() > 1024)
        return Error::kdf_limits_exceeded;

    Owned<EVP_KDF> kdf(EVP_KDF_fetch(nullptr, kdfName, nullptr));
    if (!kdf)
        return Error::kdf_unavailable;
    Owned<EVP_KDF_CTX> ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx)
        return Error::crypto_error;

    uint32_t passes = f.argonPasses;
    uint32_t memory = f.argonMemory;
    uint32_t lanes = f.argonLanes;
    uint32_t threads = 1;
    uint32_t argonVersion = 0x13;
    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<char*>(passphrase.data()), passphrase.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(f.argonSalt.data()), f.argonSalt.size()),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &passes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &argonVersion),
        OSSL_PARAM_construct_end(),
    };

    std::array<uint8_t, 80> out{};
    const bool ok = EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) == 1;
    if (ok) {
        std::memcpy(k.cipherKey.data(), out.data(), 32);
        std::memcpy(k.cipherIv.data(), out.data() + 32, 16);
        k.macKey.assign(out.begin() + 48, out.end());
    }
    SecureZeroMemory(out.data(), out.size());
    return ok ? Error::ok : Error::crypto_error;
}

bool DecryptAes256Cbc(SecureBytes& blob, const DerivedKeys& k)
{
    if (blob.empty() || blob.size() % 16)
        return false;
    Owned<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
    SecureBytes plain(blob.size() + 16);
    int n1 = 0;
    int n2 = 0;
    if (!ctx || EVP_DecryptInit_ex2(ctx.get(), EVP_aes_256_cbc(), k.cipherKey.data(), k.cipherIv.data(), nullptr) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1 ||
        EVP_DecryptUpdate(ctx.get(), plain.data(), &n1, blob.data(), static_cast<int>(blob.size())) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), plain.data() + n1, &n2) != 1)
        return false;
    plain.resize(static_cast<size_t>(n1) + static_cast<size_t>(n2));
    blob.swap(plain);
    return true;
}

bool VerifyMac(const PpkFile& f, const SecureBytes& privatePlain, const SecureBytes& macKey)
{
    SecureBytes data;
    PutString(data, f.algorithm.data(), f.algorithm.size());
    PutString(data, f.encryption.data(), f.encryption.size());
    PutString(data, f.comment.data(), f.comment.size());
    PutString(data, f.publicBlob.data(), f.publicBlob.size());
    PutString(data, privatePlain.data(), privatePlain.size());

    const char* digest = f.version == 2 ? "SHA1" : "SHA256";
    const size_t expected = f.version == 2 ? 20 : 32;
    if (f.mac.size() != expected)
        return false;

    // An empty HMAC key (unencrypted format 3) still needs a valid pointer.
    static const uint8_t kEmptyKey = 0;
    std::array<uint8_t, 32> mac{};
    size_t macLen = 0;
    const bool computed =
        EVP_Q_mac(nullptr, "HMAC", nullptr, digest, nullptr, macKey.empty() ? &kEmptyKey : macKey.data(),
                  macKey.size(), data.data(), data.size(), mac.data(), mac.size(), &macLen) != nullptr;
    return computed && macLen == expected && CRYPTO_memcmp(mac.data(), f.mac.data(), expected) == 0;
}

// ---------------------------------------------------------------------------
// Key reconstruction
// ---------------------------------------------------------------------------
Owned<EVP_PKEY> FromData(const char* keyType, OSSL_PARAM_BLD* bld)
{
    Owned<OSSL_PARAM> params(OSSL_PARAM_BLD_to_param(bld));
    Owned<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_from_name(nullptr, keyType, nullptr));
    EVP_PKEY* raw = nullptr;
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
        EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_KEYPAIR, params.get()) != 1)
        return nullptr;
    return Owned<EVP_PKEY>(raw);
}

Error BuildRsa(const PpkFile& f, const SecureBytes& priv, Owned<EVP_PKEY>& out)
{
    WireReader pub(f.publicBlob.data(), f.publicBlob.size());
    if (!pub.StringEquals("ssh-rsa"))
        return Error::invalid_format;
    Owned<BIGNUM> e = pub.Mpint();
    Owned<BIGNUM> n = pub.Mpint();
    if (!e || !n || !pub.AtEnd())
        return Error::invalid_format;

    WireReader pr(priv.data(), priv.size());
    Owned<BIGNUM> d = pr.Mpint();
    Owned<BIGNUM> p = pr.Mpint();
    Owned<BIGNUM> q = pr.Mpint();
    Owned<BIGNUM> iqmp = pr.Mpint();
    if (!d || !p || !q || !iqmp)
        return Error::invalid_format;

    // PPK omits the CRT exponents; they follow from d, p and q.
    Owned<BN_CTX> bnCtx(BN_CTX_secure_new());
    Owned<BIGNUM> pm1(BN_secure_new());
    Owned<BIGNUM> qm1(BN_secure_new());
    Owned<BIGNUM> dmp1(BN_secure_new());
    Owned<BIGNUM> dmq1(BN_secure_new());
    if (!bnCtx || !pm1 || !qm1 || !dmp1 || !dmq1 ||
        !BN_sub(pm1.get(), p.get(), BN_value_one()) || !BN_sub(qm1.get(), q.get(), BN_value_one()) ||
        BN_is_zero(pm1.get()) || BN_is_zero(qm1.get()) ||
        !BN_mod(dmp1.get(), d.get(), pm1.get(), bnCtx.get()) ||
        !BN_mod(dmq1.get(), d.get(), qm1.get(), bnCtx.get()))
        return Error::inconsistent_key;

    Owned<OSSL_PARAM_BLD> bld(OSSL_PARAM_BLD_new());
    if (!bld ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, n.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, e.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_D, d.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_FACTOR1, p.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_FACTOR2, q.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp.get()))
        return Error::crypto_error;
    out = FromData("RSA", bld.get());
    return out ? Error::ok : Error::inconsistent_key;
}

Error BuildEcdsa(const PpkFile& f, const SecureBytes& priv, Owned<EVP_PKEY>& out)
{
    struct Curve { std::string_view algorithm; std::string_view sshName; const char* opensslName; };
    static constexpr Curve kCurves[] = {
        {"ecdsa-sha2-nistp256", "nistp256", "P-256"},
        {"ecdsa-sha2-nistp384", "nistp384", "P-384"},
        {"ecdsa-sha2-nistp521", "nistp521", "P-521"},
    };
    const Curve* curve = nullptr;
    for (const auto& c : kCurves) {
        if (f.algorithm == c.algorithm)
            curve = &c;
    }
    if (!curve)
        return Error::unsupported_algorithm;

    WireReader pub(f.publicBlob.data(), f.publicBlob.size());
    const uint8_t* point = nullptr;
    size_t pointLen = 0;
    if (!pub.StringEquals(curve->algorithm) || !pub.StringEquals(curve->sshName) ||
        !pub.String(point, pointLen) || !pub.AtEnd())
        return Error::invalid_format;

    WireReader pr(priv.data(), priv.size());
    Owned<BIGNUM> k = pr.Mpint();
    if (!k)
        return Error::invalid_format;

    Owned<OSSL_PARAM_BLD> bld(OSSL_PARAM_BLD_new());
    if (!bld ||
        !OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, curve->opensslName, 0) ||
        !OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point, pointLen) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, k.get()))
        return Error::crypto_error;
    out = FromData("EC", bld.get());
    return out ? Error::ok : Error::inconsistent_key;
}

Error BuildEd25519(const PpkFile& f, const SecureBytes& priv, Owned<EVP_PKEY>& out)
{
    WireReader pub(f.publicBlob.data(), f.publicBlob.size());
    const uint8_t* pk = nullptr;
    size_t pkLen = 0;
    if (!pub.StringEquals("ssh-ed25519") || !pub.String(pk, pkLen) || pkLen != 32 || !pub.AtEnd())
        return Error::invalid_format;

    // PuTTY stores the 32-byte secret as an unsigned little-endian integer in
    // as few bytes as it needs (put_mp_le_unsigned), so a secret whose top
    // byte is zero is shorter. Zero-extend at the high end.
    WireReader pr(priv.data(), priv.size());
    const uint8_t* sk = nullptr;
    size_t skLen = 0;
    if (!pr.String(sk, skLen) || skLen > 32)
        return Error::invalid_format;
    std::array<uint8_t, 32> secret{};
    std::memcpy(secret.data(), sk, skLen);

    out.reset(EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr, secret.data(), secret.size()));
    SecureZeroMemory(secret.data(), secret.size());
    if (!out)
        return Error::crypto_error;

    std::array<uint8_t, 32> derived{};
    size_t derivedLen = derived.size();
    if (EVP_PKEY_get_raw_public_key(out.get(), derived.data(), &derivedLen) != 1 || derivedLen != 32 ||
        CRYPTO_memcmp(derived.data(), pk, 32) != 0) {
        out.reset();
        return Error::inconsistent_key;
    }
    return Error::ok;
}

Error ToPem(EVP_PKEY* key, SecureChars& outPem)
{
    // Pairwise check: RSA p*q == n, e*d == 1 (mod lambda(n)) and the CRT
    // values; EC Q == k*G on the named curve; Ed25519 public from private.
    Owned<EVP_PKEY_CTX> check(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr));
    if (!check || EVP_PKEY_pairwise_check(check.get()) != 1)
        return Error::inconsistent_key;

    Owned<BIO> bio(BIO_new(BIO_s_secmem()));
    if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
        return Error::crypto_error;
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0 || !data)
        return Error::crypto_error;
    outPem.assign(data, data + len);
    return Error::ok;
}

Error Convert(std::string_view text, const char* passphrase, SecureChars& outPem)
{
    PpkFile f;
    if (const Error e = ParsePpk(text, f); e != Error::ok)
        return e;

    const bool isRsa = f.algorithm == "ssh-rsa";
    const bool isEd25519 = f.algorithm == "ssh-ed25519";
    const bool isEcdsa = f.algorithm.rfind("ecdsa-sha2-nistp", 0) == 0;
    if (!isRsa && !isEd25519 && !isEcdsa)
        return Error::unsupported_algorithm;

    const bool encrypted = f.encryption != "none";
    const std::string_view pass = (encrypted && passphrase) ? std::string_view(passphrase) : std::string_view();
    if (encrypted && pass.empty())
        return Error::passphrase_required;

    DerivedKeys keys;
    if (f.version == 2) {
        if (const Error e = DeriveV2(pass, keys); e != Error::ok)
            return e;
    } else if (encrypted) {
        if (const Error e = DeriveV3(f, pass, keys); e != Error::ok)
            return e;
    }

    if (encrypted && !DecryptAes256Cbc(f.privateBlob, keys))
        return Error::bad_passphrase_or_mac;
    if (!VerifyMac(f, f.privateBlob, keys.macKey))
        return Error::bad_passphrase_or_mac;

    Owned<EVP_PKEY> key;
    const Error built = isRsa       ? BuildRsa(f, f.privateBlob, key)
                        : isEcdsa   ? BuildEcdsa(f, f.privateBlob, key)
                                    : BuildEd25519(f, f.privateBlob, key);
    if (built != Error::ok)
        return built;
    return ToPem(key.get(), outPem);
}

} // namespace

PpkConvertError ConvertPpkToPem(std::string_view fileContent, const char* passphrase, SecureChars& outPem) noexcept
{
    outPem.clear();
    try {
        ErrorQueueGuard errors;
        const Error e = Convert(fileContent, passphrase, outPem);
        if (e != Error::ok)
            outPem.clear();
        return e;
    } catch (...) {
        outPem.clear();
        return Error::internal_error;
    }
}

PpkConvertError ConvertPpkFileToPem(const char* ppkPath, const char* passphrase, SecureChars& outPem) noexcept
{
    outPem.clear();
    if (!ppkPath || !ppkPath[0])
        return Error::io_error;
    try {
        HANDLE file = CreateFileA(ppkPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return Error::io_error;
        LARGE_INTEGER size{};
        SecureChars content;
        bool ok = GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= static_cast<LONGLONG>(kMaxFileSize);
        if (ok) {
            content.resize(static_cast<size_t>(size.QuadPart));
            DWORD got = 0;
            ok = ReadFile(file, content.data(), static_cast<DWORD>(content.size()), &got, nullptr) && got == content.size();
        }
        CloseHandle(file);
        if (!ok)
            return Error::io_error;
        return ConvertPpkToPem(std::string_view(content.data(), content.size()), passphrase, outPem);
    } catch (...) {
        outPem.clear();
        return Error::internal_error;
    }
}

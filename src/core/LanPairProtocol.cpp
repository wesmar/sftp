#include "global.h"
#include "LanPairProtocol.h"
#include "LanPairInternal.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>

#include <algorithm>
#include <cstring>

namespace lanpair_proto {

namespace {

using namespace lanpair_internal;

// RFC 9382, section 6: M and N for P-256, compressed SEC1.
constexpr char kSpake2M[] = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
constexpr char kSpake2N[] = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";
// Bound into the confirmation keys, so a transcript of this protocol is no
// use to any other that runs SPAKE2.
constexpr std::string_view kConfirmationAad = "TCSFTP LANPAIR3";
constexpr size_t kMaxFramePlaintext = 65536;
constexpr size_t kTagSize = 16;

bool Hkdf(std::span<const uint8_t> key, std::span<const uint8_t> salt, std::string_view info,
          std::span<uint8_t> out)
{
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf)
        return false;
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx)
        return false;
    OSSL_PARAM params[5];
    size_t n = 0;
    params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(key.data()), key.size());
    if (!salt.empty())
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()), salt.size());
    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<char*>(info.data()), info.size());
    params[n] = OSSL_PARAM_construct_end();
    const bool ok = EVP_KDF_derive(ctx, out.data(), out.size(), params) == 1;
    EVP_KDF_CTX_free(ctx);
    return ok;
}

bool HmacSha256(std::span<const uint8_t> key, std::span<const uint8_t> data, std::array<uint8_t, 32>& out)
{
    size_t len = 0;
    return EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, key.data(), key.size(),
                     data.data(), data.size(), out.data(), out.size(), &len) && len == out.size();
}

void AppendWithLength(std::vector<uint8_t>& tt, std::span<const uint8_t> data)
{
    uint64_t len = data.size();
    for (int i = 0; i < 8; ++i) { // eight bytes, little-endian
        tt.push_back(static_cast<uint8_t>(len & 0xFF));
        len >>= 8;
    }
    tt.insert(tt.end(), data.begin(), data.end());
}

std::span<const uint8_t> AsBytes(std::string_view s)
{
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

// The SPAKE2 password scalar from the pair key: 48 bytes reduced modulo the
// order of P-256 keep the bias below 2^-128.
std::optional<std::array<uint8_t, 48>> ScalarFromKey(const KeyBytes& key)
{
    std::array<uint8_t, 48> w{};
    if (key.empty() || !Hkdf(key, {}, "TCSFTP LANPAIR3 w", w))
        return std::nullopt;
    return w;
}

} // namespace

// ===========================================================================
// Spake2
// ===========================================================================
struct Spake2::Impl {
    Role role = Role::A;
    std::string idA;
    std::string idB;
    EC_GROUP* group = nullptr;
    BN_CTX* bn = nullptr;
    BIGNUM* w = nullptr;
    BIGNUM* eph = nullptr;
    EC_POINT* m = nullptr;
    EC_POINT* n = nullptr;
    std::vector<uint8_t> share;
    std::vector<uint8_t> tt;
    Secrets secrets;
    bool ok = false;
    bool finished = false;

    ~Impl()
    {
        BN_clear_free(w);
        BN_clear_free(eph);
        EC_POINT_free(m);
        EC_POINT_free(n);
        EC_GROUP_free(group);
        BN_CTX_free(bn);
        OPENSSL_cleanse(&secrets, sizeof(secrets));
        if (!tt.empty())
            OPENSSL_cleanse(tt.data(), tt.size());
    }

    EC_POINT* PointFromHex(const char* hex) const
    {
        const auto bytes = hexDecode(hex);
        EC_POINT* p = EC_POINT_new(group);
        if (!bytes || !p || EC_POINT_oct2point(group, p, bytes->data(), bytes->size(), bn) != 1) {
            EC_POINT_free(p);
            return nullptr;
        }
        return p;
    }

    std::vector<uint8_t> Encode(const EC_POINT* p) const
    {
        std::vector<uint8_t> out(65);
        const size_t len = EC_POINT_point2oct(group, p, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), bn);
        out.resize(len == 65 ? len : 0);
        return out;
    }
};

Spake2::Spake2(Role role, std::string_view idA, std::string_view idB, std::span<const uint8_t> w,
               std::span<const uint8_t> ephemeral)
    : impl_(std::make_unique<Impl>())
{
    Impl& s = *impl_;
    s.role = role;
    s.idA.assign(idA);
    s.idB.assign(idB);
    s.group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    s.bn = BN_CTX_new();
    if (!s.group || !s.bn)
        return;
    const BIGNUM* order = EC_GROUP_get0_order(s.group);
    s.m = s.PointFromHex(kSpake2M);
    s.n = s.PointFromHex(kSpake2N);
    s.w = BN_bin2bn(w.data(), static_cast<int>(w.size()), nullptr);
    s.eph = BN_new();
    if (!s.m || !s.n || !s.w || !s.eph || BN_nnmod(s.w, s.w, order, s.bn) != 1)
        return;
    if (!ephemeral.empty()) {
        if (!BN_bin2bn(ephemeral.data(), static_cast<int>(ephemeral.size()), s.eph))
            return;
    } else {
        do {
            if (BN_priv_rand_range_ex(s.eph, order, 0, s.bn) != 1)
                return;
        } while (BN_is_zero(s.eph));
    }
    // pA = x*G + w*M, pB = y*G + w*N
    EC_POINT* p = EC_POINT_new(s.group);
    if (p && EC_POINT_mul(s.group, p, s.eph, role == Role::A ? s.m : s.n, s.w, s.bn) == 1)
        s.share = s.Encode(p);
    EC_POINT_free(p);
    s.ok = !s.share.empty();
}

Spake2::~Spake2() = default;

bool Spake2::ok() const noexcept { return impl_ && impl_->ok; }
const std::vector<uint8_t>& Spake2::share() const noexcept { return impl_->share; }
const Spake2::Secrets& Spake2::secrets() const noexcept { return impl_->secrets; }

bool Spake2::finish(std::span<const uint8_t> peerShare, std::string_view aad)
{
    Impl& s = *impl_;
    if (!s.ok || s.finished)
        return false;

    EC_POINT* peer = EC_POINT_new(s.group);
    EC_POINT* blind = EC_POINT_new(s.group);
    EC_POINT* k = EC_POINT_new(s.group);
    bool good = peer && blind && k &&
        EC_POINT_oct2point(s.group, peer, peerShare.data(), peerShare.size(), s.bn) == 1 &&
        EC_POINT_is_on_curve(s.group, peer, s.bn) == 1 &&
        !EC_POINT_is_at_infinity(s.group, peer) &&
        // K = x * (pB - w*N) for A, y * (pA - w*M) for B
        EC_POINT_mul(s.group, blind, nullptr, s.role == Role::A ? s.n : s.m, s.w, s.bn) == 1 &&
        EC_POINT_invert(s.group, blind, s.bn) == 1 &&
        EC_POINT_add(s.group, blind, peer, blind, s.bn) == 1 &&
        EC_POINT_mul(s.group, k, nullptr, blind, s.eph, s.bn) == 1 &&
        !EC_POINT_is_at_infinity(s.group, k);

    std::vector<uint8_t> peerEncoded;
    std::vector<uint8_t> kEncoded;
    if (good) {
        peerEncoded = s.Encode(peer);
        kEncoded = s.Encode(k);
        good = !peerEncoded.empty() && !kEncoded.empty();
    }
    EC_POINT_free(peer);
    EC_POINT_free(blind);
    EC_POINT_free(k);
    if (!good)
        return false;

    // TT = A, B, pA, pB, K, w - each preceded by its length; w big-endian,
    // padded to the length of p.
    std::array<uint8_t, 32> wBytes{};
    if (BN_bn2binpad(s.w, wBytes.data(), static_cast<int>(wBytes.size())) != static_cast<int>(wBytes.size()))
        return false;
    const std::vector<uint8_t>& pA = s.role == Role::A ? s.share : peerEncoded;
    const std::vector<uint8_t>& pB = s.role == Role::A ? peerEncoded : s.share;
    s.tt.clear();
    AppendWithLength(s.tt, AsBytes(s.idA));
    AppendWithLength(s.tt, AsBytes(s.idB));
    AppendWithLength(s.tt, pA);
    AppendWithLength(s.tt, pB);
    AppendWithLength(s.tt, kEncoded);
    AppendWithLength(s.tt, wBytes);
    OPENSSL_cleanse(kEncoded.data(), kEncoded.size());
    OPENSSL_cleanse(wBytes.data(), wBytes.size());

    // Ke || Ka = Hash(TT); KcA || KcB = HKDF(Ka, nil, "ConfirmationKeys" || AAD)
    size_t hashLen = 0;
    if (!EVP_Q_digest(nullptr, "SHA256", nullptr, s.tt.data(), s.tt.size(), s.secrets.transcriptHash.data(), &hashLen) ||
        hashLen != s.secrets.transcriptHash.size())
        return false;
    std::copy_n(s.secrets.transcriptHash.begin(), 16, s.secrets.ke.begin());
    std::copy_n(s.secrets.transcriptHash.begin() + 16, 16, s.secrets.ka.begin());
    std::string info = "ConfirmationKeys";
    info.append(aad);
    std::array<uint8_t, 32> kc{};
    if (!Hkdf(s.secrets.ka, {}, info, kc))
        return false;
    std::copy_n(kc.begin(), 16, s.secrets.kcA.begin());
    std::copy_n(kc.begin() + 16, 16, s.secrets.kcB.begin());
    OPENSSL_cleanse(kc.data(), kc.size());
    s.finished = true;
    return true;
}

std::array<uint8_t, 32> Spake2::confirmation() const
{
    std::array<uint8_t, 32> mac{};
    const Impl& s = *impl_;
    if (s.finished)
        HmacSha256(s.role == Role::A ? s.secrets.kcA : s.secrets.kcB, s.tt, mac);
    return mac;
}

bool Spake2::checkPeerConfirmation(std::span<const uint8_t> mac) const
{
    const Impl& s = *impl_;
    std::array<uint8_t, 32> expected{};
    if (!s.finished || mac.size() != expected.size() ||
        !HmacSha256(s.role == Role::A ? s.secrets.kcB : s.secrets.kcA, s.tt, expected))
        return false;
    return CRYPTO_memcmp(expected.data(), mac.data(), expected.size()) == 0;
}

// ===========================================================================
// Channel
// ===========================================================================
struct Channel::Impl {
    SOCKET sock = INVALID_SOCKET;
    bool encrypted = false;
    EVP_CIPHER_CTX* tx = nullptr;
    EVP_CIPHER_CTX* rx = nullptr;
    std::array<uint8_t, 32> txKey{};
    std::array<uint8_t, 32> rxKey{};
    std::array<uint8_t, 4> txSalt{};
    std::array<uint8_t, 4> rxSalt{};
    uint64_t txSeq = 0;
    uint64_t rxSeq = 0;
    std::vector<uint8_t> rxBuf; // decrypted, not yet consumed
    size_t rxPos = 0;

    ~Impl()
    {
        EVP_CIPHER_CTX_free(tx);
        EVP_CIPHER_CTX_free(rx);
        OPENSSL_cleanse(txKey.data(), txKey.size());
        OPENSSL_cleanse(rxKey.data(), rxKey.size());
    }

    bool rawSend(const uint8_t* data, size_t len) const
    {
        return lanpair_internal::sendAll(sock, data, len);
    }

    bool rawRecv(uint8_t* data, size_t len) const
    {
        size_t got = 0;
        while (got < len) {
            const int n = recv(sock, reinterpret_cast<char*>(data + got), static_cast<int>(len - got), 0);
            if (n <= 0)
                return false;
            got += static_cast<size_t>(n);
        }
        return true;
    }

    static std::array<uint8_t, 12> Iv(const std::array<uint8_t, 4>& salt, uint64_t seq)
    {
        std::array<uint8_t, 12> iv{};
        std::copy(salt.begin(), salt.end(), iv.begin());
        for (int i = 0; i < 8; ++i)
            iv[4 + i] = static_cast<uint8_t>(seq >> (56 - 8 * i));
        return iv;
    }

    // One frame: 4-byte big-endian length (authenticated, not encrypted),
    // the ciphertext, the 16-byte tag.
    bool sendFrame(const uint8_t* data, size_t len)
    {
        if (len == 0 || len > kMaxFramePlaintext || txSeq == UINT64_MAX)
            return false;
        std::vector<uint8_t> frame(4 + len + kTagSize);
        for (int i = 0; i < 4; ++i)
            frame[i] = static_cast<uint8_t>(len >> (24 - 8 * i));
        const auto iv = Iv(txSalt, txSeq++);
        int outLen = 0;
        int finalLen = 0;
        const bool ok =
            EVP_EncryptInit_ex2(tx, EVP_aes_256_gcm(), txKey.data(), iv.data(), nullptr) == 1 &&
            EVP_EncryptUpdate(tx, nullptr, &outLen, frame.data(), 4) == 1 &&
            EVP_EncryptUpdate(tx, frame.data() + 4, &outLen, data, static_cast<int>(len)) == 1 &&
            EVP_EncryptFinal_ex(tx, frame.data() + 4 + outLen, &finalLen) == 1 &&
            static_cast<size_t>(outLen + finalLen) == len &&
            EVP_CIPHER_CTX_ctrl(tx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(kTagSize), frame.data() + 4 + len) == 1;
        return ok && rawSend(frame.data(), frame.size());
    }

    bool readFrame()
    {
        std::array<uint8_t, 4> header{};
        if (!rawRecv(header.data(), header.size()))
            return false;
        const size_t len = (static_cast<size_t>(header[0]) << 24) | (static_cast<size_t>(header[1]) << 16) |
                           (static_cast<size_t>(header[2]) << 8) | header[3];
        if (len == 0 || len > kMaxFramePlaintext || rxSeq == UINT64_MAX)
            return false;
        std::vector<uint8_t> body(len + kTagSize);
        if (!rawRecv(body.data(), body.size()))
            return false;
        if (rxPos == rxBuf.size()) {
            rxBuf.clear();
            rxPos = 0;
        }
        const size_t at = rxBuf.size();
        rxBuf.resize(at + len);
        const auto iv = Iv(rxSalt, rxSeq++);
        int outLen = 0;
        int finalLen = 0;
        const bool ok =
            EVP_DecryptInit_ex2(rx, EVP_aes_256_gcm(), rxKey.data(), iv.data(), nullptr) == 1 &&
            EVP_DecryptUpdate(rx, nullptr, &outLen, header.data(), 4) == 1 &&
            EVP_DecryptUpdate(rx, rxBuf.data() + at, &outLen, body.data(), static_cast<int>(len)) == 1 &&
            EVP_CIPHER_CTX_ctrl(rx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kTagSize), body.data() + len) == 1 &&
            EVP_DecryptFinal_ex(rx, rxBuf.data() + at + outLen, &finalLen) == 1;
        if (!ok) {
            // An altered frame: nothing of it is handed on, and the
            // connection is over.
            OPENSSL_cleanse(rxBuf.data() + at, len);
            rxBuf.resize(at);
            return false;
        }
        return true;
    }
};

Channel::Channel(SOCKET s) noexcept : impl_(std::make_unique<Impl>()) { impl_->sock = s; }
Channel::~Channel() { close(); }

SOCKET Channel::socket() const noexcept { return impl_->sock; }
bool Channel::encrypted() const noexcept { return impl_->encrypted; }

void Channel::close() noexcept
{
    if (impl_->sock != INVALID_SOCKET) {
        closesocket(impl_->sock);
        impl_->sock = INVALID_SOCKET;
    }
}

bool Channel::sendAll(const void* data, size_t len)
{
    Impl& c = *impl_;
    if (c.sock == INVALID_SOCKET)
        return false;
    const auto* p = static_cast<const uint8_t*>(data);
    if (!c.encrypted)
        return c.rawSend(p, len);
    while (len > 0) {
        const size_t n = (std::min)(len, kMaxFramePlaintext);
        if (!c.sendFrame(p, n))
            return false;
        p += n;
        len -= n;
    }
    return true;
}

bool Channel::sendLine(std::string_view line)
{
    std::string framed(line);
    framed += '\n';
    return sendAll(framed.data(), framed.size());
}

bool Channel::recvAll(void* data, size_t len)
{
    Impl& c = *impl_;
    if (c.sock == INVALID_SOCKET)
        return false;
    auto* p = static_cast<uint8_t*>(data);
    if (!c.encrypted)
        return c.rawRecv(p, len);
    while (len > 0) {
        if (c.rxPos == c.rxBuf.size() && !c.readFrame())
            return false;
        const size_t n = (std::min)(len, c.rxBuf.size() - c.rxPos);
        std::memcpy(p, c.rxBuf.data() + c.rxPos, n);
        c.rxPos += n;
        p += n;
        len -= n;
    }
    return true;
}

bool Channel::recvLine(std::string* out, size_t maxLen)
{
    Impl& c = *impl_;
    out->clear();
    if (c.sock == INVALID_SOCKET)
        return false;
    if (!c.encrypted)
        return lanpair_internal::recvLine(c.sock, out, maxLen); // byte by byte: never reads past the line
    while (out->size() < maxLen) {
        if (c.rxPos == c.rxBuf.size() && !c.readFrame())
            return false;
        const char ch = static_cast<char>(c.rxBuf[c.rxPos++]);
        if (ch == '\n')
            return true;
        if (ch != '\r')
            out->push_back(ch);
    }
    return false;
}

bool Channel::startEncryption(const Spake2::Secrets& secrets, bool initiator)
{
    Impl& c = *impl_;
    std::array<uint8_t, 36> i2r{};
    std::array<uint8_t, 36> r2i{};
    if (!Hkdf(secrets.ke, secrets.transcriptHash, "TCSFTP LANPAIR3 initiator to responder", i2r) ||
        !Hkdf(secrets.ke, secrets.transcriptHash, "TCSFTP LANPAIR3 responder to initiator", r2i))
        return false;
    const auto& sendMaterial = initiator ? i2r : r2i;
    const auto& recvMaterial = initiator ? r2i : i2r;
    std::copy_n(sendMaterial.begin(), 32, c.txKey.begin());
    std::copy_n(sendMaterial.begin() + 32, 4, c.txSalt.begin());
    std::copy_n(recvMaterial.begin(), 32, c.rxKey.begin());
    std::copy_n(recvMaterial.begin() + 32, 4, c.rxSalt.begin());
    OPENSSL_cleanse(i2r.data(), i2r.size());
    OPENSSL_cleanse(r2i.data(), r2i.size());
    c.tx = EVP_CIPHER_CTX_new();
    c.rx = EVP_CIPHER_CTX_new();
    c.encrypted = c.tx && c.rx;
    return c.encrypted;
}

// ===========================================================================
// Handshakes
// ===========================================================================
bool ClientHandshake(Channel& ch, const std::string& clientId, lanpair::PairRole role,
                     const std::string& expectedServerId, const KeyLookup& keyFor,
                     PeerInfo* outServer, lanpair::PairError* err)
{
    const auto fail = [err](int code, const char* message) {
        if (err) {
            err->code = code;
            err->message = message;
        }
        return false;
    };

    if (!ch.sendLine("PAIR3 HELLO " + escapeToken(clientId) + " " + roleToString(role)))
        return fail(WSAGetLastError(), "Cannot reach the other computer");
    std::string line;
    if (!ch.recvLine(&line, 4096))
        return fail(ERROR_INVALID_DATA, "The other computer did not answer - it may run a plugin older than 10.3.1");
    auto t = splitBySpace(line);
    if (t.size() >= 3 && t[0] == "PAIR3" && t[1] == "FAIL")
        return fail(ERROR_ACCESS_DENIED, t[2] == "no-key"
            ? "The other computer has no LAN Pair key for this one: pair them with the same password first"
            : "The other computer refused the connection");
    if (t.size() != 6 || t[0] != "PAIR3" || t[1] != "SHARE")
        return fail(ERROR_INVALID_DATA, "Unexpected answer - the other computer may run a plugin older than 10.3.1");

    PeerInfo server{unescapeToken(t[2]), unescapeToken(t[3]), roleFromString(t[4])};
    if (!expectedServerId.empty() && server.peerId != expectedServerId)
        return fail(ERROR_ACCESS_DENIED, "Peer ID mismatch");
    const auto pB = hexDecode(t[5]);
    const auto key = keyFor(server.peerId);
    if (!key)
        return fail(ERROR_ACCESS_DENIED, "No LAN Pair password or stored key for this peer");
    auto w = ScalarFromKey(*key);
    if (!pB || !w)
        return fail(ERROR_INVALID_DATA, "Bad handshake data");

    Spake2 spake(Spake2::Role::A, clientId, server.peerId, *w);
    OPENSSL_cleanse(w->data(), w->size());
    if (!spake.ok() || !spake.finish(*pB, kConfirmationAad))
        return fail(ERROR_INVALID_DATA, "Bad handshake data");
    const auto cA = spake.confirmation();
    if (!ch.sendLine("PAIR3 CONFIRM " + hexEncode(spake.share().data(), spake.share().size()) + " " +
                     hexEncode(cA.data(), cA.size())))
        return fail(WSAGetLastError(), "Connection lost during the handshake");
    if (!ch.recvLine(&line, 4096))
        return fail(ERROR_INVALID_DATA, "Connection lost during the handshake");
    t = splitBySpace(line);
    if (t.size() >= 3 && t[0] == "PAIR3" && t[1] == "FAIL")
        return fail(ERROR_ACCESS_DENIED, "Wrong LAN Pair password, or the stored key no longer matches");
    const auto cB = t.size() == 3 && t[0] == "PAIR3" && t[1] == "OK" ? hexDecode(t[2]) : std::nullopt;
    if (!cB || !spake.checkPeerConfirmation(*cB))
        return fail(ERROR_ACCESS_DENIED, "The other computer could not prove the LAN Pair password");
    if (!ch.startEncryption(spake.secrets(), true))
        return fail(ERROR_INVALID_DATA, "Cannot start encryption");
    if (outServer)
        *outServer = std::move(server);
    return true;
}

bool ServerHandshake(Channel& ch, const std::string& serverId, const std::string& displayName,
                     lanpair::PairRole role, const KeyLookup& keyFor, PeerInfo* outClient)
{
    std::string line;
    if (!ch.recvLine(&line, 4096))
        return false;
    auto t = splitBySpace(line);
    if (!t.empty() && t[0] == "PAIR1") {
        ch.sendLine("PAIR1 FAIL upgrade-required"); // a plugin older than 10.3.1
        return false;
    }
    if (t.size() != 4 || t[0] != "PAIR3" || t[1] != "HELLO")
        return false;
    PeerInfo client{unescapeToken(t[2]), unescapeToken(t[2]), roleFromString(t[3])};

    const auto key = keyFor(client.peerId);
    auto w = key ? ScalarFromKey(*key) : std::nullopt;
    if (!w) {
        ch.sendLine("PAIR3 FAIL no-key");
        return false;
    }
    Spake2 spake(Spake2::Role::B, client.peerId, serverId, *w);
    OPENSSL_cleanse(w->data(), w->size());
    if (!spake.ok())
        return false;
    const std::string& name = displayName.empty() ? serverId : displayName;
    if (!ch.sendLine("PAIR3 SHARE " + escapeToken(serverId) + " " + escapeToken(name) + " " + roleToString(role) + " " +
                     hexEncode(spake.share().data(), spake.share().size())))
        return false;

    if (!ch.recvLine(&line, 4096))
        return false;
    t = splitBySpace(line);
    const auto pA = t.size() == 4 && t[0] == "PAIR3" && t[1] == "CONFIRM" ? hexDecode(t[2]) : std::nullopt;
    const auto cA = pA ? hexDecode(t[3]) : std::nullopt;
    if (!pA || !cA || !spake.finish(*pA, kConfirmationAad) || !spake.checkPeerConfirmation(*cA)) {
        // One guess per connection, and not many connections per second.
        Sleep(1000);
        ch.sendLine("PAIR3 FAIL bad-auth");
        return false;
    }
    const auto cB = spake.confirmation();
    if (!ch.sendLine("PAIR3 OK " + hexEncode(cB.data(), cB.size())))
        return false;
    if (!ch.startEncryption(spake.secrets(), false))
        return false;
    if (outClient)
        *outClient = std::move(client);
    return true;
}

} // namespace lanpair_proto

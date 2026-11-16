#pragma once

// LAN Pair, protocol 3 ("PAIR3").
//
// Both computers know the pair key: PBKDF2 of the pairing password, salted
// with the two peer ids (lanpair_internal::derivePairKey), or that key as
// stored in DPAPI after an earlier session. The key never crosses the wire.
//
//   client -> server   PAIR3 HELLO   <client id> <role>
//   server -> client   PAIR3 SHARE   <server id> <display name> <role> <pB>
//   client -> server   PAIR3 CONFIRM <pA> <cA>
//   server -> client   PAIR3 OK      <cB>          (or PAIR3 FAIL <reason>)
//
// pA, pB, cA and cB are SPAKE2 (RFC 9382, SPAKE2-P256-SHA256-HKDF-HMAC) with
// the client as A and the server as B. An eavesdropper learns nothing to
// guess the password with; an active attacker gets one guess per connection.
// Every byte after the handshake travels in AES-256-GCM frames keyed from
// SPAKE2's Ke, numbered per direction, so a frame that is read, altered,
// dropped, repeated or reordered on the way ends the connection.

#include <winsock2.h>
#include <windows.h>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "LanPair.h"

namespace lanpair_proto {

using KeyBytes = std::vector<uint8_t>;

// ---------------------------------------------------------------------------
// SPAKE2, suite SPAKE2-P256-SHA256-HKDF-HMAC (RFC 9382)
// ---------------------------------------------------------------------------
class Spake2 {
public:
    enum class Role { A, B };

    struct Secrets {
        std::array<uint8_t, 32> transcriptHash{}; // Hash(TT)
        std::array<uint8_t, 16> ke{};
        std::array<uint8_t, 16> ka{};
        std::array<uint8_t, 16> kcA{};
        std::array<uint8_t, 16> kcB{};
    };

    // `w` is reduced modulo the group order. `ephemeral`, when given, is the
    // secret scalar x or y - for test vectors only; otherwise it is random.
    Spake2(Role role, std::string_view idA, std::string_view idB, std::span<const uint8_t> w,
           std::span<const uint8_t> ephemeral = {});
    ~Spake2();
    Spake2(const Spake2&) = delete;
    Spake2& operator=(const Spake2&) = delete;

    bool ok() const noexcept;
    // pA or pB, uncompressed SEC1 (65 bytes).
    const std::vector<uint8_t>& share() const noexcept;
    // Takes the peer's share and derives the transcript and every key.
    // False for a share that is not a point of the curve.
    bool finish(std::span<const uint8_t> peerShare, std::string_view aad);
    // This side's confirmation (cA for A, cB for B) and the check of the
    // peer's, in constant time.
    std::array<uint8_t, 32> confirmation() const;
    bool checkPeerConfirmation(std::span<const uint8_t> mac) const;
    const Secrets& secrets() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Channel: one connection's byte stream, clear until startEncryption()
// ---------------------------------------------------------------------------
class Channel {
public:
    explicit Channel(SOCKET s) noexcept; // takes ownership of the socket
    ~Channel();
    Channel(const Channel&) = delete;
    Channel& operator=(const Channel&) = delete;

    bool sendLine(std::string_view line);
    bool recvLine(std::string* out, size_t maxLen = 65536);
    bool sendAll(const void* data, size_t len);
    bool recvAll(void* data, size_t len);

    // Both directions switch to AES-256-GCM; the initiator (client) sends
    // with one key and the responder with the other.
    bool startEncryption(const Spake2::Secrets& secrets, bool initiator);
    bool encrypted() const noexcept;

    SOCKET socket() const noexcept;
    void close() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Handshakes
// ---------------------------------------------------------------------------
struct PeerInfo {
    std::string peerId;
    std::string displayName;
    lanpair::PairRole role = lanpair::PairRole::Dual;
};

// The pair key for a peer id, or nothing when this computer has none.
using KeyLookup = std::function<std::optional<KeyBytes>(const std::string& peerId)>;

// Client side. `expectedServerId`, when not empty, must match the server's
// id. On success the channel is encrypted and `outServer` describes the peer.
bool ClientHandshake(Channel& ch, const std::string& clientId, lanpair::PairRole role,
                     const std::string& expectedServerId, const KeyLookup& keyFor,
                     PeerInfo* outServer, lanpair::PairError* err);

// Server side. On success the channel is encrypted and `outClient`
// describes the peer. A failed proof costs the client a second's delay.
bool ServerHandshake(Channel& ch, const std::string& serverId, const std::string& displayName,
                     lanpair::PairRole role, const KeyLookup& keyFor, PeerInfo* outClient);


} // namespace lanpair_proto

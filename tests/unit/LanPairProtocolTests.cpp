#include "Test.h"
#include "LanPairProtocol.h"
#include "LanPairInternal.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <future>
#include <string>
#include <thread>
#include <vector>

using lanpair_proto::Channel;
using lanpair_proto::KeyBytes;
using lanpair_proto::PeerInfo;
using lanpair_proto::Spake2;

namespace {

std::vector<uint8_t> Hex(const char* hex)
{
    auto v = lanpair_internal::hexDecode(hex);
    return v ? *v : std::vector<uint8_t>{};
}

template <size_t N>
bool Equals(const std::array<uint8_t, N>& a, const char* hex)
{
    const auto b = Hex(hex);
    return b.size() == N && std::equal(a.begin(), a.end(), b.begin());
}

// A connected TCP pair on the loopback interface.
struct SocketPair {
    SOCKET a = INVALID_SOCKET;
    SOCKET b = INVALID_SOCKET;
};

SocketPair MakeSocketPair()
{
    SocketPair p;
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int len = sizeof(addr);
    bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    listen(listener, 1);
    getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len);
    p.a = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    connect(p.a, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    p.b = accept(listener, nullptr, nullptr);
    closesocket(listener);
    lanpair_internal::setSocketTimeout(p.a, 5000);
    lanpair_internal::setSocketTimeout(p.b, 5000);
    return p;
}

struct Wsa {
    Wsa() { WSADATA d{}; WSAStartup(MAKEWORD(2, 2), &d); }
    ~Wsa() { WSACleanup(); }
};

const KeyBytes kKey(32, 0x5A);
const KeyBytes kOtherKey(32, 0xA5);

lanpair_proto::KeyLookup Fixed(const KeyBytes& key)
{
    return [key](const std::string&) { return std::optional<KeyBytes>(key); };
}

// Handshake on a pair: server on a thread, client here.
struct Handshake {
    bool client = false;
    bool server = false;
    lanpair::PairError err;
    PeerInfo serverSeen;
    PeerInfo clientSeen;
};

Handshake RunHandshake(Channel& clientCh, Channel& serverCh, const lanpair_proto::KeyLookup& clientKeys,
                       const lanpair_proto::KeyLookup& serverKeys)
{
    Handshake h;
    auto server = std::async(std::launch::async, [&] {
        return lanpair_proto::ServerHandshake(serverCh, "donor pc", "Donor PC", lanpair::PairRole::Donor, serverKeys,
                                              &h.clientSeen);
    });
    h.client = lanpair_proto::ClientHandshake(clientCh, "receiver pc", lanpair::PairRole::Receiver, "", clientKeys,
                                              &h.serverSeen, &h.err);
    h.server = server.get();
    return h;
}

// Reads one raw encrypted frame (length, ciphertext, tag) off a socket.
std::vector<uint8_t> ReadRawFrame(SOCKET s)
{
    std::vector<uint8_t> frame(4);
    if (recv(s, reinterpret_cast<char*>(frame.data()), 4, MSG_WAITALL) != 4)
        return {};
    const size_t len = (static_cast<size_t>(frame[0]) << 24) | (frame[1] << 16) | (frame[2] << 8) | frame[3];
    frame.resize(4 + len + 16);
    if (recv(s, reinterpret_cast<char*>(frame.data() + 4), static_cast<int>(len + 16), MSG_WAITALL) !=
        static_cast<int>(len + 16))
        return {};
    return frame;
}

// client <-> relay <-> server, the relay forwarding until told to stop, so
// the test can then play man in the middle on the encrypted stream.
struct Relay {
    SocketPair toClient;  // a: client's end, b: relay's end
    SocketPair toServer;  // a: relay's end,  b: server's end
    std::atomic<bool> stop{false};
    std::thread pump;

    Relay()
        : toClient(MakeSocketPair()), toServer(MakeSocketPair())
    {
        pump = std::thread([this] {
            char buf[4096];
            while (!stop) {
                fd_set set;
                FD_ZERO(&set);
                FD_SET(toClient.b, &set);
                FD_SET(toServer.a, &set);
                timeval tv{0, 20000};
                if (select(0, &set, nullptr, nullptr, &tv) <= 0)
                    continue;
                if (FD_ISSET(toClient.b, &set)) {
                    const int n = recv(toClient.b, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    send(toServer.a, buf, n, 0);
                }
                if (FD_ISSET(toServer.a, &set)) {
                    const int n = recv(toServer.a, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    send(toClient.b, buf, n, 0);
                }
            }
        });
    }
    void Stop()
    {
        stop = true;
        if (pump.joinable())
            pump.join();
    }
    ~Relay()
    {
        Stop();
        closesocket(toClient.b);
        closesocket(toServer.a);
    }
};

} // namespace

TEST_CASE("lanpair3: SPAKE2 matches the RFC 9382 P-256 test vector")
{
    const auto w = Hex("2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f");
    const auto x = Hex("43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729");
    const auto y = Hex("dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be");
    Spake2 a(Spake2::Role::A, "server", "client", w, x);
    Spake2 b(Spake2::Role::B, "server", "client", w, y);
    CHECK(a.ok() && b.ok());
    CHECK(a.finish(b.share(), "") && b.finish(a.share(), ""));
    CHECK(Equals(a.secrets().transcriptHash, "0e0672dc86f8e45565d338b0540abe6915bdf72e2b35b5c9e5663168e960a91b"));
    CHECK(Equals(a.secrets().ke, "0e0672dc86f8e45565d338b0540abe69"));
    CHECK(Equals(a.secrets().ka, "15bdf72e2b35b5c9e5663168e960a91b"));
    CHECK(Equals(a.secrets().kcA, "00c12546835755c86d8c0db7851ae86f"));
    CHECK(Equals(a.secrets().kcB, "a9fa3406c3b781b93d804485430ca27a"));
    CHECK(Equals(a.confirmation(), "58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0"));
    CHECK(Equals(b.confirmation(), "d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b"));
    CHECK(a.secrets().transcriptHash == b.secrets().transcriptHash);
    CHECK(a.checkPeerConfirmation(b.confirmation()) && b.checkPeerConfirmation(a.confirmation()));
}

TEST_CASE("lanpair3: SPAKE2 with different passwords, or a bad share, agrees on nothing")
{
    const std::vector<uint8_t> w1(48, 1);
    const std::vector<uint8_t> w2(48, 2);
    Spake2 a(Spake2::Role::A, "a", "b", w1);
    Spake2 b(Spake2::Role::B, "a", "b", w2);
    CHECK(a.finish(b.share(), "x") && b.finish(a.share(), "x"));
    CHECK(!b.checkPeerConfirmation(a.confirmation()));
    CHECK(!a.checkPeerConfirmation(b.confirmation()));
    CHECK(a.secrets().ke != b.secrets().ke);

    Spake2 c(Spake2::Role::A, "a", "b", w1);
    std::vector<uint8_t> offCurve(65, 0x04);
    offCurve[64] = 0x01;
    CHECK(!c.finish(offCurve, "x"));
    Spake2 d(Spake2::Role::A, "a", "b", w1);
    CHECK(!d.finish(std::vector<uint8_t>(3, 0), "x"));
}

TEST_CASE("lanpair3: handshake, then an encrypted stream both ways")
{
    Wsa wsa;
    auto pair = MakeSocketPair();
    Channel client(pair.a);
    Channel server(pair.b);
    const auto h = RunHandshake(client, server, Fixed(kKey), Fixed(kKey));
    CHECK(h.client && h.server);
    CHECK(client.encrypted() && server.encrypted());
    CHECK(h.serverSeen.peerId == "donor pc" && h.serverSeen.displayName == "Donor PC");
    CHECK(h.clientSeen.peerId == "receiver pc");

    std::string big(200000, '\0');
    for (size_t i = 0; i < big.size(); ++i)
        big[i] = static_cast<char>(i * 31 + 7);
    auto reader = std::async(std::launch::async, [&] {
        std::string line;
        std::string data(big.size(), '\0');
        const bool ok = server.recvLine(&line) && server.recvAll(data.data(), data.size());
        return ok && line == "LIST some path" && data == big;
    });
    CHECK(client.sendLine("LIST some path") && client.sendAll(big.data(), big.size()));
    CHECK(reader.get());
    CHECK(server.sendLine("OK 1"));
    std::string reply;
    CHECK(client.recvLine(&reply) && reply == "OK 1");
}

TEST_CASE("lanpair3: a wrong or missing key gets no session")
{
    Wsa wsa;
    {
        auto pair = MakeSocketPair();
        Channel client(pair.a);
        Channel server(pair.b);
        const auto h = RunHandshake(client, server, Fixed(kOtherKey), Fixed(kKey));
        CHECK(!h.client && !h.server);
        CHECK(h.err.message.find("Wrong LAN Pair password") != std::string::npos);
    }
    {
        auto pair = MakeSocketPair();
        Channel client(pair.a);
        Channel server(pair.b);
        const auto none = [](const std::string&) { return std::optional<KeyBytes>(); };
        const auto h = RunHandshake(client, server, Fixed(kKey), none);
        CHECK(!h.client && !h.server);
        CHECK(h.err.message.find("no LAN Pair key") != std::string::npos);
    }
}

TEST_CASE("lanpair3: an altered, replayed or reordered frame ends the connection")
{
    Wsa wsa;
    for (const char* attack : {"alter", "replay", "reorder"}) {
        Relay relay;
        Channel client(relay.toClient.a);
        Channel server(relay.toServer.b);
        const auto h = RunHandshake(client, server, Fixed(kKey), Fixed(kKey));
        CHECK(h.client && h.server);
        relay.Stop(); // from here on the test is the man in the middle

        CHECK(client.sendLine("first") && client.sendLine("second"));
        auto f1 = ReadRawFrame(relay.toClient.b);
        auto f2 = ReadRawFrame(relay.toClient.b);
        CHECK(!f1.empty() && !f2.empty());
        std::vector<uint8_t> wire;
        if (std::string(attack) == "alter") {
            f1[6] ^= 0x01;
            wire = f1;
        } else if (std::string(attack) == "replay") {
            wire = f1;
            wire.insert(wire.end(), f1.begin(), f1.end());
        } else {
            wire = f2;
            wire.insert(wire.end(), f1.begin(), f1.end());
        }
        send(relay.toServer.a, reinterpret_cast<const char*>(wire.data()), static_cast<int>(wire.size()), 0);

        std::string line;
        const bool first = server.recvLine(&line);
        if (std::string(attack) == "replay") {
            CHECK(first && line == "first");      // the genuine frame
            CHECK(!server.recvLine(&line));        // its copy is refused
        } else {
            CHECK(!first);                         // nothing gets through
        }
    }
}

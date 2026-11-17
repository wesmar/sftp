// LAN Pair end to end on the loopback interface: a LanFileServer and
// LanPairSession clients in one process, the server known under a test peer
// id. Every file, directory and DPAPI secret the tests create is removed.

#include "Test.h"
#include "LanPairSession.h"
#include "LanPairInternal.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

constexpr char kLoopback[] = "127.0.0.1";
constexpr char kPassword[] = "correct horse battery staple";

std::string TestId(const char* role)
{
    return std::string("sftpplug-test-") + role + "-" + std::to_string(GetCurrentProcessId());
}

uint16_t FreeLoopbackPort()
{
    lanpair_internal::WsaScope wsa;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int len = sizeof(addr);
    bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len);
    closesocket(s);
    return ntohs(addr.sin_port);
}

std::string Utf8(const fs::path& p)
{
    const auto u8 = p.u8string();
    return std::string(u8.begin(), u8.end());
}

std::string ReadAll(const fs::path& p)
{
    std::ifstream in(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), {});
}

// Removes what the tests leave behind, whatever way they end.
struct Cleanup {
    fs::path dir;
    std::vector<std::string> secrets;
    ~Cleanup()
    {
        std::error_code ec;
        fs::remove_all(dir, ec);
        for (const auto& s : secrets)
            lanpair::DpapiSecretStore::deleteSecret(s, nullptr);
    }
};

} // namespace

TEST_CASE("lanpair3: session against a file server - files, stored keys, refusals")
{
    using lanpair_internal::trustKeyForClient;
    using lanpair_internal::trustKeyForServer;

    const std::string serverId = TestId("srv");
    const std::string clientId = TestId("cli");
    const std::string otherId  = TestId("other");
    Cleanup cleanup;
    cleanup.dir = fs::temp_directory_path() / ("sftpplug-lanpair-" + std::to_string(GetCurrentProcessId()));
    for (const auto& c : {clientId, otherId}) {
        cleanup.secrets.push_back(trustKeyForClient(serverId, c));
        cleanup.secrets.push_back(trustKeyForServer(serverId, c));
    }
    fs::create_directories(cleanup.dir);

    const uint16_t port = FreeLoopbackPort();
    LanFileServer server;
    lanpair::PairError err;
    CHECK(server.start(port, &err, kLoopback, serverId));
    server.setPassword(kPassword);

    // Files: put, list, get, rename, delete - with a name outside ASCII.
    std::string payload(300000, '\0');
    for (size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<char>((i * 131) ^ (i >> 7));
    const fs::path local = cleanup.dir / "local.bin";
    std::ofstream(local, std::ios::binary).write(payload.data(), static_cast<std::streamsize>(payload.size()));
    const fs::path remoteDir = cleanup.dir / "remote";
    const std::string name = "data-\xC3\xBC.bin"; // a u with umlaut, in UTF-8 as the wire carries it
    const std::string remoteFile = Utf8(remoteDir) + "\\" + name;
    {
        auto session = LanPairSession::connect(kLoopback, port, clientId, serverId, kPassword, &err);
        CHECK(session && session->isConnected());
        std::vector<std::string> roots;
        CHECK(session->listRoots(roots) && !roots.empty());
        CHECK(session->mkdir(Utf8(remoteDir)));
        int fsResult = -1;
        CHECK(session->putFile(local.c_str(), remoteFile, false, false, &fsResult) && fsResult == 0);
        std::vector<LanPairSession::DirEntry> entries;
        CHECK(session->listDirectory(Utf8(remoteDir), entries));
        CHECK(entries.size() == 1 && entries[0].name == name &&
              entries[0].size == static_cast<int64_t>(payload.size()));
        const fs::path back = cleanup.dir / "back.bin";
        CHECK(session->getFile(remoteFile, back.c_str(), 0, nullptr, true, false, &fsResult) && fsResult == 0);
        CHECK(ReadAll(back) == payload);
        const std::string renamed = Utf8(remoteDir / "renamed.bin");
        bool exists = false;
        CHECK(session->rename(remoteFile, renamed, false, &exists));
        CHECK(session->remove(renamed) && session->remove(Utf8(remoteDir)));
        CHECK(!fs::exists(remoteDir));
    }

    // Both ends kept the proven key: no password needed the second time.
    {
        auto session = LanPairSession::connect(kLoopback, port, clientId, serverId, "", &err);
        CHECK(session && session->isConnected());
        std::vector<std::string> roots;
        CHECK(session && session->listRoots(roots));
    }

    // A wrong password gets nowhere, and the stored key survives it.
    {
        lanpair::PairError wrong;
        CHECK(!LanPairSession::connect(kLoopback, port, clientId, serverId, "wrong password", &wrong));
        CHECK(wrong.message.find("Wrong LAN Pair password") != std::string::npos);
        CHECK(LanPairSession::connect(kLoopback, port, clientId, serverId, "", &err) != nullptr);
    }

    // The client must be talking to the server it meant to.
    {
        lanpair::PairError mismatch;
        CHECK(!LanPairSession::connect(kLoopback, port, clientId, "someone-else", kPassword, &mismatch));
        CHECK(mismatch.message.find("Peer ID mismatch") != std::string::npos);
    }

    // A computer the server holds no key for, with no password set there.
    {
        server.setPassword("");
        lanpair::PairError noKey;
        CHECK(!LanPairSession::connect(kLoopback, port, otherId, serverId, kPassword, &noKey));
        CHECK(noKey.message.find("no LAN Pair key") != std::string::npos);
        // ...and a client with neither a password nor a stored key.
        lanpair::PairError none;
        CHECK(!LanPairSession::connect(kLoopback, port, otherId, serverId, "", &none));
    }

    // A plugin older than 10.3.1 is told to upgrade, not let in.
    {
        lanpair_internal::WsaScope wsa;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, kLoopback, &addr.sin_addr);
        lanpair_internal::setSocketTimeout(s, 5000);
        CHECK(connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
        CHECK(lanpair_internal::sendLine(s, "PAIR1 HELLO old-client donor 00112233445566778899aabbccddeeff"));
        std::string line;
        CHECK(lanpair_internal::recvLine(s, &line) && line == "PAIR1 FAIL upgrade-required");
        closesocket(s);
    }

    server.stop();
}

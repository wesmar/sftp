// LAN Pair test peer: the plugin's own LAN Pair sources in a console program,
// so two computers can be paired and exchange files without Total Commander.
// Driven by tests\run-lanpair-remote-test.ps1.
//
//   lanpair_peer serve  <bind ip> <port> <server id> <password> <seconds> <stop file>
//   lanpair_peer client <server ip> <port> <client id> <server id> <password> <remote dir>
//   lanpair_peer forget <server id> <client id>

#include "LanPairSession.h"
#include "LanPairInternal.h"

#include <windows.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace {

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

int g_failures = 0;

void Step(bool ok, const char* what, const std::string& detail = {})
{
    std::printf("%s %s%s%s\n", ok ? "ok  " : "FAIL", what, detail.empty() ? "" : ": ", detail.c_str());
    std::fflush(stdout);
    if (!ok)
        ++g_failures;
}

std::string Utf8(const fs::path& p)
{
    const auto u8 = p.u8string();
    return std::string(u8.begin(), u8.end());
}

std::string Rate(size_t bytes, Clock::duration d)
{
    const double s = std::chrono::duration<double>(d).count();
    char buf[48];
    std::snprintf(buf, sizeof(buf), "%.1f MiB/s", s > 0 ? bytes / 1048576.0 / s : 0.0);
    return buf;
}

int Serve(const char* bind, uint16_t port, const std::string& serverId, const std::string& password,
          int seconds, const fs::path& stopFile)
{
    LanFileServer server;
    lanpair::PairError err;
    if (!server.start(port, &err, bind, serverId)) {
        std::printf("FAIL server start: %s (%d)\n", err.message.c_str(), err.code);
        return 1;
    }
    server.setPassword(password);
    std::printf("READY\n");
    std::fflush(stdout);
    const auto until = Clock::now() + std::chrono::seconds(seconds);
    while (Clock::now() < until && !fs::exists(stopFile))
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    server.stop();
    std::printf("STOPPED\n");
    return 0;
}

int Client(const std::string& ip, uint16_t port, const std::string& clientId, const std::string& serverId,
           const std::string& password, const std::string& remoteDir)
{
    lanpair::PairError err;
    const fs::path localDir = fs::temp_directory_path() / ("sftpplug-lanpair-peer-" + std::to_string(GetCurrentProcessId()));
    fs::create_directories(localDir);

    // 16 MiB that no compression or pattern could flatter.
    std::vector<char> payload(16u << 20);
    lanpair_internal::WsaScope wsa;
    BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(payload.data()), static_cast<ULONG>(payload.size()),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    const fs::path local = localDir / "up.bin";
    std::ofstream(local, std::ios::binary).write(payload.data(), static_cast<std::streamsize>(payload.size()));
    const std::string name = "data-\xC3\xBC.bin"; // a u with umlaut, in UTF-8
    const std::string remoteFile = remoteDir + "\\" + name;

    {
        auto session = LanPairSession::connect(ip, port, clientId, serverId, password, &err);
        Step(session != nullptr, "pair with the password", err.message);
        if (!session)
            return 1;
        std::vector<std::string> roots;
        Step(session->listRoots(roots) && !roots.empty(), "list the drives");
        Step(session->mkdir(remoteDir), "create the remote directory");
        int fsResult = -1;
        auto t0 = Clock::now();
        const bool put = session->putFile(local.c_str(), remoteFile, false, false, &fsResult) && fsResult == 0;
        Step(put, "upload 16 MiB", Rate(payload.size(), Clock::now() - t0));
        std::vector<LanPairSession::DirEntry> entries;
        Step(session->listDirectory(remoteDir, entries) && entries.size() == 1 && entries[0].name == name &&
                 entries[0].size == static_cast<int64_t>(payload.size()),
             "list it back, UTF-8 name and size intact");
        const fs::path back = localDir / "down.bin";
        t0 = Clock::now();
        const bool get = session->getFile(remoteFile, back.c_str(), 0, nullptr, true, false, &fsResult) && fsResult == 0;
        Step(get, "download 16 MiB", Rate(payload.size(), Clock::now() - t0));
        std::ifstream in(back, std::ios::binary);
        const std::vector<char> got((std::istreambuf_iterator<char>(in)), {});
        Step(got == payload, "downloaded bytes equal the uploaded ones");
        bool exists = false;
        const std::string renamed = remoteDir + "\\renamed.bin";
        Step(session->rename(remoteFile, renamed, false, &exists), "rename");
        Step(session->remove(renamed) && session->remove(remoteDir), "delete the file and the directory");
    }
    {
        auto session = LanPairSession::connect(ip, port, clientId, serverId, "", &err);
        std::vector<std::string> roots;
        Step(session && session->listRoots(roots), "second session on the stored keys, no password", err.message);
    }
    {
        lanpair::PairError wrong;
        auto session = LanPairSession::connect(ip, port, clientId, serverId, "not the password", &wrong);
        Step(!session && wrong.message.find("Wrong LAN Pair password") != std::string::npos,
             "a wrong password is refused", wrong.message);
    }
    std::error_code ec;
    fs::remove_all(localDir, ec);
    std::printf(g_failures ? "LAN PAIR REMOTE TEST FAILED\n" : "LAN PAIR REMOTE TEST PASSED\n");
    return g_failures ? 1 : 0;
}

int Forget(const std::string& serverId, const std::string& clientId)
{
    lanpair::DpapiSecretStore::deleteSecret(lanpair_internal::trustKeyForServer(serverId, clientId), nullptr);
    lanpair::DpapiSecretStore::deleteSecret(lanpair_internal::trustKeyForClient(serverId, clientId), nullptr);
    std::printf("FORGOTTEN\n");
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    const std::vector<std::string> a(argv, argv + argc);
    if (a.size() == 8 && a[1] == "serve")
        return Serve(a[2].c_str(), static_cast<uint16_t>(std::stoi(a[3])), a[4], a[5], std::stoi(a[6]), fs::path(a[7]));
    if (a.size() == 8 && a[1] == "client")
        return Client(a[2], static_cast<uint16_t>(std::stoi(a[3])), a[4], a[5], a[6], a[7]);
    if (a.size() == 4 && a[1] == "forget")
        return Forget(a[2], a[3]);
    std::fprintf(stderr, "usage: see the head of LanPairPeer.cpp\n");
    return 2;
}

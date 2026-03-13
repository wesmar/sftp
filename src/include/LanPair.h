#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace smb {

struct PairError {
    int code = 0;
    std::string message;
};

enum class PairRole : uint8_t {
    Donor = 0,
    Receiver = 1,
    Dual = 2,
};

struct PeerAnnouncement {
    std::string peerId;
    std::string hostName;
    std::string displayName;
    std::string ip;
    uint16_t tcpPort = 0;
    PairRole role = PairRole::Dual;
    std::chrono::steady_clock::time_point lastSeen;
};

struct DiscoveryConfig {
    uint16_t udpPort = 45845;
    uint16_t tcpPort = 45846;
    std::chrono::milliseconds broadcastInterval{1500};
    std::string bindAddress = "0.0.0.0";
    std::string broadcastAddress = "255.255.255.255";
    std::string appTag = "KVCPAIR/1";
};

class DiscoveryService {
public:
    using AnnouncementHandler = std::function<void(const PeerAnnouncement&)>;

    DiscoveryService();
    ~DiscoveryService();

    DiscoveryService(const DiscoveryService&) = delete;
    DiscoveryService& operator=(const DiscoveryService&) = delete;

    bool start(const DiscoveryConfig& cfg,
               const std::string& peerId,
               const std::string& displayName,
               PairRole role,
               AnnouncementHandler onPeer,
               PairError* err = nullptr);

    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

struct PairServerConfig {
    uint16_t port = 45846;
    std::string bindAddress = "0.0.0.0";
    std::string displayName;
    std::string peerId;
    PairRole role = PairRole::Receiver;
    std::string password;
    std::chrono::milliseconds authTimeout{8000};
};

struct PairClientConfig {
    std::string targetIp;
    uint16_t targetPort = 45846;
    std::string peerId;
    std::string password;
    std::chrono::milliseconds timeout{8000};
};

struct PairSessionInfo {
    std::string remotePeerId;
    std::string remoteDisplayName;
    std::string remoteIp;
    PairRole remoteRole = PairRole::Dual;
};

class PairServer {
public:
    using AcceptHandler = std::function<void(const PairSessionInfo&)>;

    PairServer();
    ~PairServer();

    PairServer(const PairServer&) = delete;
    PairServer& operator=(const PairServer&) = delete;

    bool start(const PairServerConfig& cfg,
               AcceptHandler onAccepted,
               PairError* err = nullptr);

    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class PairClient {
public:
    PairClient();
    ~PairClient();

    PairClient(const PairClient&) = delete;
    PairClient& operator=(const PairClient&) = delete;

    bool connectAndAuthenticate(const PairClientConfig& cfg,
                                PairSessionInfo* outInfo,
                                PairError* err = nullptr);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Free functions in a namespace — no class needed, no instance state.
namespace DpapiSecretStore {

bool saveSecret(const std::string& key,
                const std::string& secret,
                PairError* err = nullptr);

bool loadSecret(const std::string& key,
                std::string* outSecret,
                PairError* err = nullptr);

bool deleteSecret(const std::string& key,
                  PairError* err = nullptr);

} // namespace DpapiSecretStore

// Planned command channel — type tags used in LAN2 wire protocol
enum class PairCommandType : uint8_t {
    Handshake = 1,
    ListRoots = 2,
    ListDirectory = 3,
    StartSend = 4,
    StartReceive = 5,
    DataChunk = 6,
    Ack = 7,
    Error = 8,
};

struct PairFrameHeader {
    uint32_t magic = 0x4B564350; // "KVCP"
    uint16_t version = 1;
    PairCommandType type = PairCommandType::Handshake;
    uint8_t reserved = 0;
    uint32_t payloadSize = 0;
};

} // namespace smb

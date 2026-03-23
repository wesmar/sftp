#pragma once
#include "LanPair.h"
#include <memory>
#include <string>
#include <vector>
#include <windows.h>

// ============================================================
// LanPairSession.h
// Active authenticated file-transfer session to a LAN peer,
// and a background file server that accepts such sessions.
// ============================================================

// Derive trust keys from shared password and store in DPAPI.
// Call when saving a LAN Pair profile on both machines.
bool PrepareLanPairTrustKeys(const std::string& localPeerId,
                              const std::string& remotePeerId,
                              const std::string& password) noexcept;

class LanPairSession {
public:
    struct DirEntry {
        bool      isDir     = false;
        std::string name;
        int64_t   size      = 0;
        FILETIME  lastWrite = {};
        DWORD     winAttrs  = 0;
    };

    // Private constructor/destructor pair: create via connect().
    ~LanPairSession();

    LanPairSession(const LanPairSession&) = delete;
    LanPairSession& operator=(const LanPairSession&) = delete;

    // Factory.  password empty → use DPAPI-stored trust key.
    static std::unique_ptr<LanPairSession> connect(
        const std::string& targetIp,
        uint16_t           targetPort,
        const std::string& localPeerId,
        const std::string& remotePeerId,
        const std::string& password,
        lanpair::PairError*    err = nullptr) noexcept;

    bool isConnected() const noexcept;
    void disconnect()  noexcept;
    // Set session lifetime. If > 0, any operation attempted after this many
    // minutes since connect() will silently disconnect and return failure.
    // 0 = no limit (default).
    void setTimeoutMin(int minutes) noexcept;

    // Enable or disable TrustedInstaller impersonation for client file operations.
    void setTrustedInstaller(bool enabled) noexcept;

    // Remote filesystem operations.
    bool listRoots(std::vector<std::string>& roots) noexcept;

    bool listDirectory(const std::string&      path,
                       std::vector<DirEntry>&  entries) noexcept;

    // Download remotePath → localPath.
    // remoteSize / ft may be 0/nullptr if unknown.
    // fsResult receives FS_FILE_* constant.
    bool getFile(const std::string& remotePath,
                 LPCWSTR            localPath,
                 int64_t            remoteSize,
                 const FILETIME*    ft,
                 bool               overwrite,
                 bool               resume,
                 int*               fsResult) noexcept;

    // Upload localPath → remotePath.
    bool putFile(LPCWSTR            localPath,
                 const std::string& remotePath,
                 bool               overwrite,
                 bool               resume,
                 int*               fsResult) noexcept;

    bool mkdir (const std::string& path)                          noexcept;
    bool remove(const std::string& path)                          noexcept;
    bool rename(const std::string& oldPath,
                const std::string& newPath)                       noexcept;

private:
    struct Impl;
    explicit LanPairSession(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

// ============================================================
// LanFileServer
// Background TCP server: accepts PAIR1 + LAN2 clients and
// serves file-system commands in per-connection threads.
// ============================================================

class LanFileServer {
public:
    LanFileServer();
    ~LanFileServer();

    LanFileServer(const LanFileServer&) = delete;
    LanFileServer& operator=(const LanFileServer&) = delete;

    bool start(uint16_t        port = 45846,
               lanpair::PairError* err  = nullptr) noexcept;

    void stop()       noexcept;
    bool isRunning()  const noexcept;

    // Set the shared password used to verify first-time connections from new peers.
    // Call after start(); may be called at any time from any thread.
    void setPassword(const std::string& password) noexcept;

    // Enable or disable TrustedInstaller impersonation for incoming file operations.
    void setTrustedInstaller(bool enabled) noexcept;

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

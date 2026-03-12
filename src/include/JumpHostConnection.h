#pragma once
// JumpHostConnection.h — SSH ProxyJump / jump host support.
//
// Flow:
//   1. TCP connect to jump host
//   2. SSH handshake + fingerprint + auth on jump host
//   3. libssh2_channel_direct_tcpip_ex() to target host
//   4. Return ITransportStream wrapping that channel
//   5. Caller builds second SSH session over that stream (target)
//
// The returned stream keeps the jump session and socket alive for its
// entire lifetime. The underlying SOCKET is placed in cs->sock so that
// all IsSocketReadable() wait loops used during target session handshake
// operate on the correct fd.

#include <memory>
#include <string>
#include "ITransportStream.h"
#include "SftpClient.h"   // for pConnectSettings / tConnectSettings

struct ISshBackend;

// ---------------------------------------------------------------------------
// JumpHostSettings
// All jump-host-specific parameters (separate from target host auth).
// ---------------------------------------------------------------------------
struct JumpHostSettings {
    std::string host;
    unsigned short port     = 22;
    std::string user;
    std::string password;
    std::string pubkeyfile;
    std::string privkeyfile;
    bool        useagent    = false;
    std::string fingerprint;   // saved MD5 hex fingerprint (empty = first-time)
};

// ---------------------------------------------------------------------------
// ConnectViaJumpHost
//
// Performs the full jump-host sequence and returns a transport stream
// pointing at targetHost:targetPort through the jump host.
//
// On success:
//   - returns non-null stream
//   - cs->sock is set to the underlying jump TCP socket
//     (used by IsSocketReadable() during target session startup)
//
// On failure:
//   - shows error via ShowStatus/ShowError on cs->feedback
//   - returns nullptr
//   - cs->sock is 0 / INVALID_SOCKET
// ---------------------------------------------------------------------------
std::unique_ptr<ITransportStream> ConnectViaJumpHost(
    pConnectSettings          cs,
    JumpHostSettings&         jump,
    ISshBackend*              backend,
    const std::string&        targetHost,
    unsigned short            targetPort,
    int&                      progress,
    int&                      loop,
    SYSTICKS&                 lasttime);

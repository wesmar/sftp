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
    // Resolved out of the stored secret: the password is offered to the jump
    // host, the passphrase only unlocks privkeyfile.
    std::string password;
    std::string keyPassphrase;
    std::string pubkeyfile;
    std::string privkeyfile;
    bool        useagent    = false;
    std::string fingerprint;   // saved MD5 hex fingerprint (empty = first-time)

    // Where `fingerprint` was read from, and therefore where an accepted one
    // must be written back. A referenced session owns the host, so its own
    // `fingerprint` key is the right home; a manually configured jump host
    // is described only by the current session, under `jumpfingerprint`.
    // Keeping read and write in one place stops the "accept the fingerprint
    // on every connect" loop that happens when they disagree.
    std::string fingerprintSection;
    std::string fingerprintKey;
};

// ---------------------------------------------------------------------------
// Resolving the jump-host configuration
//
// A session describes its jump host either by naming another saved session
// (`jumpsessionref`) or through its own `jump_*` fields. One function decides
// which applies, so the connect path, the dialog and anything else agree on
// what a given profile actually does.
// ---------------------------------------------------------------------------
enum class JumpConfigStatus {
    Disabled,        // no jump host wanted
    Ready,           // endpoint below is usable
    NotConfigured,   // wanted, but neither a reference nor a host is set
    RefNotFound,     // referenced session no longer exists
    RefChained,      // referenced session has a jump host of its own
};

struct JumpConfig {
    JumpConfigStatus status = JumpConfigStatus::Disabled;
    JumpHostSettings endpoint;
    std::string      error;   // ready-to-show text for the failure states
};

// `cs` supplies use_jump_host, jump_session_ref and the manual jump_* fields.
// Never returns Ready with an empty host — a profile that asks for a jump
// host but does not say which one is reported as NotConfigured rather than
// silently letting the caller connect straight to the target.
JumpConfig ResolveJumpConfig(pConnectSettings cs, LPCSTR iniFileName);

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

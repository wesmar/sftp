#pragma once
// ITransportStream.h — Abstract transport layer for SSH sessions.
// Allows SSH sessions to run over an arbitrary byte stream (socket, SSH channel, etc.)
// rather than being hardwired to a Winsock SOCKET.

#include <cstddef>
#include <windows.h>
#include <basetsd.h>

#if defined(_MSC_VER) && !defined(HAVE_SSIZE_T)
typedef SSIZE_T ssize_t;
#define HAVE_SSIZE_T
#endif

// ---------------------------------------------------------------------------
// ITransportStream
// ---------------------------------------------------------------------------
// Minimal interface needed by the libssh2 SEND/RECV custom callbacks.
// Implementations must be thread-safe for concurrent read+write.
//
// Return conventions (matching libssh2 callback contract):
//   read/write:
//     >  0  — bytes transferred
//     == LIBSSH2_EAGAIN_SENTINEL — would block, call again (maps to WSA EAGAIN)
//     <  0  — unrecoverable error
//
// Use ITRANSPORT_EAGAIN to signal would-block from implementations.
struct ITransportStream {
    virtual ~ITransportStream() = default;

    // Read up to `len` bytes into `buf`. See return conventions above.
    virtual ssize_t read(void* buf, size_t len) = 0;

    // Write up to `len` bytes from `buf`. See return conventions above.
    virtual ssize_t write(const void* buf, size_t len) = 0;

    // Block until the stream is readable or `timeoutMs` expires.
    // Returns true if data is available.
    virtual bool waitReadable(DWORD timeoutMs) = 0;

    // Human-readable description for logging.
    virtual const char* describe() const = 0;

    // Release resources (channel, sessions). Called before socket is closed.
    virtual void close() = 0;
};

// Sentinel returned by ITransportStream implementations to signal EAGAIN.
// Value matches LIBSSH2_ERROR_EAGAIN.
static constexpr ssize_t ITRANSPORT_EAGAIN = -37;

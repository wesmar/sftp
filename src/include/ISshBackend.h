#pragma once
// ISshBackend.h — Pure virtual interface for SSH backend abstraction.
// All SSH library calls go through these interfaces, allowing backend swapping.

#include <memory>
#include <cstdint>
#include <basetsd.h>

#if defined(_MSC_VER) && !defined(HAVE_SSIZE_T)
typedef SSIZE_T ssize_t;
#define HAVE_SSIZE_T
#endif

#include <libssh2/libssh2.h>
#include <libssh2/libssh2_sftp.h>

// Forward declarations for interface types
struct ISshSession;
struct ISftpSession;
struct ISftpHandle;
struct ISshChannel;
struct ISshAgent;

// ---------------------------------------------------------------------------
// ISftpHandle — wraps LIBSSH2_SFTP_HANDLE* (file or directory)
// ---------------------------------------------------------------------------
struct ISftpHandle {
    virtual ~ISftpHandle() = default;

    virtual ssize_t read(char* buf, size_t len) = 0;
    virtual ssize_t write(const char* buf, size_t len) = 0;
    virtual int readdir(char* buf, size_t blen,
                        char* longentry, size_t llen,
                        LIBSSH2_SFTP_ATTRIBUTES* attrs) = 0;
    virtual int close() = 0;
    virtual void seek(size_t offset) = 0;
    virtual size_t tell() = 0;
    virtual int fstat(LIBSSH2_SFTP_ATTRIBUTES* attrs, int setstat) = 0;
};

// ---------------------------------------------------------------------------
// ISshChannel — wraps LIBSSH2_CHANNEL*
// ---------------------------------------------------------------------------
struct ISshChannel {
    virtual ~ISshChannel() = default;

    virtual ssize_t read(char* buf, size_t len) = 0;
    virtual ssize_t readStderr(char* buf, size_t len) = 0;
    virtual ssize_t write(const char* buf, size_t len) = 0;
    virtual ssize_t writeEx(int streamId, const char* buf, size_t len) = 0;
    virtual int exec(const char* cmd) = 0;
    virtual int shell() = 0;
    virtual int sendEof() = 0;
    virtual int eof() = 0;
    virtual int waitEof() = 0;
    virtual int channelClose() = 0;
    virtual int channelFree() = 0;
    virtual int flush() = 0;
    virtual int getExitStatus() = 0;
    virtual void setBlocking(int blocking) = 0;
    virtual int requestPty(const char* term, unsigned termLen,
                           const char* modes, unsigned modesLen,
                           int width, int height,
                           int widthPx, int heightPx) = 0;
};

// ---------------------------------------------------------------------------
// ISshAgent — wraps LIBSSH2_AGENT*
// ---------------------------------------------------------------------------
struct ISshAgent {
    virtual ~ISshAgent() = default;

    virtual int connect() = 0;
    virtual int listIdentities() = 0;
    virtual int getIdentity(struct libssh2_agent_publickey** store,
                            struct libssh2_agent_publickey* prev) = 0;
    virtual int userauth(const char* user,
                         struct libssh2_agent_publickey* id) = 0;
    virtual int disconnect() = 0;
    // NOTE: no free() — implementations must call libssh2_agent_free() in their destructor.
};

// ---------------------------------------------------------------------------
// ISftpSession — wraps LIBSSH2_SFTP*
// ---------------------------------------------------------------------------
struct ISftpSession {
    virtual ~ISftpSession() = default;

    virtual std::unique_ptr<ISftpHandle> open(const char* path,
                                              unsigned long flags,
                                              long mode) = 0;
    virtual std::unique_ptr<ISftpHandle> openDir(const char* path) = 0;
    virtual int shutdown() = 0;
    virtual unsigned long lastError() = 0;
    virtual int stat(const char* path, LIBSSH2_SFTP_ATTRIBUTES* attrs) = 0;
    virtual int lstat(const char* path, LIBSSH2_SFTP_ATTRIBUTES* attrs) = 0;
    virtual int realpath(const char* path, char* target, unsigned tlen) = 0;
    virtual int setstat(const char* path, LIBSSH2_SFTP_ATTRIBUTES* attrs) = 0;
    virtual int rename(const char* src, const char* dst) = 0;
    virtual int unlink(const char* path) = 0;
    virtual int mkdir(const char* path, long mode) = 0;
    virtual int rmdir(const char* path) = 0;
    virtual int symlink(const char* path, char* target,
                        unsigned tlen, int type) = 0;
};

// ---------------------------------------------------------------------------
// ISshSession — wraps LIBSSH2_SESSION*
// ---------------------------------------------------------------------------
struct ISshSession {
    virtual ~ISshSession() = default;

    virtual int startup(int sock) = 0;
    virtual void setBlocking(int blocking) = 0;
    virtual int getBlocking() = 0;
    virtual int disconnect(const char* desc) = 0;
    virtual int free() = 0;
    virtual const char* hostkeyHash(int hashType) = 0;
    virtual int methodPref(int methodType, const char* prefs) = 0;
    virtual const char* methods(int methodType) = 0;
    virtual char* userauthList(const char* user, unsigned len) = 0;
    virtual int userauthAuthenticated() = 0;
    virtual int userauthPassword(const char* user, unsigned ulen,
                                 const char* pass, unsigned plen,
                                 LIBSSH2_PASSWD_CHANGEREQ_FUNC((*changeCb))) = 0;
    virtual int userauthPubkeyFromFile(const char* user, unsigned ulen,
                                       const char* pub, const char* priv,
                                       const char* passphrase) = 0;
    virtual int userauthKeyboardInteractive(
        const char* user, unsigned ulen,
        LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC((*responseCb))) = 0;
    virtual int lastError(char** msg, int* len, int wantBuf) = 0;
    virtual int lastErrno() = 0;
    virtual int sessionFlag(int flag, int value) = 0;
    virtual int blockDirections() = 0;

    virtual std::unique_ptr<ISftpSession> sftpInit() = 0;
    virtual std::unique_ptr<ISshChannel> openChannel() = 0;
    virtual std::unique_ptr<ISshChannel> scpRecv2(const char* path,
                                                   libssh2_struct_stat* sb) = 0;
    virtual std::unique_ptr<ISshChannel> scpSend64(const char* path, int mode,
                                                    uint64_t size,
                                                    int64_t mtime,
                                                    int64_t atime) = 0;
    virtual std::unique_ptr<ISshChannel> scpSendEx(const char* path, int mode,
                                                     size_t size,
                                                     long mtime,
                                                     long atime) = 0;
    virtual std::unique_ptr<ISshAgent> agentInit() = 0;

    // Open a direct-tcpip channel to host:port through this session.
    // shost/sport are the originator address (usually "127.0.0.1", 0).
    // Returns nullptr on failure.
    virtual std::unique_ptr<ISshChannel> directTcpip(
        const char* host, int port,
        const char* shost, int sport) = 0;

    virtual void** abstractPtr() = 0;
    virtual void* callbackSet(int cbtype, void* cb) = 0;
    virtual int trace(int bitmask) = 0;
    virtual int bannerSet(const char* banner) = 0;
};

// ---------------------------------------------------------------------------
// ISshBackend — factory for creating sessions
// ---------------------------------------------------------------------------
struct ISshBackend {
    virtual ~ISshBackend() = default;

    virtual std::unique_ptr<ISshSession> createSession(
        LIBSSH2_ALLOC_FUNC((*allocFunc)),
        LIBSSH2_FREE_FUNC((*freeFunc)),
        LIBSSH2_REALLOC_FUNC((*reallocFunc)),
        void* abstract) = 0;

    virtual const char* version(int reqVersion) = 0;
};

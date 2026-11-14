#pragma once
// Libssh2Backend.h — Concrete ISshBackend adapter for libssh2 (statically linked).

#include "ISshBackend.h"

// ---------------------------------------------------------------------------
// Concrete implementations
// ---------------------------------------------------------------------------

class Libssh2SftpHandle : public ISftpHandle {
public:
    explicit Libssh2SftpHandle(LIBSSH2_SFTP_HANDLE* h) : handle_(h) {}
    // RAII close: without this, dropping the unique_ptr leaks the libssh2
    // handle entirely. Server-side sftp-server keeps the file descriptor open
    // until the whole SFTP session terminates, which on a long-lived TC
    // connection means the file shows up as held by sftp-server long after
    // the upload finished.
    ~Libssh2SftpHandle() override;

    ssize_t read(char* buf, size_t len) override;
    ssize_t write(const char* buf, size_t len) override;
    int readdir(char* buf, size_t blen, char* longentry, size_t llen,
                LIBSSH2_SFTP_ATTRIBUTES* attrs) override;
    int close() override;
    void seek(size_t offset) override;
    size_t tell() override;
    int fstat(LIBSSH2_SFTP_ATTRIBUTES* attrs, int setstat) override;

    LIBSSH2_SFTP_HANDLE* raw() const { return handle_; }
private:
    LIBSSH2_SFTP_HANDLE* handle_;
};

class Libssh2Channel : public ISshChannel {
public:
    explicit Libssh2Channel(LIBSSH2_CHANNEL* ch) : channel_(ch) {}
    // RAII free: matches Libssh2SftpHandle pattern. Without explicit destructor
    // a dropped unique_ptr leaks the libssh2 channel, which on the server side
    // counts against MaxSessions per SSH connection.
    ~Libssh2Channel() override;

    ssize_t read(char* buf, size_t len) override;
    ssize_t readStderr(char* buf, size_t len) override;
    ssize_t write(const char* buf, size_t len) override;
    ssize_t writeEx(int streamId, const char* buf, size_t len) override;
    int exec(const char* cmd) override;
    int shell() override;
    int sendEof() override;
    int eof() override;
    int waitEof() override;
    int channelClose() override;
    int channelFree() override;
    int flush() override;
    int getExitStatus() override;
    void setBlocking(int blocking) override;
    int requestPty(const char* term, unsigned termLen,
                   const char* modes, unsigned modesLen,
                   int width, int height,
                   int widthPx, int heightPx) override;

    LIBSSH2_CHANNEL* raw() const { return channel_; }
private:
    LIBSSH2_CHANNEL* channel_;
};

class Libssh2Agent : public ISshAgent {
public:
    explicit Libssh2Agent(LIBSSH2_AGENT* a) : agent_(a) {}
    ~Libssh2Agent() override;   // defined in .cpp — calls libssh2_agent_free

    int connect() override;
    int listIdentities() override;
    int getIdentity(struct libssh2_agent_publickey** store,
                    struct libssh2_agent_publickey* prev) override;
    int userauth(const char* user, struct libssh2_agent_publickey* id) override;
    int disconnect() override;

    LIBSSH2_AGENT* raw() const { return agent_; }
private:
    LIBSSH2_AGENT* agent_;
};

class Libssh2SftpSession : public ISftpSession {
public:
    explicit Libssh2SftpSession(LIBSSH2_SFTP* sftp) : sftp_(sftp) {}
    // RAII shutdown: leaks the SFTP subsystem channel without this. Visible
    // server-side as a stray channel counted against MaxSessions.
    ~Libssh2SftpSession() override;

    std::unique_ptr<ISftpHandle> open(const char* path, unsigned long flags,
                                      long mode) override;
    std::unique_ptr<ISftpHandle> openDir(const char* path) override;
    int shutdown() override;
    unsigned long lastError() override;
    int stat(const char* path, LIBSSH2_SFTP_ATTRIBUTES* attrs) override;
    int lstat(const char* path, LIBSSH2_SFTP_ATTRIBUTES* attrs) override;
    int realpath(const char* path, char* target, unsigned tlen) override;
    int setstat(const char* path, LIBSSH2_SFTP_ATTRIBUTES* attrs) override;
    int rename(const char* src, const char* dst) override;
    int unlink(const char* path) override;
    int mkdir(const char* path, long mode) override;
    int rmdir(const char* path) override;
    int symlink(const char* path, char* target, unsigned tlen,
                int type) override;

    LIBSSH2_SFTP* raw() const { return sftp_; }
private:
    LIBSSH2_SFTP* sftp_;
};

class Libssh2Session : public ISshSession {
public:
    explicit Libssh2Session(LIBSSH2_SESSION* s) : session_(s) {}
    // RAII disconnect+free: without this a dropped unique_ptr leaks the SSH
    // session entirely (socket level + sshd-side process). Best-effort
    // disconnect first to inform the server, then free the libssh2 struct.
    ~Libssh2Session() override;

    int handshake(libssh2_socket_t sock) override;
    void setBlocking(int blocking) override;
    int getBlocking() override;
    int disconnect(const char* desc) override;
    int free() override;
    const char* hostkeyHash(int hashType) override;
    int methodPref(int methodType, const char* prefs) override;
    const char* methods(int methodType) override;
    char* userauthList(const char* user, unsigned len) override;
    int userauthAuthenticated() override;
    int userauthPassword(const char* user, unsigned ulen,
                         const char* pass, unsigned plen,
                         LIBSSH2_PASSWD_CHANGEREQ_FUNC((*changeCb))) override;
    int userauthPubkeyFromFile(const char* user, unsigned ulen,
                               const char* pub, const char* priv,
                               const char* passphrase) override;
    int userauthPubkeyFromMemory(const char* user, unsigned ulen,
                                 const char* privData, size_t privLen,
                                 const char* passphrase) override;
    int userauthKeyboardInteractive(
        const char* user, unsigned ulen,
        LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC((*responseCb))) override;
    int lastError(char** msg, int* len, int wantBuf) override;
    int lastErrno() override;
    int sessionFlag(int flag, int value) override;
    int blockDirections() override;

    std::unique_ptr<ISftpSession> sftpInit(std::string_view serverCommand) override;
    std::unique_ptr<ISshChannel> openChannel() override;
    std::unique_ptr<ISshChannel> scpRecv2(const char* path,
                                           libssh2_struct_stat* sb) override;
    std::unique_ptr<ISshChannel> scpSend64(const char* path, int mode,
                                            uint64_t size, int64_t mtime,
                                            int64_t atime) override;
    std::unique_ptr<ISshChannel> scpSendEx(const char* path, int mode,
                                             size_t size, long mtime,
                                             long atime) override;
    std::unique_ptr<ISshAgent> agentInit() override;

    std::unique_ptr<ISshChannel> directTcpip(
        const char* host, int port,
        const char* shost, int sport) override;

    void** abstractPtr() override;
    void setCallback(int cbtype, libssh2_cb_generic* cb) override;
    int trace(int bitmask) override;

    LIBSSH2_SESSION* raw() const { return session_; }
private:
    LIBSSH2_SESSION* session_;
};

class Libssh2Backend : public ISshBackend {
public:
    Libssh2Backend() = default;
    ~Libssh2Backend() override = default;

    std::unique_ptr<ISshSession> createSession(
        LIBSSH2_ALLOC_FUNC((*allocFunc)),
        LIBSSH2_FREE_FUNC((*freeFunc)),
        LIBSSH2_REALLOC_FUNC((*reallocFunc)),
        void* abstract) override;

    const char* version(int reqVersion) override;
};

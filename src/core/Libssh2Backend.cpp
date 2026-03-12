// Libssh2Backend.cpp — Concrete adapter that delegates to libssh2.
// This is the ONLY file that should contain direct libssh2_* calls.

#include "global.h"
#include <windows.h>
#include "Libssh2Backend.h"

// Modern static linking: include headers from libssh2/ subdirectory in PHP deps.
#include <libssh2/libssh2.h>
#include <libssh2/libssh2_sftp.h>

// In dynamic mode (if ever needed), this would be handled elsewhere.
// For now, we are YOLO All-in-one.

// ===========================================================================
// Libssh2SftpHandle
// ===========================================================================

ssize_t Libssh2SftpHandle::read(char* buf, size_t len)
{
    return libssh2_sftp_read(handle_, buf, len);
}

ssize_t Libssh2SftpHandle::write(const char* buf, size_t len)
{
    return libssh2_sftp_write(handle_, buf, len);
}

int Libssh2SftpHandle::readdir(char* buf, size_t blen,
                                char* longentry, size_t llen,
                                LIBSSH2_SFTP_ATTRIBUTES* attrs)
{
    return libssh2_sftp_readdir_ex(handle_, buf, blen, longentry, llen, attrs);
}

int Libssh2SftpHandle::close()
{
    return libssh2_sftp_close_handle(handle_);
}

void Libssh2SftpHandle::seek(size_t offset)
{
    libssh2_sftp_seek(handle_, offset);
}

size_t Libssh2SftpHandle::tell()
{
    return libssh2_sftp_tell(handle_);
}

int Libssh2SftpHandle::fstat(LIBSSH2_SFTP_ATTRIBUTES* attrs, int setstat)
{
    return libssh2_sftp_fstat_ex(handle_, attrs, setstat);
}

// ===========================================================================
// Libssh2Channel
// ===========================================================================

ssize_t Libssh2Channel::read(char* buf, size_t len)
{
    return libssh2_channel_read_ex(channel_, 0, buf, len);
}

ssize_t Libssh2Channel::readStderr(char* buf, size_t len)
{
    return libssh2_channel_read_ex(channel_, SSH_EXTENDED_DATA_STDERR, buf, len);
}

ssize_t Libssh2Channel::write(const char* buf, size_t len)
{
    return libssh2_channel_write_ex(channel_, 0, buf, len);
}

ssize_t Libssh2Channel::writeEx(int streamId, const char* buf, size_t len)
{
    return libssh2_channel_write_ex(channel_, streamId, buf, len);
}

int Libssh2Channel::exec(const char* cmd)
{
    return libssh2_channel_process_startup(channel_, "exec", 4, cmd,
                                           (unsigned int)strlen(cmd));
}

int Libssh2Channel::shell()
{
    return libssh2_channel_process_startup(channel_, "shell", 5, nullptr, 0);
}

int Libssh2Channel::sendEof()
{
    return libssh2_channel_send_eof(channel_);
}

int Libssh2Channel::eof()
{
    return libssh2_channel_eof(channel_);
}

int Libssh2Channel::waitEof()
{
    return libssh2_channel_wait_eof(channel_);
}

int Libssh2Channel::channelClose()
{
    return libssh2_channel_close(channel_);
}

int Libssh2Channel::channelFree()
{
    return libssh2_channel_free(channel_);
}

int Libssh2Channel::flush()
{
    return libssh2_channel_flush_ex(channel_, 0);
}

int Libssh2Channel::getExitStatus()
{
    return libssh2_channel_get_exit_status(channel_);
}

void Libssh2Channel::setBlocking(int blocking)
{
    libssh2_channel_set_blocking(channel_, blocking);
}

int Libssh2Channel::requestPty(const char* term, unsigned termLen,
                                const char* modes, unsigned modesLen,
                                int width, int height,
                                int widthPx, int heightPx)
{
    return libssh2_channel_request_pty_ex(channel_, term, termLen,
                                          modes, modesLen,
                                          width, height, widthPx, heightPx);
}

// ===========================================================================
// Libssh2Agent
// ===========================================================================

int Libssh2Agent::connect()
{
    return libssh2_agent_connect(agent_);
}

int Libssh2Agent::listIdentities()
{
    return libssh2_agent_list_identities(agent_);
}

int Libssh2Agent::getIdentity(struct libssh2_agent_publickey** store,
                               struct libssh2_agent_publickey* prev)
{
    return libssh2_agent_get_identity(agent_, store, prev);
}

int Libssh2Agent::userauth(const char* user,
                            struct libssh2_agent_publickey* id)
{
    return libssh2_agent_userauth(agent_, user, id);
}

int Libssh2Agent::disconnect()
{
    return libssh2_agent_disconnect(agent_);
}

Libssh2Agent::~Libssh2Agent()
{
    // libssh2_agent_free() must be called exactly once; doing it here ensures
    // it runs even on error paths, regardless of whether disconnect() was called.
    if (agent_)
        libssh2_agent_free(agent_);
}

// ===========================================================================
// Libssh2SftpSession
// ===========================================================================

std::unique_ptr<ISftpHandle> Libssh2SftpSession::open(const char* path,
                                                       unsigned long flags,
                                                       long mode)
{
    LIBSSH2_SFTP_HANDLE* h = libssh2_sftp_open_ex(
        sftp_, path, (unsigned int)strlen(path), flags, mode,
        LIBSSH2_SFTP_OPENFILE);
    if (!h)
        return nullptr;
    return std::make_unique<Libssh2SftpHandle>(h);
}

std::unique_ptr<ISftpHandle> Libssh2SftpSession::openDir(const char* path)
{
    LIBSSH2_SFTP_HANDLE* h = libssh2_sftp_open_ex(
        sftp_, path, (unsigned int)strlen(path), 0, 0,
        LIBSSH2_SFTP_OPENDIR);
    if (!h)
        return nullptr;
    return std::make_unique<Libssh2SftpHandle>(h);
}

int Libssh2SftpSession::shutdown()
{
    return libssh2_sftp_shutdown(sftp_);
}

unsigned long Libssh2SftpSession::lastError()
{
    return libssh2_sftp_last_error(sftp_);
}

int Libssh2SftpSession::stat(const char* path,
                              LIBSSH2_SFTP_ATTRIBUTES* attrs)
{
    return libssh2_sftp_stat_ex(sftp_, path, (unsigned int)strlen(path),
                                LIBSSH2_SFTP_STAT, attrs);
}

int Libssh2SftpSession::lstat(const char* path,
                               LIBSSH2_SFTP_ATTRIBUTES* attrs)
{
    return libssh2_sftp_stat_ex(sftp_, path, (unsigned int)strlen(path),
                                LIBSSH2_SFTP_LSTAT, attrs);
}

int Libssh2SftpSession::realpath(const char* path, char* target, unsigned tlen)
{
    return libssh2_sftp_symlink_ex(sftp_, path, (unsigned int)strlen(path),
                                   target, tlen, LIBSSH2_SFTP_REALPATH);
}

int Libssh2SftpSession::setstat(const char* path,
                                 LIBSSH2_SFTP_ATTRIBUTES* attrs)
{
    return libssh2_sftp_stat_ex(sftp_, path, (unsigned int)strlen(path),
                                LIBSSH2_SFTP_SETSTAT, attrs);
}

int Libssh2SftpSession::rename(const char* src, const char* dst)
{
    return libssh2_sftp_rename_ex(sftp_, src, (unsigned int)strlen(src),
                                  dst, (unsigned int)strlen(dst),
                                  LIBSSH2_SFTP_RENAME_OVERWRITE |
                                  LIBSSH2_SFTP_RENAME_ATOMIC |
                                  LIBSSH2_SFTP_RENAME_NATIVE);
}

int Libssh2SftpSession::unlink(const char* path)
{
    return libssh2_sftp_unlink_ex(sftp_, path, (unsigned int)strlen(path));
}

int Libssh2SftpSession::mkdir(const char* path, long mode)
{
    return libssh2_sftp_mkdir_ex(sftp_, path, (unsigned int)strlen(path), mode);
}

int Libssh2SftpSession::rmdir(const char* path)
{
    return libssh2_sftp_rmdir_ex(sftp_, path, (unsigned int)strlen(path));
}

int Libssh2SftpSession::symlink(const char* path, char* target,
                                 unsigned tlen, int type)
{
    return libssh2_sftp_symlink_ex(sftp_, path, (unsigned int)strlen(path),
                                   target, tlen, type);
}

// ===========================================================================
// Libssh2Session
// ===========================================================================

int Libssh2Session::startup(int sock)
{
    return libssh2_session_startup(session_, sock);
}

void Libssh2Session::setBlocking(int blocking)
{
    libssh2_session_set_blocking(session_, blocking);
}

int Libssh2Session::getBlocking()
{
    return libssh2_session_get_blocking(session_);
}

int Libssh2Session::disconnect(const char* desc)
{
    return libssh2_session_disconnect_ex(session_, SSH_DISCONNECT_BY_APPLICATION,
                                         desc, "");
}

int Libssh2Session::free()
{
    return libssh2_session_free(session_);
}

const char* Libssh2Session::hostkeyHash(int hashType)
{
    return libssh2_hostkey_hash(session_, hashType);
}

int Libssh2Session::methodPref(int methodType, const char* prefs)
{
    return libssh2_session_method_pref(session_, methodType, prefs);
}

const char* Libssh2Session::methods(int methodType)
{
    return libssh2_session_methods(session_, methodType);
}

char* Libssh2Session::userauthList(const char* user, unsigned len)
{
    return libssh2_userauth_list(session_, user, len);
}

int Libssh2Session::userauthAuthenticated()
{
    return libssh2_userauth_authenticated(session_);
}

int Libssh2Session::userauthPassword(const char* user, unsigned ulen,
                                      const char* pass, unsigned plen,
                                      LIBSSH2_PASSWD_CHANGEREQ_FUNC((*changeCb)))
{
    return libssh2_userauth_password_ex(session_, user, ulen, pass, plen,
                                        changeCb);
}

int Libssh2Session::userauthPubkeyFromFile(const char* user, unsigned ulen,
                                            const char* pub, const char* priv,
                                            const char* passphrase)
{
    return libssh2_userauth_publickey_fromfile_ex(session_, user, ulen,
                                                   pub, priv, passphrase);
}

int Libssh2Session::userauthKeyboardInteractive(
    const char* user, unsigned ulen,
    LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC((*responseCb)))
{
    return libssh2_userauth_keyboard_interactive_ex(session_, user, ulen,
                                                     responseCb);
}

int Libssh2Session::lastError(char** msg, int* len, int wantBuf)
{
    return libssh2_session_last_error(session_, msg, len, wantBuf);
}

int Libssh2Session::lastErrno()
{
    return libssh2_session_last_errno(session_);
}

int Libssh2Session::sessionFlag(int flag, int value)
{
    return libssh2_session_flag(session_, flag, value);
}

std::unique_ptr<ISftpSession> Libssh2Session::sftpInit()
{
    LIBSSH2_SFTP* sftp = libssh2_sftp_init(session_);
    if (!sftp)
        return nullptr;
    return std::make_unique<Libssh2SftpSession>(sftp);
}

std::unique_ptr<ISshChannel> Libssh2Session::openChannel()
{
    LIBSSH2_CHANNEL* ch = libssh2_channel_open_ex(
        session_, "session", sizeof("session") - 1,
        LIBSSH2_CHANNEL_WINDOW_DEFAULT,
        LIBSSH2_CHANNEL_PACKET_DEFAULT,
        nullptr, 0);
    if (!ch)
        return nullptr;
    return std::make_unique<Libssh2Channel>(ch);
}

std::unique_ptr<ISshChannel> Libssh2Session::scpRecv2(const char* path,
                                                        libssh2_struct_stat* sb)
{
    LIBSSH2_CHANNEL* ch = libssh2_scp_recv2(session_, path, sb);
    if (!ch)
        return nullptr;
    return std::make_unique<Libssh2Channel>(ch);
}

std::unique_ptr<ISshChannel> Libssh2Session::scpSend64(const char* path,
                                                         int mode,
                                                         uint64_t size,
                                                         int64_t mtime,
                                                         int64_t atime)
{
    LIBSSH2_CHANNEL* ch = libssh2_scp_send64(session_, path, mode,
                                              (libssh2_uint64_t)size,
                                              mtime, atime);
    if (!ch)
        return nullptr;
    return std::make_unique<Libssh2Channel>(ch);
}

std::unique_ptr<ISshChannel> Libssh2Session::scpSendEx(const char* path,
                                                         int mode,
                                                         size_t size,
                                                         long mtime,
                                                         long atime)
{
    LIBSSH2_CHANNEL* ch = libssh2_scp_send_ex(session_, path, mode, size,
                                               mtime, atime);
    if (!ch)
        return nullptr;
    return std::make_unique<Libssh2Channel>(ch);
}

std::unique_ptr<ISshAgent> Libssh2Session::agentInit()
{
    LIBSSH2_AGENT* a = libssh2_agent_init(session_);
    if (!a)
        return nullptr;
    return std::make_unique<Libssh2Agent>(a);
}

void** Libssh2Session::abstractPtr()
{
    return libssh2_session_abstract(session_);
}

std::unique_ptr<ISshChannel> Libssh2Session::directTcpip(
    const char* host, int port,
    const char* shost, int sport)
{
    LIBSSH2_CHANNEL* ch = libssh2_channel_direct_tcpip_ex(
        session_, host, port, shost, sport);
    if (!ch)
        return nullptr;
    return std::make_unique<Libssh2Channel>(ch);
}

void* Libssh2Session::callbackSet(int cbtype, void* cb)
{
    return libssh2_session_callback_set(session_, cbtype, cb);
}

int Libssh2Session::trace(int bitmask)
{
    return libssh2_trace(session_, bitmask);
}

int Libssh2Session::bannerSet(const char* banner)
{
    return libssh2_banner_set(session_, banner);
}

// ===========================================================================
// Libssh2Backend
// ===========================================================================

std::unique_ptr<ISshSession> Libssh2Backend::createSession(
    LIBSSH2_ALLOC_FUNC((*allocFunc)),
    LIBSSH2_FREE_FUNC((*freeFunc)),
    LIBSSH2_REALLOC_FUNC((*reallocFunc)),
    void* abstract)
{
    LIBSSH2_SESSION* s = libssh2_session_init_ex(allocFunc, freeFunc,
                                                  reallocFunc, abstract);
    if (!s)
        return nullptr;
    return std::make_unique<Libssh2Session>(s);
}

const char* Libssh2Backend::version(int reqVersion)
{
    return libssh2_version(reqVersion);
}

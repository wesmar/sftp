#include "global.h"
#include <windows.h>
#include <array>
#include <string>
#include <format>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"
#include "ProxyNegotiator.h"
#include "IUserFeedback.h"
#include "AuthMethodParser.h"
#include "ConnectionAuth.h"
#include "PasswordCrypto.h"
#include "res/resource.h"

extern "C"
void newpassfunc(LIBSSH2_SESSION* /*session*/, LPSTR* newpw, int* newpw_len, LPVOID* abstract)
{
    pConnectSettings PassConnectSettings = static_cast<pConnectSettings>(*abstract);
    if (newpw)
        *newpw = nullptr;
    if (newpw_len)
        *newpw_len = 0;
    if (!newpw || !newpw_len)
        return;

    std::array<char, 128> title{};
    std::array<char, 128> prompt{};
    std::array<char, 128> newpass{};
    LoadStr(title, IDS_PASS_TITLE);
    LoadStr(prompt, IDS_PASS_CHANGE_REQUEST);
    if (!RequestInput(RT_Password, title.data(), prompt.data(), newpass)) {
        SecureZeroMemory(newpass.data(), newpass.size());
        return;
    }

    // libssh2 releases the answer with its default allocator, free().
    const size_t length = strlen(newpass.data());
    *newpw = static_cast<char*>(malloc(length + 1));
    if (*newpw) {
        memcpy(*newpw, newpass.data(), length + 1);
        *newpw_len = static_cast<int>(length);
    }
    if (*newpw && PassConnectSettings) {
        // A server-mandated password change replaces the whole stored
        // secret, so both forms become the new plain password.
        PassConnectSettings->password         = newpass.data();
        PassConnectSettings->account_password = newpass.data();
        switch (PassConnectSettings->passSaveMode) {
        case sftp::PassSaveMode::crypt:
            CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD, PassConnectSettings->DisplayName.c_str(), newpass.data(), 0);
            break;
        case sftp::PassSaveMode::plain: {
            const std::string stored = password_crypto::Protect(newpass.data());
            WritePrivateProfileString(PassConnectSettings->DisplayName.c_str(), "password",
                                      stored.empty() ? nullptr : stored.c_str(),
                                      PassConnectSettings->IniFileName.c_str());
            break;
        }
        default:
            break;
        }
    }
    SecureZeroMemory(newpass.data(), newpass.size());
}

int NegotiateProxy(
    pConnectSettings ConnectSettings,
    unsigned short connecttoport,
    int& progress,
    int& loop,
    SYSTICKS& lasttime)
{
    if (ConnectSettings->proxytype == sftp::Proxy::notused)
        return 0;

    progress = 20; // PROG_SOCKET_CONNECT
    std::array<char, 250> progressbuf{};
    LoadStr(progressbuf, IDS_PROXY_CONNECT);
    if (ProgressProc(PluginNumber, progressbuf.data(), "-", progress))
        return -40;

    int hr = 0;
    switch (ConnectSettings->proxytype) {
    case sftp::Proxy::http:
        hr = SftpConnectProxyHttp(ConnectSettings, progressbuf.data(), progress, &loop, &lasttime);
        if (hr) return -12040 - hr;
        break;
    case sftp::Proxy::socks4:
        hr = SftpConnectProxySocks4(ConnectSettings, progressbuf.data(), progress, &loop, &lasttime);
        if (hr) return -13040 - hr;
        break;
    case sftp::Proxy::socks5:
        hr = SftpConnectProxySocks5(ConnectSettings, connecttoport, progressbuf.data(), progress, &loop, &lasttime);
        if (hr) return -14040 - hr;
        break;
    default:
        break;
    }
    return 0;
}

int PerformAuthentication(
    pConnectSettings ConnectSettings,
    int& progress,
    int& loop,
    SYSTICKS& lasttime,
    char* progressbuf)
{
    std::array<char, 1024> buf{};
    char* userauthlist = nullptr;
    int auth_pw = 0;

    // Split the stored secret once, here, before any method runs. Everything
    // downstream reads account_password or key_passphrase by name. A
    // passphrase already remembered from an earlier attempt on this
    // connection survives, so reconnects do not prompt again.
    {
        const StoredSecret secret = SplitStoredSecret(ConnectSettings->password);
        // Reconnects run this again on the same settings, so a secret entered
        // at a prompt during an earlier attempt must not be wiped by a stored
        // form that does not carry one.
        if (!secret.accountPassword.empty())
            ConnectSettings->account_password = secret.accountPassword;
        if (secret.labelled) {
            if (!secret.keyPassphrase.empty())
                ConnectSettings->key_passphrase = secret.keyPassphrase;
        } else if (ConnectSettings->key_passphrase.empty()) {
            ConnectSettings->key_passphrase = secret.keyPassphrase;
        }
    }

    // A private key entered in the public-key field is still the key to log
    // in with; left there it is ignored, and a key-only server then ends the
    // login without a word. The swap is for this connection only.
    if (ConnectSettings->privkeyfile.empty() &&
        KeyFileHoldsPrivateKey(ConnectSettings->pubkeyfile, ConnectSettings->user)) {
        SFTP_LOG("AUTH", "Private key found in the public-key field: %s",
                 ConnectSettings->pubkeyfile.c_str());
        ShowStatus("Using the private key entered as the public key file");
        ConnectSettings->privkeyfile = ConnectSettings->pubkeyfile;
        ConnectSettings->pubkeyfile.clear();
    }

    // The probe is skipped only when there are credentials to try anyway.
    // With nothing configured it runs — shell-only mode included — so a
    // server that takes keys only is recognised instead of being asked for
    // a password it will refuse. A slow answer costs at most the probe's
    // own timeout, after which every method is assumed.
    const bool skipProbe = !ConnectSettings->password.empty()
        || !ConnectSettings->privkeyfile.empty();
    if (skipProbe) {
        ShowStatusId(IDS_LOG_SCP_SKIP_PROBE, nullptr, true);
        // Skip userauthList probe when credentials are known: avoids hanging on
        // servers (e.g. OVH) that respond slowly to the "none" auth request.
        auth_pw = SSH_AUTH_PASSWORD | SSH_AUTH_KEYBOARD | SSH_AUTH_PUBKEY;
    } else {
        SYSTICKS authListStart = get_sys_ticks();
        do {
            userauthlist = ConnectSettings->session->userauthList(ConnectSettings->user.c_str(), (UINT)ConnectSettings->user.size());
            LoadStr(buf, IDS_USER_AUTH_LIST);
            if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                break;
            if (get_ticks_between(authListStart) > SSH_PROBE_TIMEOUT_MS) {
                ShowStatusId(IDS_LOG_AUTH_METHODS_TIMEOUT, nullptr, true);
                break;
            }
            if (!userauthlist && ConnectSettings->session->lastErrno() == LIBSSH2_ERROR_EAGAIN)
                WaitForTransportReadable(ConnectSettings);
        } while (userauthlist == nullptr && ConnectSettings->session->lastErrno() == LIBSSH2_ERROR_EAGAIN);

        const std::string uaLog = std::format("userauthlist='{}' errno={}",
            userauthlist ? userauthlist : "(null)", ConnectSettings->session->lastErrno());
        ShowStatus(uaLog.c_str());

        if (userauthlist) {
            ShowStatusId(IDS_SUPPORTED_AUTH_METHODS, userauthlist, true);
            auth_pw = ParseAuthMethodsFromUserauthList(userauthlist);
            if (auth_pw == 0) {
                ShowStatusId(IDS_LOG_AUTH_METHODS_NONE, nullptr, true);
                // Some servers return malformed method lists; keep a compatibility path.
                auth_pw = SSH_AUTH_PASSWORD | SSH_AUTH_KEYBOARD | SSH_AUTH_PUBKEY;
            }
        } else {
            SftpLogLastError("libssh2_userauth_list: ", ConnectSettings->session->lastErrno());
            // NULL list after timeout/EAGAIN is treated as non-fatal for compatibility.
            auth_pw = SSH_AUTH_PASSWORD | SSH_AUTH_KEYBOARD | SSH_AUTH_PUBKEY;
        }
    }

    int auth = 0;
    if (ConnectSettings->session->userauthAuthenticated()) {
        ShowStatusId(IDS_LOG_AUTH_NO_PASSWORD, nullptr, true);
    } else if ((auth_pw & SSH_AUTH_PUBKEY) && ConnectSettings->useagent) {
        progress = 65;
        int rc = SftpAuthPageant(ConnectSettings, progressbuf, progress, &loop, &lasttime);
        auth = (rc < 0) ? LIBSSH2_ERROR_AGENT_PROTOCOL : 0;
        const std::string status = std::format("Pageant: rc={} auth={}", rc, auth);
        ShowStatus(status.c_str());
    } else if ((auth_pw & SSH_AUTH_PUBKEY) && ConnectSettings->privkeyfile[0]) {
        progress = 65;
        if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== Calling SftpAuthPubKey ===");
        int rc = SftpAuthPubKey(ConnectSettings, progress, &loop, &lasttime, &auth_pw);
        auth = (rc < 0) ? LIBSSH2_ERROR_FILE : 0;
        if (rc == -LIBSSH2_ERROR_FILE) {
            SFTP_LOG("CONN", "Public-key auth aborted due to local key file error.");
            return SFTP_FAILED;
        }
        if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== SftpAuthPubKey returned ===");
        const std::string status = std::format("PubKey: rc={} auth={} pw=0x{:x}", rc, auth, auth_pw);
        ShowStatus(status.c_str());
    } else {
        // A server that takes keys only, with neither a key file nor a
        // running Pageant to offer it, leaves nothing to try; say so rather
        // than let the login end without a word.
        if (auth_pw == SSH_AUTH_PUBKEY) {
            SFTP_LOG("AUTH", "Server accepts only public keys; none to offer");
            ShowErrorId(IDS_ERR_KEY_ONLY_NO_KEY);
        }
        auth_pw &= ~SSH_AUTH_PUBKEY;
    }

    if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== Auth section done ===");
    progress = 70; // PROG_AUTH_DONE
    if (auth != 0 || (auth_pw & SSH_AUTH_PUBKEY) == 0) {
        if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "Trying password/keyboard auth fallback");
        const bool canKeyboardAuth = (auth_pw & SSH_AUTH_KEYBOARD) != 0;
        const bool canPasswordAuth = (auth_pw & SSH_AUTH_PASSWORD) != 0;
        // If the probe was done and confirmed password auth, try it first to avoid
        // consuming keyboard-interactive attempts on OTP/MFA prompts.
        // When probe was skipped we don't know the server's supported methods,
        // so keyboard-interactive goes first; kbd_callback will auto-send the
        // stored password for password-like prompts (e.g. OVH).
        const bool preferPasswordFirst = !skipProbe && canPasswordAuth && !ConnectSettings->account_password.empty();
        bool skippedKeyboardFirst = false;

        if (canKeyboardAuth && !preferPasswordFirst) {
            ShowStatusId(IDS_AUTH_KEYBDINT_FOR, ConnectSettings->user.c_str(), true);
            LoadStr(buf, IDS_AUTH_KEYBDINT);
            pConnectSettings cs = ConnectSettings;
            cs->InteractivePasswordSent = false;
            const SYSTICKS authStart = get_sys_ticks();
            int kbdIter = 0;
            while ((auth = cs->session->userauthKeyboardInteractive(cs->user.c_str(), (unsigned)cs->user.size(), &kbd_callback)) == LIBSSH2_ERROR_EAGAIN) {
                const int dirs = cs->session->blockDirections();
                const DWORD elapsed = (DWORD)get_ticks_between(authStart);
                SFTP_LOG("AUTH", "kbd EAGAIN #%d dirs=0x%x elapsed=%u cbSent=%d", ++kbdIter, dirs, elapsed, cs->InteractivePasswordSent ? 1 : 0);
                if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                    break;
                if (elapsed > SSH_AUTH_STAGE_TIMEOUT_MS) {
                    ShowStatusId(IDS_LOG_KBD_AUTH_TIMEOUT, nullptr, true);
                    break;
                }
                WaitForSshIo(cs);
            }
            SFTP_LOG("AUTH", "kbd done auth=%d iters=%d cbSent=%d", auth, kbdIter, ConnectSettings->InteractivePasswordSent ? 1 : 0);
            if (auth) {
                SftpLogLastError("libssh2_userauth_keyboard_interactive: ", auth);
                if ((auth_pw & SSH_AUTH_PASSWORD) == 0)
                    ShowErrorId(IDS_ERR_AUTH_KEYBDINT);
            }
        } else {
            auth = LIBSSH2_ERROR_INVAL;
            skippedKeyboardFirst = canKeyboardAuth;
        }
        if (auth != 0 && canPasswordAuth) {
            std::string passphrase = ConnectSettings->account_password;
            if (passphrase.empty()) {
                std::string title = std::format("SFTP password for {}@{}", ConnectSettings->user, ConnectSettings->server);
                if (ConnectSettings->feedback) {
                    ConnectSettings->feedback->RequestText(title, "", passphrase, true);
                } else {
                    std::array<char, 256> tmpBuf{};
                    RequestInput(RT_Password, title.c_str(), nullptr, tmpBuf);
                    passphrase = tmpBuf.data();
                }
            }

            ShowStatusId(IDS_AUTH_PASSWORD_FOR, ConnectSettings->user.c_str(), true);
            LoadStr(buf, IDS_AUTH_PASSWORD);
            const SYSTICKS authStart = get_sys_ticks();
            int passIter = 0;
            while (1) {
                auth = ConnectSettings->session->userauthPassword(ConnectSettings->user.c_str(), (unsigned)ConnectSettings->user.size(), passphrase.c_str(), (unsigned)passphrase.length(), &newpassfunc);
                if (auth != LIBSSH2_ERROR_EAGAIN && auth != LIBSSH2_ERROR_PASSWORD_EXPIRED)
                    break;
                if (auth == LIBSSH2_ERROR_EAGAIN) {
                    const int dirs = ConnectSettings->session->blockDirections();
                    const DWORD elapsed = (DWORD)get_ticks_between(authStart);
                    SFTP_LOG("AUTH", "pass EAGAIN #%d dirs=0x%x elapsed=%u", ++passIter, dirs, elapsed);
                    if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                        break;
                    if (elapsed > SSH_AUTH_STAGE_TIMEOUT_MS) {
                        ShowStatusId(IDS_LOG_PASS_AUTH_TIMEOUT, nullptr, true);
                        break;
                    }
                    WaitForSshIo(ConnectSettings);
                }
            }
            SFTP_LOG("AUTH", "pass done auth=%d iters=%d", auth, passIter);
            if (auth) {
                SftpLogLastError("libssh2_userauth_password_ex: ", auth);
                if (!skippedKeyboardFirst)
                    ShowErrorId(IDS_ERR_AUTH_PASSWORD);
                else
                    ShowStatusId(IDS_ERR_AUTH_PASSWORD, nullptr, true);
            } else if (ConnectSettings->account_password.empty()) {
                // Remember it for the reconnects that run mid-transfer. The
                // stored form only takes it over when it holds nothing at
                // all, so a profile that packs a passphrase keeps it.
                ConnectSettings->account_password = passphrase;
                if (ConnectSettings->password.empty())
                    ConnectSettings->password = passphrase;
            }
        }

        if (auth != 0 && skippedKeyboardFirst) {
            // Retry keyboard-interactive after password failure for servers that expose
            // both methods but only accept one depending on account policy.
            ShowStatusId(IDS_AUTH_KEYBDINT_FOR, ConnectSettings->user.c_str(), true);
            LoadStr(buf, IDS_AUTH_KEYBDINT);
            pConnectSettings cs = ConnectSettings;
            cs->InteractivePasswordSent = false;
            const SYSTICKS authStart = get_sys_ticks();
            int kbdIter2 = 0;
            while ((auth = cs->session->userauthKeyboardInteractive(cs->user.c_str(), (unsigned)cs->user.size(), &kbd_callback)) == LIBSSH2_ERROR_EAGAIN) {
                const int dirs = cs->session->blockDirections();
                const DWORD elapsed = (DWORD)get_ticks_between(authStart);
                SFTP_LOG("AUTH", "kbd2 EAGAIN #%d dirs=0x%x elapsed=%u cbSent=%d", ++kbdIter2, dirs, elapsed, cs->InteractivePasswordSent ? 1 : 0);
                if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                    break;
                if (elapsed > SSH_AUTH_STAGE_TIMEOUT_MS) {
                    ShowStatusId(IDS_LOG_KBD_AUTH_TIMEOUT, nullptr, true);
                    break;
                }
                WaitForSshIo(cs);
            }
            SFTP_LOG("AUTH", "kbd2 done auth=%d iters=%d cbSent=%d", auth, kbdIter2, ConnectSettings->InteractivePasswordSent ? 1 : 0);
            if (auth) {
                SftpLogLastError("libssh2_userauth_keyboard_interactive: ", auth);
                ShowErrorId(IDS_ERR_AUTH_KEYBDINT);
            }
        }
    }

    const std::string authLog = std::format("Auth complete: auth={} auth_pw=0x{:x} scponly={}", auth, auth_pw, ConnectSettings->scponly);
    ShowStatus(authLog.c_str());
    SFTP_LOG("CONN", "%s", authLog.c_str());

    if (auth) {
        if (LogProc) {
            const std::string msg = std::format("SFTP: Authentication failed for '{}@{}'",
                ConnectSettings->user, ConnectSettings->server);
            LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, msg.c_str());
        }
        SFTP_LOG("CONN", "Auth failed, returning SFTP_FAILED");
        return SFTP_FAILED;
    }
    return 0;
}

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
#include "res/resource.h"

extern "C"
void newpassfunc(LIBSSH2_SESSION* /*session*/, LPSTR* newpw, int* newpw_len, LPVOID* abstract)
{
    pConnectSettings PassConnectSettings = static_cast<pConnectSettings>(*abstract);
    std::array<char, 128> title{};
    std::array<char, 128> buf1{};
    std::array<char, 128> newpass{};
    LoadStr(title.data(), IDS_PASS_TITLE);
    LoadStr(buf1.data(), IDS_PASS_CHANGE_REQUEST);
    newpass[0] = 0;
    if (newpw)
        *newpw = nullptr;
    if (newpw_len)
        *newpw_len = 0;
    if (RequestProc(PluginNumber, RT_Password, title.data(), buf1.data(), newpass.data(), newpass.size()-1)) {
        size_t bufsize = strlen(newpass.data()) + 1;
        *newpw = static_cast<char*>(malloc(bufsize));
        if (!*newpw)
            return;
        strlcpy(*newpw, newpass.data(), bufsize);
        *newpw_len = (int)strlen(newpass.data());
        if (PassConnectSettings) {
            PassConnectSettings->password = newpass.data();
            switch (PassConnectSettings->passSaveMode) {
            case sftp::PassSaveMode::crypt:
                CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD, PassConnectSettings->DisplayName.c_str(), newpass.data(), 0);
                break;
            case sftp::PassSaveMode::plain:
                if (newpass[0] == 0) {
                    WritePrivateProfileString(PassConnectSettings->DisplayName.c_str(), "password", nullptr, PassConnectSettings->IniFileName.c_str());
                } else {
                    std::array<char, 256> szEncryptedPassword{};
                    EncryptString(newpass.data(), szEncryptedPassword.data(), szEncryptedPassword.size());
                    WritePrivateProfileString(PassConnectSettings->DisplayName.c_str(), "password", szEncryptedPassword.data(), PassConnectSettings->IniFileName.c_str());
                }
                break;
            }
        }
    }
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
    LoadStr(progressbuf.data(), IDS_PROXY_CONNECT);
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
    char* progressbuf,
    bool agentAvailable)
{
    std::array<char, 1024> buf{};
    char* userauthlist = nullptr;
    int auth_pw = 0;
    if (ConnectSettings->scponly) {
        ShowStatus("SCP-only: skipping auth-methods probe.");
        // SCP-only servers often reject method probing while still accepting auth.
        // Start with a broad method mask and let runtime attempts narrow it.
        auth_pw = SSH_AUTH_PASSWORD | SSH_AUTH_KEYBOARD | SSH_AUTH_PUBKEY;
    } else {
        SYSTICKS authListStart = get_sys_ticks();
        do {
            userauthlist = ConnectSettings->session->userauthList(ConnectSettings->user.c_str(), (UINT)ConnectSettings->user.size());
            LoadStr(buf.data(), IDS_USER_AUTH_LIST);
            if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                break;
            if (get_ticks_between(authListStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
                ShowStatus("Getting authentication methods timed out, using fallback.");
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
                ShowStatus("Auth methods list parsed to none, using fallback methods.");
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
        ShowStatus("User authenticated without password.");
    } else if ((auth_pw & SSH_AUTH_PUBKEY) && ConnectSettings->useagent && agentAvailable) {
        progress = 65;
        int rc = SftpAuthPageant(ConnectSettings, progressbuf, progress, &loop, &lasttime, &auth_pw);
        auth = (rc < 0) ? LIBSSH2_ERROR_AGENT_PROTOCOL : 0;
        const std::string status = std::format("Pageant: rc={} auth={}", rc, auth);
        ShowStatus(status.c_str());
    } else if ((auth_pw & SSH_AUTH_PUBKEY) && ConnectSettings->privkeyfile[0]) {
        progress = 65;
        if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== Calling SftpAuthPubKey ===");
        int rc = SftpAuthPubKey(ConnectSettings, progressbuf, progress, &loop, &lasttime, &auth_pw);
        auth = (rc < 0) ? LIBSSH2_ERROR_FILE : 0;
        if (rc == -LIBSSH2_ERROR_FILE) {
            SFTP_LOG("CONN", "Public-key auth aborted due to local key file error.");
            return SFTP_FAILED;
        }
        if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== SftpAuthPubKey returned ===");
        const std::string status = std::format("PubKey: rc={} auth={} pw=0x{:x}", rc, auth, auth_pw);
        ShowStatus(status.c_str());
    } else {
        auth_pw &= ~SSH_AUTH_PUBKEY;
    }

    if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== Auth section done ===");
    progress = 70; // PROG_AUTH_DONE
    if (auth != 0 || (auth_pw & SSH_AUTH_PUBKEY) == 0) {
        if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "Trying password/keyboard auth fallback");
        const bool canKeyboardAuth = (auth_pw & SSH_AUTH_KEYBOARD) != 0;
        const bool canPasswordAuth = (auth_pw & SSH_AUTH_PASSWORD) != 0;
        // If we already have a password, try password auth first to avoid consuming
        // keyboard-interactive attempts on OTP/MFA prompts.
        const bool preferPasswordFirst = canPasswordAuth && ConnectSettings->password[0] != 0;
        bool skippedKeyboardFirst = false;

        if (canKeyboardAuth && !preferPasswordFirst) {
            ShowStatusId(IDS_AUTH_KEYBDINT_FOR, ConnectSettings->user.c_str(), true);
            LoadStr(buf.data(), IDS_AUTH_KEYBDINT);
            pConnectSettings cs = ConnectSettings;
            cs->InteractivePasswordSent = false;
            const SYSTICKS authStart = get_sys_ticks();
            while ((auth = cs->session->userauthKeyboardInteractive(cs->user.c_str(), (unsigned)cs->user.size(), &kbd_callback)) == LIBSSH2_ERROR_EAGAIN) {
                if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                    break;
                if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
                    ShowStatus("Keyboard-interactive authentication timed out.");
                    break;
                }
                WaitForTransportReadable(ConnectSettings);
            }
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
            std::string passphrase;
            const char* passwordCStr = ConnectSettings->password.c_str();
            const char* p = strstr(passwordCStr, "\",\"");
            size_t len = ConnectSettings->password.size();
            if (p && !ConnectSettings->password.empty() && ConnectSettings->password.front() == '"' && ConnectSettings->password.back() == '"') {
                passphrase = std::string(p + 3, (passwordCStr + len - 1) - (p + 3));
            } else {
                passphrase = ConnectSettings->password;
            }
            if (passphrase.empty()) {
                std::string title = std::format("SFTP password for {}@{}", ConnectSettings->user, ConnectSettings->server);
                if (ConnectSettings->feedback) {
                    ConnectSettings->feedback->RequestText(title, "", passphrase, true);
                } else {
                    std::array<char, 256> tmpBuf{};
                    RequestProc(PluginNumber, RT_Password, title.c_str(), nullptr, tmpBuf.data(), tmpBuf.size()-1);
                    passphrase = tmpBuf.data();
                }
            }

            ShowStatusId(IDS_AUTH_PASSWORD_FOR, ConnectSettings->user.c_str(), true);
            LoadStr(buf.data(), IDS_AUTH_PASSWORD);
            const SYSTICKS authStart = get_sys_ticks();
            while (1) {
                auth = ConnectSettings->session->userauthPassword(ConnectSettings->user.c_str(), (unsigned)ConnectSettings->user.size(), passphrase.c_str(), (unsigned)passphrase.length(), &newpassfunc);
                if (auth != LIBSSH2_ERROR_EAGAIN && auth != LIBSSH2_ERROR_PASSWORD_EXPIRED)
                    break;
                if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                    break;
                if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
                    ShowStatus("Password authentication timed out.");
                    break;
                }
                WaitForTransportReadable(ConnectSettings);
            }
            if (auth) {
                SftpLogLastError("libssh2_userauth_password_ex: ", auth);
                ShowErrorId(IDS_ERR_AUTH_PASSWORD);
            } else if (ConnectSettings->password.empty()) {
                ConnectSettings->password = passphrase;
            }
        }

        if (auth != 0 && skippedKeyboardFirst) {
            // Retry keyboard-interactive after password failure for servers that expose
            // both methods but only accept one depending on account policy.
            ShowStatusId(IDS_AUTH_KEYBDINT_FOR, ConnectSettings->user.c_str(), true);
            LoadStr(buf.data(), IDS_AUTH_KEYBDINT);
            pConnectSettings cs = ConnectSettings;
            cs->InteractivePasswordSent = false;
            const SYSTICKS authStart = get_sys_ticks();
            while ((auth = cs->session->userauthKeyboardInteractive(cs->user.c_str(), (unsigned)cs->user.size(), &kbd_callback)) == LIBSSH2_ERROR_EAGAIN) {
                if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                    break;
                if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
                    ShowStatus("Keyboard-interactive authentication timed out.");
                    break;
                }
                WaitForTransportReadable(ConnectSettings);
            }
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
        SFTP_LOG("CONN", "Auth failed, returning SFTP_FAILED");
        return SFTP_FAILED;
    }
    return 0;
}

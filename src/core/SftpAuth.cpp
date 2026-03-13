#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <stdio.h>
#include <array>
#include <string>
#include <format>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "UtfConversion.h"
#include "SftpInternal.h"
#include "PpkConverter.h"

#define AUTH_LOG(fmt, ...) SFTP_LOG("AUTH", fmt, ##__VA_ARGS__)

static bool PromptLooksLikePasswordRequest(char* promptTextLower) noexcept
{
    if (!promptTextLower || !promptTextLower[0])
        return false;
    // Must contain "pass".
    if (!strstr(promptTextLower, "pass"))
        return false;
    // Exclude common OTP prompts.
    if (strstr(promptTextLower, "oath") || strstr(promptTextLower, "one time") || strstr(promptTextLower, "one-time"))
        return false;
    return true;
}

static bool TryGetSecondQuotedPassword(const char* storedPassword, std::string& outSecondPassword)
{
    if (!storedPassword)
        return false;
    size_t len = strlen(storedPassword);
    if (len < 5 || storedPassword[0] != '"' || storedPassword[len - 1] != '"')
        return false;
    const char* p = strstr(storedPassword, "\",\"");
    if (!p || p[3] == 0)
        return false;
    outSecondPassword.assign(p + 3);
    return !outSecondPassword.empty();
}

extern "C"
void kbd_callback(LPCSTR name, int name_len,
                  LPCSTR instruction, int instruction_len, int num_prompts,
                  const LIBSSH2_USERAUTH_KBDINT_PROMPT * prompts,
                  LIBSSH2_USERAUTH_KBDINT_RESPONSE * responses,
                  LPVOID * abstract)
{
    std::array<char, 1024> buf{};
    std::array<char, 256> retbuf{};
    pConnectSettings ConnectSettings = static_cast<pConnectSettings>(*abstract);

    for (int i = 0; i < num_prompts; i++) {
        // Pass the stored password as the first response for password-like prompts.
        // Multiple callback invocations are tracked via InteractivePasswordSent.
        strlcpy(retbuf.data(), reinterpret_cast<LPCSTR>(prompts[i].text), min(static_cast<size_t>(prompts[i].length), retbuf.size()-1));
        ShowStatus(retbuf.data());
        bool autoSendPassword = (ConnectSettings && !ConnectSettings->password.empty() && !ConnectSettings->InteractivePasswordSent);
        if (autoSendPassword) {
            _strlwr_s(retbuf.data(), retbuf.size());
            autoSendPassword = PromptLooksLikePasswordRequest(retbuf.data());
        }
        if (autoSendPassword) {
            ConnectSettings->InteractivePasswordSent = true;
            std::string secondPassword;
            if (TryGetSecondQuotedPassword(ConnectSettings->password.c_str(), secondPassword)) {
                responses[i].text = _strdup(secondPassword.c_str());
            } else {
                responses[i].text = _strdup(ConnectSettings->password.c_str());
            }
            if (responses[i].text) {
                responses[i].length = (unsigned int)strlen(responses[i].text);
                ShowStatus("sending stored password");
            } else {
                autoSendPassword = false;
            }
        }
        if (!autoSendPassword) {
            std::string promptMsg;
            if (instruction && instruction_len)
                promptMsg = std::string(instruction, instruction_len) + "\n";
            if (prompts[i].length && prompts[i].text)
                promptMsg += std::string(reinterpret_cast<LPCSTR>(prompts[i].text), prompts[i].length);
            if (promptMsg.empty())
                promptMsg = "Password:";

            std::string title;
            if (name && name_len)
                title.assign(name, static_cast<size_t>(name_len));
            else
                title = "SFTP password for";
            if (ConnectSettings)
                title = std::format("{} {}@{}", title, ConnectSettings->user, ConnectSettings->server);
            retbuf[0] = 0;

            ShowStatus("requesting password from user...");
            if (RequestProc(PluginNumber, RT_Password, title.c_str(), promptMsg.c_str(), retbuf.data(), retbuf.size()-1)) {
                responses[i].text = _strdup(retbuf.data());
                responses[i].length = (unsigned int)strlen(retbuf.data());
                // Remember password for background transfers
                if (ConnectSettings && ConnectSettings->password.empty())
                    ConnectSettings->password = retbuf.data();
                ShowStatus("sending password entered by user");
            } else {
                responses[i].text = nullptr;
                responses[i].length = 0;
            }
        }
    }
} /* kbd_callback */

static bool ismimechar(const char ch)
{
    return ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
             ch == '/' || ch == '+' || ch == '=' || ch == '\r' || ch == '\n');
}

static bool EndsWithNoCase(LPCSTR text, LPCSTR suffix) noexcept
{
    if (!text || !suffix)
        return false;
    size_t tlen = strlen(text);
    size_t slen = strlen(suffix);
    if (tlen < slen)
        return false;
    return _stricmp(text + tlen - slen, suffix) == 0;
}

static void ShowPpkConversionFailure(PpkConvertError convErr)
{
    switch (convErr) {
    case PpkConvertError::unsupported_version:
        ShowStatus("Failed to convert .ppk: unsupported PPK version.");
        break;
    case PpkConvertError::unsupported_algorithm:
        ShowStatus("Failed to convert .ppk: unsupported key algorithm.");
        break;
    case PpkConvertError::unsupported_encryption:
    case PpkConvertError::unsupported_kdf:
        ShowStatus("Failed to convert .ppk: unsupported encryption/KDF.");
        break;
    case PpkConvertError::kdf_unavailable:
        ShowStatus("Failed to convert .ppk: Argon2 runtime not available.");
        break;
    case PpkConvertError::passphrase_required:
    case PpkConvertError::bad_passphrase_or_mac:
        ShowStatus("Failed to convert .ppk: wrong passphrase or corrupted key.");
        break;
    default:
        ShowStatus("Failed to convert .ppk.");
        break;
    }
}

static void ExpandAuthPath(char* path, size_t pathLen, LPCSTR user)
{
    if (!path || pathLen == 0)
        return;
    ReplaceSubString(path, "%USER%", user ? user : "", pathLen - 1);
    ReplaceEnvVars(path, pathLen - 1);
}

static bool DetectPrivateKeyEncrypted(LPCSTR privkeyfile, bool* outEncrypted)
{
    if (!privkeyfile || !outEncrypted)
        return false;

    DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
    handle_util::FileHandle hf(CreateFileA(privkeyfile, GENERIC_READ, dwShareMode, nullptr, OPEN_EXISTING, dwFlags, nullptr));
    if (!hf)
        return false;

    std::array<char, 1024> filebuf{};
    DWORD dataread = 0;
    bool isencrypted = true;
    if (ReadFile(hf.get(), filebuf.data(), static_cast<DWORD>(filebuf.size() - 32), &dataread, nullptr)) {
        filebuf[dataread] = 0;
        LPSTR p = strchr(filebuf.data(), '\n');
        if (!p)
            p = strchr(filebuf.data(), '\r');
        if (p) {
            p++;
            while (p[0] == '\r' || p[0] == '\n')
                p++;
            isencrypted = false;
            for (int i = 0; i < 32; i++)
                if (!ismimechar(p[i]))
                    isencrypted = true;
            if (!isencrypted) {
                char* p2 = filebuf.data();
                while (p2[0] == '\r' || p2[0] == '\n')
                    p2++;
                if (strncmp(p2, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0) {
                    std::array<char, 64> outbuf{};
                    int len = MimeDecode(p, min(64, strlen(p)), outbuf.data(), outbuf.size());
                    for (int i = 0; i < len - 6; i++) {
                        if (outbuf[i] == 'b' && strncmp(outbuf.data() + i, "bcrypt", 6) == 0) {
                            isencrypted = true;
                            break;
                        }
                    }
                }
            }
        }
    }
    *outEncrypted = isencrypted;
    return true;
}

static void BuildUserAtServerTitle(char* out, size_t outLen, int prefixResId, pConnectSettings cs)
{
    if (!out || outLen == 0)
        return;
    out[0] = 0;
    LoadStr(out, prefixResId);
    if (!cs)
        return;
    strlcat(out, cs->user.c_str(), outLen - 1);
    strlcat(out, "@", outLen - 1);
    strlcat(out, cs->server.c_str(), outLen - 1);
}

static bool PreparePrivateKeyForAuth(
    pConnectSettings cs,
    char* ioPrivKeyFile,
    size_t privKeyLen,
    char** ioPubKeyPtr,
    bool* outRemoveConvertedPrivateKey,
    char* outConvertedPrivateKey,
    size_t convertedLen,
    char* ioPromptBuf)
{
    if (!cs || !ioPrivKeyFile || !ioPubKeyPtr || !outRemoveConvertedPrivateKey || !outConvertedPrivateKey || !ioPromptBuf)
        return false;
    if (!EndsWithNoCase(ioPrivKeyFile, ".ppk"))
        return true;

    const char* ppkPass = cs->password.empty() ? "" : cs->password.c_str();
    PpkConvertError convErr = PpkConvertError::internal_error;
    ShowStatus("Converting PPK file...");
    bool converted = ConvertPpkToOpenSsh(ioPrivKeyFile, ppkPass, outConvertedPrivateKey, convertedLen - 1, &convErr);
    const std::string convStatus = std::format("PPK conv: {}, err={}", converted, static_cast<int>(convErr));
    AUTH_LOG("PPK conversion: converted=%d, convErr=%d, pemPath=%s", converted, convErr, outConvertedPrivateKey);
    ShowStatus(convStatus.c_str());

    if (!converted && (convErr == PpkConvertError::passphrase_required ||
                       convErr == PpkConvertError::bad_passphrase_or_mac)) {
        std::array<char, 250> title{};
        std::array<char, 256> ppkPassBuf{};
        title[0] = 0;
        ppkPassBuf[0] = 0;
        LoadStr(ioPromptBuf, IDS_KEYPASSPHRASE);
        BuildUserAtServerTitle(title.data(), title.size(), IDS_PASSPHRASE, cs);
        if (RequestProc(PluginNumber, RT_Password, title.data(), ioPromptBuf, ppkPassBuf.data(), ppkPassBuf.size() - 1)) {
            converted = ConvertPpkToOpenSsh(ioPrivKeyFile, ppkPassBuf.data(), outConvertedPrivateKey, convertedLen - 1, &convErr);
            if (converted && cs->password.empty())
                cs->password = ppkPassBuf.data();
        }
        SecureZeroMemory(ppkPassBuf.data(), ppkPassBuf.size());
    }

    if (!converted) {
        ShowPpkConversionFailure(convErr);
        return false;
    }

    strlcpy(ioPrivKeyFile, outConvertedPrivateKey, privKeyLen - 1);
    *ioPubKeyPtr = nullptr;
    *outRemoveConvertedPrivateKey = true;
    return true;
}

static bool ValidatePublicKeyFileIfPresent(
    char* pubkeyfileptr,
    LPCSTR convertedPrivateKey,
    bool removeConvertedPrivateKey,
    LPCSTR pubkeyfile,
    DWORD dwShareMode,
    DWORD dwFlags)
{
    if (!pubkeyfileptr || !pubkeyfile[0])
        return true;

    DWORD dataread = 0;
    std::array<char, 1024> filebuf{};
    handle_util::FileHandle hf(CreateFileA(pubkeyfile, GENERIC_READ, dwShareMode, nullptr, OPEN_EXISTING, dwFlags, nullptr));
    if (!hf) {
        if (removeConvertedPrivateKey)
            DeleteFileA(convertedPrivateKey);
        ShowStatusId(IDS_ERR_LOAD_PUBKEY, pubkeyfile, true);
        return false;
    }

    if (ReadFile(hf.get(), filebuf.data(), 35, &dataread, nullptr)) {
        if (_strnicmp(filebuf.data(), "ssh-", 4) != 0 &&
            _strnicmp(filebuf.data(), "ecdsa-", 6) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN OPENSSH PRIVATE KEY-----", 35) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN RSA PRIVATE KEY-----", 31) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN EC PRIVATE KEY-----", 30) != 0)
        {
            if (removeConvertedPrivateKey)
                DeleteFileA(convertedPrivateKey);
            ShowStatusId(IDS_ERR_PUBKEY_WRONG_FORMAT, nullptr, true);
            return false;
        }
    }
    return true;
}


int SftpAuthPageant(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime, int * auth_pw)
{
    std::array<char, 1024> buf{};
    struct libssh2_agent_publickey * identity = nullptr;
    struct libssh2_agent_publickey * prev_identity = nullptr;

    std::unique_ptr<ISshAgent> agent = ConnectSettings->session->agentInit();
    auto finish = [&](int code) -> int {
        if (code < 0) {
            ShowStatusId(-code, nullptr, true);
        } else if (code == 0) {
            ShowStatusId(IDS_AGENT_AUTHSUCCEEDED, nullptr, true);
        }
        if (agent) {
            agent->disconnect();
        }
        return code;
    };

    if (!agent || agent->connect() != 0) {
        if (agent) {
            agent->disconnect();
            // agent->free() removed: ~Libssh2Agent() calls libssh2_agent_free()
            agent.reset();
        }
        // Attempt to launch Pageant.
        std::array<char, MAX_PATH> dirname{};
        dirname[0] = 0;
        GetModuleFileName(hinst, dirname.data(), dirname.size()-10);
        char* p = strrchr(dirname.data(), '\\');
        p = p ? p + 1 : dirname.data();
        p[0] = 0;
        const std::string linkname = std::string(dirname.data()) + "pageant.lnk";
        if (GetFileAttributesA(linkname.c_str()) == INVALID_FILE_ATTRIBUTES)
            return finish(-IDS_AGENT_CONNECTERROR);

        HWND active = GetForegroundWindow();
        ShellExecute(active, nullptr, linkname.c_str(), nullptr, dirname.data(), SW_SHOW);
        Sleep(PAGEANT_WAIT_MS);
        SYSTICKS starttime = get_sys_ticks();
        while (active != GetForegroundWindow() && get_ticks_between(starttime) < PAGEANT_TIMEOUT_MS) {
            Sleep(200);
            if (ProgressLoop(progressbuf, progress, progress + 5, ploop, plasttime))
                break;
        }
        agent = ConnectSettings->session->agentInit();
        if (!agent)
            return finish(-IDS_AGENT_CONNECTERROR);
        int rc = agent->connect();
        if (rc)
            return finish(-IDS_AGENT_CONNECTERROR);
    }

    int rc = agent->listIdentities();
    if (rc)
        return finish(-IDS_AGENT_REQUESTIDENTITIES);
    while (1) {
        int auth = agent->getIdentity(&identity, prev_identity);
        if (auth == 1)
            return finish(-IDS_AGENT_AUTHFAILED);  /* pub key */
        if (auth < 0)
            return finish(-IDS_AGENT_NOIDENTITY);
        std::array<char, 128> str1{}, str2{}, str3{};
        LoadStr(str1.data(), IDS_AGENT_TRYING1);
        LoadStr(str2.data(), IDS_AGENT_TRYING2);
        LoadStr(str3.data(), IDS_AGENT_TRYING3);
        ShowStatus((std::string(str1.data()) + ConnectSettings->user + str2.data() + identity->comment + str3.data()).c_str());
        const SYSTICKS authStart = get_sys_ticks();
        while ((auth = agent->userauth(ConnectSettings->user.c_str(), identity)) == LIBSSH2_ERROR_EAGAIN) {
            if (ProgressLoop(progressbuf, progress, progress + 5, ploop, plasttime))
                return finish(-IDS_AGENT_AUTHFAILED);
            if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
                ShowStatus("Pageant authentication timed out.");
                return finish(-IDS_AGENT_AUTHFAILED);
            }
            WaitForTransportReadable(ConnectSettings);  // Sleep to avoid 100% CPU usage.
        }
#ifndef SFTP_ALLINONE
        // NOTE: LIBSSH2_ERROR_REQUIRE_KEYBOARD / REQUIRE_PASSWORD are non-standard error codes
        // provided by the local libssh2 fork to signal mid-auth method switching.
        if (auth == LIBSSH2_ERROR_REQUIRE_KEYBOARD) {
            *auth_pw = SSH_AUTH_KEYBOARD;
            return finish(SSH_AUTH_KEYBOARD);
        }
        if (auth == LIBSSH2_ERROR_REQUIRE_PASSWORD) {
            *auth_pw = SSH_AUTH_PASSWORD;
            return finish(SSH_AUTH_PASSWORD);
        }
#endif
        if (auth == 0)
            return finish(0);   /* OK */
        prev_identity = identity;
    }
}

int SftpAuthPubKey(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime, int * auth_pw)
{
    std::array<char, 1024> buf{};
    std::array<char, 256> passphrase{};
    std::array<char, MAX_PATH> pubkeyfile{};
    std::array<char, MAX_PATH> privkeyfile{};
    std::array<char, MAX_PATH> convertedPrivateKey{};
    bool removeConvertedPrivateKey = false;
    char* pubkeyfileptr = pubkeyfile.data();
    auto cleanupConvertedIfNeeded = [&]() {
        if (removeConvertedPrivateKey)
            DeleteFileA(convertedPrivateKey.data());
    };
    auto clearPassphrase = [&]() {
        SecureZeroMemory(passphrase.data(), passphrase.size());
    };

    AUTH_LOG("=== SftpAuthPubKey START ===");
    // Check if LogProc is available
    extern tLogProc LogProc;
    if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== SftpAuthPubKey called from SftpConnection ===");
    AUTH_LOG("privkeyfile=%s", ConnectSettings->privkeyfile.c_str());
    AUTH_LOG("pubkeyfile=%s", ConnectSettings->pubkeyfile.c_str());
    AUTH_LOG("password_empty=%d", ConnectSettings->password.empty() ? 1 : 0);
    AUTH_LOG("server=%s", ConnectSettings->server.c_str());
    AUTH_LOG("user=%s", ConnectSettings->user.c_str());

    strlcpy(pubkeyfile.data(), ConnectSettings->pubkeyfile.c_str(), pubkeyfile.size()-1);
    ExpandAuthPath(pubkeyfile.data(), pubkeyfile.size(), ConnectSettings->user.c_str());
    strlcpy(privkeyfile.data(), ConnectSettings->privkeyfile.c_str(), privkeyfile.size()-1);
    ExpandAuthPath(privkeyfile.data(), privkeyfile.size(), ConnectSettings->user.c_str());
    convertedPrivateKey[0] = 0;

    AUTH_LOG("After expand: privkeyfile=%s", privkeyfile.data());
    AUTH_LOG("After expand: pubkeyfile=%s", pubkeyfile.data());
    AUTH_LOG("privkeyfile exists=%d", GetFileAttributesA(privkeyfile.data()) != INVALID_FILE_ATTRIBUTES);

    // Fail-fast on explicit key paths that do not exist.
    if (privkeyfile.data()[0] && GetFileAttributesA(privkeyfile.data()) == INVALID_FILE_ATTRIBUTES) {
        ShowStatusId(IDS_ERR_LOAD_PRIVKEY, privkeyfile.data(), true);
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }
    if (pubkeyfileptr && pubkeyfile.data()[0] && GetFileAttributesA(pubkeyfile.data()) == INVALID_FILE_ATTRIBUTES) {
        ShowStatusId(IDS_ERR_LOAD_PUBKEY, pubkeyfile.data(), true);
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    if (!PreparePrivateKeyForAuth(ConnectSettings, privkeyfile.data(), privkeyfile.size(), &pubkeyfileptr,
                                  &removeConvertedPrivateKey, convertedPrivateKey.data(), convertedPrivateKey.size(),
                                  buf.data())) {
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    passphrase[0] = 0;
    // verify that we have a valid public key file (optional when private key is enough)
    DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
    if (!ValidatePublicKeyFileIfPresent(pubkeyfileptr, convertedPrivateKey.data(), removeConvertedPrivateKey, pubkeyfile.data(), dwShareMode, dwFlags))
    {
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    // Skip passphrase prompt for unencrypted keys.
    // Converted PPK output PEM is unencrypted.
    bool isencrypted = true;  // Assume encrypted by default
    bool skipEncryptionCheck = removeConvertedPrivateKey;  // Converted PPK -> skip check, we know it's unencrypted
    
    if (!skipEncryptionCheck) {
        if (!DetectPrivateKeyEncrypted(privkeyfile.data(), &isencrypted)) {
            cleanupConvertedIfNeeded();
            ShowStatusId(IDS_ERR_LOAD_PRIVKEY, privkeyfile.data(), true);
            clearPassphrase();
            return -LIBSSH2_ERROR_FILE;
        }
    } else {
        // Converted from PPK; encryption is already known.
        isencrypted = false;
    }
    
    const std::string encStatus = std::format("Key: {}", isencrypted ? "encrypted" : "unencrypted");
    AUTH_LOG("Encryption check result: %s", encStatus.c_str());
    ShowStatus(encStatus.c_str());
    if (isencrypted) {
        AUTH_LOG("Key is encrypted, requesting passphrase");
        std::array<char, 250> title{};
        BuildUserAtServerTitle(title.data(), title.size(), IDS_PASSPHRASE, ConnectSettings);
        LoadStr(buf.data(), IDS_KEYPASSPHRASE);
        if (!ConnectSettings->password.empty()) {
            AUTH_LOG("Using stored password");
            std::string secondPassword;
            if (TryGetSecondQuotedPassword(ConnectSettings->password.c_str(), secondPassword)) {
                strlcpy(passphrase.data(), secondPassword.c_str(), passphrase.size()-1);
            } else {
                strlcpy(passphrase.data(), ConnectSettings->password.c_str(), passphrase.size()-1);
            }
        } else {
            AUTH_LOG("No stored password, requesting from user");
            RequestProc(PluginNumber, RT_Password, title.data(), buf.data(), passphrase.data(), passphrase.size()-1);
        }
    } else {
        AUTH_LOG("Key is NOT encrypted, no passphrase needed");
    }

    ShowStatusId(IDS_AUTH_PUBKEY_FOR, ConnectSettings->user.c_str(), true);

    if (pubkeyfileptr && _stricmp(pubkeyfile.data(), privkeyfile.data()) == 0)
        pubkeyfileptr = nullptr;

    LoadStr(buf.data(), IDS_AUTH_PUBKEY);
    pConnectSettings cs = ConnectSettings;
    int auth;
    const char* passphrasePtr = isencrypted ? passphrase.data() : nullptr;
    AUTH_LOG("Calling userauthPubkeyFromFile: priv=%s pub=%s passphrase=%s",
             privkeyfile.data(),
             pubkeyfileptr ? pubkeyfileptr : "(null)",
             passphrasePtr ? "(set)" : "(null)");
    SYSTICKS authStart = get_sys_ticks();
    while ((auth = cs->session->userauthPubkeyFromFile(cs->user.c_str(), (unsigned)cs->user.size(), pubkeyfileptr, privkeyfile.data(), passphrasePtr)) == LIBSSH2_ERROR_EAGAIN) {
        if (ProgressLoop(buf.data(), progress, progress + 10, ploop, plasttime))
            break;
        if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
            ShowStatus("Public key authentication timed out.");
            auth = LIBSSH2_ERROR_TIMEOUT;
            break;
        }
        WaitForTransportReadable(ConnectSettings);  // Sleep to avoid 100% CPU usage.
    }
    AUTH_LOG("userauthPubkeyFromFile result=%d", auth);
#ifndef SFTP_ALLINONE
        // NOTE: LIBSSH2_ERROR_REQUIRE_KEYBOARD / REQUIRE_PASSWORD are non-standard error codes
        // provided by the local libssh2 fork to signal mid-auth method switching.
        if (auth == LIBSSH2_ERROR_REQUIRE_KEYBOARD) {
            *auth_pw = SSH_AUTH_KEYBOARD;
            return SSH_AUTH_KEYBOARD;
        }
        if (auth == LIBSSH2_ERROR_REQUIRE_PASSWORD) {
            *auth_pw = SSH_AUTH_PASSWORD;
            return SSH_AUTH_PASSWORD;
        }
#endif
    if (auth) {
        cleanupConvertedIfNeeded();
        char* errMsg = nullptr;
        int errLen = 0;
        ConnectSettings->session->lastError(&errMsg, &errLen, false);
        SftpLogLastError("libssh2_userauth_publickey_fromfile: ", auth);
        std::array<char, 1024> loadedMsg{};
        LoadStr(loadedMsg.data(), IDS_ERR_AUTH_PUBKEY);
        std::string uiMsg;
        if (loadedMsg[0] == 0 || _stricmp(loadedMsg.data(), "Error:") == 0 || strstr(loadedMsg.data(), "%s"))
            uiMsg = "Error: Authentication by client certificate failed!";
        else
            uiMsg = loadedMsg.data();
        if (errMsg && errMsg[0])
            uiMsg += "\n" + std::string(errMsg);
        const bool hasFallbackAuth =
            auth_pw && ((*auth_pw & SSH_AUTH_PASSWORD) != 0 || (*auth_pw & SSH_AUTH_KEYBOARD) != 0);
        if (hasFallbackAuth) {
            // Avoid modal noise when we can continue with password/keyboard.
            ShowStatus(uiMsg.c_str());
        } else {
            ShowError(uiMsg.c_str());
        }
        AUTH_LOG("SftpAuthPubKey returning -IDS_ERR_AUTH_PUBKEY");
        clearPassphrase();
        return -IDS_ERR_AUTH_PUBKEY;
    }
    cleanupConvertedIfNeeded();

    // Only store password if it was actually entered by the user and we didn't have one
    if (auth == 0 && isencrypted && passphrase[0] && ConnectSettings->password.empty())
        ConnectSettings->password = passphrase.data();

    clearPassphrase();
    AUTH_LOG("SftpAuthPubKey returning 0 (SUCCESS)");
    return 0;
}

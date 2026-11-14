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

StoredSecret SplitStoredSecret(const std::string& stored)
{
    StoredSecret out;
    if (stored.size() >= 2 && stored.front() == '"' && stored.back() == '"') {
        const size_t sep = stored.find("\",\"");
        // The passphrase runs from after the separator up to the closing quote.
        if (sep >= 1 && sep != std::string::npos && sep + 3 <= stored.size() - 1) {
            out.accountPassword = stored.substr(1, sep - 1);
            out.keyPassphrase   = stored.substr(sep + 3, stored.size() - sep - 4);
            out.labelled        = true;
            return out;
        }
    }
    // Nothing labels the two halves of a plain string, so it stands for
    // whichever secret is asked for: a profile carrying only a passphrase is
    // as common as one carrying only a password. Trying it as a passphrase
    // costs nothing — that use never leaves the machine — while the quoted
    // form above is what states which secret is which.
    out.accountPassword = stored;
    out.keyPassphrase   = stored;
    return out;
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
        const size_t copyLen = min(static_cast<size_t>(prompts[i].length), retbuf.size() - 1);
        memcpy(retbuf.data(), prompts[i].text, copyLen);
        retbuf[copyLen] = '\0';
        ShowStatus(retbuf.data());
        _strlwr_s(retbuf.data(), retbuf.size());
        const bool passwordPrompt = PromptLooksLikePasswordRequest(retbuf.data());
        bool autoSendPassword = passwordPrompt && ConnectSettings &&
                                !ConnectSettings->account_password.empty() &&
                                !ConnectSettings->InteractivePasswordSent;
        if (autoSendPassword) {
            ConnectSettings->InteractivePasswordSent = true;
            responses[i].text = _strdup(ConnectSettings->account_password.c_str());
            if (responses[i].text) {
                responses[i].length = (unsigned int)strlen(responses[i].text);
                ShowStatusId(IDS_LOG_SEND_STORED_PASS, nullptr, true);
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

            ShowStatusId(IDS_LOG_REQUEST_PASS, nullptr, true);
            if (RequestInput(RT_Password, title.c_str(), promptMsg.c_str(), retbuf)) {
                responses[i].text = _strdup(retbuf.data());
                responses[i].length = (unsigned int)strlen(retbuf.data());
                // Remember the password for background transfers and
                // reconnects. Only an answer to a password prompt: a one-time
                // code kept here would be replayed as the password next time.
                if (passwordPrompt && ConnectSettings && ConnectSettings->account_password.empty()) {
                    ConnectSettings->account_password = retbuf.data();
                    if (ConnectSettings->password.empty())
                        ConnectSettings->password = retbuf.data();
                }
                ShowStatusId(IDS_LOG_SEND_USER_PASS, nullptr, true);
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
        ShowStatusId(IDS_LOG_PPK_ERR_VERSION, nullptr, true);
        break;
    case PpkConvertError::unsupported_algorithm:
        ShowStatusId(IDS_LOG_PPK_ERR_ALGO, nullptr, true);
        break;
    case PpkConvertError::unsupported_encryption:
    case PpkConvertError::unsupported_kdf:
        ShowStatusId(IDS_LOG_PPK_ERR_ENC, nullptr, true);
        break;
    case PpkConvertError::kdf_unavailable:
        ShowStatusId(IDS_LOG_PPK_ERR_ARGON2, nullptr, true);
        break;
    case PpkConvertError::passphrase_required:
    case PpkConvertError::bad_passphrase_or_mac:
        ShowStatusId(IDS_LOG_PPK_ERR_PASSPHRASE, nullptr, true);
        break;
    case PpkConvertError::kdf_limits_exceeded:
        ShowStatusId(IDS_LOG_PPK_ERR_LIMITS, nullptr, true);
        break;
    case PpkConvertError::inconsistent_key:
        ShowStatusId(IDS_LOG_PPK_ERR_INCONSISTENT, nullptr, true);
        break;
    default:
        ShowStatusId(IDS_LOG_PPK_ERR_GENERIC, nullptr, true);
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

bool KeyFileHoldsPrivateKey(const std::string& path, const std::string& user)
{
    if (path.empty())
        return false;
    std::array<char, 1024> expanded{};
    strlcpy(expanded.data(), path.c_str(), expanded.size() - 1);
    ExpandAuthPath(expanded.data(), expanded.size(), user.c_str());

    handle_util::FileHandle hf(CreateFileA(expanded.data(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!hf)
        return false;

    // Every private format the plugin takes says so in its opening line —
    // "...PRIVATE KEY-----" for OpenSSH and PEM, "PuTTY-User-Key-File-" for
    // PPK — and no public one does.
    std::array<char, 512> head{};
    DWORD got = 0;
    if (!ReadFile(hf.get(), head.data(), static_cast<DWORD>(head.size() - 1), &got, nullptr))
        return false;
    const std::string_view text(head.data(), got);
    return text.find("PRIVATE KEY-----") != std::string_view::npos ||
           text.find("PuTTY-User-Key-File-") != std::string_view::npos;
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

static void BuildUserAtServerTitle(char* out, size_t outLen, int prefixResId,
                                   LPCSTR user, LPCSTR host)
{
    if (!out || outLen == 0)
        return;
    out[0] = 0;
    LoadStr(out, outLen, prefixResId);
    strlcat(out, user ? user : "", outLen - 1);
    strlcat(out, "@", outLen - 1);
    strlcat(out, host ? host : "", outLen - 1);
}

// A PuTTY key is decoded into an in-memory PEM; any other key file is left
// for libssh2 to read from disk. When the passphrase already held does not
// open the key, the user is asked once.
static bool PreparePrivateKeyForAuth(
    LPCSTR user,
    LPCSTR host,
    std::string& keyPassphrase,
    LPCSTR privKeyFile,
    SecureChars& outPem,
    char* ioPromptBuf,
    size_t ioPromptBufLen)
{
    outPem.clear();
    if (!privKeyFile || !ioPromptBuf || !EndsWithNoCase(privKeyFile, ".ppk"))
        return true;

    ShowStatusId(IDS_LOG_PPK_CONVERTING, nullptr, true);
    PpkConvertError convErr = ConvertPpkFileToPem(privKeyFile, keyPassphrase.c_str(), outPem);
    AUTH_LOG("PPK conversion result=%d", static_cast<int>(convErr));

    if (convErr == PpkConvertError::passphrase_required || convErr == PpkConvertError::bad_passphrase_or_mac) {
        std::array<char, 250> title{};
        std::array<char, 256> ppkPassBuf{};
        LoadStr(ioPromptBuf, ioPromptBufLen, IDS_KEYPASSPHRASE);
        BuildUserAtServerTitle(title.data(), title.size(), IDS_PASSPHRASE, user, host);
        if (RequestInput(RT_Password, title.data(), ioPromptBuf, ppkPassBuf)) {
            convErr = ConvertPpkFileToPem(privKeyFile, ppkPassBuf.data(), outPem);
            // This prompt is only reached once the passphrase already held
            // failed to open the key, so a conversion that succeeds here
            // replaces it: what opened the key outranks what was assumed.
            if (convErr == PpkConvertError::ok)
                keyPassphrase = ppkPassBuf.data();
        }
        SecureZeroMemory(ppkPassBuf.data(), ppkPassBuf.size());
    }

    if (convErr != PpkConvertError::ok) {
        ShowPpkConversionFailure(convErr);
        return false;
    }
    return true;
}

static bool ValidatePublicKeyFileIfPresent(LPCSTR pubkeyfileptr, DWORD dwShareMode, DWORD dwFlags)
{
    if (!pubkeyfileptr || !pubkeyfileptr[0])
        return true;

    DWORD dataread = 0;
    std::array<char, 1024> filebuf{};
    handle_util::FileHandle hf(CreateFileA(pubkeyfileptr, GENERIC_READ, dwShareMode, nullptr, OPEN_EXISTING, dwFlags, nullptr));
    if (!hf) {
        ShowStatusId(IDS_ERR_LOAD_PUBKEY, pubkeyfileptr, true);
        return false;
    }

    if (ReadFile(hf.get(), filebuf.data(), 35, &dataread, nullptr)) {
        if (_strnicmp(filebuf.data(), "ssh-", 4) != 0 &&
            _strnicmp(filebuf.data(), "ecdsa-", 6) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN OPENSSH PRIVATE KEY-----", 35) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN RSA PRIVATE KEY-----", 31) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN EC PRIVATE KEY-----", 30) != 0)
        {
            ShowStatusId(IDS_ERR_PUBKEY_WRONG_FORMAT, nullptr, true);
            return false;
        }
    }
    return true;
}


int SftpAuthPageantOn(const SshAuthTarget& target, LPCSTR progressbuf, int progress, int* ploop, SYSTICKS* plasttime)
{
    std::array<char, 1024> buf{};
    struct libssh2_agent_publickey * identity = nullptr;
    struct libssh2_agent_publickey * prev_identity = nullptr;

    std::unique_ptr<ISshAgent> agent = target.session->agentInit();
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
        const DWORD len = GetModuleFileName(hinst, dirname.data(), static_cast<DWORD>(dirname.size()));
        if (len == 0 || len >= dirname.size())
            return finish(-IDS_AGENT_CONNECTERROR);
        char* slash = strrchr(dirname.data(), '\\');
        (slash ? slash + 1 : dirname.data())[0] = 0;
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
        agent = target.session->agentInit();
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
        LoadStr(str1, IDS_AGENT_TRYING1);
        LoadStr(str2, IDS_AGENT_TRYING2);
        LoadStr(str3, IDS_AGENT_TRYING3);
        ShowStatus((std::string(str1.data()) + target.user + str2.data() + identity->comment + str3.data()).c_str());
        const SYSTICKS authStart = get_sys_ticks();
        while ((auth = agent->userauth(target.user.c_str(), identity)) == LIBSSH2_ERROR_EAGAIN) {
            if (ProgressLoop(progressbuf, progress, progress + 5, ploop, plasttime))
                return finish(-IDS_AGENT_AUTHFAILED);
            if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
                ShowStatusId(IDS_LOG_PAGEANT_TIMEOUT, nullptr, true);
                return finish(-IDS_AGENT_AUTHFAILED);
            }
            if (target.waitIo) target.waitIo();
        }
        if (auth == 0)
            return finish(0);   /* OK */
        prev_identity = identity;
    }
}

// Bind the agent flow to the target server.
int SftpAuthPageant(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int* ploop, SYSTICKS* plasttime)
{
    SshAuthTarget target;
    target.session  = ConnectSettings->session.get();
    target.host     = ConnectSettings->server;
    target.user     = ConnectSettings->user;
    target.password = &ConnectSettings->account_password;
    target.keyPassphrase = &ConnectSettings->key_passphrase;
    target.waitIo   = [ConnectSettings]() { WaitForSshIo(ConnectSettings); };
    return SftpAuthPageantOn(target, progressbuf, progress, ploop, plasttime);
}

int SftpAuthPubKeyOn(const SshAuthTarget& target, int progress, int* ploop, SYSTICKS* plasttime, int* auth_pw, AuthFailureUi onFailure)
{
    // Both secrets are dereferenced throughout; a caller that leaves either
    // unset fails here instead of faulting further in.
    if (!target.password || !target.keyPassphrase)
        return -IDS_ERR_AUTH_PUBKEY;

    std::array<char, 1024> buf{};
    std::array<char, 256> passphrase{};
    std::array<char, MAX_PATH> pubkeyfile{};
    std::array<char, MAX_PATH> privkeyfile{};
    SecureChars convertedPem; // a decoded PuTTY key, never written to disk
    char* pubkeyfileptr = pubkeyfile.data();
    auto clearPassphrase = [&]() {
        SecureZeroMemory(passphrase.data(), passphrase.size());
    };

    AUTH_LOG("=== SftpAuthPubKey START (host=%s) ===", target.host.c_str());
    // Check if LogProc is available
    extern tLogProc LogProc;
    if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== SftpAuthPubKey ===");
    AUTH_LOG("privkeyfile=%s", target.privkeyfile.c_str());
    AUTH_LOG("pubkeyfile=%s", target.pubkeyfile.c_str());
    AUTH_LOG("password_empty=%d", target.password->empty() ? 1 : 0);
    AUTH_LOG("host=%s", target.host.c_str());
    AUTH_LOG("user=%s", target.user.c_str());

    strlcpy(pubkeyfile.data(), target.pubkeyfile.c_str(), pubkeyfile.size()-1);
    ExpandAuthPath(pubkeyfile.data(), pubkeyfile.size(), target.user.c_str());
    strlcpy(privkeyfile.data(), target.privkeyfile.c_str(), privkeyfile.size()-1);
    ExpandAuthPath(privkeyfile.data(), privkeyfile.size(), target.user.c_str());

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

    if (!PreparePrivateKeyForAuth(target.user.c_str(), target.host.c_str(), *target.keyPassphrase,
                                  privkeyfile.data(), convertedPem, buf.data(), buf.size())) {
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }
    const bool fromMemory = !convertedPem.empty();
    // A .ppk carries its public key; the field may then be left as it is.
    if (fromMemory)
        pubkeyfileptr = nullptr;

    passphrase[0] = 0;
    // verify that we have a valid public key file (optional when private key is enough)
    DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
    if (!ValidatePublicKeyFileIfPresent(pubkeyfileptr, dwShareMode, dwFlags))
    {
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    // A decoded PuTTY key is an unencrypted PEM; any other key file is
    // inspected so an unencrypted one never triggers a passphrase prompt.
    bool isencrypted = false;
    if (!fromMemory && !DetectPrivateKeyEncrypted(privkeyfile.data(), &isencrypted)) {
        ShowStatusId(IDS_ERR_LOAD_PRIVKEY, privkeyfile.data(), true);
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    const std::string encStatus = std::format("Key: {}", isencrypted ? "encrypted" : "unencrypted");
    AUTH_LOG("Encryption check result: %s", encStatus.c_str());
    ShowStatus(encStatus.c_str());
    if (isencrypted) {
        AUTH_LOG("Key is encrypted, requesting passphrase");
        std::array<char, 250> title{};
        BuildUserAtServerTitle(title.data(), title.size(), IDS_PASSPHRASE, target.user.c_str(), target.host.c_str());
        LoadStr(buf, IDS_KEYPASSPHRASE);
        if (!target.keyPassphrase->empty()) {
            AUTH_LOG("Using stored passphrase");
            strlcpy(passphrase.data(), target.keyPassphrase->c_str(), passphrase.size()-1);
        } else {
            AUTH_LOG("No stored passphrase, requesting from user");
            RequestInput(RT_Password, title.data(), buf.data(), passphrase);
        }
    } else {
        AUTH_LOG("Key is NOT encrypted, no passphrase needed");
    }

    ShowStatusId(IDS_AUTH_PUBKEY_FOR, target.user.c_str(), true);

    // libssh2's userauth_publickey_fromfile treats a non-NULL publickey arg as
    // a path to read; an empty string makes it call fopen("") and bail with
    // LIBSSH2_ERROR_FILE. We must hand it NULL when the user left the field
    // blank (so OpenSSL backend derives the public key from the private one)
    // or pointed both fields at the same file.
    if (pubkeyfileptr && (pubkeyfile.data()[0] == 0 ||
                          _stricmp(pubkeyfile.data(), privkeyfile.data()) == 0))
        pubkeyfileptr = nullptr;

    LoadStr(buf, IDS_AUTH_PUBKEY);
    int auth;
    const char* passphrasePtr = isencrypted ? passphrase.data() : nullptr;
    AUTH_LOG("Public key auth: priv=%s%s pub=%s passphrase=%s",
             privkeyfile.data(), fromMemory ? " (decoded in memory)" : "",
             pubkeyfileptr ? pubkeyfileptr : "(null)",
             passphrasePtr ? "(set)" : "(null)");
    auto attempt = [&]() {
        const unsigned userLen = static_cast<unsigned>(target.user.size());
        return fromMemory
            ? target.session->userauthPubkeyFromMemory(target.user.c_str(), userLen,
                                                       convertedPem.data(), convertedPem.size(), nullptr)
            : target.session->userauthPubkeyFromFile(target.user.c_str(), userLen,
                                                     pubkeyfileptr, privkeyfile.data(), passphrasePtr);
    };
    SYSTICKS authStart = get_sys_ticks();
    while ((auth = attempt()) == LIBSSH2_ERROR_EAGAIN) {
        if (ProgressLoop(buf.data(), progress, progress + 10, ploop, plasttime))
            break;
        if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
            ShowStatusId(IDS_LOG_PUBKEY_TIMEOUT, nullptr, true);
            auth = LIBSSH2_ERROR_TIMEOUT;
            break;
        }
        if (target.waitIo) target.waitIo();
    }
    AUTH_LOG("Public key auth result=%d", auth);
    if (auth) {
        char* errMsg = nullptr;
        int errLen = 0;
        target.session->lastError(&errMsg, &errLen, false);
        SftpLogLastError("libssh2_userauth_publickey_fromfile: ", auth);
        std::array<char, 1024> loadedMsg{};
        LoadStr(loadedMsg, IDS_ERR_AUTH_PUBKEY);
        std::string uiMsg;
        if (loadedMsg[0] == 0 || _stricmp(loadedMsg.data(), "Error:") == 0 || strstr(loadedMsg.data(), "%s"))
            uiMsg = "Error: Authentication by client certificate failed!";
        else
            uiMsg = loadedMsg.data();
        if (errMsg && errMsg[0])
            uiMsg += "\n" + std::string(errMsg);
        // Stay quiet when the caller still has methods to try, or when it
        // asked to report failures without a dialog.
        const bool hasFallbackAuth =
            auth_pw && ((*auth_pw & SSH_AUTH_PASSWORD) != 0 || (*auth_pw & SSH_AUTH_KEYBOARD) != 0);
        if (onFailure == AuthFailureUi::StatusOnly || hasFallbackAuth) {
            ShowStatus(uiMsg.c_str());
        } else {
            ShowError(uiMsg.c_str());
        }
        AUTH_LOG("SftpAuthPubKey returning -IDS_ERR_AUTH_PUBKEY");
        clearPassphrase();
        return -IDS_ERR_AUTH_PUBKEY;
    }
    // The key opened with this passphrase, so keep it whatever was there
    // before — a guess drawn from an unlabelled password field would
    // otherwise be re-tried, and fail, on every reconnect.
    if (auth == 0 && isencrypted && passphrase[0])
        *target.keyPassphrase = passphrase.data();
    clearPassphrase();
    AUTH_LOG("SftpAuthPubKey returning 0 (SUCCESS)");
    return 0;
}

// Bind the public-key flow to the target server. A failure here is a dead
// end for key auth, so it may raise a dialog — unlike a jump host, which
// still has password and keyboard-interactive left to try.
int SftpAuthPubKey(pConnectSettings ConnectSettings, int progress, int* ploop, SYSTICKS* plasttime, int* auth_pw)
{
    SshAuthTarget target;
    target.session     = ConnectSettings->session.get();
    target.host        = ConnectSettings->server;
    target.user        = ConnectSettings->user;
    target.password    = &ConnectSettings->account_password;
    target.keyPassphrase = &ConnectSettings->key_passphrase;
    target.pubkeyfile  = ConnectSettings->pubkeyfile;
    target.privkeyfile = ConnectSettings->privkeyfile;
    target.waitIo      = [ConnectSettings]() { WaitForSshIo(ConnectSettings); };
    return SftpAuthPubKeyOn(target, progress, ploop, plasttime,
                            auth_pw, AuthFailureUi::Modal);
}

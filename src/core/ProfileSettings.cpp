#include "global.h"
#include <windows.h>
#include <array>
#include <format>
#include "SftpClient.h"
#include "SftpInternal.h"
#include "ConnectionDialog.h"
#include "ProfileSettings.h"

bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName)
{
    if (proxynr > 0) {
        const std::string proxyentry = proxynr > 1 ? std::format("proxy{}", proxynr) : "proxy";
        ConnectResults->proxytype = sftp::Proxy::notused;
        int type = GetPrivateProfileInt(proxyentry.data(), "proxytype", -1, iniFileName);
        if (type >= 0)
            ConnectResults->proxytype = (sftp::Proxy)type;
        std::array<char, MAX_PATH> proxyServer{};
        std::array<char, MAX_PATH> proxyUser{};
        GetPrivateProfileString(proxyentry.data(), "proxyserver", "", proxyServer.data(), proxyServer.size() - 1, iniFileName);
        GetPrivateProfileString(proxyentry.data(), "proxyuser", "", proxyUser.data(), proxyUser.size() - 1, iniFileName);
        ConnectResults->proxyserver = proxyServer.data();
        ConnectResults->proxyuser = proxyUser.data();
        std::array<char, MAX_PATH> szPassword{};
        if (GetPrivateProfileString(proxyentry.data(), "proxypassword", "", szPassword.data(), szPassword.size(), iniFileName)) {
            std::array<char, MAX_PATH> decPassword{};
            DecryptString(szPassword.data(), decPassword.data(), static_cast<UINT>(decPassword.size()));
            ConnectResults->proxypassword = decPassword.data();
        } else
            ConnectResults->proxypassword.clear();
        return (type != -1 || proxynr == 1);
    } else {
        ConnectResults->proxytype = sftp::Proxy::notused;
        ConnectResults->proxyserver.clear();
        ConnectResults->proxyuser.clear();
        ConnectResults->proxypassword.clear();
        return false;
    }
}

bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults, LPCSTR iniFileName)
{
    std::array<char, MAX_PATH> szPassword{};
    std::array<char, 6> modbuf{};
    ConnectResults->DisplayName = DisplayName ? DisplayName : "";
    ConnectResults->IniFileName = iniFileName ? iniFileName : "";
    std::array<char, MAX_PATH> serverBuf{};
    GetPrivateProfileString(DisplayName, "server", "", serverBuf.data(), serverBuf.size() - 1, iniFileName);
    ConnectResults->server = serverBuf.data();
    ConnectResults->protocoltype=GetPrivateProfileInt(DisplayName, "protocol", 0, iniFileName);
    ConnectResults->transfermode = GetPrivateProfileInt(DisplayName, "transfermode", 0, iniFileName);
    if (ConnectResults->transfermode < 0 || ConnectResults->transfermode > 3)
        ConnectResults->transfermode = 0;
    std::array<char, MAX_PATH> userBuf{};
    std::array<char, MAX_PATH> fingerprintBuf{};
    std::array<char, MAX_PATH> pubKeyBuf{};
    std::array<char, MAX_PATH> privKeyBuf{};
    GetPrivateProfileString(DisplayName, "user", "", userBuf.data(), userBuf.size() - 1, iniFileName);
    GetPrivateProfileString(DisplayName, "fingerprint", "", fingerprintBuf.data(), fingerprintBuf.size() - 1, iniFileName);
    GetPrivateProfileString(DisplayName, "pubkeyfile", "", pubKeyBuf.data(), pubKeyBuf.size() - 1, iniFileName);
    GetPrivateProfileString(DisplayName, "privkeyfile", "", privKeyBuf.data(), privKeyBuf.size() - 1, iniFileName);
    ConnectResults->user = userBuf.data();
    ConnectResults->savedfingerprint = fingerprintBuf.data();
    ConnectResults->pubkeyfile = pubKeyBuf.data();
    ConnectResults->privkeyfile = privKeyBuf.data();
    ConnectResults->useagent = GetPrivateProfileInt(DisplayName, "useagent", 0, iniFileName) != 0;

    GetPrivateProfileString(DisplayName, "filemod", "644", modbuf.data(), modbuf.size() - 1, iniFileName);
    ConnectResults->filemod = strtol(modbuf.data(), nullptr, 8);
    GetPrivateProfileString(DisplayName, "dirmod", "755", modbuf.data(), modbuf.size() - 1, iniFileName);
    ConnectResults->dirmod = strtol(modbuf.data(), nullptr, 8);

    ConnectResults->compressed = GetPrivateProfileInt(DisplayName, "compression", 0, iniFileName) != 0;
    ConnectResults->scpfordata = GetPrivateProfileInt(DisplayName, "scpfordata", 0, iniFileName) != 0;
    ConnectResults->scponly = GetPrivateProfileInt(DisplayName, "scponly", 0, iniFileName) != 0;
    if (ConnectResults->scponly)
        ConnectResults->scpfordata = true;
    ConnectResults->shell_transfer_dd = GetPrivateProfileInt(DisplayName, "shelltransfer", 0, iniFileName) != 0;
    ConnectResults->shell_transfer_force =
        GetPrivateProfileInt(DisplayName, "shelltransferforce",
                             ConnectResults->shell_transfer_dd ? 1 : 0,
                             iniFileName) != 0;
    ConnectResults->shell_dd_b64only  = false;
    ConnectResults->php_http_mode = GetPrivateProfileInt(DisplayName, "phphttpmode", 0, iniFileName);
    if (ConnectResults->php_http_mode < 0 || ConnectResults->php_http_mode > 2)
        ConnectResults->php_http_mode = 0;
    ConnectResults->php_chunk_mib = GetPrivateProfileInt(DisplayName, "phpchunkmb", 0, iniFileName);
    if (!(ConnectResults->php_chunk_mib == 0 || ConnectResults->php_chunk_mib == 1 ||
          ConnectResults->php_chunk_mib == 2 || ConnectResults->php_chunk_mib == 4 ||
          ConnectResults->php_chunk_mib == 8 || ConnectResults->php_chunk_mib == 16 ||
          ConnectResults->php_chunk_mib == 32 || ConnectResults->php_chunk_mib == 64))
        ConnectResults->php_chunk_mib = 0;
    ConnectResults->php_recommended_chunk_mib = 0;
    ConnectResults->lan_pair_role = GetPrivateProfileInt(DisplayName, "lanpairrole", 0, iniFileName);
    if (ConnectResults->lan_pair_role < 0 || ConnectResults->lan_pair_role > 2)
        ConnectResults->lan_pair_role = 0;
    std::array<char, MAX_PATH> lanPeerBuf{};
    GetPrivateProfileString(DisplayName, "lanpairpeer", "", lanPeerBuf.data(), lanPeerBuf.size() - 1, iniFileName);
    ConnectResults->lan_pair_peer = lanPeerBuf.data();
    ConnectResults->lan_pair_timeout_min = GetPrivateProfileInt(DisplayName, "lanpairtimeout", 0, iniFileName);
    if (ConnectResults->lan_pair_timeout_min < 0)
        ConnectResults->lan_pair_timeout_min = 0;
    ConnectResults->trycustomlistcommand = 2;

    ConnectResults->detailedlog = GetPrivateProfileInt(DisplayName, "detailedlog", 0, iniFileName) != 0;
    ConnectResults->utf8names = GetPrivateProfileInt(DisplayName, "utf8", -1, iniFileName);
    ConnectResults->codepage = GetPrivateProfileInt(DisplayName, "codepage", 0, iniFileName);
    ConnectResults->unixlinebreaks = GetPrivateProfileInt(DisplayName, "unixlinebreaks", -1, iniFileName);
    ConnectResults->scpserver64bit = GetPrivateProfileInt(DisplayName, "largefilesupport", -1, iniFileName);
    ConnectResults->password.clear();
    if (GetPrivateProfileString(DisplayName, "password", "",  szPassword.data(),  szPassword.size(),  iniFileName)) {
        if (!ConnectResults->useagent) {
            std::array<char, MAX_PATH> decPassword{};
            DecryptString(szPassword.data(), decPassword.data(), static_cast<UINT>(decPassword.size()));
            ConnectResults->password = decPassword.data();
        }
        else if (strcmp(szPassword.data(), "!") == 0)
            ConnectResults->password = "\001";
    }
    ConnectResults->proxynr = GetPrivateProfileInt(DisplayName, "proxynr", 0, iniFileName);

    LoadProxySettingsFromNr(ConnectResults->proxynr, ConnectResults, iniFileName);

    // -----------------------------------------------------------------------
    // Jump host (ProxyJump) settings
    // -----------------------------------------------------------------------
    ConnectResults->use_jump_host = GetPrivateProfileInt(DisplayName, "usejumphost", 0, iniFileName) != 0;
    {
        std::array<char, MAX_PATH> jumpHost{};
        std::array<char, MAX_PATH> jumpUser{};
        std::array<char, MAX_PATH> jumpPub{};
        std::array<char, MAX_PATH> jumpPriv{};
        std::array<char, MAX_PATH> jumpFp{};
        GetPrivateProfileString(DisplayName, "jumphost",       "", jumpHost.data(),  jumpHost.size() - 1,  iniFileName);
        GetPrivateProfileString(DisplayName, "jumpuser",       "", jumpUser.data(),  jumpUser.size() - 1,  iniFileName);
        GetPrivateProfileString(DisplayName, "jumppubkeyfile", "", jumpPub.data(),   jumpPub.size() - 1,   iniFileName);
        GetPrivateProfileString(DisplayName, "jumpprivkeyfile","", jumpPriv.data(),  jumpPriv.size() - 1,  iniFileName);
        GetPrivateProfileString(DisplayName, "jumpfingerprint","", jumpFp.data(),    jumpFp.size() - 1,    iniFileName);
        ConnectResults->jump_host        = jumpHost.data();
        ConnectResults->jump_user        = jumpUser.data();
        ConnectResults->jump_pubkeyfile  = jumpPub.data();
        ConnectResults->jump_privkeyfile = jumpPriv.data();
        ConnectResults->jump_fingerprint = jumpFp.data();
        ConnectResults->jump_port        = static_cast<unsigned short>(
            GetPrivateProfileInt(DisplayName, "jumpport", 22, iniFileName));
        ConnectResults->jump_useagent    = GetPrivateProfileInt(DisplayName, "jumpuseagent", 0, iniFileName) != 0;

        std::array<char, MAX_PATH> jumpPass{};
        if (GetPrivateProfileString(DisplayName, "jumppassword", "", jumpPass.data(), jumpPass.size(), iniFileName)) {
            std::array<char, MAX_PATH> decJumpPass{};
            DecryptString(jumpPass.data(), decJumpPass.data(), static_cast<UINT>(decJumpPass.size()));
            ConnectResults->jump_password = decJumpPass.data();
        } else {
            ConnectResults->jump_password.clear();
        }
    }

    ConnectResults->neednewchannel = false;
    std::array<char, MAX_PATH> sendCommandBuf{};
    GetPrivateProfileString(DisplayName, "sendcommand", "", sendCommandBuf.data(), sendCommandBuf.size() - 1, iniFileName);
    ConnectResults->connectsendcommand = sendCommandBuf.data();
    ConnectResults->sendcommandmode = GetPrivateProfileInt(DisplayName, "sendcommandmode", 0, iniFileName);
    return !ConnectResults->server.empty();
}

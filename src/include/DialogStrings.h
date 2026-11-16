#pragma once

#include <windows.h>
#include "../res/resource.h"

// The string every localised control of the plugin's dialogs shows. Shared by
// the dialogs and by the layout test, which renders each dialog in every
// language from exactly these tables.
struct DialogString {
    int control;
    UINT string;
};

inline constexpr UINT kConnectionDialogCaption = IDS_DLG_CAPTION;
inline constexpr DialogString kConnectionDialogStrings[] = {
    {IDC_LABEL_CONNECTTO,      IDS_DLG_CONNECTTO},
    {IDC_PROTOAUTO,            IDS_DLG_PROTO_AUTO},
    {IDC_LABEL_USERNAME,       IDS_DLG_USERNAME},
    {IDC_PASSLABEL,            IDS_JUMP_DLG_PASS},
    {IDC_USEAGENT,             IDS_DLG_USEAGENT},
    {IDC_EDITPASS,             IDS_DLG_CHANGEPASS},
    {IDC_CRYPTPASS,            IDS_DLG_CRYPTPASS},
    {IDC_LABEL_CERTGROUP,      IDS_DLG_CERTGROUP},
    {IDC_STATICPUB,            IDS_DLG_PUBKEY},
    {IDC_STATICPEM,            IDS_DLG_PRIVKEY},
    {IDC_COMPRESS,             IDS_DLG_COMPRESS},
    {IDC_DETAILED_LOG,         IDS_DLG_DETAILED_LOG},
    {IDC_SHELLTRANSFER,        IDS_DLG_SHELLTRANSFER},
    {IDC_SCP_DATA,             IDS_DLG_SCP_DATA},
    {IDC_SCP_ALL,              IDS_DLG_SCP_ALL},
    {IDC_LABEL_TRANSFER,       IDS_DLG_TRANSFER},
    {IDC_SYSTEMLABEL,          IDS_DLG_SYSTEM},
    {IDC_CODEPAGELABEL,        IDS_DLG_ENCODING},
    {IDC_PERMISSIONS_GROUP,    IDS_DLG_PERMISSIONS_GROUP},
    {IDC_LANPAIR_GROUP,        IDS_DLG_LANPAIR_GROUP},
    {IDC_LAN_TIMEOUT_LABEL,    IDS_DLG_LAN_TIMEOUT},
    {IDC_LAN_TIMEOUT_HINT,     IDS_DLG_LAN_TIMEOUT_HINT},
    {IDC_FILEMOD_LABEL,        IDS_DLG_FILEMOD},
    {IDC_DIRMOD_LABEL,         IDS_DLG_DIRMOD},
    {IDC_LABEL_SESSION,        IDS_DLG_SESSION},
    {IDC_PHPSHELL,             IDS_BUTTON_SHELL},
    {IDC_LABEL_JUMPHOST_GRP,   IDS_DLG_JUMPHOST_GRP},
    {IDC_JUMP_ENABLE,          IDS_DLG_USE_JUMPHOST},
    {IDC_JUMP_BUTTON,          IDS_DLG_JUMP_BUTTON},
    {IDC_LABEL_PROXY_SETTINGS, IDS_DLG_PROXY_SETTINGS},
    {IDC_PHP_TAR,              IDS_DLG_PHP_TAR},
    {IDC_LAN_TI,               IDS_LAN_TI},
    {IDC_PLUGINHELP,           IDS_BTN_HELP},
    {IDOK,                     IDS_BTN_OK},
    {IDCANCEL,                 IDS_BTN_CANCEL},
};

inline constexpr UINT kJumpHostDialogCaption = IDS_JUMP_DLG_CAPTION;
inline constexpr DialogString kJumpHostDialogStrings[] = {
    {IDC_JUMP_GROUP,         IDS_JUMP_DLG_GROUP},
    {IDC_JUMP_LABEL_HOST,    IDS_JUMP_DLG_HOST},
    {IDC_JUMP_LABEL_PORT,    IDS_JUMP_DLG_PORT},
    {IDC_JUMP_LABEL_USER,    IDS_JUMP_DLG_USER},
    {IDC_JUMP_LABEL_PASS,    IDS_JUMP_DLG_PASS},
    {IDC_JUMP_LABEL_PUBKEY,  IDS_JUMP_DLG_PUBKEY},
    {IDC_JUMP_LABEL_PRIVKEY, IDS_JUMP_DLG_PRIVKEY},
    {IDC_JUMP_USEAGENT,      IDS_JUMP_DLG_USEAGENT},
    {IDC_JUMP_CRYPTPASS,     IDS_DLG_CRYPTPASS},
    {IDC_JUMP_EDITPASS,      IDS_DLG_CHANGEPASS},
    {IDOK,                   IDS_BTN_OK},
    {IDCANCEL,               IDS_BTN_CANCEL},
};

inline constexpr UINT kProxyDialogCaption = IDS_PROXY_DLG_CAPTION;
inline constexpr DialogString kProxyDialogStrings[] = {
    {IDC_PROXY_GROUP,      IDS_PROXY_DLG_GROUP},
    {IDC_NOPROXY,          IDS_PROXY_DLG_NOPROXY},
    {IDC_OTHERPROXY,       IDS_PROXY_DLG_HTTP},
    {IDC_SOCKS4APROXY,     IDS_PROXY_DLG_SOCKS4A},
    {IDC_SOCKS5PROXY,      IDS_PROXY_DLG_SOCKS5},
    {IDC_PROXY_LABEL_HOST, IDS_PROXY_DLG_HOST},
    {IDC_PROXY_LABEL_USER, IDS_PROXY_DLG_USER},
    {IDC_PROXY_LABEL_PASS, IDS_PROXY_DLG_PASS},
    {IDC_CRYPTPASS,        IDS_DLG_CRYPTPASS},
    {IDC_EDITPASS,         IDS_DLG_CHANGEPASS},
    {IDOK,                 IDS_BTN_OK},
    {IDCANCEL,             IDS_BTN_CANCEL},
};

inline constexpr UINT kPropertiesDialogCaption = IDS_PROP_CAPTION;
inline constexpr DialogString kPropertiesDialogStrings[] = {
    {IDC_PROP_GRP_FILE,     IDS_PROP_GRP_FILE},
    {IDC_PROP_LBL_NAME,     IDS_PROP_LBL_NAME},
    {IDC_PROP_LBL_OWNER,    IDS_PROP_LBL_OWNER},
    {IDC_PROP_LBL_GROUP,    IDS_PROP_LBL_GROUP},
    {IDC_PROP_LBL_PERMS,    IDS_PROP_LBL_PERMS},
    {IDC_PROP_LBL_SIZE,     IDS_PROP_LBL_SIZE},
    {IDC_PROP_LBL_MODIFIED, IDS_PROP_LBL_MODIFIED},
    {IDC_PROP_GRP_RAW,      IDS_PROP_GRP_RAW},
};

inline constexpr UINT kDownloadErrorDialogCaption = IDS_DOWNLOAD_ERROR_TITLE;
inline constexpr DialogString kDownloadErrorDialogStrings[] = {
    {IDC_DOWNLOAD_ERROR_TEXT, IDS_DOWNLOAD_ERROR_TEXT},
    {IDC_DOWNLOAD_SKIP,       IDS_DOWNLOAD_SKIP},
    {IDC_DOWNLOAD_SKIP_ALL,   IDS_DOWNLOAD_SKIP_ALL},
    {IDCANCEL,                IDS_BTN_CANCEL},
};

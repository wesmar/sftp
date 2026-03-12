// ConnectionDialogClass.cpp - Modern C++20 refactored connection dialog
// Refactored from ConnectionDialog.cpp to use class-based structure

#include "global.h"
#include <windows.h>
#include <commdlg.h>
#include <array>
#include <string>
#include <vector>
#include <algorithm>
#include <format>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "UnicodeHelpers.h"
#include "SftpInternal.h"
#include "WindowsUserFeedback.h"
#include "PhpAgentClient.h"
#include "PhpShellConsole.h"
#include "ConnectionDialog.h"
#include "LanPair.h"
#include "JumpHostConnection.h"

// Forward declarations from original file
extern bool serverfieldchangedbyuser;
extern HINSTANCE hinst;
extern int PluginNumber;
extern tLogProcW LogProcW;

struct ConnectDialogContext;

// ============================================================================
// ConnectionDialog class implementation
// ============================================================================

ConnectionDialog::ConnectionDialog(HWND hWnd, ConnectDialogContext* ctx)
    : m_hWnd(hWnd)
    , m_ctx(ctx)
    , m_settings(ctx ? ctx->connectResults : nullptr)
    , m_initialized(false)
{
}

ConnectionDialog::~ConnectionDialog()
{
    // Cleanup handled by ConnectDialogContext destructor
}

INT_PTR ConnectionDialog::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG:
        return OnInitDialog(lParam);
    case WM_SHOWWINDOW:
        return OnShowWindow(LOWORD(wParam));
    case WM_COMMAND:
        return OnCommand(wParam, lParam);
    case WM_APP_LAN_PEER:
        return OnLanPeerMessage(wParam, lParam);
    case WM_DESTROY:
        OnDestroy();
        return 0;
    }
    return 0;
}

INT_PTR ConnectionDialog::OnInitDialog(LPARAM lParam)
{
    // Delegate to existing initialization logic for now
    // This will be refactored incrementally
    return OnConnectDlgInit(m_hWnd, lParam);
}

INT_PTR ConnectionDialog::OnShowWindow(BOOL fShow)
{
    UNREFERENCED_PARAMETER(fShow);
    if (m_ctx && m_ctx->focusset)
        SetFocus(GetDlgItem(m_hWnd, m_ctx->focusset));
    return 0;
}

INT_PTR ConnectionDialog::OnCommand(WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    
    switch (LOWORD(wParam)) {
    case IDOK:
        OnOk();
        return 1;
    case IDCANCEL:
        OnCancel();
        return 1;
    case IDC_SESSIONCOMBO:
        if (HIWORD(wParam) == CBN_SELCHANGE || HIWORD(wParam) == CBN_CLOSEUP)
            OnSessionChanged();
        break;
    case IDC_TRANSFERMODE:
        if (HIWORD(wParam) == CBN_SELCHANGE)
            OnTransferModeChanged();
        break;
    case IDC_PHPSHELL:
        OnPhpShellBtn();
        break;
    case IDC_LOADPUBKEY:
    case IDC_LOADPRIVKEY:
        OnBrowseKeyFile(LOWORD(wParam) == IDC_LOADPUBKEY);
        break;
    case IDC_PRIVKEY:
        if (HIWORD(wParam) == EN_CHANGE)
            OnPrivateKeyChanged();
        break;
    case IDC_USEAGENT:
        OnUseAgentChanged();
        break;
    case IDC_JUMP_ENABLE:
        OnJumpEnableChanged();
        break;
    case IDC_JUMP_BUTTON:
        OnJumpButton();
        break;
    case IDC_PROXYBUTTON:
        OnProxyButton();
        break;
    case IDC_PROXYCOMBO:
        if (HIWORD(wParam) == CBN_SELCHANGE)
            OnProxyComboChanged();
        break;
    case IDC_DELETELAST:
        OnDeleteLastProxy();
        break;
    case IDC_IMPORTSESSIONS:
        OnImportSessions();
        break;
    case IDC_PLUGINHELP:
        OnPluginHelp();
        break;
    case IDC_CERTHELP:
    case IDC_CERTHELPPRIV:
        OnCertHelp();
        break;
    case IDC_PASSWORDHELP:
        OnPasswordHelp();
        break;
    case IDC_UTF8HELP:
        OnUtf8Help();
        break;
    case IDC_EDITPASS:
        OnEditPass();
        break;
    case IDC_CONNECTTO:
        if (HIWORD(wParam) == EN_CHANGE)
            OnConnectToChanged();
        break;
    }
    return 0;
}

void ConnectionDialog::OnDestroy()
{
    StopLanPairing(m_ctx);
}

INT_PTR ConnectionDialog::OnLanPeerMessage(WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(wParam);
    auto* ann = reinterpret_cast<smb::PeerAnnouncement*>(lParam);
    if (m_ctx && ann) {
        const bool peerWasNew = m_ctx->lanPeers.find(ann->peerId) == m_ctx->lanPeers.end();
        const std::string newPeerId = ann->peerId;
        m_ctx->lanPeers[ann->peerId] = *ann;
        delete ann;
        
        const int transferMode = (int)SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_GETCURSEL, 0, 0);
        if (transferMode == static_cast<int>(sftp::TransferMode::smb_lan)) {
            const BOOL dropped = (BOOL)SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_GETDROPPEDSTATE, 0, 0);
            if (!dropped) {
                RefreshLanPeerCombo(m_hWnd, m_ctx, m_settings ? m_settings->lan_pair_peer : std::string{});
            }
            
            const int roleSel = (int)SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0);
            if (peerWasNew && roleSel == 0 && !m_ctx->lanRolePromptShown) {
                m_ctx->lanRolePromptShown = true;
                const std::wstring titleW = LoadResStringW(IDS_LAN_TITLE);
                const std::wstring msgW = LoadResStringW(IDS_LAN_ROLE_PROMPT);
                const int choice = MessageBoxW(
                    m_hWnd,
                    msgW.empty() ? L"Znaleziono peera LAN Pair.\nWybierz rolę:\n\nTak = Dawca\nNie = Biorca\nAnuluj = bez zmian" : msgW.c_str(),
                    titleW.empty() ? L"LAN Pair" : titleW.c_str(),
                    MB_ICONQUESTION | MB_YESNOCANCEL | MB_DEFBUTTON1);
                if (choice == IDYES || choice == IDNO) {
                    const int newRole = (choice == IDYES) ? 2 : 1;
                    SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_SETCURSEL, newRole, 0);
                    if (choice == IDYES) {
                        for (size_t i = 0; i < m_ctx->lanPeerOrder.size(); ++i) {
                            if (m_ctx->lanPeerOrder[i] == newPeerId) {
                                SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_SETCURSEL, static_cast<WPARAM>(i + 1), 0);
                                break;
                            }
                        }
                    }
                    HandleLanPairAction(m_hWnd, m_ctx, m_settings);
                }
                m_ctx->lanRolePromptShown = false;
            }
        }
        return 1;
    }
    delete ann;
    return 1;
}

void ConnectionDialog::OnOk()
{
    StopLanPairing(m_ctx);
    OnConnectDlgOk(m_hWnd, m_ctx);
}

void ConnectionDialog::OnCancel()
{
    StopLanPairing(m_ctx);
    EndDialog(m_hWnd, IDCANCEL);
}

void ConnectionDialog::OnSessionChanged()
{
    std::array<char, wdirtypemax> sessionName{};
    GetDlgItemText(m_hWnd, IDC_SESSIONCOMBO, sessionName.data(), sessionName.size() - 1);
    TrimSessionName(sessionName.data());
    
    if (sessionName[0] && _stricmp(sessionName.data(), s_quickconnect) != 0) {
        tConnectSettings loaded{};
        if (LoadServerSettings(sessionName.data(), &loaded, m_ctx->iniFileName))
            ApplyLoadedSessionToDialog(m_hWnd, &loaded, m_ctx->iniFileName);
    }
}

void ConnectionDialog::OnTransferModeChanged()
{
    if (m_ctx) {
        if (m_ctx->lastTransferMode == static_cast<int>(sftp::TransferMode::ssh_auto)) {
            m_settings->unixlinebreaks = (char)SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0) - 1;
            const int encSel = (int)SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0);
            if (encSel == 0)
                m_settings->utf8names = -1;
            else if (encSel == 1)
                m_settings->utf8names = 1;
            else if (encSel >= 0 && encSel < kCodepageListCount) {
                m_settings->utf8names = 0;
                const int cp = codepagelist[encSel];
                if (cp > 0)
                    m_settings->codepage = cp;
            }
        } else if (m_ctx->lastTransferMode == static_cast<int>(sftp::TransferMode::php_agent) ||
                   m_ctx->lastTransferMode == static_cast<int>(sftp::TransferMode::php_shell)) {
            m_settings->php_http_mode = (int)SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0);
            if (m_settings->php_http_mode < 0 || m_settings->php_http_mode > 2)
                m_settings->php_http_mode = 0;
            m_settings->php_chunk_mib = PhpChunkComboIndexToValue(
                (int)SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0));
        } else if (m_ctx->lastTransferMode == static_cast<int>(sftp::TransferMode::smb_lan)) {
            m_settings->lan_pair_role = LanRoleComboToValue(
                (int)SendDlgItemMessage(m_hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0));
            const int peerIdx = (int)SendDlgItemMessage(m_hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0);
            if (peerIdx > 0 && peerIdx <= (int)m_ctx->lanPeerOrder.size()) {
                m_settings->lan_pair_peer = m_ctx->lanPeerOrder[peerIdx - 1];
            } else {
                m_settings->lan_pair_peer.clear();
            }
            m_settings->lan_pair_timeout_min = ReadLanTimeoutMinutes(m_hWnd);
        }
    }
    RebuildSystemAndEncodingCombos(m_hWnd, m_ctx, m_settings);
    if (m_ctx)
        m_ctx->lastTransferMode = (int)SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_GETCURSEL, 0, 0);
    UpdateScpOnlyDependentControls(m_hWnd);
}

void ConnectionDialog::OnPhpShellBtn()
{
    int transferMode = (int)SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_GETCURSEL, 0, 0);
    if (transferMode == static_cast<int>(sftp::TransferMode::smb_lan)) {
        HandleLanPairAction(m_hWnd, m_ctx, m_settings);
        return;
    }
    if (transferMode == static_cast<int>(sftp::TransferMode::php_agent)) {
        SendDlgItemMessage(m_hWnd, IDC_TRANSFERMODE, CB_SETCURSEL, (WPARAM)static_cast<int>(sftp::TransferMode::php_shell), 0);
        UpdateScpOnlyDependentControls(m_hWnd);
        transferMode = static_cast<int>(sftp::TransferMode::php_shell);
    }
    if (transferMode != static_cast<int>(sftp::TransferMode::php_shell)) {
        WindowsUserFeedback tempFeedback(m_hWnd);
        tempFeedback.ShowMessage("Select Transfer = PHP Shell (HTTP).", "PHP Shell");
        return;
    }
    tConnectSettings shellSettings{};
    shellSettings.sock = INVALID_SOCKET;
    GetDlgItemText(m_hWnd, IDC_CONNECTTO, shellSettings.server);
    GetDlgItemText(m_hWnd, IDC_USERNAME, shellSettings.user);
    GetDlgItemText(m_hWnd, IDC_PASSWORD, shellSettings.password);
    std::string authError;
    if (PhpAgentValidateAuth(&shellSettings, authError) != SFTP_OK) {
        std::string localPhpPath;
        std::string pluginDir;
        if (GetPluginDirectoryA(pluginDir)) {
            localPhpPath = pluginDir;
            localPhpPath += "\\sftp.php";
        }
        std::string msg = authError.empty() ? "Wrong credentials for PHP Agent." : authError;
        if (!localPhpPath.empty()) {
            msg += "\n\nPlease copy your plugin script from:\n";
            msg += localPhpPath;
            msg += "\nand upload it to your server URL path.";
        } else {
            msg += "\n\nPlease check URL syntax, file name, and sftp.php deployment path on server.";
        }
        WindowsUserFeedback tempFeedback(m_hWnd);
        tempFeedback.ShowError(msg, "PHP Shell");
        return;
    }
    ShowPhpShellConsole(m_hWnd, std::move(shellSettings));
}

void ConnectionDialog::OnBrowseKeyFile(bool isPublicKey)
{
    OPENFILENAME ofn{};
    std::array<char, MAX_PATH> szFileName{};
    ofn.lStructSize = sizeof(OPENFILENAME);
    ofn.hwndOwner = m_hWnd;
    ofn.nFilterIndex = 1;
    ofn.lpstrFile = szFileName.data();
    ofn.nMaxFile = szFileName.size();
    
    if (isPublicKey) {
        lstrcpy(szFileName.data(), TEXT("*.pub"));
        ofn.lpstrFilter = TEXT("Public key files (*.pub)\0*.pub\0All Files\0*.*\0");
        ofn.lpstrTitle = TEXT("Select public key file");
    } else {
        lstrcpy(szFileName.data(), TEXT("*.pem"));
        ofn.lpstrFilter = TEXT("Private key files (*.pem;*.ppk)\0*.pem;*.ppk\0OpenSSH private key (*.pem)\0*.pem\0PuTTY private key (*.ppk)\0*.ppk\0All Files\0*.*\0");
        ofn.lpstrTitle = TEXT("Select private key file");
    }
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    
    if (GetOpenFileName(&ofn)) {
        SetDlgItemText(m_hWnd, isPublicKey ? IDC_PUBKEY : IDC_PRIVKEY, szFileName.data());
        if (!isPublicKey)
            UpdateCertSectionState(m_hWnd);
    }
}

void ConnectionDialog::OnPrivateKeyChanged()
{
    UpdateCertSectionState(m_hWnd);
}

void ConnectionDialog::OnUseAgentChanged()
{
    UpdateCertSectionState(m_hWnd);
}

void ConnectionDialog::OnJumpEnableChanged()
{
    if (m_settings)
        m_settings->use_jump_host = IsDlgButtonChecked(m_hWnd, IDC_JUMP_ENABLE) == BST_CHECKED;
}

void ConnectionDialog::OnJumpButton()
{
    if (!m_settings) return;
    
    JumpDialogContext jumpCtx;
    jumpCtx.cs = m_settings;
    jumpCtx.iniFileName = m_ctx->iniFileName;
    jumpCtx.hasCryptProc = (CryptProc != nullptr);
    
    if (m_ctx->displayName)
        m_settings->DisplayName = m_ctx->displayName;
    
    ShowLocalizedDialogBoxParam(IDD_JUMPHOST, m_hWnd, JumpHostDlgProc, (LPARAM)&jumpCtx);
    
    CheckDlgButton(m_hWnd, IDC_JUMP_ENABLE,
        m_settings->use_jump_host ? BST_CHECKED : BST_UNCHECKED);
}

void ConnectionDialog::OnProxyButton()
{
    int proxynr = (int)SendDlgItemMessage(m_hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
    if (proxynr > 0) {
        ProxyDialogContext proxyCtx;
        proxyCtx.proxynr = proxynr;
        proxyCtx.ownerConnectResults = m_settings;
        proxyCtx.iniFileName = m_ctx->iniFileName;
        
        if (IDOK == ShowLocalizedDialogBoxParam(IDD_PROXY, GetActiveWindow(), ProxyDlgProc, (LPARAM)&proxyCtx))
            fillProxyCombobox(m_hWnd, proxynr, m_ctx->iniFileName);
    }
}

void ConnectionDialog::OnProxyComboChanged()
{
    if ((int)SendDlgItemMessage(m_hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0) ==
        (int)SendDlgItemMessage(m_hWnd, IDC_PROXYCOMBO, CB_GETCOUNT, 0, 0) - 1) {
        PostMessage(m_hWnd, WM_COMMAND, IDC_PROXYBUTTON, 0);
    }
}

void ConnectionDialog::OnDeleteLastProxy()
{
    int proxynr = (int)SendDlgItemMessage(m_hWnd, IDC_PROXYCOMBO, CB_GETCOUNT, 0, 0) - 2;
    if (proxynr >= 2) {
        std::array<char, 1024> errorstr{};
        LoadString(hinst, IDS_ERROR_INUSE, errorstr.data(), static_cast<int>(errorstr.size()));
        strlcat(errorstr.data(), "\n", errorstr.size() - 1);
        
        if (DeleteLastProxy(proxynr, m_settings->DisplayName.c_str(), m_ctx->iniFileName, errorstr.data(), errorstr.size() - 1)) {
            int proxynrSel = (int)SendDlgItemMessage(m_hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
            fillProxyCombobox(m_hWnd, proxynrSel, m_ctx->iniFileName);
        } else {
            std::array<WCHAR, 1024> werrorstr{};
            MultiByteToWideChar(CP_ACP, 0, errorstr.data(), -1, werrorstr.data(), static_cast<int>(werrorstr.size() - 1));
            if (RequestProcW)
                RequestProcW(PluginNumber, RT_MsgOK, L"SFTP", werrorstr.data(), nullptr, 0);
            else
                MessageBoxW(m_hWnd, werrorstr.data(), L"SFTP", MB_OK | MB_ICONSTOP);
        }
    } else {
        MessageBeep(MB_ICONSTOP);
    }
}

void ConnectionDialog::OnImportSessions()
{
    pConnectSettings importApplyTarget = m_settings->dialogforconnection ? nullptr : m_settings;
    std::array<char, wdirtypemax> importedSession{};
    importedSession[0] = 0;
    
    int importedCount = sftp::ShowExternalSessionImportMenu(
        m_hWnd, m_ctx->iniFileName, importApplyTarget, importedSession.data(), importedSession.size());
    
    LoadServersFromIni(m_ctx->iniFileName, s_quickconnect);
    
    std::array<char, wdirtypemax> currentSession{};
    GetDlgItemText(m_hWnd, IDC_SESSIONCOMBO, currentSession.data(), currentSession.size() - 1);
    
    if (importedCount > 0 && importedSession[0]) {
        FillSessionCombo(m_hWnd, importedSession.data());
        tConnectSettings loaded{};
        if (LoadServerSettings(importedSession.data(), &loaded, m_ctx->iniFileName))
            ApplyLoadedSessionToDialog(m_hWnd, &loaded, m_ctx->iniFileName);
    } else {
        FillSessionCombo(m_hWnd, currentSession.data());
    }
    fillProxyCombobox(m_hWnd, m_settings->proxynr, m_ctx->iniFileName);
}

void ConnectionDialog::OnPluginHelp()
{
    OpenPluginHelp(m_hWnd);
}

void ConnectionDialog::OnCertHelp()
{
    ShowHelpDialog(m_hWnd, IDS_HELP_CERT);
}

void ConnectionDialog::OnPasswordHelp()
{
    ShowHelpDialog(m_hWnd, IDS_HELP_PASSWORD);
}

void ConnectionDialog::OnUtf8Help()
{
    ShowHelpDialog(m_hWnd, IDS_HELP_UTF8);
}

void ConnectionDialog::OnEditPass()
{
    bool doshow = true;
    std::array<char, MAX_PATH> sessionPassword{};
    int err = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, m_ctx->displayName, sessionPassword.data(), static_cast<int>(sessionPassword.size() - 1));
    
    if (err == FS_FILE_OK) {
        m_settings->password = sessionPassword.data();
        SetDlgItemText(m_hWnd, IDC_PASSWORD, m_settings->password);
    } else if (err == FS_FILE_READERROR) {
        SetDlgItemText(m_hWnd, IDC_PASSWORD, "");
    } else {
        doshow = false;
    }
    
    if (doshow) {
        ShowWindow(GetDlgItem(m_hWnd, IDC_PASSWORD), SW_SHOW);
        ShowWindow(GetDlgItem(m_hWnd, IDC_CRYPTPASS), SW_SHOW);
        ShowWindow(GetDlgItem(m_hWnd, IDC_EDITPASS), SW_HIDE);
        if (!m_settings->password.empty())
            CheckDlgButton(m_hWnd, IDC_CRYPTPASS, BST_CHECKED);
    }
}

void ConnectionDialog::OnConnectToChanged()
{
    serverfieldchangedbyuser = true;
}

void ConnectionDialog::UpdateCertSectionState()
{
    ::UpdateCertSectionState(m_hWnd);
}

void ConnectionDialog::UpdateScpDependentControls()
{
    ::UpdateScpOnlyDependentControls(m_hWnd);
}

void ConnectionDialog::RebuildCombos()
{
    RebuildSystemAndEncodingCombos(m_hWnd, m_ctx, m_settings);
}

// ============================================================================
// Thin wrapper for original dialog procedure - uses ConnectionDialog class
// ============================================================================

INT_PTR WINAPI ConnectDlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
    auto* dlg = reinterpret_cast<ConnectionDialog*>(GetWindowLongPtr(hWnd, DWLP_USER));
    
    if (Message != WM_INITDIALOG && !dlg)
        return 0;

    switch (Message) {
    case WM_INITDIALOG: {
        ConnectDialogContext* dlgCtx = reinterpret_cast<ConnectDialogContext*>(lParam);
        if (!dlgCtx || !dlgCtx->connectResults || !dlgCtx->displayName || !dlgCtx->iniFileName) {
            EndDialog(hWnd, IDCANCEL);
            return 1;
        }
        SetWindowLongPtr(hWnd, DWLP_USER, lParam);
        dlg = new ConnectionDialog(hWnd, dlgCtx);
        return dlg->HandleMessage(Message, wParam, lParam);
    }
    case WM_DESTROY: {
        INT_PTR result = dlg->HandleMessage(Message, wParam, lParam);
        delete dlg;
        SetWindowLongPtr(hWnd, DWLP_USER, 0);
        return result;
    }
    default:
        return dlg->HandleMessage(Message, wParam, lParam);
    }
}

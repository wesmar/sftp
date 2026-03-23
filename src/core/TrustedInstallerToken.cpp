/*******************************************************************************
*
*  (C) COPYRIGHT WESMAR, 2026
*
*  TITLE:       TRUSTEDINSTALLERTOKEN.CPP
*
*  AUTHOR:      Marek Wesołowski - Wesmar 2026
*
*  Acquires a TrustedInstaller impersonation token by opening the
*  TrustedInstaller service process and duplicating its token. Used
*  to access SYSTEM-owned registry keys when running as Administrator.
*
*******************************************************************************/

#include "TrustedInstallerToken.h"
#include <tlhelp32.h>
#include <winsvc.h>
#include <sddl.h>
#include <strsafe.h>

#pragma comment(lib, "advapi32.lib")

#define TI_DEBUG_OUT(msg) ((void)0)

static HANDLE g_hTrustedInstallerToken = NULL;
static BOOL g_fTrustedInstallerImpersonationActive = FALSE;
static WCHAR g_szOriginalUserSid[SECURITY_MAX_SID_STRING_CHARACTERS] = { 0 };

// ============================================================================
// Internal helpers
// ============================================================================

static BOOL EnablePrivilege(LPCWSTR privilegeName)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    return ok && (err == ERROR_SUCCESS);
}

static BOOL EnablePrivilegeOnToken(HANDLE hToken, LPCWSTR privilegeName)
{
    LUID luid;
    TOKEN_PRIVILEGES tp;
    BOOL ok;
    DWORD err;

    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
        return FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    err = GetLastError();

    return ok && (err == ERROR_SUCCESS);
}

static BOOL EnablePrivilegeOnCurrentSecurityContext(LPCWSTR privilegeName)
{
    HANDLE hToken = NULL;
    BOOL ok = FALSE;

    if (OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, TRUE, &hToken)) {
        ok = EnablePrivilegeOnToken(hToken, privilegeName);
        CloseHandle(hToken);
        return ok;
    }

    if (GetLastError() != ERROR_NO_TOKEN)
        return FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    ok = EnablePrivilegeOnToken(hToken, privilegeName);
    CloseHandle(hToken);
    return ok;
}

static BOOL CaptureOriginalUserSid(void)
{
    HANDLE hToken = NULL;
    DWORD cb = 0;
    PTOKEN_USER pTokenUser = NULL;
    LPWSTR pSidString = NULL;
    HRESULT hr;
    BOOL ok = FALSE;

    if (g_szOriginalUserSid[0] != L'\0')
        return TRUE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        goto cleanup;

    GetTokenInformation(hToken, TokenUser, NULL, 0, &cb);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || cb == 0)
        goto cleanup;

    pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, cb);
    if (!pTokenUser)
        goto cleanup;

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, cb, &cb))
        goto cleanup;

    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &pSidString))
        goto cleanup;

    hr = StringCchCopyW(g_szOriginalUserSid, ARRAYSIZE(g_szOriginalUserSid), pSidString);
    if (FAILED(hr))
        goto cleanup;

    ok = TRUE;

cleanup:
    if (pSidString)
        LocalFree(pSidString);
    if (pTokenUser)
        LocalFree(pTokenUser);
    if (hToken)
        CloseHandle(hToken);
    return ok;
}

static DWORD FindProcessId(LPCWSTR processName)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pid;
}

static BOOL ImpersonateSystem(void)
{
    DWORD pid = FindProcessId(L"winlogon.exe");
    if (!pid) return FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    CloseHandle(hProcess);

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenImpersonation, &hDup)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);

    BOOL ok = ImpersonateLoggedOnUser(hDup);
    CloseHandle(hDup);
    return ok;
}

static DWORD StartTIService(void)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return 0;

    SC_HANDLE hSvc = OpenServiceW(hSCM, L"TrustedInstaller",
                                  SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD needed;
    DWORD pid = 0;

    if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp,
                              sizeof(ssp), &needed))
        goto done;

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
        pid = ssp.dwProcessId;
        goto done;
    }

    if (ssp.dwCurrentState == SERVICE_STOPPED) {
        if (!StartServiceW(hSvc, 0, NULL))
            goto done;
    }

    // Poll for running state
    for (int i = 0; i < 20; i++) {
        Sleep(100);
        if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp,
                                 sizeof(ssp), &needed)) {
            if (ssp.dwCurrentState == SERVICE_RUNNING) {
                pid = ssp.dwProcessId;
                goto done;
            }
        }
    }

done:
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return pid;
}

// ============================================================================
// Public API
// ============================================================================

extern "C" BOOL AcquireTrustedInstallerToken(void)
{
    static SRWLOCK s_tiLock = SRWLOCK_INIT;
    AcquireSRWLockExclusive(&s_tiLock);

    CaptureOriginalUserSid();

    if (g_hTrustedInstallerToken != NULL) {
        if (!ImpersonateLoggedOnUser(g_hTrustedInstallerToken)) {
            TI_DEBUG_OUT(L"[TI] Failed to impersonate cached TI token\n");
            ReleaseSRWLockExclusive(&s_tiLock);
            return FALSE;
        }
        g_fTrustedInstallerImpersonationActive = TRUE;
        EnablePrivilegeOnCurrentSecurityContext(L"SeBackupPrivilege");
        EnablePrivilegeOnCurrentSecurityContext(L"SeRestorePrivilege");
        TI_DEBUG_OUT(L"[TI] Successfully impersonating cached TrustedInstaller\n");
        ReleaseSRWLockExclusive(&s_tiLock);
        return TRUE;
    }

    // Step 1: Enable SeDebugPrivilege + SeImpersonatePrivilege on our process token
    if (!EnablePrivilege(L"SeDebugPrivilege")) {
        TI_DEBUG_OUT(L"[TI] Failed to enable SeDebugPrivilege\n");
        ReleaseSRWLockExclusive(&s_tiLock);
        return FALSE;
    }
    if (!EnablePrivilege(L"SeImpersonatePrivilege")) {
        TI_DEBUG_OUT(L"[TI] Failed to enable SeImpersonatePrivilege\n");
        ReleaseSRWLockExclusive(&s_tiLock);
        return FALSE;
    }

    // Step 2: Impersonate SYSTEM (via winlogon.exe) so we can start/open TI service
    if (!ImpersonateSystem()) {
        TI_DEBUG_OUT(L"[TI] Failed to impersonate SYSTEM\n");
        ReleaseSRWLockExclusive(&s_tiLock);
        return FALSE;
    }

    // Step 3: Start TrustedInstaller service and get its PID
    DWORD tiPid = StartTIService();
    if (!tiPid) {
        RevertToSelf();
        TI_DEBUG_OUT(L"[TI] Failed to start TrustedInstaller service\n");
        ReleaseSRWLockExclusive(&s_tiLock);
        return FALSE;
    }

    // Step 4: Open TrustedInstaller process and duplicate its token
    HANDLE hTIProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, tiPid);
    if (!hTIProcess) {
        RevertToSelf();
        TI_DEBUG_OUT(L"[TI] Failed to open TI process\n");
        ReleaseSRWLockExclusive(&s_tiLock);
        return FALSE;
    }

    HANDLE hTIToken = NULL;
    if (!OpenProcessToken(hTIProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hTIToken)) {
        CloseHandle(hTIProcess);
        RevertToSelf();
        TI_DEBUG_OUT(L"[TI] Failed to open TI token\n");
        ReleaseSRWLockExclusive(&s_tiLock);
        return FALSE;
    }
    CloseHandle(hTIProcess);

    HANDLE hDupToken = NULL;
    if (!DuplicateTokenEx(hTIToken,
                          TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_DUPLICATE,
                          NULL,
                          SecurityImpersonation, TokenImpersonation, &hDupToken)) {
        CloseHandle(hTIToken);
        RevertToSelf();
        TI_DEBUG_OUT(L"[TI] Failed to duplicate TI token\n");
        ReleaseSRWLockExclusive(&s_tiLock);
        return FALSE;
    }
    CloseHandle(hTIToken);

    // Enable required backup/restore privileges directly on duplicated TI token.
    if (!EnablePrivilegeOnToken(hDupToken, L"SeBackupPrivilege")) {
        TI_DEBUG_OUT(L"[TI] Failed to enable SeBackupPrivilege on duplicated TI token\n");
    }
    if (!EnablePrivilegeOnToken(hDupToken, L"SeRestorePrivilege")) {
        TI_DEBUG_OUT(L"[TI] Failed to enable SeRestorePrivilege on duplicated TI token\n");
    }

    // Step 5: Revert SYSTEM impersonation, then impersonate TrustedInstaller
    RevertToSelf();

    if (!ImpersonateLoggedOnUser(hDupToken)) {
        CloseHandle(hDupToken);
        TI_DEBUG_OUT(L"[TI] Failed to impersonate TI token\n");
        ReleaseSRWLockExclusive(&s_tiLock);
        return FALSE;
    }

    if (g_hTrustedInstallerToken != NULL) {
        CloseHandle(g_hTrustedInstallerToken);
        g_hTrustedInstallerToken = NULL;
    }

    g_hTrustedInstallerToken = hDupToken;
    g_fTrustedInstallerImpersonationActive = TRUE;

    if (!EnablePrivilegeOnCurrentSecurityContext(L"SeBackupPrivilege")) {
        TI_DEBUG_OUT(L"[TI] Failed to enable SeBackupPrivilege on TI token\n");
    }
    if (!EnablePrivilegeOnCurrentSecurityContext(L"SeRestorePrivilege")) {
        TI_DEBUG_OUT(L"[TI] Failed to enable SeRestorePrivilege on TI token\n");
    }

    // The thread now runs as NT SERVICE\TrustedInstaller.
    TI_DEBUG_OUT(L"[TI] Successfully impersonating TrustedInstaller\n");
    ReleaseSRWLockExclusive(&s_tiLock);
    return TRUE;
}

extern "C" BOOL IsTrustedInstallerImpersonationActive(void)
{
    return g_fTrustedInstallerImpersonationActive;
}

extern "C" BOOL GetOriginalUserSid(PWSTR pBuffer, DWORD cchBuffer)
{
    HRESULT hr;

    if (pBuffer == NULL || cchBuffer == 0)
        return FALSE;

    if (!CaptureOriginalUserSid())
        return FALSE;

    hr = StringCchCopyW(pBuffer, cchBuffer, g_szOriginalUserSid);
    return SUCCEEDED(hr);
}

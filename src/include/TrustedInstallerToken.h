/*******************************************************************************
*
*  (C) COPYRIGHT WESMAR, 2026
*
*  TITLE:       TRUSTEDINSTALLERTOKEN.H
*
*  AUTHOR:      Marek Wesołowski - Wesmar 2026
*
*  Public interface for TrustedInstaller token impersonation.
*
*******************************************************************************/

#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Acquires TrustedInstaller token and impersonates it on the current thread.
// After this call, all registry/file operations run under TI identity.
// Requires: process running as Administrator (elevated).
// Returns TRUE on success, FALSE on failure.
BOOL AcquireTrustedInstallerToken(void);
BOOL IsTrustedInstallerImpersonationActive(void);
BOOL GetOriginalUserSid(PWSTR pBuffer, DWORD cchBuffer);

#ifdef __cplusplus
}
#endif

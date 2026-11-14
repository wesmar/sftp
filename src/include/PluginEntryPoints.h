#pragma once

#include <array>
#include <climits>
#include "CoreUtils.h"
#include "fsplugin.h"
#include "SftpClient.h"

extern HINSTANCE hinst;
extern int PluginNumber;
extern int CryptoNumber;
extern DWORD mainthreadid;

extern tProgressProc  ProgressProc;
extern tProgressProcW ProgressProcW;
extern tLogProc       LogProc;
extern tLogProcW      LogProcW;
extern tRequestProc   RequestProc;
extern tRequestProcW  RequestProcW;
extern tCryptProc     CryptProc;

extern bool CryptCheckPass;

extern char pluginname[];

// Asks Total Commander for one line of input. The length comes from the
// buffer's type, so no caller can hand over a wrong one.
template <size_t N>
bool RequestInput(int requestType, LPCSTR title, LPCSTR text, std::array<char, N>& buf) noexcept
{
    static_assert(N >= 2 && N <= INT_MAX);
    return RequestProc(PluginNumber, requestType, title, text, buf.data(), static_cast<int>(N - 1)) != 0;
}

__forceinline
bool IsMainThread() noexcept
{
    return GetCurrentThreadId() == mainthreadid;
}

void ShowStatus(LPCSTR status) noexcept;
void ShowStatusW(LPCWSTR status) noexcept;
bool UpdatePercentBar(pConnectSettings ConnectSettings, int percent, LPCWSTR source = nullptr, LPCWSTR target = nullptr) noexcept;
void ApplyConfiguredUiLanguageForCurrentThread() noexcept;
LANGID GetConfiguredUiLanguageId() noexcept;

// Diagnostic prefix for status messages: when a guard is active in the
// current thread, ShowStatus* prepends "[<session>] " to the message so
// multi-session users can tell which connection is logging. Install at
// Fs*-entry points (or any function with pConnectSettings in scope) —
// propagates automatically to all nested calls on the same thread via
// thread-local storage. Restores previous context on scope exit (RAII),
// so nested guards for different sessions interleave correctly.
class SessionContextGuard {
public:
    explicit SessionContextGuard(const tConnectSettings* cs) noexcept;
    ~SessionContextGuard() noexcept;
    SessionContextGuard(const SessionContextGuard&) = delete;
    SessionContextGuard& operator=(const SessionContextGuard&) = delete;
private:
    const tConnectSettings* prev_;
};

// Current thread's active session for diagnostic prefixing, or nullptr.
const tConnectSettings* GetCurrentSession() noexcept;



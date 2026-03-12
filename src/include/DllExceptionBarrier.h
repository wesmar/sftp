#pragma once

// DllExceptionBarrier.h — Exception firewall at the DLL/TC boundary.
//
// C++ exceptions must never propagate out of an exported DLL function.
// Total Commander (the host) is not built with the same compiler/flags and
// would crash instantly on an unhandled exception crossing the ABI boundary.
//
// When an exception is caught, the barrier:
//   1. Saves the exception via std::exception_ptr (preserves type, no RTTI needed)
//   2. Captures a stack trace via Windows DbgHelp (Windows SDK — no third-party libs)
//   3. Logs everything through SFTP_LOG
//   4. Shows a MessageBoxW to the user (once per incident)
//
// IMPORTANT: symbols resolve only when the PDB sits next to sftpplug.wfx.
// In both Debug and Release the project already sets GenerateDebugInformation=true
// and ProgramDataBaseFileName so PDBs are always emitted.
//
// Note on /GR- : project builds with RuntimeTypeInfo=false, so typeid is
// forbidden. Exception identification uses std::exception hierarchy only.
//
// Note on stack trace scope: with /EHsc the C++ stack is unwound before
// catch(...) executes, so CaptureStackBackTrace shows the catch-site chain
// (which Fs* was active, the barrier, dll_invoke) — not the throw site.
// That is still the most actionable info: it identifies exactly which
// exported operation failed.
//
// Usage — every exported Fs* function:
//
//   int WINAPI FsGetFileW(LPCWSTR RemoteName, LPWSTR LocalName, ...) {
//       sftp::DllExceptionBarrier barrier;
//       return sftp::dll_invoke(barrier, FS_FILE_READERROR, [&]() -> int {
//           // real implementation — may throw freely
//       });
//   }
//
//   void WINAPI FsSetCryptCallback(tCryptProc p, int nr, int flags) {
//       sftp::DllExceptionBarrier barrier;
//       sftp::dll_invoke_void(barrier, [&] { ... });
//   }

#include "global.h"
#include <exception>
#include <string>
#include <type_traits>

namespace sftp {

// ---------------------------------------------------------------------------
// ShutdownSymbols() — call from DllMain on DLL_PROCESS_DETACH.
//
// Releases DbgHelp resources acquired by SymInitialize(). Required so that
// if TC ever unloads and reloads the plugin DLL within the same process,
// SymInitialize() works correctly on the next load.
// Safe no-op when DbgHelp was never initialised (no exceptions were thrown).
// ---------------------------------------------------------------------------
void ShutdownSymbols() noexcept;

// ---------------------------------------------------------------------------
// DllExceptionBarrier — stack-local RAII exception firewall.
//
// One instance per exported Fs* function. Non-copyable and non-moveable:
// it must live as a named local variable at the top of the entry point.
// ---------------------------------------------------------------------------
class DllExceptionBarrier final {
public:
    DllExceptionBarrier() noexcept = default;

    // Destructor logs and shows error UI if an exception was caught.
    // MUST be noexcept: a throwing destructor during stack-unwinding of
    // another exception invokes std::terminate() immediately.
    ~DllExceptionBarrier() noexcept;

    // capture() — call ONLY from within a catch(...) block.
    //
    // Saves the active exception via std::current_exception(), captures
    // the current call stack via CaptureStackBackTrace + DbgHelp symbol
    // resolution, then rethrows locally to extract what() text.
    // Every inner operation is guarded — this function never propagates.
    void capture() noexcept;

    [[nodiscard]] bool               has_exception() const noexcept { return static_cast<bool>(m_captured); }
    [[nodiscard]] const std::string& diagnostic()    const noexcept { return m_diagnostic; }
    [[nodiscard]] const std::string& stack_trace()   const noexcept { return m_stack_trace; }

    DllExceptionBarrier(const DllExceptionBarrier&)            = delete;
    DllExceptionBarrier& operator=(const DllExceptionBarrier&) = delete;
    DllExceptionBarrier(DllExceptionBarrier&&)                 = delete;
    DllExceptionBarrier& operator=(DllExceptionBarrier&&)      = delete;

private:
    void show_error_ui() noexcept;

    std::exception_ptr m_captured;
    std::string        m_diagnostic;   // exception message
    std::string        m_stack_trace;  // resolved symbol names + file:line
    bool               m_ui_shown = false;
};

// ---------------------------------------------------------------------------
// dll_invoke — wraps a callable; barrier catches everything.
//
// R is deduced from the lambda's return type (std::invoke_result_t<F>),
// NOT from `fallback`. This prevents the C2440 error that occurs when
// fallback is `nullptr`, which would otherwise deduce R = std::nullptr_t
// instead of the intended HANDLE.
// static_cast<R>(fallback) handles integral/pointer conversions safely.
// ---------------------------------------------------------------------------
template <typename F, typename Fallback,
          typename R = std::invoke_result_t<F>>
[[nodiscard]] R dll_invoke(DllExceptionBarrier& barrier, Fallback fallback, F&& func) noexcept
{
    try {
        return std::forward<F>(func)();
    }
    catch (...) {
        barrier.capture();
    }
    return static_cast<R>(fallback);
}

// ---------------------------------------------------------------------------
// dll_invoke_void — same for void-returning entry points.
// ---------------------------------------------------------------------------
template <typename F>
void dll_invoke_void(DllExceptionBarrier& barrier, F&& func) noexcept
{
    try {
        std::forward<F>(func)();
    }
    catch (...) {
        barrier.capture();
    }
}

} // namespace sftp

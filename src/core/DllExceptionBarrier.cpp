// DllExceptionBarrier.cpp — Exception firewall at the DLL/TC boundary.
//
// DbgHelp usage notes:
//   - DbgHelp is NOT thread-safe. All calls are serialised via g_sym_lock (SRWLOCK).
//   - SymInitialize() is called lazily on the first exception: zero overhead when
//     no exception ever occurs (the normal case).
//   - SymInitialize(..., TRUE) loads symbols for all currently loaded modules.
//     This is the most reliable option for a plugin where we do not control
//     the search path at load time.
//   - CaptureStackBackTrace() lives in kernel32 (always linked) and is safe
//     to call without the sym lock — it does not touch DbgHelp state.
//   - We skip 2 frames from CaptureStackBackTrace:
//       #0  BuildStackTrace()       — internal helper, not interesting
//       #1  DllExceptionBarrier::capture()  — barrier infrastructure
//     Output starts at dll_invoke (frame #0 in output), then the Fs* function,
//     then TC's call chain above it.

#include "global.h"
#include "DllExceptionBarrier.h"

#include <windows.h>
#include <dbghelp.h>
#include <atomic>
#include <exception>
#include <stdexcept>
#include <system_error>
#include <string>

#include <csignal>
#include <cstdlib>
#include <new>

// Link dbghelp at compile time (also added to vcxproj AdditionalDependencies).
#pragma comment(lib, "dbghelp.lib")

namespace sftp {

// ============================================================================
// DbgHelp symbol subsystem — private to this translation unit
// ============================================================================

namespace {

SRWLOCK                  g_sym_lock        = SRWLOCK_INIT; // serialises all DbgHelp calls
std::atomic<bool>        g_sym_initialized{false};         // acquire/release, see EnsureSymbols()

// Returns the directory of the DLL that contains EnsureSymbols (i.e., our
// own plugin module). Returned string is suitable as a DbgHelp search path.
// On failure returns an empty string.
std::string GetModuleDir() noexcept
{
    HMODULE self = nullptr;
    if (!::GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&GetModuleDir),
            &self) || !self) {
        return {};
    }
    char path[MAX_PATH] = {};
    DWORD n = ::GetModuleFileNameA(self, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return {};
    if (char* slash = std::strrchr(path, '\\')) {
        *slash = '\0';
        return std::string(path);
    }
    return {};
}

// EnsureSymbols — idempotent, lazy.  Acquires exclusive lock for first call.
void EnsureSymbols() noexcept
{
    // Fast path: acquire-load guarantees that if we see true, every store
    // performed by the initialising thread (SymInitialize etc.) is visible
    // to us.  This is the double-checked locking pattern, correct under the
    // C++ memory model (unlike a plain bool read which is formally UB and
    // also subject to compiler hoisting across the lock).
    if (g_sym_initialized.load(std::memory_order_acquire))
        return;

    ::AcquireSRWLockExclusive(&g_sym_lock);
    if (!g_sym_initialized.load(std::memory_order_relaxed)) {
        // SYMOPT_UNDNAME    — demangle C++ names
        // SYMOPT_LOAD_LINES — load source file / line number info from PDB
        // (SYMOPT_DEFERRED_LOADS dropped — we want PDB matched eagerly so
        // CaptureStackBackTrace + SymFromAddr resolves frames inside libssh2
        // and OpenSSL static-lib code, whose PDBs are baked into sftpplug.pdb.)
        ::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);

        // Build a symbol search path that explicitly includes the plugin's
        // own directory: TC drops sftpplug.pdb next to sftpplug.wfx64 there,
        // and the default DbgHelp search path (EXE dir + _NT_SYMBOL_PATH)
        // does NOT cover that location.
        const std::string moduleDir = GetModuleDir();
        const char* searchPath = moduleDir.empty() ? nullptr : moduleDir.c_str();

        // fInvadeProcess=TRUE: enumerate and load symbols for every module
        // already mapped into the process.
        ::SymInitialize(::GetCurrentProcess(), searchPath, TRUE);

        // Defensive: explicitly nudge DbgHelp to (re)scan loaded modules.
        // Some hosts load modules after SymInitialize; without this,
        // late-loaded symbols would resolve only by export name.
        ::SymRefreshModuleList(::GetCurrentProcess());

        g_sym_initialized.store(true, std::memory_order_release);
    }
    ::ReleaseSRWLockExclusive(&g_sym_lock);
}

// BuildStackTrace — captures the call stack at the point of invocation and
// resolves each frame to a human-readable "function  file(line)" string.
//
// `skip` — number of frames to discard from the top of the captured stack.
//   Pass 2 to hide BuildStackTrace() itself and DllExceptionBarrier::capture().
//
// Returns a multi-line string, one frame per line, indented with "  ".
// If PDB is not present, addresses are printed as hex (still useful).
std::string BuildStackTrace(USHORT skip) noexcept
{
    constexpr USHORT kMaxFrames = 28;
    void* frames[kMaxFrames] = {};

    // CaptureStackBackTrace lives in kernel32 — no DbgHelp lock needed.
    const USHORT count = ::CaptureStackBackTrace(skip, kMaxFrames, frames, nullptr);
    if (count == 0)
        return "  (no frames captured)\n";

    EnsureSymbols();

    std::string result;
    result.reserve(count * 96u);

    // SYMBOL_INFO needs trailing storage for the name string.
    alignas(SYMBOL_INFO)
    char sym_buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)] = {};
    auto* sym = reinterpret_cast<SYMBOL_INFO*>(sym_buf);

    IMAGEHLP_LINE64 line_info = {};
    line_info.SizeOfStruct    = sizeof(line_info);

    ::AcquireSRWLockExclusive(&g_sym_lock);

    for (USHORT i = 0; i < count; ++i) {
        const DWORD64 addr = reinterpret_cast<DWORD64>(frames[i]);

        // Reset sym_buf for each frame — MaxNameLen must remain set.
        ::ZeroMemory(sym_buf, sizeof(sym_buf));
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen   = MAX_SYM_NAME;

        DWORD64 sym_disp  = 0;
        DWORD   line_disp = 0;

        const BOOL have_sym  = ::SymFromAddr(::GetCurrentProcess(), addr, &sym_disp, sym);
        const BOOL have_line = have_sym &&
            ::SymGetLineFromAddr64(::GetCurrentProcess(), addr, &line_disp, &line_info);

        char frame_line[600];

        if (have_sym && have_line) {
            // Trim the full path to just the filename for readability.
            const char* fname = line_info.FileName ? line_info.FileName : "?";
            if (const char* slash = ::strrchr(fname, '\\'))
                fname = slash + 1;

            _snprintf_s(frame_line, _TRUNCATE,
                "  #%02u  %-55s  %s(%lu)\n",
                i, sym->Name, fname, line_info.LineNumber);
        }
        else if (have_sym) {
            _snprintf_s(frame_line, _TRUNCATE,
                "  #%02u  %s  (+0x%llx)\n",
                i, sym->Name,
                static_cast<unsigned long long>(sym_disp));
        }
        else {
            _snprintf_s(frame_line, _TRUNCATE,
                "  #%02u  0x%016llx\n",
                i, static_cast<unsigned long long>(addr));
        }

        result += frame_line;
    }

    ::ReleaseSRWLockExclusive(&g_sym_lock);
    return result;
}

} // anonymous namespace

// ============================================================================
// sftp::ShutdownSymbols — called from DllMain DLL_PROCESS_DETACH
// ============================================================================

void ShutdownSymbols() noexcept
{
    ::AcquireSRWLockExclusive(&g_sym_lock);
    if (g_sym_initialized.load(std::memory_order_relaxed)) {
        ::SymCleanup(::GetCurrentProcess());
        g_sym_initialized.store(false, std::memory_order_relaxed);
    }
    ::ReleaseSRWLockExclusive(&g_sym_lock);
}

// ============================================================================
// Native crash handler — top-level SEH filter
// ============================================================================
//
// Catches unhandled hardware/system exceptions (AV, stack overflow, illegal
// instruction, etc.) that DllExceptionBarrier (C++ try/catch) cannot see.
// On the rare path where libssh2 / OpenSSL / our channel callbacks crash, we
// otherwise lose all context because the host process dies silently.

namespace {

LPTOP_LEVEL_EXCEPTION_FILTER g_prev_filter   = nullptr;
PVOID                        g_veh_handle    = nullptr;
std::terminate_handler       g_prev_terminate = nullptr;

const char* ExceptionCodeName(DWORD code) noexcept
{
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:         return "ACCESS_VIOLATION";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_DATATYPE_MISALIGNMENT:    return "DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_INVALID_OPERATION:    return "FLT_INVALID_OPERATION";
        case EXCEPTION_ILLEGAL_INSTRUCTION:      return "ILLEGAL_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR:            return "IN_PAGE_ERROR";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "INT_DIVIDE_BY_ZERO";
        case EXCEPTION_INT_OVERFLOW:             return "INT_OVERFLOW";
        case EXCEPTION_PRIV_INSTRUCTION:         return "PRIV_INSTRUCTION";
        case EXCEPTION_STACK_OVERFLOW:           return "STACK_OVERFLOW";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "NONCONTINUABLE";
        case EXCEPTION_BREAKPOINT:               return "BREAKPOINT";
        case EXCEPTION_SINGLE_STEP:              return "SINGLE_STEP";
        case 0xE06D7363u:                        return "CXX_EXCEPTION";
        default:                                 return "UNKNOWN";
    }
}

// Log basic exception info FIRST (no DbgHelp), THEN attempt the stack trace.
// This way we still see exception code + address even if symbol resolution
// crashes inside a fragile process state.
void LogExceptionBasic(const char* origin, EXCEPTION_POINTERS* ep) noexcept
{
    if (!ep || !ep->ExceptionRecord) {
        SFTP_LOG("CRASH", "!!! [%s] no ExceptionRecord", origin);
        return;
    }
    const EXCEPTION_RECORD* rec = ep->ExceptionRecord;
    SFTP_LOG("CRASH", "!!! [%s] %s (code=0x%08lx) at %p tid=%lu nparams=%lu",
             origin,
             ExceptionCodeName(rec->ExceptionCode),
             (unsigned long)rec->ExceptionCode,
             rec->ExceptionAddress,
             (unsigned long)::GetCurrentThreadId(),
             (unsigned long)rec->NumberParameters);

    if ((rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
         rec->ExceptionCode == EXCEPTION_IN_PAGE_ERROR) &&
        rec->NumberParameters >= 2)
    {
        const ULONG_PTR op    = rec->ExceptionInformation[0];   // 0=read, 1=write, 8=DEP
        const ULONG_PTR fault = rec->ExceptionInformation[1];
        const char* opStr = (op == 0) ? "read" : (op == 1) ? "write" : (op == 8) ? "DEP" : "?";
        SFTP_LOG("CRASH", "!!! [%s]   %s of address 0x%llx",
                 origin, opStr, (unsigned long long)fault);
    }
}

bool IsInterestingVehCode(DWORD code) noexcept
{
    // Filter out chatty exceptions that are routinely caught by the runtime
    // and would otherwise spam the log on every C++ throw / first-chance hit.
    switch (code) {
        case 0x406D1388u: return false;                  // SetThreadName
        case DBG_PRINTEXCEPTION_C:        return false;  // OutputDebugString
        case DBG_PRINTEXCEPTION_WIDE_C:   return false;
        case 0xE06D7363u: return false;                  // C++ EH (SEH wrapper for throw)
        case EXCEPTION_BREAKPOINT:        return false;
        case EXCEPTION_SINGLE_STEP:       return false;
        default: return true;
    }
}

LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep) noexcept
{
    LogExceptionBasic("UEF", ep);

    // Stack trace — done after basic info so we still see something if this
    // crashes. BuildStackTrace acquires the DbgHelp lock; safe in a top-level
    // SEH filter context (system-invoked callback, not the faulting thread's
    // unwind path).
    const std::string trace = BuildStackTrace(0);
    SFTP_LOG("CRASH", "!!! [UEF] Stack trace:\n%s", trace.c_str());

    // Hand off to whatever was installed before us (typically WerFault or
    // Total Commander's own filter). EXCEPTION_CONTINUE_SEARCH preserves the
    // host's normal crash UX.
    if (g_prev_filter)
        return g_prev_filter(ep);
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI VectoredCrashFilter(EXCEPTION_POINTERS* ep) noexcept
{
    // Vectored handlers run BEFORE the SEH chain — we see exceptions even if
    // someone above (CRT, libssh2, OpenSSL) catches them. Filter to interesting
    // codes only so we don't drown in noise from regular C++ throws.
    if (!ep || !ep->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!IsInterestingVehCode(ep->ExceptionRecord->ExceptionCode))
        return EXCEPTION_CONTINUE_SEARCH;

    LogExceptionBasic("VEH", ep);
    const std::string trace = BuildStackTrace(0);
    SFTP_LOG("CRASH", "!!! [VEH] Stack trace:\n%s", trace.c_str());
    return EXCEPTION_CONTINUE_SEARCH;   // never swallow — let SEH continue
}

void OnTerminate() noexcept
{
    // std::terminate() — fired on uncaught C++ exception, throw from noexcept,
    // unhandled std::bad_alloc inside catch(), etc. This bypasses
    // SetUnhandledExceptionFilter entirely on most CRTs.
    SFTP_LOG("CRASH", "!!! [TERMINATE] std::terminate() invoked");
    const std::string trace = BuildStackTrace(0);
    SFTP_LOG("CRASH", "!!! [TERMINATE] Stack trace:\n%s", trace.c_str());

    if (g_prev_terminate)
        g_prev_terminate();
    // If prev handler returned, fall back to abort.
    std::abort();
}

void OnSignal(int sig) noexcept
{
    const char* name = "UNKNOWN";
    switch (sig) {
        case SIGABRT: name = "SIGABRT"; break;
        case SIGSEGV: name = "SIGSEGV"; break;
        case SIGFPE:  name = "SIGFPE";  break;
        case SIGILL:  name = "SIGILL";  break;
    }
    SFTP_LOG("CRASH", "!!! [SIGNAL] %s (%d)", name, sig);
    const std::string trace = BuildStackTrace(0);
    SFTP_LOG("CRASH", "!!! [SIGNAL] Stack trace:\n%s", trace.c_str());
    // Re-raise default handler so the process actually dies (don't loop).
    std::signal(sig, SIG_DFL);
    std::raise(sig);
}

void OnPureCall() noexcept
{
    SFTP_LOG("CRASH", "!!! [PURECALL] pure virtual function call");
    const std::string trace = BuildStackTrace(0);
    SFTP_LOG("CRASH", "!!! [PURECALL] Stack trace:\n%s", trace.c_str());
    std::abort();
}

void OnInvalidParameter(const wchar_t*, const wchar_t*, const wchar_t*,
                        unsigned int, uintptr_t) noexcept
{
    SFTP_LOG("CRASH", "!!! [INVPARAM] CRT invalid parameter");
    const std::string trace = BuildStackTrace(0);
    SFTP_LOG("CRASH", "!!! [INVPARAM] Stack trace:\n%s", trace.c_str());
    // Don't abort — let CRT decide. Returning falls through to the default
    // CRT behaviour (typically debug break in debug builds, no-op in release).
}

} // anonymous namespace

void InstallCrashHandler() noexcept
{
    // 1. Top-level SEH filter — for unhandled hardware exceptions.
    g_prev_filter = ::SetUnhandledExceptionFilter(CrashFilter);

    // 2. Vectored handler at FIRST priority — sees every exception before
    //    the SEH chain. Filtered to interesting codes only.
    g_veh_handle = ::AddVectoredExceptionHandler(1, VectoredCrashFilter);

    // 3. C++ runtime hooks — these BYPASS the top-level SEH filter on most
    //    CRTs and would otherwise leave no trace.
    g_prev_terminate = std::set_terminate(OnTerminate);
    _set_purecall_handler(OnPureCall);
    _set_invalid_parameter_handler(OnInvalidParameter);

    // 4. POSIX signals (CRT layer). On Windows MSVC these fire for abort(),
    //    /GS buffer-overrun checks (signal-style fallback), and a few CRT
    //    fatal paths. They DO bypass UEF.
    std::signal(SIGABRT, OnSignal);
    std::signal(SIGSEGV, OnSignal);
    std::signal(SIGFPE,  OnSignal);
    std::signal(SIGILL,  OnSignal);
}

void UninstallCrashHandler() noexcept
{
    ::SetUnhandledExceptionFilter(g_prev_filter);
    g_prev_filter = nullptr;
    if (g_veh_handle) {
        ::RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = nullptr;
    }
    if (g_prev_terminate)
        std::set_terminate(g_prev_terminate);
    g_prev_terminate = nullptr;
    std::signal(SIGABRT, SIG_DFL);
    std::signal(SIGSEGV, SIG_DFL);
    std::signal(SIGFPE,  SIG_DFL);
    std::signal(SIGILL,  SIG_DFL);
}

// ============================================================================
// DllExceptionBarrier::capture()
// ============================================================================

void DllExceptionBarrier::capture() noexcept
{
    // --- 1. Capture stack FIRST, before anything else touches the stack ---
    // skip=2: hides BuildStackTrace() and capture() itself.
    // Output frame #0 will be the dll_invoke catch block, #1 the Fs* function.
    m_stack_trace = BuildStackTrace(2);

    // --- 2. Save the live exception so it stays alive until the destructor ---
    m_captured = std::current_exception();

    if (!m_captured) {
        m_diagnostic = "[DllExceptionBarrier] capture() called outside a catch block";
        SFTP_LOG("EXC", "!!! %s", m_diagnostic.c_str());
        return;
    }

    // --- 3. Rethrow locally to extract a human-readable description ---
    //        typeid is intentionally avoided: /GR- (RuntimeTypeInfo=false)
    //        makes it UB on polymorphic types (warning C4541).
    try {
        std::rethrow_exception(m_captured);
    }
    catch (const std::system_error& ex) {
        try {
            m_diagnostic  = "system_error [";
            m_diagnostic += std::to_string(ex.code().value());
            m_diagnostic += '/';
            m_diagnostic += ex.code().category().name();
            m_diagnostic += "]: ";
            m_diagnostic += ex.what();
        }
        catch (...) { m_diagnostic = "system_error (OOM building message)"; }
    }
    catch (const std::bad_alloc&) {
        // No heap allocation here — keep it lean.
        m_diagnostic = "std::bad_alloc: out of memory";
    }
    catch (const std::exception& ex) {
        try {
            m_diagnostic  = "std::exception: ";
            m_diagnostic += ex.what();
        }
        catch (...) { m_diagnostic = "std::exception (OOM building message)"; }
    }
    catch (...) {
        m_diagnostic = "Unknown exception (not derived from std::exception)";
    }

    SFTP_LOG("EXC", "!!! DLL exception: %s", m_diagnostic.c_str());
    SFTP_LOG("EXC", "!!! Stack trace:\n%s", m_stack_trace.c_str());
}

// ============================================================================
// DllExceptionBarrier::show_error_ui()
// ============================================================================

void DllExceptionBarrier::show_error_ui() noexcept
{
    try {
        // Convert UTF-8 diagnostic to wide for MessageBoxW.
        const int needed = ::MultiByteToWideChar(
            CP_UTF8, 0,
            m_diagnostic.c_str(), static_cast<int>(m_diagnostic.size()),
            nullptr, 0);

        std::wstring wdiag;
        if (needed > 0) {
            wdiag.resize(needed);
            ::MultiByteToWideChar(CP_UTF8, 0,
                m_diagnostic.c_str(), static_cast<int>(m_diagnostic.size()),
                wdiag.data(), needed);
        }
        else {
            wdiag = L"(could not convert error text to Unicode)";
        }

        // Convert stack trace.
        const int st_needed = ::MultiByteToWideChar(
            CP_UTF8, 0,
            m_stack_trace.c_str(), static_cast<int>(m_stack_trace.size()),
            nullptr, 0);

        std::wstring wstack;
        if (st_needed > 0) {
            wstack.resize(st_needed);
            ::MultiByteToWideChar(CP_UTF8, 0,
                m_stack_trace.c_str(), static_cast<int>(m_stack_trace.size()),
                wstack.data(), st_needed);
        }

        std::wstring msg =
            L"An unhandled exception escaped the SFTP plugin.\n"
            L"The current operation was aborted to protect Total Commander.\n\n"
            L"Exception:\n    "
            + wdiag;

        if (!wstack.empty()) {
            msg += L"\n\nCall stack (catch-site):\n";
            msg += wstack;
        }

        msg += L"\n\nIf this repeats, please report it together with the log.";

        ::MessageBoxW(
            ::GetActiveWindow(),
            msg.c_str(),
            L"SFTP Plugin \u2014 Unhandled Exception",
            MB_OK | MB_ICONERROR | MB_TASKMODAL);
    }
    catch (...) {
        ::OutputDebugStringA("[SFTP] DllExceptionBarrier::show_error_ui "
                             "— secondary exception, giving up\n");
    }
}

// ============================================================================
// DllExceptionBarrier::~DllExceptionBarrier()
// ============================================================================

DllExceptionBarrier::~DllExceptionBarrier() noexcept
{
    if (!m_captured || m_ui_shown)
        return;

    m_ui_shown = true;

    SFTP_LOG("EXC", "!!! DllExceptionBarrier: Fs* call aborted — %s",
             m_diagnostic.c_str());

    show_error_ui();
}

} // namespace sftp

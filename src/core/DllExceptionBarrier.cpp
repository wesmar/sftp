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

// Link dbghelp at compile time (also added to vcxproj AdditionalDependencies).
#pragma comment(lib, "dbghelp.lib")

namespace sftp {

// ============================================================================
// DbgHelp symbol subsystem — private to this translation unit
// ============================================================================

namespace {

SRWLOCK                  g_sym_lock        = SRWLOCK_INIT; // serialises all DbgHelp calls
std::atomic<bool>        g_sym_initialized{false};         // acquire/release, see EnsureSymbols()

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
        // SYMOPT_DEFERRED_LOADS — don't load all modules up front (faster init)
        ::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS);

        // fInvadeProcess=TRUE: enumerate and load symbols for every module
        // already mapped into the process.  This is the most robust option
        // for a plugin where we cannot predict the search path at runtime.
        ::SymInitialize(::GetCurrentProcess(), nullptr, TRUE);
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

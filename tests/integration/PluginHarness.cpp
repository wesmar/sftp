// Drives a built SFTPplug.wfx through the exported Fs* entry points Total
// Commander uses, against a real SSH server, without Total Commander.
//
//   plugin_harness <plugin.wfx> <ini-dir> <session> <remote-base> [text]
//
//   ini-dir      directory holding the sftpplug.ini the plugin is pointed at
//   session      section of that ini to connect with
//   remote-base  existing writable remote directory, e.g. /tmp
//   text         also run the text-mode (CRLF <-> LF) checks
//
// Non-destructive by construction: everything the run creates lives in
// <remote-base>/sftpplug-it-<random>, and only that directory is removed.
// The plugin's prompts are answered by policy, never by a person: a host key
// is accepted only when SFTP_IT_ACCEPT_NEW_HOSTKEY=1, and any other unexpected
// prompt is declined and fails the run.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <fstream>
#include <map>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "fsplugin.h"
#include "../res/resource.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")

namespace {

// ---------------------------------------------------------------------------
// Plugin exports
// ---------------------------------------------------------------------------
struct Plugin {
    HMODULE module = nullptr;
    int (WINAPI* InitW)(int, tProgressProcW, tLogProcW, tRequestProcW) = nullptr;
    void (WINAPI* SetDefaultParams)(FsDefaultParamStruct*) = nullptr;
    HANDLE (WINAPI* FindFirstW)(LPCWSTR, LPWIN32_FIND_DATAW) = nullptr;
    BOOL (WINAPI* FindNextW)(HANDLE, LPWIN32_FIND_DATAW) = nullptr;
    int (WINAPI* FindClose)(HANDLE) = nullptr;
    BOOL (WINAPI* MkDirW)(LPCWSTR) = nullptr;
    BOOL (WINAPI* RemoveDirW)(LPCWSTR) = nullptr;
    BOOL (WINAPI* DeleteFileW)(LPCWSTR) = nullptr;
    int (WINAPI* PutFileW)(LPCWSTR, LPCWSTR, int) = nullptr;
    int (WINAPI* GetFileW)(LPCWSTR, LPWSTR, int, RemoteInfoStruct*) = nullptr;
    int (WINAPI* RenMovFileW)(LPCWSTR, LPCWSTR, BOOL, BOOL, RemoteInfoStruct*) = nullptr;
    int (WINAPI* ExecuteFileW)(HWND, LPWSTR, LPCWSTR) = nullptr;
    void (WINAPI* StatusInfo)(LPCSTR, int, int) = nullptr;
    BOOL (WINAPI* Disconnect)(LPCSTR) = nullptr;

    template <class F> bool Bind(F& fn, const char* name)
    {
        fn = reinterpret_cast<F>(GetProcAddress(module, name));
        if (!fn)
            std::printf("FATAL export %s missing\n", name);
        return fn != nullptr;
    }

    bool Load(const wchar_t* path)
    {
        module = LoadLibraryW(path);
        if (!module) {
            std::printf("FATAL cannot load plugin (error %lu)\n", GetLastError());
            return false;
        }
        return Bind(InitW, "FsInitW") && Bind(SetDefaultParams, "FsSetDefaultParams") &&
               Bind(FindFirstW, "FsFindFirstW") && Bind(FindNextW, "FsFindNextW") && Bind(FindClose, "FsFindClose") &&
               Bind(MkDirW, "FsMkDirW") && Bind(RemoveDirW, "FsRemoveDirW") && Bind(DeleteFileW, "FsDeleteFileW") &&
               Bind(PutFileW, "FsPutFileW") && Bind(GetFileW, "FsGetFileW") && Bind(RenMovFileW, "FsRenMovFileW") &&
               Bind(ExecuteFileW, "FsExecuteFileW") && Bind(StatusInfo, "FsStatusInfo") &&
               Bind(Disconnect, "FsDisconnect");
    }
} g_plugin;

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------
int g_unexpectedPrompts = 0;
bool g_verbose = false;

std::string Narrow(const std::wstring& w)
{
    if (w.empty())
        return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

bool EnvIs(const wchar_t* name, const wchar_t* value)
{
    wchar_t buf[16] = {};
    return GetEnvironmentVariableW(name, buf, 16) > 0 && std::wcscmp(buf, value) == 0;
}

int WINAPI OnProgress(int, LPCWSTR, LPCWSTR, int) { return 0; }

void WINAPI OnLog(int, int, LPCWSTR text)
{
    if (g_verbose && text)
        std::printf("      log: %s\n", Narrow(text).c_str());
}

BOOL WINAPI OnRequest(int, int type, LPCWSTR title, LPCWSTR text, LPWSTR, int)
{
    const std::wstring t = text ? text : L"";
    const std::wstring all = (title ? std::wstring(title) + L" | " : std::wstring()) + t;
    const bool aboutHostKey = t.find(L"ingerprint") != std::wstring::npos || t.find(L"host key") != std::wstring::npos ||
                              t.find(L"Host key") != std::wstring::npos;
    if ((type == RT_MsgYesNo || type == RT_MsgOKCancel) && aboutHostKey) {
        const bool accept = EnvIs(L"SFTP_IT_ACCEPT_NEW_HOSTKEY", L"1");
        std::printf("      prompt (host key, %s): %s\n", accept ? "accepted" : "declined", Narrow(all).c_str());
        if (!accept)
            ++g_unexpectedPrompts;
        return accept;
    }
    if (type == RT_MsgOK) {
        std::printf("      message: %s\n", Narrow(all).c_str());
        return TRUE;
    }
    std::printf("      UNEXPECTED prompt type %d declined: %s\n", type, Narrow(all).c_str());
    ++g_unexpectedPrompts;
    return FALSE;
}

// ---------------------------------------------------------------------------
// Checks and helpers
// ---------------------------------------------------------------------------
int g_passed = 0;
int g_failed = 0;

bool Check(bool ok, const std::string& what)
{
    std::printf("  %s %s\n", ok ? "ok  " : "FAIL", what.c_str());
    (ok ? g_passed : g_failed)++;
    return ok;
}

std::string Sha256File(const std::wstring& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return "unreadable";
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
    std::vector<char> buf(1 << 16);
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        if (in.gcount() > 0)
            BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf.data()), static_cast<ULONG>(in.gcount()), 0);
    }
    UCHAR digest[32] = {};
    BCryptFinishHash(hash, digest, sizeof(digest), 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    std::string hex;
    for (UCHAR b : digest) {
        char two[3];
        std::snprintf(two, sizeof(two), "%02x", b);
        hex += two;
    }
    return hex;
}

void WriteFileBytes(const std::wstring& path, const std::string& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::string RandomBytes(size_t n, uint32_t seed)
{
    std::mt19937 rng(seed);
    std::string s(n, '\0');
    for (auto& c : s)
        c = static_cast<char>(rng() & 0xFF);
    return s;
}

struct RemoteEntry {
    uint64_t size = 0;
    DWORD attributes = 0;
    DWORD unixMode = 0;
};

std::map<std::wstring, RemoteEntry> ListDir(const std::wstring& tcPath, bool& ok)
{
    std::map<std::wstring, RemoteEntry> entries;
    WIN32_FIND_DATAW fd{};
    HANDLE h = g_plugin.FindFirstW(tcPath.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        ok = GetLastError() == ERROR_NO_MORE_FILES;
        return entries;
    }
    ok = true;
    do {
        const std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..")
            continue;
        RemoteEntry e;
        e.size = (static_cast<uint64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
        e.attributes = fd.dwFileAttributes;
        e.unixMode = (fd.dwFileAttributes & FS_ATTR_UNIXMODE) ? fd.dwReserved0 : 0;
        entries[name] = e;
    } while (g_plugin.FindNextW(h, &fd));
    g_plugin.FindClose(h);
    return entries;
}

// Total Commander always passes what its listing knows about the source of a
// download; the plugin relies on the size it gets here.
RemoteInfoStruct InfoFor(const std::wstring& dir, const std::wstring& name)
{
    RemoteInfoStruct ri{};
    bool ok = false;
    const auto entries = ListDir(dir, ok);
    const auto it = entries.find(name);
    if (it != entries.end()) {
        ri.SizeLow = static_cast<DWORD>(it->second.size & 0xFFFFFFFFu);
        ri.SizeHigh = static_cast<DWORD>(it->second.size >> 32);
        ri.Attr = it->second.attributes;
    }
    return ri;
}

bool LocalFileExists(const std::wstring& path)
{
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// Answers the plugin's own dialogs the way a user does: a thread watches for
// a dialog of this process that carries `buttonId`, clicks it, and waits
// until that dialog is gone before looking for the next one.
class DialogResponder {
public:
    explicit DialogResponder(int buttonId) : button_(buttonId), watcher_([this] { Watch(); }) {}
    ~DialogResponder()
    {
        stop_ = true;
        watcher_.join();
    }
    DialogResponder(const DialogResponder&) = delete;
    DialogResponder& operator=(const DialogResponder&) = delete;

    int Answered() const { return answered_.load(); }

private:
    struct Search {
        int button;
        HWND found;
    };

    static BOOL CALLBACK Visit(HWND h, LPARAM param)
    {
        auto* search = reinterpret_cast<Search*>(param);
        DWORD pid = 0;
        GetWindowThreadProcessId(h, &pid);
        if (pid == GetCurrentProcessId() && IsWindowVisible(h) && GetDlgItem(h, search->button)) {
            search->found = h;
            return FALSE;
        }
        return TRUE;
    }

    void Watch()
    {
        while (!stop_) {
            Search search{button_, nullptr};
            EnumWindows(&Visit, reinterpret_cast<LPARAM>(&search));
            if (search.found) {
                ++answered_;
                PostMessageW(search.found, WM_COMMAND, MAKEWPARAM(button_, BN_CLICKED),
                             reinterpret_cast<LPARAM>(GetDlgItem(search.found, button_)));
                while (!stop_ && IsWindow(search.found))
                    Sleep(10);
            }
            Sleep(20);
        }
    }

    const int button_;
    std::atomic<bool> stop_{false};
    std::atomic<int> answered_{0};
    std::thread watcher_; // last: starts once everything above exists
};

std::wstring NewTempDir(const wchar_t* tag)
{
    wchar_t base[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, base);
    std::wstring dir = std::wstring(base) + L"sftpplug-it-" + tag + L"-" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\";
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    if (argc < 5) {
        std::printf("usage: plugin_harness <plugin.wfx> <ini-dir> <session> <remote-base> [text]\n");
        return 2;
    }
    const std::wstring pluginPath = argv[1];
    const std::wstring iniDir = argv[2];
    const std::wstring session = argv[3];
    std::wstring remoteBase = argv[4];
    const bool textChecks = argc > 5 && std::wcscmp(argv[5], L"text") == 0;
    g_verbose = EnvIs(L"SFTP_IT_VERBOSE", L"1");

    for (auto& c : remoteBase)
        if (c == L'/') c = L'\\';
    if (!remoteBase.empty() && remoteBase.back() == L'\\')
        remoteBase.pop_back();

    if (!g_plugin.Load(pluginPath.c_str()))
        return 2;
    g_plugin.InitW(1, OnProgress, OnLog, OnRequest);
    FsDefaultParamStruct dps{};
    dps.size = sizeof(dps);
    dps.PluginInterfaceVersionLow = 30;
    dps.PluginInterfaceVersionHi = 2;
    WideCharToMultiByte(CP_ACP, 0, (iniDir + L"\\fsplugin.ini").c_str(), -1, dps.DefaultIniName, MAX_PATH, nullptr, nullptr);
    g_plugin.SetDefaultParams(&dps);

    // A random suffix keeps parallel or repeated runs apart.
    std::random_device rd;
    const std::wstring runName = L"sftpplug-it-" + std::to_wstring(rd() % 1000000000u);
    const std::wstring root = L"\\" + session + remoteBase;
    const std::wstring dir = root + L"\\" + runName;
    std::printf("session %s, remote directory %s\n", Narrow(session).c_str(), Narrow(dir).c_str());

    bool listed = false;
    ListDir(root, listed);
    if (!Check(listed && g_unexpectedPrompts == 0, "connect and list " + Narrow(remoteBase)))
        return 1;
    if (!Check(g_plugin.MkDirW(dir.c_str()) == TRUE, "create the run directory"))
        return 1;

    const std::wstring local = NewTempDir(L"src");
    const std::wstring back = NewTempDir(L"dst");

    struct Sample { std::wstring name; std::string content; };
    std::vector<Sample> samples = {
        {L"random.bin", RandomBytes(3000017, 1)},
        {L"empty.dat", std::string()},
        {L"zażółć gęślą jaźń.txt", "Polish name\n"},
        {L"unicode ✓ данные.txt", "outside the ANSI code page\n"},
        {L"it's a ; $(x) & `y` [z].bin", RandomBytes(70000, 2)},
    };

    std::map<std::wstring, std::string> expectedHash;
    for (const auto& s : samples) {
        WriteFileBytes(local + s.name, s.content);
        expectedHash[s.name] = Sha256File(local + s.name);
        const int rc = g_plugin.PutFileW((local + s.name).c_str(), (dir + L"\\" + s.name).c_str(), 0);
        Check(rc == FS_FILE_OK, "upload " + Narrow(s.name) + " (rc=" + std::to_string(rc) + ")");
    }

    {
        const int rc = g_plugin.PutFileW((local + samples[0].name).c_str(), (dir + L"\\" + samples[0].name).c_str(), 0);
        Check(rc == FS_FILE_EXISTS || rc == FS_FILE_EXISTSRESUMEALLOWED,
              "a second upload without overwrite reports the existing file (rc=" + std::to_string(rc) + ")");
    }

    bool ok = false;
    auto entries = ListDir(dir, ok);
    Check(ok, "list the run directory");
    for (const auto& s : samples) {
        const auto it = entries.find(s.name);
        Check(it != entries.end() && it->second.size == s.content.size(),
              "listing shows " + Narrow(s.name) + " with " + std::to_string(s.content.size()) + " bytes");
    }

    for (const auto& s : samples) {
        std::wstring target = back + s.name;
        RemoteInfoStruct ri = InfoFor(dir, s.name);
        const int rc = g_plugin.GetFileW((dir + L"\\" + s.name).c_str(), target.data(), FS_COPYFLAGS_OVERWRITE, &ri);
        Check(rc == FS_FILE_OK && Sha256File(target) == expectedHash[s.name],
              "download " + Narrow(s.name) + " is byte-identical (rc=" + std::to_string(rc) + ")");
    }

    {
        const int rc = g_plugin.RenMovFileW((dir + L"\\random.bin").c_str(), (dir + L"\\renamed.bin").c_str(), TRUE, FALSE, nullptr);
        entries = ListDir(dir, ok);
        Check(rc == FS_FILE_OK && entries.count(L"renamed.bin") && !entries.count(L"random.bin"),
              "rename random.bin to renamed.bin (rc=" + std::to_string(rc) + ")");
    }

    {
        const std::string full = RandomBytes(2000003, 3);
        WriteFileBytes(local + L"resume.bin", full.substr(0, 700001));
        g_plugin.PutFileW((local + L"resume.bin").c_str(), (dir + L"\\resume.bin").c_str(), 0);
        WriteFileBytes(local + L"resume.bin", full);
        const int rc = g_plugin.PutFileW((local + L"resume.bin").c_str(), (dir + L"\\resume.bin").c_str(), FS_COPYFLAGS_RESUME);
        if (rc == FS_FILE_NOTSUPPORTED) {
            Check(true, "resumed upload not offered in this mode");
        } else {
            std::wstring target = back + L"resume.bin";
            RemoteInfoStruct ri = InfoFor(dir, L"resume.bin");
            const int get = g_plugin.GetFileW((dir + L"\\resume.bin").c_str(), target.data(), FS_COPYFLAGS_OVERWRITE, &ri);
            Check(rc == FS_FILE_OK && get == FS_FILE_OK && Sha256File(target) == Sha256File(local + L"resume.bin"),
                  "resumed upload completes a partial file (rc=" + std::to_string(rc) + ")");
        }
    }

    {
        std::wstring target = dir + L"\\renamed.bin";
        const int rc = g_plugin.ExecuteFileW(nullptr, target.data(), L"chmod 640");
        entries = ListDir(dir, ok);
        const auto it = entries.find(L"renamed.bin");
        const DWORD mode = it != entries.end() ? (it->second.unixMode & 0777) : 0;
        char octal[8];
        std::snprintf(octal, sizeof(octal), "%03lo", static_cast<unsigned long>(mode));
        Check(rc == FS_EXEC_OK && mode == 0640, std::string("chmod 640 is reported back as ") + octal);
    }

    {
        // A multi-file download meets files it cannot read: the first one
        // asks, "Skip all" answers for the rest, and the batch goes on.
        DialogResponder responder(IDC_DOWNLOAD_SKIP_ALL);
        const std::string dirA = Narrow(dir); // FsStatusInfo takes the ANSI path
        auto get = [&](const wchar_t* name, int flags) {
            std::wstring target = back + name;
            RemoteInfoStruct ri = InfoFor(dir, name);
            const int rc = g_plugin.GetFileW((dir + L"\\" + name).c_str(), target.data(), flags, &ri);
            return std::pair<int, std::wstring>(rc, back + name);
        };

        g_plugin.StatusInfo(dirA.c_str(), FS_STATUS_START, FS_STATUS_OP_GET_MULTI);
        const auto first = get(L"missing-1.bin", FS_COPYFLAGS_OVERWRITE);
        Check(first.first == FS_FILE_OK && responder.Answered() == 1 && !LocalFileExists(first.second),
              "a failed file in a batch asks once; skipping leaves nothing behind (rc=" + std::to_string(first.first) + ")");
        const auto second = get(L"missing-2.bin", FS_COPYFLAGS_OVERWRITE);
        Check(second.first == FS_FILE_OK && responder.Answered() == 1 && !LocalFileExists(second.second),
              "\"Skip all\" answers the next failure without asking (rc=" + std::to_string(second.first) + ")");
        const auto good = get(L"renamed.bin", FS_COPYFLAGS_OVERWRITE);
        Check(good.first == FS_FILE_OK && Sha256File(good.second) == expectedHash[samples[0].name],
              "the batch goes on: the next file arrives intact (rc=" + std::to_string(good.first) + ")");
        const auto moved = get(L"missing-3.bin", FS_COPYFLAGS_OVERWRITE | FS_COPYFLAGS_MOVE);
        Check(moved.first == FS_FILE_READERROR && responder.Answered() == 1,
              "a move keeps its read error, so its source is never deleted (rc=" + std::to_string(moved.first) + ")");
        g_plugin.StatusInfo(dirA.c_str(), FS_STATUS_END, FS_STATUS_OP_GET_MULTI);

        const auto single = get(L"missing-4.bin", FS_COPYFLAGS_OVERWRITE);
        Check(single.first == FS_FILE_READERROR && responder.Answered() == 1,
              "outside a batch the read error stands and nothing asks (rc=" + std::to_string(single.first) + ")");
        DeleteFileW(good.second.c_str());
    }

    if (textChecks) {
        // CRLF pairs straddle every chunk boundary the transfer code uses.
        std::string crlf;
        while (crlf.size() < 1500000)
            crlf += "line of text " + std::to_string(crlf.size()) + "\r\n";
        std::string lf;
        for (char c : crlf)
            if (c != '\r') lf += c;
        WriteFileBytes(local + L"text.txt", crlf);
        // Total Commander selects the transfer mode through this verb.
        std::wstring modeTarget = dir;
        g_plugin.ExecuteFileW(nullptr, modeTarget.data(), L"mode A");
        const int up = g_plugin.PutFileW((local + L"text.txt").c_str(), (dir + L"\\text.txt").c_str(), 0);
        entries = ListDir(dir, ok);
        const auto it = entries.find(L"text.txt");
        Check(up == FS_FILE_OK && it != entries.end() && it->second.size == lf.size(),
              "text upload stores LF line ends (" + std::to_string(lf.size()) + " bytes)");
        std::wstring target = back + L"text.txt";
        RemoteInfoStruct ri = InfoFor(dir, L"text.txt");
        const int get = g_plugin.GetFileW((dir + L"\\text.txt").c_str(), target.data(), FS_COPYFLAGS_OVERWRITE, &ri);
        Check(get == FS_FILE_OK && Sha256File(target) == Sha256File(local + L"text.txt"),
              "text download restores CRLF line ends");
        g_plugin.ExecuteFileW(nullptr, modeTarget.data(), L"mode I");
    }

    // Cleanup: only what this run created.
    entries = ListDir(dir, ok);
    for (const auto& e : entries)
        Check(g_plugin.DeleteFileW((dir + L"\\" + e.first).c_str()) == TRUE, "delete " + Narrow(e.first));
    Check(g_plugin.RemoveDirW(dir.c_str()) == TRUE, "remove the run directory");
    auto rootEntries = ListDir(root, ok);
    Check(ok && !rootEntries.count(runName), "the run directory is gone");

    const std::string sessionRoot = "\\" + Narrow(session);
    g_plugin.Disconnect(sessionRoot.c_str());
    Check(g_unexpectedPrompts == 0, "no unexpected prompts");

    std::printf("%d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}

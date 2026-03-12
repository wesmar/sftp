#include "global.h"
#include "PhpShellConsole.h"
#include "PhpAgentClient.h"
#include "PluginEntryPoints.h"
#include "ShellHistory.h"

#include <richedit.h>
#include <array>
#include <string>
#include <vector>
#include <algorithm>

namespace {

constexpr const char* kShellWndClass = "TcPhpShellConsoleWnd";
constexpr int IDC_SHELL_TERMINAL = 7001;
constexpr int kPadding = 8;

struct ShellConsoleState {
    tConnectSettings settings{};
    HWND hwndTerminal = nullptr;
    HFONT font = nullptr;
    WNDPROC oldTerminalProc = nullptr;
    COLORREF colorBack = RGB(0, 0, 0);
    COLORREF colorText = RGB(245, 245, 245);
    COLORREF colorPrompt = RGB(0, 220, 0);
    COLORREF colorCommand = RGB(255, 210, 40);
    std::vector<std::string> history;   // in-memory shadow (owned by shellHistory)
    ShellHistory shellHistory;          // persistent history manager
    size_t historyCursor = 0;
    LONG inputStart = 0;
    std::string promptUser;
    std::string promptHost;
    std::string promptCwd = ".";
};

static std::string ExtractHostFromServerUrl(const char* server)
{
    if (!server || !server[0])
        return "server";
    std::string s(server);
    size_t start = 0;
    size_t scheme = s.find("://");
    if (scheme != std::string::npos)
        start = scheme + 3;
    size_t end = s.find('/', start);
    if (end == std::string::npos)
        end = s.size();
    std::string hostPort = s.substr(start, end - start);
    if (hostPort.empty())
        return "server";
    return hostPort;
}

static std::string NormalizeUnixPath(std::string path)
{
    if (path.empty())
        return ".";
    const bool absolute = !path.empty() && path[0] == '/';
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= path.size()) {
        size_t slash = path.find('/', start);
        if (slash == std::string::npos)
            slash = path.size();
        std::string part = path.substr(start, slash - start);
        if (part.empty() || part == ".") {
            // ignore
        } else if (part == "..") {
            if (!parts.empty())
                parts.pop_back();
        } else {
            parts.push_back(part);
        }
        if (slash == path.size())
            break;
        start = slash + 1;
    }
    std::string out = absolute ? "/" : "";
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0)
            out.push_back('/');
        out += parts[i];
    }
    if (out.empty())
        return absolute ? "/" : ".";
    return out;
}

static std::string TrimSpaces(std::string value)
{
    size_t b = 0;
    size_t e = value.size();
    while (b < e && (value[b] == ' ' || value[b] == '\t'))
        ++b;
    while (e > b && (value[e - 1] == ' ' || value[e - 1] == '\t'))
        --e;
    return value.substr(b, e - b);
}

static bool StartsWith(const std::string& value, const std::string& prefix)
{
    if (prefix.size() > value.size())
        return false;
    return std::equal(prefix.begin(), prefix.end(), value.begin());
}

static bool IsNoisyShellLine(const std::string& line)
{
    return StartsWith(line, "[exit_code=");
}

static std::string ShellQuoteSingle(const std::string& text)
{
    std::string out = "'";
    for (char c : text) {
        if (c == '\'')
            out += "'\\''";
        else
            out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

static std::vector<std::string> SplitLines(const std::string& text)
{
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos)
            eol = text.size();
        std::string line = text.substr(pos, eol - pos);
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
        pos = eol + 1;
    }
    return out;
}

static std::string FilterShellDisplayNoise(const std::string& text)
{
    if (text.empty())
        return {};
    auto lines = SplitLines(text);
    std::string out;
    for (const auto& line : lines) {
        if (IsNoisyShellLine(line))
            continue;
        if (!out.empty())
            out += '\n';
        out += line;
    }
    return out;
}

static std::string LongestCommonPrefix(const std::vector<std::string>& values)
{
    if (values.empty())
        return {};
    std::string prefix = values.front();
    for (size_t i = 1; i < values.size() && !prefix.empty(); ++i) {
        const std::string& v = values[i];
        size_t n = 0;
        while (n < prefix.size() && n < v.size() && prefix[n] == v[n])
            ++n;
        prefix.resize(n);
    }
    return prefix;
}

static std::vector<std::string> FilterCompletionCandidates(const std::vector<std::string>& lines)
{
    std::vector<std::string> out;
    out.reserve(lines.size());
    for (const auto& line : lines) {
        if (line.empty())
            continue;
        if (line == "(no output)")
            continue;
        if (StartsWith(line, "[exit_code="))
            continue;
        if (StartsWith(line, "ls: "))
            continue;
        if (StartsWith(line, "[error]"))
            continue;
        if (IsNoisyShellLine(line))
            continue;
        out.push_back(line);
    }
    return out;
}

static std::string NormalizeForTerminal(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + 16);
    for (size_t i = 0; i < in.size(); ++i) {
        const char c = in[i];
        if (c == '\r') {
            out.push_back('\r');
            if (i + 1 < in.size() && in[i + 1] == '\n')
                out.push_back('\n');
            else
                out.push_back('\n');
        } else if (c == '\n') {
            if (i == 0 || in[i - 1] != '\r')
                out.push_back('\r');
            out.push_back('\n');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

static LONG GetTerminalLength(HWND h)
{
    if (!h)
        return 0;
    CHARRANGE oldSel{};
    SendMessageA(h, EM_EXGETSEL, 0, (LPARAM)&oldSel);
    SendMessageA(h, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    CHARRANGE endSel{};
    SendMessageA(h, EM_EXGETSEL, 0, (LPARAM)&endSel);
    SendMessageA(h, EM_EXSETSEL, 0, (LPARAM)&oldSel);
    return endSel.cpMin;
}

static void SetSelEnd(HWND h)
{
    LONG len = GetTerminalLength(h);
    SendMessageA(h, EM_SETSEL, (WPARAM)len, (LPARAM)len);
}

static void SetSelectionColor(HWND h, COLORREF color)
{
    CHARFORMAT2A cf{};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    SendMessageA(h, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
}

static void ColorRange(HWND h, LONG from, LONG to, COLORREF color)
{
    if (!h || to <= from)
        return;
    SendMessageA(h, EM_SETSEL, (WPARAM)from, (LPARAM)to);
    SetSelectionColor(h, color);
    SetSelEnd(h);
}

static void AppendTerminal(HWND h, const std::string& text, COLORREF color)
{
    if (!h || text.empty())
        return;
    SetSelEnd(h);
    SetSelectionColor(h, color);
    SendMessageA(h, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
}

static std::string BuildPromptText(const ShellConsoleState* s)
{
    const std::string user = s && !s->promptUser.empty() ? s->promptUser : "user";
    const std::string host = s && !s->promptHost.empty() ? s->promptHost : "server";
    const std::string cwd = s && !s->promptCwd.empty() ? s->promptCwd : ".";
    return user + "@" + host + ":" + cwd + "# ";
}

static void PrintPrompt(ShellConsoleState* s)
{
    if (!s || !s->hwndTerminal)
        return;
    const std::string prompt = BuildPromptText(s);
    AppendTerminal(s->hwndTerminal, prompt, s->colorPrompt);
    s->inputStart = GetTerminalLength(s->hwndTerminal);
    SetSelEnd(s->hwndTerminal);
    // Keep user input color distinct from prompt/output.
    SetSelectionColor(s->hwndTerminal, s->colorCommand);
}

static std::string GetCurrentInput(ShellConsoleState* s)
{
    if (!s || !s->hwndTerminal)
        return {};
    LONG total = GetTerminalLength(s->hwndTerminal);
    if (total <= s->inputStart)
        return {};
    CHARRANGE oldSel{};
    SendMessageA(s->hwndTerminal, EM_EXGETSEL, 0, (LPARAM)&oldSel);
    CHARRANGE range{};
    range.cpMin = s->inputStart;
    range.cpMax = total;
    SendMessageA(s->hwndTerminal, EM_EXSETSEL, 0, (LPARAM)&range);
    LONG bytes = total - s->inputStart;
    if (bytes < 0)
        bytes = 0;
    std::string input((size_t)bytes + 8, '\0');
    LRESULT copied = SendMessageA(s->hwndTerminal, EM_GETSELTEXT, 0, (LPARAM)input.data());
    SendMessageA(s->hwndTerminal, EM_EXSETSEL, 0, (LPARAM)&oldSel);
    if (copied > 0)
        input.resize((size_t)copied);
    else
        input.clear();
    while (!input.empty() && (input.back() == '\r' || input.back() == '\n'))
        input.pop_back();
    return input;
}

static void ReplaceCurrentInput(ShellConsoleState* s, const std::string& value)
{
    if (!s || !s->hwndTerminal)
        return;
    LONG total = GetTerminalLength(s->hwndTerminal);
    SendMessageA(s->hwndTerminal, EM_SETSEL, (WPARAM)s->inputStart, (LPARAM)total);
    SetSelectionColor(s->hwndTerminal, s->colorCommand);
    SendMessageA(s->hwndTerminal, EM_REPLACESEL, FALSE, (LPARAM)value.c_str());
    SetSelEnd(s->hwndTerminal);
    SetSelectionColor(s->hwndTerminal, s->colorCommand);
}

static void EnsureCaretInInput(ShellConsoleState* s)
{
    if (!s || !s->hwndTerminal)
        return;
    CHARRANGE cr{};
    SendMessageA(s->hwndTerminal, EM_EXGETSEL, 0, (LPARAM)&cr);
    if (cr.cpMin < s->inputStart || cr.cpMax < s->inputStart)
        SetSelEnd(s->hwndTerminal);
    SetSelectionColor(s->hwndTerminal, s->colorCommand);
}

static void RestorePromptAndInput(ShellConsoleState* s, const std::string& currentInput)
{
    PrintPrompt(s);
    if (!currentInput.empty())
        AppendTerminal(s->hwndTerminal, currentInput, s->colorCommand);
    SetSelEnd(s->hwndTerminal);
    SetSelectionColor(s->hwndTerminal, s->colorCommand);
}

static void ShowSuggestions(ShellConsoleState* s, const std::vector<std::string>& candidates, const std::string& currentInput)
{
    if (!s || !s->hwndTerminal)
        return;
    AppendTerminal(s->hwndTerminal, "\r\n", s->colorText);
    for (const auto& c : candidates) {
        AppendTerminal(s->hwndTerminal, c, s->colorText);
        AppendTerminal(s->hwndTerminal, "\r\n", s->colorText);
    }
    RestorePromptAndInput(s, currentInput);
}

static void ShowSuggestionsInline(ShellConsoleState* s, std::vector<std::string> candidates, const std::string& currentInput)
{
    if (!s || !s->hwndTerminal || candidates.empty())
        return;
    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
    AppendTerminal(s->hwndTerminal, "\r\n", s->colorText);
    std::string line;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (i > 0)
            line += "  ";
        line += candidates[i];
    }
    AppendTerminal(s->hwndTerminal, line, s->colorText);
    AppendTerminal(s->hwndTerminal, "\r\n", s->colorText);
    RestorePromptAndInput(s, currentInput);
}

static bool CompleteInput(ShellConsoleState* s)
{
    if (!s || !s->hwndTerminal)
        return false;

    std::string input = GetCurrentInput(s);
    std::string trimmed = TrimSpaces(input);
    if (trimmed.empty())
        return false;

    const size_t lastSpace = input.find_last_of(" \t");
    const bool firstToken = (lastSpace == std::string::npos);

    if (firstToken) {
        static const std::array<const char*, 14> kCmds = {
            "pwd", "cd", "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "find", "grep", "clear", "exit", "logout"
        };
        std::vector<std::string> matches;
        for (const auto* cmd : kCmds) {
            std::string c(cmd);
            if (StartsWith(c, trimmed))
                matches.push_back(c);
        }
        if (matches.empty())
            return false;
        if (matches.size() == 1) {
            ReplaceCurrentInput(s, matches[0]);
            return true;
        }
        const std::string lcp = LongestCommonPrefix(matches);
        if (!lcp.empty() && lcp.size() > trimmed.size()) {
            ReplaceCurrentInput(s, lcp);
            return true;
        }
        ShowSuggestionsInline(s, matches, input);
        return true;
    }

    const std::string token = input.substr(lastSpace + 1);
    if (token.empty())
        return false;

    std::string remoteListCmd =
        "find . -maxdepth 1 -mindepth 1 -name " + ShellQuoteSingle(token + "*") +
        " -exec basename {} \\; 2>/dev/null";
    std::string output;
    std::string cwdAbs;
    int rc = PhpShellExecuteCommand(&s->settings, remoteListCmd.c_str(), output, &cwdAbs, &s->promptCwd);
    if (rc != SFTP_OK)
        return false;
    if (!cwdAbs.empty())
        s->promptCwd = cwdAbs;

    auto matches = FilterCompletionCandidates(SplitLines(output));
    if (matches.empty())
        return false;
    if (matches.size() == 1) {
        std::string replaced = input.substr(0, lastSpace + 1) + matches[0];
        ReplaceCurrentInput(s, replaced);
        return true;
    }
    const std::string lcp = LongestCommonPrefix(matches);
    if (!lcp.empty() && lcp.size() > token.size()) {
        std::string replaced = input.substr(0, lastSpace + 1) + lcp;
        ReplaceCurrentInput(s, replaced);
        return true;
    }
    ShowSuggestionsInline(s, matches, input);
    return true;
}

static void ShowTerminalContextMenu(ShellConsoleState* s, HWND hwnd, int x, int y)
{
    if (!s || !hwnd)
        return;
    if (x == -1 && y == -1) {
        POINT pt{};
        GetCaretPos(&pt);
        ClientToScreen(hwnd, &pt);
        x = pt.x;
        y = pt.y;
    }

    HMENU menu = CreatePopupMenu();
    if (!menu)
        return;
    AppendMenuA(menu, MF_STRING, 1, "Copy");
    AppendMenuA(menu, MF_STRING, 2, "Paste");
    AppendMenuA(menu, MF_STRING, 3, "Select all");

    const UINT cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, x, y, 0, hwnd, nullptr);
    switch (cmd) {
    case 1:
        SendMessageA(hwnd, WM_COPY, 0, 0);
        break;
    case 2:
        EnsureCaretInInput(s);
        SendMessageA(hwnd, WM_PASTE, 0, 0);
        break;
    case 3:
        SendMessageA(hwnd, EM_SETSEL, 0, -1);
        break;
    default:
        break;
    }
    DestroyMenu(menu);
}

static void ExecuteCommand(ShellConsoleState* s)
{
    if (!s || !s->hwndTerminal)
        return;

    const LONG cmdStart = s->inputStart;
    const LONG cmdEnd = GetTerminalLength(s->hwndTerminal);
    ColorRange(s->hwndTerminal, cmdStart, cmdEnd, s->colorCommand);

    std::string cmd = TrimSpaces(GetCurrentInput(s));
    AppendTerminal(s->hwndTerminal, "\r\n", s->colorText);

    if (cmd.empty()) {
        PrintPrompt(s);
        return;
    }

    if (cmd == "exit" || cmd == "logout") {
        DestroyWindow(GetParent(s->hwndTerminal));
        return;
    }

    if (cmd == "clear" || cmd == "cls") {
        SetWindowTextA(s->hwndTerminal, "");
        PrintPrompt(s);
        return;
    }

    // Clear command history (in memory and on disk).
    if (cmd == "history -c" || cmd == "clear history") {
        s->shellHistory.Clear();
        s->history.clear();
        s->historyCursor = 0;
        AppendTerminal(s->hwndTerminal, "History cleared.\r\n", s->colorText);
        PrintPrompt(s);
        return;
    }

    // Add to persistent history; then sync the local shadow vector used for navigation.
    s->shellHistory.Add(cmd);
    s->history = s->shellHistory.Entries(); // keep shadow in sync
    s->historyCursor = s->history.size();

    bool isCdCommand = false;
    std::string requestedCwd = s->promptCwd;
    if (cmd == "cd" || cmd.rfind("cd ", 0) == 0) {
        isCdCommand = true;
        std::string arg = (cmd.size() <= 2) ? std::string(".") : TrimSpaces(cmd.substr(2));
        if (arg.empty())
            arg = ".";
        if (!arg.empty() && arg[0] == '/') {
            requestedCwd = NormalizeUnixPath(arg);
        } else {
            std::string base = s->promptCwd.empty() ? "." : s->promptCwd;
            if (base == ".")
                requestedCwd = NormalizeUnixPath(arg);
            else
                requestedCwd = NormalizeUnixPath(base + "/" + arg);
        }
    }

    std::string output;
    std::string cwdAbs;
    const std::string* cwdArg = requestedCwd.empty() ? nullptr : &requestedCwd;
    const char* remoteCmd = isCdCommand ? "pwd" : cmd.c_str();
    int rc = PhpShellExecuteCommand(&s->settings, remoteCmd, output, &cwdAbs, cwdArg);
    if (rc == SFTP_OK && !cwdAbs.empty())
        s->promptCwd = cwdAbs;

    output = FilterShellDisplayNoise(output);

    if (rc != SFTP_OK) {
        if (output.empty())
            output = "Shell command execution failed.";
        AppendTerminal(s->hwndTerminal, "[error] ", s->colorText);
        AppendTerminal(s->hwndTerminal, NormalizeForTerminal(output), s->colorText);
        AppendTerminal(s->hwndTerminal, "\r\n", s->colorText);
    } else if (!isCdCommand) {
        if (!output.empty()) {
            std::string norm = NormalizeForTerminal(output);
            AppendTerminal(s->hwndTerminal, norm, s->colorText);
            if (norm.empty() || norm.back() != '\n')
                AppendTerminal(s->hwndTerminal, "\r\n", s->colorText);
        }
    }

    PrintPrompt(s);
}

static LRESULT CALLBACK TerminalEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    auto* s = reinterpret_cast<ShellConsoleState*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));
    if (!s || !s->oldTerminalProc)
        return DefWindowProcA(hwnd, msg, wParam, lParam);

    switch (msg) {
    case WM_GETDLGCODE:
        return DLGC_WANTALLKEYS | DLGC_WANTCHARS | DLGC_WANTTAB;
    case WM_KEYDOWN:
    {
        if (wParam == VK_CONTROL || wParam == VK_SHIFT || wParam == VK_MENU) {
            // Modifier-only key press must not alter selection/caret.
            return CallWindowProcA(s->oldTerminalProc, hwnd, msg, wParam, lParam);
        }
        const bool ctrlDown = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
        if (ctrlDown) {
            if (wParam == 'C' || wParam == VK_INSERT) {
                SendMessageA(hwnd, WM_COPY, 0, 0);
                return 0;
            }
            if (wParam == 'V') {
                // Paste always goes to current input area.
                EnsureCaretInInput(s);
                SendMessageA(hwnd, WM_PASTE, 0, 0);
                return 0;
            }
            if (wParam == 'A') {
                // Select all output.
                SendMessageA(hwnd, EM_SETSEL, 0, -1);
                return 0;
            }
        }

        EnsureCaretInInput(s);
        switch (wParam) {
        case VK_RETURN:
            ExecuteCommand(s);
            return 0;
        case VK_TAB:
            CompleteInput(s);
            return 0;
        case VK_BACK:
        {
            CHARRANGE cr{};
            SendMessageA(hwnd, EM_EXGETSEL, 0, (LPARAM)&cr);
            if (cr.cpMin <= s->inputStart && cr.cpMax <= s->inputStart)
                return 0;
            if (cr.cpMin == cr.cpMax) {
                if (cr.cpMin <= s->inputStart)
                    return 0;
                SendMessageA(hwnd, EM_SETSEL, (WPARAM)(cr.cpMin - 1), (LPARAM)cr.cpMin);
                SendMessageA(hwnd, EM_REPLACESEL, FALSE, (LPARAM)"");
                return 0;
            }
            LONG from = std::max<LONG>(s->inputStart, cr.cpMin);
            LONG to = std::max<LONG>(from, cr.cpMax);
            SendMessageA(hwnd, EM_SETSEL, (WPARAM)from, (LPARAM)to);
            SendMessageA(hwnd, EM_REPLACESEL, FALSE, (LPARAM)"");
            return 0;
        }
        case VK_LEFT:
        {
            CHARRANGE cr{};
            SendMessageA(hwnd, EM_EXGETSEL, 0, (LPARAM)&cr);
            if (cr.cpMin <= s->inputStart && cr.cpMax <= s->inputStart)
                return 0;
            break;
        }
        case VK_HOME:
            SendMessageA(hwnd, EM_SETSEL, (WPARAM)s->inputStart, (LPARAM)s->inputStart);
            return 0;
        case VK_UP:
            if (!s->history.empty() && s->historyCursor > 0) {
                s->historyCursor--;
                ReplaceCurrentInput(s, s->history[s->historyCursor]);
            }
            return 0;
        case VK_DOWN:
            if (s->historyCursor + 1 < s->history.size()) {
                s->historyCursor++;
                ReplaceCurrentInput(s, s->history[s->historyCursor]);
            } else {
                s->historyCursor = s->history.size();
                ReplaceCurrentInput(s, "");
            }
            return 0;
        }
        break;
    }
    case WM_CHAR:
        if (wParam == '\t')
            return 0;
        EnsureCaretInInput(s);
        break;
    case WM_PASTE:
        EnsureCaretInInput(s);
        break;
    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_MOUSEMOVE:
    case WM_LBUTTONDBLCLK:
        // Keep native mouse selection behavior.
        return CallWindowProcA(s->oldTerminalProc, hwnd, msg, wParam, lParam);
    case WM_RBUTTONUP:
    {
        POINT pt{};
        GetCursorPos(&pt);
        ShowTerminalContextMenu(s, hwnd, pt.x, pt.y);
        return 0;
    }
    case WM_CONTEXTMENU:
        ShowTerminalContextMenu(s, hwnd, (int)(short)LOWORD(lParam), (int)(short)HIWORD(lParam));
        return 0;
    }

    return CallWindowProcA(s->oldTerminalProc, hwnd, msg, wParam, lParam);
}

static void LayoutControls(HWND hwnd, ShellConsoleState* s)
{
    if (!hwnd || !s || !s->hwndTerminal)
        return;
    RECT rc{};
    GetClientRect(hwnd, &rc);
    MoveWindow(s->hwndTerminal, kPadding, kPadding,
               (rc.right - rc.left) - (kPadding * 2),
               (rc.bottom - rc.top) - (kPadding * 2), TRUE);
}

static void InitializeConsoleUi(HWND hwnd, ShellConsoleState* s)
{
    LoadLibraryA("Riched20.dll");

    s->promptUser = "root";
    s->promptHost = ExtractHostFromServerUrl(s->settings.server.c_str());

    s->font = CreateFontA(
        -18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        FF_MODERN, "Consolas");

    s->hwndTerminal = CreateWindowExA(
        WS_EX_CLIENTEDGE, RICHEDIT_CLASSA, "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | ES_NOHIDESEL,
        0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)IDC_SHELL_TERMINAL, hinst, nullptr);

    if (s->font)
        SendMessageA(s->hwndTerminal, WM_SETFONT, (WPARAM)s->font, TRUE);

    SendMessageA(s->hwndTerminal, EM_SETBKGNDCOLOR, 0, (LPARAM)s->colorBack);

    CHARFORMAT2A cf{};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = s->colorText;
    SendMessageA(s->hwndTerminal, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

    SetSelectionColor(s->hwndTerminal, s->colorText);
    SendMessageA(s->hwndTerminal, EM_SETLIMITTEXT, (WPARAM)0x7FFFFFFE, 0);

    SetWindowLongPtrA(s->hwndTerminal, GWLP_USERDATA, (LONG_PTR)s);
    s->oldTerminalProc = (WNDPROC)SetWindowLongPtrA(s->hwndTerminal, GWLP_WNDPROC, (LONG_PTR)TerminalEditProc);

    LayoutControls(hwnd, s);

    // Load persistent history from disk; initialize the navigation shadow vector.
    s->shellHistory.Load();
    s->history = s->shellHistory.Entries();
    s->historyCursor = s->history.size();

    AppendTerminal(s->hwndTerminal, "PHP Shell Console ready.\r\n", s->colorText);
    AppendTerminal(s->hwndTerminal, "Type commands and press Enter. Use Up/Down for history. Type 'history -c' to clear history.\r\n\r\n", s->colorText);
    PrintPrompt(s);
    SetFocus(s->hwndTerminal);
}

static void DestroyConsoleUi(ShellConsoleState* s)
{
    if (!s)
        return;
    if (s->oldTerminalProc && s->hwndTerminal)
        SetWindowLongPtrA(s->hwndTerminal, GWLP_WNDPROC, (LONG_PTR)s->oldTerminalProc);
    if (s->font)
        DeleteObject(s->font);
    s->font = nullptr;
}

static LRESULT CALLBACK ShellWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    auto* s = reinterpret_cast<ShellConsoleState*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE:
    {
        auto* cs = reinterpret_cast<CREATESTRUCTA*>(lParam);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, (LONG_PTR)cs->lpCreateParams);
        return TRUE;
    }
    case WM_CREATE:
        s = reinterpret_cast<ShellConsoleState*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));
        if (s)
            InitializeConsoleUi(hwnd, s);
        return 0;
    case WM_SIZE:
        if (s)
            LayoutControls(hwnd, s);
        return 0;
    case WM_SETFOCUS:
        if (s && s->hwndTerminal)
            SetFocus(s->hwndTerminal);
        return 0;
    case WM_ACTIVATE:
        if (s && s->hwndTerminal && LOWORD(wParam) == WA_ACTIVE) {
            SetFocus(s->hwndTerminal);
            EnsureCaretInInput(s);
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_NCDESTROY:
        if (s) {
            DestroyConsoleUi(s);
            delete s;
            SetWindowLongPtrA(hwnd, GWLP_USERDATA, 0);
        }
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static bool EnsureClassRegistered()
{
    static bool registered = false;
    if (registered)
        return true;

    WNDCLASSEXA wc{};
    wc.cbSize = sizeof(wc);
    wc.hInstance = hinst;
    wc.lpfnWndProc = ShellWndProc;
    wc.lpszClassName = kShellWndClass;
    wc.hCursor = LoadCursor(nullptr, IDC_IBEAM);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    if (!RegisterClassExA(&wc))
        return false;
    registered = true;
    return true;
}

} // namespace

void ShowPhpShellConsole(HWND owner, tConnectSettings settings)
{
    if (!EnsureClassRegistered())
        return;

    auto* s = new ShellConsoleState();
    s->settings = std::move(settings);

    HWND hwnd = CreateWindowExA(
        WS_EX_APPWINDOW,
        kShellWndClass,
        "PHP Shell Console",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 960, 620,
        nullptr, nullptr, hinst, s);
    if (!hwnd) {
        delete s;
        return;
    }
    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
}

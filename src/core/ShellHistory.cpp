#include "global.h"
#include "ShellHistory.h"

#include <shlobj.h>     // SHGetFolderPathA / CSIDL_APPDATA
#include <fstream>
#include <algorithm>

// ---------------------------------------------------------------------------
// ShellHistory implementation
// ---------------------------------------------------------------------------

ShellHistory::ShellHistory() = default;

// static
std::string ShellHistory::ResolveFilePath()
{
    // Obtain %APPDATA% via the shell API so we respect roaming profile paths.
    char appDataPath[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, appDataPath)))
    {
        // Fallback: read the environment variable directly.
        DWORD n = GetEnvironmentVariableA("APPDATA", appDataPath, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return {};
    }

    // Build the plugin subdirectory path and ensure it exists.
    // Total Commander stores all its plugin data under %APPDATA%\GHISLER.
    std::string dir = std::string(appDataPath) + "\\GHISLER";
    CreateDirectoryA(dir.c_str(), nullptr); // no-op if it already exists

    return dir + "\\shell_history.txt";
}

void ShellHistory::Load()
{
    if (loaded_)
        return;
    loaded_ = true;

    filePath_ = ResolveFilePath();
    if (filePath_.empty())
        return;

    std::ifstream in(filePath_);
    if (!in.is_open())
        return; // file doesn't exist yet — that's fine

    std::string line;
    while (std::getline(in, line))
    {
        // Strip trailing CR so the file works on both Unix and Windows line endings.
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        if (!line.empty())
            entries_.push_back(std::move(line));
    }

    // If the file somehow grew beyond the limit (e.g. manual edits), trim it now.
    if (entries_.size() > kMaxEntries)
    {
        entries_.erase(entries_.begin(),
                       entries_.begin() + static_cast<std::ptrdiff_t>(entries_.size() - kMaxEntries));
        Rewrite();
    }
}

void ShellHistory::Add(const std::string& cmd)
{
    if (cmd.empty())
        return;

    // Suppress consecutive duplicate entries (same behaviour as bash HISTCONTROL=ignoredups).
    if (!entries_.empty() && entries_.back() == cmd)
        return;

    entries_.push_back(cmd);

    // Enforce ring-buffer capacity — trim oldest entry from the front.
    if (entries_.size() > kMaxEntries)
        entries_.erase(entries_.begin());

    // Persist immediately: rewrite the whole file (128 lines ≈ a few kB — negligible).
    Rewrite();
}

void ShellHistory::Clear()
{
    entries_.clear();

    if (!filePath_.empty())
        DeleteFileA(filePath_.c_str());
}

void ShellHistory::Rewrite() const
{
    if (filePath_.empty())
        return;

    // Write a temporary file first, then rename — avoids corrupt history on a crash/power-loss.
    std::string tmp = filePath_ + ".tmp";

    {
        std::ofstream out(tmp, std::ios::out | std::ios::trunc);
        if (!out.is_open())
        {
            // If we can't write the temp file, try writing directly.
            std::ofstream direct(filePath_, std::ios::out | std::ios::trunc);
            if (!direct.is_open())
                return;
            for (const auto& entry : entries_)
                direct << entry << '\n';
            return;
        }
        for (const auto& entry : entries_)
            out << entry << '\n';
    } // out is flushed and closed here

    // Atomic rename (on the same volume this is a metadata-only operation on NTFS).
    MoveFileExA(tmp.c_str(), filePath_.c_str(), MOVEFILE_REPLACE_EXISTING);
}

#pragma once

#include <string>
#include <vector>

// Persistent shell command history backed by a plain-text file.
//
// Storage location: %APPDATA%\sftpplug\shell_history.txt
// Capacity       : kMaxEntries (128) most-recent unique commands.
//
// Design decisions:
//  - Separate file from the INI config: history is transient runtime data,
//    not configuration; mixing it into the INI would complicate parsing and
//    risk corrupting connection profiles.
//  - Full rewrite on every Add(): 128 lines is trivially small (~a few kB);
//    this avoids stale-line edge cases that arise with pure-append strategies
//    when the ring wraps around.
//  - Load once at session start, write on every accepted command.
class ShellHistory
{
public:
    static constexpr size_t kMaxEntries = 128;

    ShellHistory();

    // Load history from disk. Safe to call multiple times (no-op after first call).
    void Load();

    // Append a command. Consecutive duplicates are suppressed.
    // Trims to kMaxEntries and rewrites the backing file immediately.
    void Add(const std::string& cmd);

    // Erase all entries in memory and delete the history file.
    void Clear();

    // Read-only access to the ordered list of commands (oldest first).
    const std::vector<std::string>& Entries() const { return entries_; }

private:
    std::vector<std::string> entries_;
    std::string              filePath_;
    bool                     loaded_ = false;

    // Resolve %APPDATA%\sftpplug\shell_history.txt; creates the directory if needed.
    static std::string ResolveFilePath();

    // Overwrite the backing file with the current entries_ contents.
    void Rewrite() const;
};

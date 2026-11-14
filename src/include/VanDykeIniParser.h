#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace sftp {

// One key/value pair from a VanDyke .ini file.
// Type letter (S/D/Z/B) is preserved because our field lookup uses it to
// distinguish e.g. an empty S:"key"="" from an absent one.
enum class VanDykeValueType {
    String,          // S:"key"=value
    DWord,           // D:"key"=00000000 (8 hex digits)
    Zero,            // Z:"key"=<count> (marker; payload skipped)
    Blob             // B:"key"=<size>\n hex bytes (payload skipped)
};

struct VanDykeEntry {
    VanDykeValueType type  = VanDykeValueType::String;
    std::string      value;   // Raw string for String; hex text for DWord;
                              // empty for Zero and Blob (payload discarded)
};

// Parsed representation of a single VanDyke .ini file, keyed by the field
// name inside quotes (e.g. "Hostname", "[SSH2] Port").
using VanDykeFile = std::unordered_map<std::string, VanDykeEntry>;

// Parse a VanDyke .ini file from disk. Handles UTF-8 BOM, CRLF/LF, multi-line
// B:/Z: continuations (payload dropped). Returns empty map on I/O failure.
VanDykeFile ParseVanDykeFile(const std::string& path);

// Parse from an already-loaded UTF-8 buffer. Public for testability.
VanDykeFile ParseVanDykeContent(std::string_view content);

// Convenience getters. Return default if key absent or of wrong type.
std::string GetString(const VanDykeFile& file, std::string_view key,
                      std::string_view defaultValue = "") noexcept;
uint32_t    GetDWord (const VanDykeFile& file, std::string_view key,
                      uint32_t defaultValue = 0) noexcept;

}  // namespace sftp

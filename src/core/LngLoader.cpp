// LngLoader.cpp — loads external language\XX.lng translation files at runtime.
//
// File format (UTF-8, one entry per line):
//   ID=text
// where ID is the numeric resource id, and text uses RC-style escape sequences:
//   \n  \r  \t  \\
// Lines starting with # are comments; blank lines are ignored.
//
// Deployment layout (inside the plugin ZIP / install dir):
//   language\pol.lng   (Polish)
//   language\deu.lng   (German)
//   language\fra.lng   (French)
//   language\esp.lng   (Spanish)
//   language\ita.lng   (Italian)
//   language\rus.lng   (Russian)
//   language\cs.lng    (Czech)
//   language\hu.lng    (Hungarian)
//   language\ja.lng    (Japanese)
//   language\nl.lng    (Dutch)
//   language\pt-br.lng (Portuguese — Brazil)
//   language\ro.lng    (Romanian)
//   language\sk.lng    (Slovak)
//   language\uk.lng    (Ukrainian)
//   language\zh-cn.lng (Chinese Simplified)

#include <windows.h>
#include <string>
#include <unordered_map>
#include <array>
#include "LngLoader.h"

// Map from resource id to translated string value.
static std::unordered_map<UINT, std::string> g_lngMap;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static std::string UnescapeRcString(const std::string& raw)
{
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] == '\\' && i + 1 < raw.size()) {
            switch (raw[i + 1]) {
            case 'n':  out += '\n'; ++i; break;
            case 'r':  out += '\r'; ++i; break;
            case 't':  out += '\t'; ++i; break;
            case '\\': out += '\\'; ++i; break;
            default:   out += raw[i]; break;
            }
        } else {
            out += raw[i];
        }
    }
    return out;
}

static bool ParseLngLine(const std::string& line, UINT& outId, std::string& outText)
{
    if (line.empty() || line[0] == '#')
        return false;

    const size_t eq = line.find('=');
    if (eq == std::string::npos || eq == 0)
        return false;

    char* endPtr = nullptr;
    const unsigned long id = strtoul(line.c_str(), &endPtr, 10);
    if (endPtr != line.c_str() + eq)
        return false;

    outId   = static_cast<UINT>(id);
    outText = UnescapeRcString(line.substr(eq + 1));
    return true;
}

// Map LANGID to the lng filename stem used in language\XX.lng filenames.
// Simple 3-letter codes match TC's own .LNG stems (WCMD_POL.LNG → "pol").
// Languages with multiple regional variants are handled before the switch.
static const char* LangIdToTcCode(LANGID id) noexcept
{
    // Sublanguage disambiguation for Portuguese and Chinese
    if (PRIMARYLANGID(id) == LANG_PORTUGUESE)
        return (SUBLANGID(id) == SUBLANG_PORTUGUESE_BRAZILIAN) ? "pt-br" : nullptr;
    if (PRIMARYLANGID(id) == LANG_CHINESE)
        return (SUBLANGID(id) == SUBLANG_CHINESE_SIMPLIFIED)   ? "zh-cn" : nullptr;

    switch (PRIMARYLANGID(id)) {
    case LANG_POLISH:     return "pol";
    case LANG_GERMAN:     return "deu";
    case LANG_FRENCH:     return "fra";
    case LANG_SPANISH:    return "esp";
    case LANG_ITALIAN:    return "ita";
    case LANG_RUSSIAN:    return "rus";
    case LANG_CZECH:      return "cs";
    case LANG_HUNGARIAN:  return "hu";
    case LANG_JAPANESE:   return "ja";
    case LANG_DUTCH:      return "nl";
    case LANG_ROMANIAN:   return "ro";
    case LANG_SLOVAK:     return "sk";
    case LANG_UKRAINIAN:  return "uk";
    default:              return nullptr;
    }
}

// ---------------------------------------------------------------------------
// Internal file loader
// ---------------------------------------------------------------------------

static void LoadLngFromPath(const std::string& lngPath) noexcept
{
    HANDLE hFile = CreateFileA(lngPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    const DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return;
    }

    std::string content(fileSize, '\0');
    DWORD bytesRead = 0;
    const BOOL ok = ReadFile(hFile, content.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);
    if (!ok)
        return;
    content.resize(bytesRead);

    // Strip UTF-8 BOM if present
    if (content.size() >= 3 &&
        static_cast<unsigned char>(content[0]) == 0xEF &&
        static_cast<unsigned char>(content[1]) == 0xBB &&
        static_cast<unsigned char>(content[2]) == 0xBF)
    {
        content.erase(0, 3);
    }

    // Parse line by line (handle both CRLF and LF)
    size_t pos = 0;
    while (pos < content.size()) {
        size_t end = content.find('\n', pos);
        if (end == std::string::npos)
            end = content.size();

        std::string line = content.substr(pos, end - pos);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        UINT id = 0;
        std::string text;
        if (ParseLngLine(line, id, text))
            g_lngMap.emplace(id, std::move(text));

        pos = end + 1;
    }
}

static std::string GetPluginLangDir(HINSTANCE hPluginInst) noexcept
{
    std::array<char, MAX_PATH> dllPath{};
    if (GetModuleFileNameA(hPluginInst, dllPath.data(),
                           static_cast<DWORD>(dllPath.size()) - 1) == 0)
        return {};
    char* lastSlash = strrchr(dllPath.data(), '\\');
    if (!lastSlash)
        return {};
    lastSlash[1] = '\0';
    return std::string(dllPath.data()) + "language\\";
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void LngLoadForLanguage(LANGID langId, HINSTANCE hPluginInst) noexcept
{
    g_lngMap.clear();

    const char* code = LangIdToTcCode(langId);
    if (!code)
        return;  // English or unknown — use built-in RC strings

    const std::string dir = GetPluginLangDir(hPluginInst);
    if (dir.empty())
        return;

    LoadLngFromPath(dir + code + ".lng");
}

void LngLoadByCode(const char* code, HINSTANCE hPluginInst) noexcept
{
    g_lngMap.clear();

    if (!code || !code[0])
        return;

    const std::string dir = GetPluginLangDir(hPluginInst);
    if (dir.empty())
        return;

    LoadLngFromPath(dir + code + ".lng");
}

const char* LngGetString(UINT id) noexcept
{
    const auto it = g_lngMap.find(id);
    if (it == g_lngMap.end())
        return nullptr;
    return it->second.c_str();
}

bool LngLoadStringW(HINSTANCE hInst, UINT id, WCHAR* buf, int bufLen) noexcept
{
    if (!buf || bufLen <= 0)
        return false;
    const char* utf8 = LngGetString(id);
    if (utf8) {
        int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, buf, bufLen);
        return n > 0;
    }
    return LoadStringW(hInst, id, buf, bufLen) > 0;
}

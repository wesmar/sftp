#include "global.h"
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>
#include "ConnectionDialog.h"

#pragma comment(lib, "bcrypt.lib")

static std::string BytesToHexLower(const BYTE* data, size_t len)
{
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = kHex[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

static bool GenerateRandomHex(size_t bytesCount, std::string& outHex)
{
    if (bytesCount == 0)
        return false;
    std::vector<BYTE> bytes(bytesCount);
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return false;
    outHex = BytesToHexLower(bytes.data(), bytes.size());
    return true;
}

static bool ComputeSha256Hex(const std::string& input, std::string& outHex)
{
    struct AlgCloser {
        void operator()(void* h) const noexcept {
            if (h) {
                BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(h), 0);
            }
        }
    };
    struct HashCloser {
        void operator()(void* h) const noexcept {
            if (h) {
                BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(h));
            }
        }
    };
    struct HeapBufferCloser {
        void operator()(BYTE* p) const noexcept {
            if (p) {
                HeapFree(GetProcessHeap(), 0, p);
            }
        }
    };

    BCRYPT_ALG_HANDLE hAlgRaw = nullptr;
    DWORD objLen = 0;
    DWORD cb = 0;
    DWORD hashLen = 0;

    if (BCryptOpenAlgorithmProvider(&hAlgRaw, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return false;
    }
    std::unique_ptr<void, AlgCloser> hAlg(hAlgRaw);

    if (BCryptGetProperty(static_cast<BCRYPT_ALG_HANDLE>(hAlg.get()), BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cb, 0) != 0) {
        return false;
    }
    if (BCryptGetProperty(static_cast<BCRYPT_ALG_HANDLE>(hAlg.get()), BCRYPT_HASH_LENGTH,
                          reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cb, 0) != 0) {
        return false;
    }

    std::unique_ptr<BYTE, HeapBufferCloser> obj(
        static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, objLen)));
    if (!obj) {
        return false;
    }

    BCRYPT_HASH_HANDLE hHashRaw = nullptr;
    if (BCryptCreateHash(static_cast<BCRYPT_ALG_HANDLE>(hAlg.get()), &hHashRaw,
                         obj.get(), objLen, nullptr, 0, 0) != 0) {
        return false;
    }
    std::unique_ptr<void, HashCloser> hHash(hHashRaw);

    if (BCryptHashData(static_cast<BCRYPT_HASH_HANDLE>(hHash.get()),
                       reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                       static_cast<ULONG>(input.size()), 0) != 0) {
        return false;
    }

    std::vector<BYTE> hash(hashLen);
    if (BCryptFinishHash(static_cast<BCRYPT_HASH_HANDLE>(hHash.get()),
                         hash.data(), static_cast<ULONG>(hash.size()), 0) != 0) {
        return false;
    }
    outHex = BytesToHexLower(hash.data(), hash.size());
    return true;
}

static bool ReadTextFileUtf8(const std::string& path, std::string& outText)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return false;
    outText.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

static bool WriteTextFileUtf8(const std::string& path, const std::string& text)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out)
        return false;
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    return out.good();
}

static bool ReplacePhpSingleQuotedConst(std::string& script, const char* constName, const std::string& newValue)
{
    std::string needle = "const ";
    needle += constName;
    needle += " = '";
    size_t pos = script.find(needle);
    if (pos == std::string::npos)
        return false;
    size_t valueStart = pos + needle.size();
    size_t valueEnd = script.find("';", valueStart);
    if (valueEnd == std::string::npos)
        return false;
    script.replace(valueStart, valueEnd - valueStart, newValue);
    return true;
}

bool UpdateLocalPhpAgentScriptWithPassword(LPCSTR plainPassword)
{
    if (!plainPassword || !plainPassword[0])
        return false;

    std::string pluginDir;
    if (!GetPluginDirectoryA(pluginDir) || pluginDir.empty())
        return false;

    std::string scriptPath = pluginDir + "\\sftp.php";
    std::string script;
    if (!ReadTextFileUtf8(scriptPath, script))
        return false;

    std::string salt;
    std::string hashHex;
    {
        if (!GenerateRandomHex(16, salt))
            return false;
        // Must match PHP agent verifier: hash('sha256', AGENT_PSK_SALT . ':' . candidate)
        std::string material = salt;
        material += ":";
        material += plainPassword;
        if (!ComputeSha256Hex(material, hashHex))
            return false;
    }

    static constexpr const char* kPhpAgentDefaultPskPlaceholder = "CHANGE_ME_TO_LONG_RANDOM_SECRET";
    bool ok = true;
    ok = ReplacePhpSingleQuotedConst(script, "AGENT_PSK", kPhpAgentDefaultPskPlaceholder) && ok;
    ok = ReplacePhpSingleQuotedConst(script, "AGENT_PSK_SALT", salt) && ok;
    ok = ReplacePhpSingleQuotedConst(script, "AGENT_PSK_SHA256", hashHex) && ok;
    if (!ok)
        return false;

    return WriteTextFileUtf8(scriptPath, script);
}

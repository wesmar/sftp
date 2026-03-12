#include "global.h"
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <optional>
#include <memory>
#include "SftpInternal.h"
#include "PluginEntryPoints.h"

namespace {

// RAII wrapper for CryptProtectData / CryptUnprotectData
// Manages DATA_BLOB memory allocated by Windows Crypto API (LocalAlloc/LocalFree)
class DataBlob {
public:
    DataBlob() noexcept : blob_{} {}
    
    ~DataBlob() { 
        // CryptProtectData/CryptUnprotectData allocate output via LocalAlloc
        if (blob_.pbData) {
            SecureZeroMemory(blob_.pbData, blob_.cbData);
            LocalFree(blob_.pbData); 
        }
    }

    DATA_BLOB* get() noexcept { return &blob_; }
    const DATA_BLOB* get() const noexcept { return &blob_; }
    
    // Encrypt plain text - allocates blob_.pbData via CryptProtectData
    bool encrypt(const std::string& plain) {
        DATA_BLOB in{ static_cast<DWORD>(plain.size()), reinterpret_cast<BYTE*>(const_cast<char*>(plain.data())) };
        return CryptProtectData(&in, L"SFTP Password", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &blob_) != FALSE;
    }

    // Decrypt - returns decrypted string, caller doesn't own memory
    std::optional<std::string> decrypt() const {
        DATA_BLOB in = blob_;
        DATA_BLOB out{};
        if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
            return std::nullopt;
        std::string result(reinterpret_cast<char*>(out.pbData), out.cbData);
        SecureZeroMemory(out.pbData, out.cbData);
        LocalFree(out.pbData);
        return result;
    }

private:
    DATA_BLOB blob_{};
};

// Base64 encoding/decoding using Windows CryptoAPI
class Base64 {
public:
    static std::optional<std::string> Encode(const std::vector<BYTE>& data) {
        DWORD needed = 0;
        if (!CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &needed))
            return std::nullopt;
        std::string result(needed, '\0');
        if (!CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, result.data(), &needed))
            return std::nullopt;
        result.resize(needed - 1); // remove null terminator
        return result;
    }

    static std::optional<std::vector<BYTE>> Decode(std::string_view b64) {
        DWORD needed = 0;
        if (!CryptStringToBinaryA(b64.data(), static_cast<DWORD>(b64.size()), CRYPT_STRING_BASE64, nullptr, &needed, nullptr, nullptr))
            return std::nullopt;
        std::vector<BYTE> result(needed);
        if (!CryptStringToBinaryA(b64.data(), static_cast<DWORD>(b64.size()), CRYPT_STRING_BASE64, result.data(), &needed, nullptr, nullptr))
            return std::nullopt;
        return result;
    }
};

const char* kDpapiPrefix = "dpapi:";
const char* kPlainPrefix = "plain:";

// Legacy XOR key for decrypting old password format (pre-DPAPI).
// This is NOT used for new passwords - those use DPAPI (CryptProtectData).
// The key is hardcoded because:
//   1. It's only for reading legacy passwords, not writing new ones
//   2. XOR is not real encryption, just obfuscation
//   3. Moving it to config/resources wouldn't add security (XOR is trivially breakable)
//   4. We need this for backward compatibility with existing user profiles
// DO NOT use this for any new encryption - always use DPAPI via DataBlob class.
LPCSTR g_pszKey = "unpzScGeCInX7XcRM2z+svTK+gegRLhz9KXVbYKJl5boSvVCcfym";

std::optional<std::string> LegacyDecryptXor(std::string_view encrypted)
{
    if (encrypted.size() % 3 != 0)
        return std::nullopt;

    const size_t keyLen = strlen(g_pszKey);
    const int iPos = (static_cast<int>(encrypted.size() / 3)) % static_cast<int>(keyLen);

    std::string result;
    result.reserve(encrypted.size() / 3);

    for (size_t i = 0; i < encrypted.size(); i += 3) {
        if (!isdigit(encrypted[i]) || !isdigit(encrypted[i+1]) || !isdigit(encrypted[i+2]))
            return std::nullopt;

        int num = (encrypted[i] - '0') * 100 +
                  (encrypted[i+1] - '0') * 10 +
                  (encrypted[i+2] - '0');

        char ch = static_cast<char>(num ^ g_pszKey[(i/3 + iPos) % keyLen]);
        result.push_back(ch);
    }
    return result;
}

} // anonymous namespace

void EncryptString(LPCTSTR pszPlain, LPTSTR pszEncrypted, UINT cchEncrypted)
{
    if (!pszEncrypted || cchEncrypted == 0)
        return;
    pszEncrypted[0] = '\0';
    if (!pszPlain)
        return;

    std::string plain(pszPlain);

    // Try DPAPI first
    DataBlob blob;
    if (blob.encrypt(plain)) {
        auto b64 = Base64::Encode({ blob.get()->pbData, blob.get()->pbData + blob.get()->cbData });
        if (b64) {
            std::string result = kDpapiPrefix + *b64;
            if (result.size() < cchEncrypted) {
                strcpy(pszEncrypted, result.c_str());
                return;
            }
        }
    }

    // Fallback to plain
    std::string result = kPlainPrefix + plain;
    if (result.size() < cchEncrypted) {
        strcpy(pszEncrypted, result.c_str());
    }
}

void DecryptString(LPCTSTR pszEncrypted, LPTSTR pszPlain, UINT cchPlain)
{
    if (!pszPlain || cchPlain == 0)
        return;
    pszPlain[0] = 0;
    if (!pszEncrypted)
        return;

    std::string_view input(pszEncrypted);

    // Special marker "!" for TC master password
    if (input == "!") {
        if (CryptProc)
            strlcpy(pszPlain, "\001", cchPlain - 1);
        return;
    }

    // Plain prefix
    if (input.substr(0, strlen(kPlainPrefix)) == kPlainPrefix) {
        auto plain = input.substr(strlen(kPlainPrefix));
        if (plain.size() < cchPlain) {
            memcpy(pszPlain, plain.data(), plain.size());
            pszPlain[plain.size()] = '\0';
        }
        return;
    }

    // DPAPI
    if (input.substr(0, strlen(kDpapiPrefix)) == kDpapiPrefix) {
        auto b64 = input.substr(strlen(kDpapiPrefix));
        auto bin = Base64::Decode(b64);
        if (bin) {
            DATA_BLOB in{ static_cast<DWORD>(bin->size()), bin->data() };
            DATA_BLOB out{};
            if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
                std::string plain(reinterpret_cast<char*>(out.pbData), out.cbData);
                SecureZeroMemory(out.pbData, out.cbData);
                LocalFree(out.pbData);
                if (plain.size() < cchPlain) {
                    memcpy(pszPlain, plain.data(), plain.size());
                    pszPlain[plain.size()] = '\0';
                }
                SecureZeroMemory(plain.data(), plain.size());
                return;
            }
        }
    }

    // Legacy XOR
    auto plain = LegacyDecryptXor(input);
    if (plain && plain->size() < cchPlain) {
        memcpy(pszPlain, plain->data(), plain->size());
        pszPlain[plain->size()] = '\0';
        SecureZeroMemory(plain->data(), plain->size());
    }
}
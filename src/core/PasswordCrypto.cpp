#include "global.h"
#include <windows.h>
#include <wincrypt.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include "PasswordCrypto.h"

namespace {

constexpr std::string_view kDpapiPrefix = "dpapi:";
constexpr std::string_view kPlainPrefix = "plain:";

// Key of the pre-DPAPI format. XOR with a published key is obfuscation, not
// encryption; it stays only so profiles written by older releases still load.
constexpr std::string_view kLegacyKey = "unpzScGeCInX7XcRM2z+svTK+gegRLhz9KXVbYKJl5boSvVCcfym";

// Owns a DATA_BLOB that CryptProtectData/CryptUnprotectData filled in.
class LocalBlob {
public:
    LocalBlob() noexcept = default;
    ~LocalBlob()
    {
        if (blob_.pbData) {
            SecureZeroMemory(blob_.pbData, blob_.cbData);
            LocalFree(blob_.pbData);
        }
    }
    LocalBlob(const LocalBlob&) = delete;
    LocalBlob& operator=(const LocalBlob&) = delete;

    DATA_BLOB* out() noexcept { return &blob_; }
    std::string_view view() const noexcept
    {
        return { reinterpret_cast<const char*>(blob_.pbData), blob_.cbData };
    }

private:
    DATA_BLOB blob_{};
};

std::optional<std::string> Base64Encode(std::string_view data)
{
    const auto* bytes = reinterpret_cast<const BYTE*>(data.data());
    const auto size = static_cast<DWORD>(data.size());
    constexpr DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    DWORD needed = 0;
    if (!CryptBinaryToStringA(bytes, size, flags, nullptr, &needed))
        return std::nullopt;
    std::string result(needed, '\0');
    if (!CryptBinaryToStringA(bytes, size, flags, result.data(), &needed))
        return std::nullopt;
    result.resize(needed); // characters written, without the terminator
    return result;
}

std::optional<std::vector<BYTE>> Base64Decode(std::string_view b64)
{
    const auto size = static_cast<DWORD>(b64.size());
    DWORD needed = 0;
    if (!CryptStringToBinaryA(b64.data(), size, CRYPT_STRING_BASE64, nullptr, &needed, nullptr, nullptr))
        return std::nullopt;
    std::vector<BYTE> result(needed);
    if (!CryptStringToBinaryA(b64.data(), size, CRYPT_STRING_BASE64, result.data(), &needed, nullptr, nullptr))
        return std::nullopt;
    result.resize(needed);
    return result;
}

std::optional<std::string> DpapiProtect(std::string_view plain)
{
    if (plain.size() > MAXDWORD)
        return std::nullopt;
    DATA_BLOB in{ static_cast<DWORD>(plain.size()),
                  reinterpret_cast<BYTE*>(const_cast<char*>(plain.data())) };
    LocalBlob out;
    if (!CryptProtectData(&in, L"SFTP Password", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, out.out()))
        return std::nullopt;
    auto b64 = Base64Encode(out.view());
    if (!b64)
        return std::nullopt;
    return std::string(kDpapiPrefix) + *b64;
}

std::optional<std::string> DpapiUnprotect(std::string_view b64)
{
    auto bin = Base64Decode(b64);
    if (!bin || bin->size() > MAXDWORD)
        return std::nullopt;
    DATA_BLOB in{ static_cast<DWORD>(bin->size()), bin->data() };
    LocalBlob out;
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, out.out()))
        return std::nullopt;
    return std::string(out.view());
}

// Each byte becomes three decimal digits after XOR with the key, read from
// an offset of (length mod key length).
std::string LegacyXorEncode(std::string_view plain)
{
    const size_t offset = plain.size() % kLegacyKey.size();
    std::string result;
    result.reserve(plain.size() * 3);
    for (size_t i = 0; i < plain.size(); ++i) {
        const unsigned value = static_cast<unsigned char>(plain[i])
                             ^ static_cast<unsigned char>(kLegacyKey[(i + offset) % kLegacyKey.size()]);
        result += static_cast<char>('0' + value / 100);
        result += static_cast<char>('0' + value / 10 % 10);
        result += static_cast<char>('0' + value % 10);
    }
    return result;
}

std::optional<std::string> LegacyXorDecode(std::string_view encoded)
{
    if (encoded.size() % 3 != 0)
        return std::nullopt;
    const size_t length = encoded.size() / 3;
    const size_t offset = length % kLegacyKey.size();
    const auto digit = [](char c) { return c >= '0' && c <= '9'; };

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        const char* triplet = encoded.data() + i * 3;
        if (!digit(triplet[0]) || !digit(triplet[1]) || !digit(triplet[2]))
            return std::nullopt;
        const unsigned value = (triplet[0] - '0') * 100u + (triplet[1] - '0') * 10u + (triplet[2] - '0');
        if (value > 0xFF)
            return std::nullopt;
        result += static_cast<char>(value ^ static_cast<unsigned char>(kLegacyKey[(i + offset) % kLegacyKey.size()]));
    }
    return result;
}

} // namespace

namespace password_crypto {

std::string Protect(std::string_view plain)
{
    if (plain.empty())
        return {};
    if (auto stored = DpapiProtect(plain))
        return std::move(*stored);
    // Without DPAPI (a broken user profile) the password would otherwise be
    // lost; the old format at least keeps it out of plain sight.
    SFTP_LOG("CRYPT", "CryptProtectData failed (%lu), password stored in the legacy format", GetLastError());
    return LegacyXorEncode(plain);
}

std::string Unprotect(std::string_view stored)
{
    if (stored.starts_with(kPlainPrefix))
        return std::string(stored.substr(kPlainPrefix.size()));
    if (stored.starts_with(kDpapiPrefix)) {
        auto plain = DpapiUnprotect(stored.substr(kDpapiPrefix.size()));
        return plain ? std::move(*plain) : std::string();
    }
    auto plain = LegacyXorDecode(stored);
    return plain ? std::move(*plain) : std::string();
}

} // namespace password_crypto

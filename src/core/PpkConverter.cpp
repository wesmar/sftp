// PpkConverter.cpp
// Native PuTTY PPK v2/v3 -> traditional PEM converter.
// No external converter dependency.
//
// PPK v3 Specification:
// - KDF: Argon2d/i/id with memory, passes, parallelism, salt
// - Encryption: aes256-cbc
// - MAC: HMAC-SHA-256 over (algorithm || encryption || comment || public_blob || private_blob_plain)
// - MAC key: from Argon2 output (bytes 48-79) for encrypted keys, empty string for unencrypted

#pragma comment(lib, "bcrypt.lib")

#include "global.h"
#include "PpkConverter.h"
#include "CoreUtils.h"
#include <bcrypt.h>
#include <argon2.h>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <stdint.h>
#include <array>

#define PPK_LOG(fmt, ...) SFTP_LOG("PPK", fmt, ##__VA_ARGS__)
#define PPK_LOG_ERROR(fmt, ...) SFTP_LOG("PPK ERROR", fmt, ##__VA_ARGS__)

// ---------------------------------------------------------------------------
// SSH wire format helpers
// ---------------------------------------------------------------------------

static void AppendU32(std::vector<uint8_t>& buf, uint32_t val)
{
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

static void AppendSshStr(std::vector<uint8_t>& buf, const void* data, size_t len)
{
    AppendU32(buf, static_cast<uint32_t>(len));
    if (len > 0) {
        const auto* p = static_cast<const uint8_t*>(data);
        buf.insert(buf.end(), p, p + len);
    }
}

static void AppendSshStr(std::vector<uint8_t>& buf, const char* s)
{
    AppendSshStr(buf, s, s ? strlen(s) : 0);
}

static uint32_t ReadU32(const std::vector<uint8_t>& buf, size_t offset)
{
    if (offset + 4 > buf.size()) return 0;
    return (static_cast<uint32_t>(buf[offset]) << 24) |
           (static_cast<uint32_t>(buf[offset + 1]) << 16) |
           (static_cast<uint32_t>(buf[offset + 2]) << 8) |
           static_cast<uint32_t>(buf[offset + 3]);
}

static bool ReadSshStr(const std::vector<uint8_t>& buf, size_t& offset,
                       const uint8_t*& data, size_t& len)
{
    if (offset + 4 > buf.size()) return false;
    len = ReadU32(buf, offset);
    offset += 4;
    if (offset + len > buf.size()) return false;
    data = buf.data() + offset;
    offset += len;
    return true;
}

static bool ReadSshStrVec(const std::vector<uint8_t>& buf, size_t& offset,
                          std::vector<uint8_t>& out)
{
    const uint8_t* d;
    size_t l;
    if (!ReadSshStr(buf, offset, d, l)) return false;
    out.assign(d, d + l);
    return true;
}

// ---------------------------------------------------------------------------
// PPK parsed data
// ---------------------------------------------------------------------------

struct PpkData {
    int version = 0;          // 2 or 3
    std::string algorithm;
    std::string encryption;   // "none" or "aes256-cbc"
    std::string comment;

    // v3 KDF fields (only for encrypted v3)
    std::string keyDerivation; // Argon2d / Argon2i / Argon2id
    uint32_t argon2Memory = 0; // KiB
    uint32_t argon2Passes = 0;
    uint32_t argon2Parallelism = 0;
    std::vector<uint8_t> argon2Salt;

    std::vector<uint8_t> publicBlob;
    std::vector<uint8_t> privateBlob; // encrypted or plaintext depending on encryption field
    std::string macHex;
};

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

static std::string ReadLine(const char* buf, size_t& pos, size_t total)
{
    std::string line;
    while (pos < total && buf[pos] != '\n' && buf[pos] != '\r')
        line += buf[pos++];
    while (pos < total && (buf[pos] == '\n' || buf[pos] == '\r'))
        ++pos;
    return line;
}

static bool MatchField(const std::string& line, const char* key, std::string& value)
{
    const size_t klen = strlen(key);
    if (line.size() <= klen + 1) return false;
    if (_strnicmp(line.c_str(), key, klen) != 0) return false;
    if (line[klen] != ':') return false;
    size_t start = klen + 1;
    while (start < line.size() && line[start] == ' ') ++start;
    value = line.substr(start);
    return true;
}

static bool DecodePpkBase64(const std::string& raw, std::vector<uint8_t>& out)
{
    if (raw.empty()) return false;
    const size_t maxOut = raw.size() * 3 / 4 + 4;
    out.resize(maxOut);
    const int n = MimeDecode(raw.c_str(), raw.size(), out.data(), maxOut);
    if (n <= 0) return false;
    out.resize(static_cast<size_t>(n));
    return true;
}

static int HexDigit(char c) noexcept
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static bool HexDecode(const std::string& hex, uint8_t* out, size_t outLen)
{
    if (hex.size() != outLen * 2) return false;
    for (size_t i = 0; i < outLen; ++i) {
        int hi = HexDigit(hex[2 * i]);
        int lo = HexDigit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static bool HexDecodeToVec(const std::string& hex, std::vector<uint8_t>& out)
{
    if (hex.empty() || (hex.size() % 2) != 0) return false;
    out.resize(hex.size() / 2);
    return HexDecode(hex, out.data(), out.size());
}

static bool ParseU32Dec(const std::string& s, uint32_t& out)
{
    if (s.empty()) return false;
    char* end = nullptr;
    unsigned long v = strtoul(s.c_str(), &end, 10);
    if (!end || *end != 0) return false;
    out = static_cast<uint32_t>(v);
    return true;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

static bool ParsePpkFile(const char* path, PpkData& ppk)
{
    PPK_LOG("Parsing PPK file: %s", path);

    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        PPK_LOG_ERROR("Cannot open file: %s, error=%lu", path, err);
        return false;
    }

    DWORD fsize = GetFileSize(hf, nullptr);
    if (fsize == INVALID_FILE_SIZE || fsize == 0 || fsize > 512 * 1024) {
        CloseHandle(hf);
        PPK_LOG_ERROR("Invalid file size: %lu", fsize);
        return false;
    }

    std::vector<char> content(fsize + 1, '\0');
    DWORD bytesRead = 0;
    bool rdOk = ReadFile(hf, content.data(), fsize, &bytesRead, nullptr) != FALSE;
    CloseHandle(hf);
    if (!rdOk || bytesRead == 0) return false;
    content[bytesRead] = '\0';

    size_t pos = 0;
    size_t total = static_cast<size_t>(bytesRead);

    std::string line = ReadLine(content.data(), pos, total);
    const char* prefix = "PuTTY-User-Key-File-";
    if (_strnicmp(line.c_str(), prefix, strlen(prefix)) != 0) {
        PPK_LOG_ERROR("Invalid PPK header");
        return false;
    }
    const char* p = line.c_str() + strlen(prefix);
    char* end = nullptr;
    long version = strtol(p, &end, 10);
    if (!end || *end != ':' || (version != 2 && version != 3)) {
        PPK_LOG_ERROR("Unsupported PPK version: %ld", version);
        return false;
    }
    ppk.version = static_cast<int>(version);
    PPK_LOG("PPK version: %d", ppk.version);
    while (*++end == ' ') {}
    ppk.algorithm = end;
    PPK_LOG("Algorithm: %s", ppk.algorithm.c_str());

    std::string val;
    std::string rawPub, rawPriv;
    int pubLines = 0, privLines = 0;

    while (pos < total) {
        line = ReadLine(content.data(), pos, total);
        if (line.empty()) continue;

        if (MatchField(line, "Encryption", val)) {
            ppk.encryption = val;
            PPK_LOG("Encryption: %s", ppk.encryption.c_str());
        } else if (MatchField(line, "Comment", val)) {
            ppk.comment = val;
        } else if (MatchField(line, "Public-Lines", val)) {
            pubLines = atoi(val.c_str());
            for (int i = 0; i < pubLines && pos < total; ++i)
                rawPub += ReadLine(content.data(), pos, total);
        } else if (MatchField(line, "Private-Lines", val)) {
            privLines = atoi(val.c_str());
            for (int i = 0; i < privLines && pos < total; ++i)
                rawPriv += ReadLine(content.data(), pos, total);
        } else if (MatchField(line, "Private-MAC", val)) {
            ppk.macHex = val;
        } else if (ppk.version == 3 && MatchField(line, "Key-Derivation", val)) {
            ppk.keyDerivation = val;
            PPK_LOG("KDF: %s", ppk.keyDerivation.c_str());
        } else if (ppk.version == 3 && MatchField(line, "Argon2-Memory", val)) {
            if (!ParseU32Dec(val, ppk.argon2Memory)) return false;
            PPK_LOG("Argon2 Memory: %u KiB", ppk.argon2Memory);
        } else if (ppk.version == 3 && MatchField(line, "Argon2-Passes", val)) {
            if (!ParseU32Dec(val, ppk.argon2Passes)) return false;
            PPK_LOG("Argon2 Passes: %u", ppk.argon2Passes);
        } else if (ppk.version == 3 && MatchField(line, "Argon2-Parallelism", val)) {
            if (!ParseU32Dec(val, ppk.argon2Parallelism)) return false;
            PPK_LOG("Argon2 Parallelism: %u", ppk.argon2Parallelism);
        } else if (ppk.version == 3 && MatchField(line, "Argon2-Salt", val)) {
            if (!HexDecodeToVec(val, ppk.argon2Salt)) return false;
            PPK_LOG("Argon2 Salt: %zu bytes", ppk.argon2Salt.size());
        }
    }

    if (ppk.algorithm.empty() || ppk.encryption.empty() || pubLines <= 0 || privLines <= 0 || ppk.macHex.empty()) {
        PPK_LOG_ERROR("Missing required PPK fields");
        return false;
    }

    if (ppk.encryption != "none" && ppk.encryption != "aes256-cbc") {
        PPK_LOG_ERROR("Unsupported encryption: %s", ppk.encryption.c_str());
        return false;
    }

    if (ppk.version == 3 && ppk.encryption != "none") {
        if (ppk.keyDerivation.empty() || ppk.argon2Memory == 0 || ppk.argon2Passes == 0 ||
            ppk.argon2Parallelism == 0 || ppk.argon2Salt.empty()) {
            PPK_LOG_ERROR("Missing Argon2 parameters for encrypted v3 key");
            return false;
        }
    }

    PPK_LOG("Decoding public and private blobs...");
    bool pubOk = DecodePpkBase64(rawPub, ppk.publicBlob);
    bool privOk = DecodePpkBase64(rawPriv, ppk.privateBlob);
    PPK_LOG("Decode result: public=%d private=%d publicBlobSize=%zu privateBlobSize=%zu", 
            pubOk, privOk, ppk.publicBlob.size(), ppk.privateBlob.size());
    
    if (!pubOk || !privOk) {
        PPK_LOG_ERROR("Base64 decode failed");
    }
    
    return pubOk && privOk;
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

static bool Sha1WithPrefix(uint32_t prefix, const uint8_t* data, size_t dataLen, uint8_t out20[20])
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0)
        return false;

    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
        const uint8_t be[4] = {
            static_cast<uint8_t>(prefix >> 24),
            static_cast<uint8_t>(prefix >> 16),
            static_cast<uint8_t>(prefix >> 8),
            static_cast<uint8_t>(prefix)
        };
        if (BCryptHashData(hHash, const_cast<PUCHAR>(be), 4, 0) == 0 &&
            BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(dataLen), 0) == 0 &&
            BCryptFinishHash(hHash, out20, 20, 0) == 0)
            ok = true;
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static bool HmacDigest(const wchar_t* algName,
                       const uint8_t* key, size_t keyLen,
                       const uint8_t* data, size_t dataLen,
                       uint8_t* out, size_t outLen)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, algName, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return false;

    // For HMAC with empty key (keyLen=0), we still need to pass a valid pointer
    // BCryptCreateHash requires a non-null key pointer even for zero-length keys
    static const uint8_t emptyKey[1] = { 0 };
    PUCHAR keyPtr = keyLen ? const_cast<PUCHAR>(key) : const_cast<PUCHAR>(emptyKey);

    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, keyPtr, static_cast<ULONG>(keyLen), 0) == 0) {
        if (BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(dataLen), 0) == 0 &&
            BCryptFinishHash(hHash, out, static_cast<ULONG>(outLen), 0) == 0)
            ok = true;
        BCryptDestroyHash(hHash);
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static bool DecryptAes256Cbc(std::vector<uint8_t>& blob, const uint8_t key[32], const uint8_t ivIn[16])
{
    if (blob.empty() || (blob.size() % 16) != 0) return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) == 0) {
        wchar_t cbcMode[] = L"ChainingModeCBC";
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(cbcMode), sizeof(cbcMode), 0) == 0) {
            DWORD objLen = 0;
            DWORD dummy = 0;
            BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                              reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &dummy, 0);
            std::vector<uint8_t> keyObj(objLen ? objLen : 256, 0);
            if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), static_cast<ULONG>(keyObj.size()),
                                           const_cast<PUCHAR>(key), 32, 0) == 0) {
                uint8_t iv[16];
                memcpy(iv, ivIn, 16);
                ULONG outLen = 0;
                NTSTATUS st = BCryptDecrypt(hKey,
                                            blob.data(), static_cast<ULONG>(blob.size()),
                                            nullptr,
                                            iv, 16,
                                            blob.data(), static_cast<ULONG>(blob.size()),
                                            &outLen, 0);
                ok = (st == 0);
            }
        }
        if (hKey) BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return ok;
}

// ---------------------------------------------------------------------------
// v2 key derivation and MAC
// ---------------------------------------------------------------------------

static bool DerivePpkV2Material(const char* passphrase,
                                uint8_t cipherKey[32], uint8_t cipherIv[16],
                                uint8_t macKey[20])
{
    const char* pass = passphrase ? passphrase : "";
    const auto* p = reinterpret_cast<const uint8_t*>(pass);
    size_t plen = strlen(pass);

    uint8_t h0[20], h1[20];
    if (!Sha1WithPrefix(0, p, plen, h0)) return false;
    if (!Sha1WithPrefix(1, p, plen, h1)) return false;

    memcpy(cipherKey, h0, 20);
    memcpy(cipherKey + 20, h1, 12);
    SecureZeroMemory(h0, sizeof(h0));
    SecureZeroMemory(h1, sizeof(h1));
    memset(cipherIv, 0, 16);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
            const char* pfx = "putty-private-key-file-mac-key";
            if (BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(pfx)), static_cast<ULONG>(strlen(pfx)), 0) == 0 &&
                BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(pass)), static_cast<ULONG>(plen), 0) == 0 &&
                BCryptFinishHash(hHash, macKey, 20, 0) == 0)
                ok = true;
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return ok;
}

static bool VerifyPpkV2Mac(const PpkData& ppk, const uint8_t macKey[20], const std::vector<uint8_t>& privateBlobForMac)
{
    std::vector<uint8_t> macData;
    AppendSshStr(macData, ppk.algorithm.c_str());
    AppendSshStr(macData, ppk.encryption.c_str());
    AppendSshStr(macData, ppk.comment.c_str());
    AppendSshStr(macData, ppk.publicBlob.data(), ppk.publicBlob.size());
    AppendSshStr(macData, privateBlobForMac.data(), privateBlobForMac.size());

    uint8_t hmac[20] = {};
    if (!HmacDigest(BCRYPT_SHA1_ALGORITHM, macKey, 20, macData.data(), macData.size(), hmac, sizeof(hmac)))
        return false;

    uint8_t stored[20] = {};
    if (!HexDecode(ppk.macHex, stored, sizeof(stored))) return false;
    return memcmp(hmac, stored, sizeof(stored)) == 0;
}

// ---------------------------------------------------------------------------
// v3 Argon2 derivation and MAC
// ---------------------------------------------------------------------------

static bool DerivePpkV3Material(const PpkData& ppk, const char* passphrase,
                                uint8_t cipherKey[32], uint8_t cipherIv[16], uint8_t macKey[32],
                                PpkConvertError& err)
{
    memset(cipherKey, 0, 32);
    memset(cipherIv, 0, 16);
    memset(macKey, 0, 32);

    if (ppk.encryption == "none")
        return true;

    if (_stricmp(ppk.encryption.c_str(), "aes256-cbc") != 0) {
        err = PpkConvertError::unsupported_encryption;
        return false;
    }

    const char* kdf = ppk.keyDerivation.c_str();
    argon2_type type = Argon2_type::Argon2_id;  // default
    if (_stricmp(kdf, "Argon2d") == 0) type = Argon2_type::Argon2_d;
    else if (_stricmp(kdf, "Argon2i") == 0) type = Argon2_type::Argon2_i;
    else if (_stricmp(kdf, "Argon2id") == 0) type = Argon2_type::Argon2_id;
    else {
        err = PpkConvertError::unsupported_kdf;
        return false;
    }

    const char* pass = passphrase ? passphrase : "";
    const size_t passLen = strlen(pass);

    std::vector<uint8_t> out(80, 0);
    
    // Use static Argon2 library directly
    int rc = argon2_hash(
        ppk.argon2Passes,
        ppk.argon2Memory,
        ppk.argon2Parallelism,
        pass, passLen,
        ppk.argon2Salt.data(), ppk.argon2Salt.size(),
        out.data(), out.size(),
        nullptr, 0,  // no separate output buffer needed
        type,
        ARGON2_VERSION_NUMBER
    );
    
    if (rc != ARGON2_OK) {
        err = PpkConvertError::crypto_error;
        return false;
    }

    memcpy(cipherKey, out.data(), 32);
    memcpy(cipherIv, out.data() + 32, 16);
    memcpy(macKey, out.data() + 48, 32);
    SecureZeroMemory(out.data(), out.size());
    return true;
}

static bool VerifyPpkV3Mac(const PpkData& ppk, const uint8_t* macKey, size_t macKeyLen,
                           const std::vector<uint8_t>& privateBlobPlain)
{
    std::vector<uint8_t> macData;
    AppendSshStr(macData, ppk.algorithm.c_str());
    AppendSshStr(macData, ppk.encryption.c_str());
    AppendSshStr(macData, ppk.comment.c_str());
    AppendSshStr(macData, ppk.publicBlob.data(), ppk.publicBlob.size());
    AppendSshStr(macData, privateBlobPlain.data(), privateBlobPlain.size());

    // PPK v3 uses HMAC-SHA-256
    // For encrypted keys: macKey is 32 bytes from Argon2 output
    // For unencrypted keys: macKey is empty string (0 bytes) - RFC 2104 compliant
    PPK_LOG("VerifyPpkV3Mac: macKeyLen=%zu privateBlobPlain size=%zu macData size=%zu",
            macKeyLen, privateBlobPlain.size(), macData.size());
    PPK_LOG("VerifyPpkV3Mac: algorithm='%s' encryption='%s' comment='%s'",
            ppk.algorithm.c_str(), ppk.encryption.c_str(), ppk.comment.c_str());
    PPK_LOG("VerifyPpkV3Mac: stored MAC=%s", ppk.macHex.c_str());

    // Log the MAC data bytes for debugging
    std::array<char, 1024> macDataHex{};
    for (size_t i = 0; i < macData.size() && i < 500; i++) {
        sprintf_s(macDataHex.data() + i * 2, 3, "%02x", macData[i]);
    }
    PPK_LOG("VerifyPpkV3Mac: macData (first 500 bytes)=%s", macDataHex.data());

    uint8_t hmac[32] = {};
    if (!HmacDigest(BCRYPT_SHA256_ALGORITHM, macKey, macKeyLen, macData.data(), macData.size(), hmac, sizeof(hmac))) {
        PPK_LOG_ERROR("HmacDigest failed");
        return false;
    }

    // Log computed MAC for debugging
    std::array<char, 65> computedMac{};
    for (int i = 0; i < 32; i++) {
        sprintf_s(computedMac.data() + i * 2, 3, "%02x", hmac[i]);
    }
    PPK_LOG("VerifyPpkV3Mac: computed MAC=%s", computedMac.data());

    uint8_t stored[32] = {};
    if (!HexDecode(ppk.macHex, stored, sizeof(stored))) {
        PPK_LOG_ERROR("HexDecode of stored MAC failed");
        return false;
    }

    int cmpResult = memcmp(hmac, stored, sizeof(stored));
    PPK_LOG("VerifyPpkV3Mac: memcmp result=%d", cmpResult);

    if (cmpResult != 0) {
        PPK_LOG_ERROR("MAC mismatch! Key file may be corrupted or wrong passphrase.");
    }

    return cmpResult == 0;
}

// ---------------------------------------------------------------------------
// ASN.1 helpers for traditional PEM
// ---------------------------------------------------------------------------

static void Asn1AppendLen(std::vector<uint8_t>& out, size_t len)
{
    if (len < 128) {
        out.push_back(static_cast<uint8_t>(len));
        return;
    }
    std::array<uint8_t, 8> tmp{};
    int n = 0;
    while (len) {
        tmp[n++] = static_cast<uint8_t>(len & 0xFF);
        len >>= 8;
    }
    out.push_back(static_cast<uint8_t>(0x80 | n));
    for (int i = n - 1; i >= 0; --i)
        out.push_back(tmp[i]);
}

static void Asn1AppendTagged(std::vector<uint8_t>& out, uint8_t tag, const std::vector<uint8_t>& payload)
{
    out.push_back(tag);
    Asn1AppendLen(out, payload.size());
    out.insert(out.end(), payload.begin(), payload.end());
}

static std::vector<uint8_t> TrimLeadingZeros(const std::vector<uint8_t>& in)
{
    size_t i = 0;
    while (i < in.size() && in[i] == 0)
        ++i;
    if (i == in.size())
        return std::vector<uint8_t>{0};
    return std::vector<uint8_t>(in.begin() + i, in.end());
}

static void Asn1AppendInteger(std::vector<uint8_t>& out, const std::vector<uint8_t>& inUnsigned)
{
    std::vector<uint8_t> n = TrimLeadingZeros(inUnsigned);
    if (!n.empty() && (n[0] & 0x80))
        n.insert(n.begin(), 0);
    Asn1AppendTagged(out, 0x02, n);
}

static void Asn1AppendIntegerU32(std::vector<uint8_t>& out, uint32_t val)
{
    std::vector<uint8_t> tmp;
    if (val == 0)
        tmp.push_back(0);
    else {
        while (val) {
            tmp.insert(tmp.begin(), static_cast<uint8_t>(val & 0xFF));
            val >>= 8;
        }
    }
    Asn1AppendInteger(out, tmp);
}

static void Asn1AppendOctetString(std::vector<uint8_t>& out, const std::vector<uint8_t>& in)
{
    Asn1AppendTagged(out, 0x04, in);
}

static void Asn1AppendBitString(std::vector<uint8_t>& out, const std::vector<uint8_t>& in)
{
    std::vector<uint8_t> payload;
    payload.reserve(in.size() + 1);
    payload.push_back(0); // unused bits
    payload.insert(payload.end(), in.begin(), in.end());
    Asn1AppendTagged(out, 0x03, payload);
}

static std::vector<uint8_t> Asn1WrapSequence(const std::vector<uint8_t>& body)
{
    std::vector<uint8_t> seq;
    Asn1AppendTagged(seq, 0x30, body);
    return seq;
}

// Big-int helpers (base-256 big-endian), enough for RSA CRT reductions.
static int BigCmp(const std::vector<uint8_t>& aIn, const std::vector<uint8_t>& bIn)
{
    auto a = TrimLeadingZeros(aIn);
    auto b = TrimLeadingZeros(bIn);
    if (a.size() < b.size()) return -1;
    if (a.size() > b.size()) return 1;
    int c = memcmp(a.data(), b.data(), a.size());
    if (c < 0) return -1;
    if (c > 0) return 1;
    return 0;
}

static bool BigSubInPlace(std::vector<uint8_t>& a, const std::vector<uint8_t>& b)
{
    if (BigCmp(a, b) < 0)
        return false;
    auto aa = TrimLeadingZeros(a);
    auto bb = TrimLeadingZeros(b);
    if (aa.size() < bb.size())
        aa.insert(aa.begin(), bb.size() - aa.size(), 0);

    int ia = static_cast<int>(aa.size()) - 1;
    int ib = static_cast<int>(bb.size()) - 1;
    int borrow = 0;
    while (ia >= 0) {
        int av = aa[ia];
        int bv = (ib >= 0) ? bb[ib] : 0;
        int v = av - bv - borrow;
        if (v < 0) {
            v += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        aa[ia] = static_cast<uint8_t>(v);
        --ia; --ib;
    }
    a = TrimLeadingZeros(aa);
    return true;
}

static bool BigDec1(std::vector<uint8_t>& a)
{
    a = TrimLeadingZeros(a);
    if (a.size() == 1 && a[0] == 0)
        return false;
    for (int i = static_cast<int>(a.size()) - 1; i >= 0; --i) {
        if (a[i] > 0) {
            --a[i];
            a = TrimLeadingZeros(a);
            return true;
        }
        a[i] = 0xFF;
    }
    return false;
}

static std::vector<uint8_t> BigMod(const std::vector<uint8_t>& aIn, const std::vector<uint8_t>& mIn)
{
    auto m = TrimLeadingZeros(mIn);
    if (m.size() == 1 && m[0] == 0)
        return {};

    std::vector<uint8_t> r;
    r.reserve(m.size() + 1);
    auto a = TrimLeadingZeros(aIn);
    for (uint8_t byte : a) {
        r.push_back(byte);
        r = TrimLeadingZeros(r);
        while (BigCmp(r, m) >= 0) {
            if (!BigSubInPlace(r, m))
                return {};
        }
    }
    return TrimLeadingZeros(r);
}

static bool BuildTraditionalRsaDer(const PpkData& ppk, const std::vector<uint8_t>& privateBlobPlain,
                                   std::vector<uint8_t>& outDer)
{
    PPK_LOG("BuildTraditionalRsaDer: publicBlob=%zu privateBlob=%zu", ppk.publicBlob.size(), privateBlobPlain.size());
    
    size_t po = 0, pr = 0;
    std::vector<uint8_t> algV, e, n, d, p, q, iqmp;
    if (!ReadSshStrVec(ppk.publicBlob, po, algV)) { PPK_LOG_ERROR("Failed to read algV"); return false; }
    if (!ReadSshStrVec(ppk.publicBlob, po, e)) { PPK_LOG_ERROR("Failed to read e"); return false; }
    if (!ReadSshStrVec(ppk.publicBlob, po, n)) { PPK_LOG_ERROR("Failed to read n"); return false; }
    if (!ReadSshStrVec(privateBlobPlain, pr, d)) { PPK_LOG_ERROR("Failed to read d"); return false; }
    if (!ReadSshStrVec(privateBlobPlain, pr, p)) { PPK_LOG_ERROR("Failed to read p"); return false; }
    if (!ReadSshStrVec(privateBlobPlain, pr, q)) { PPK_LOG_ERROR("Failed to read q"); return false; }
    if (!ReadSshStrVec(privateBlobPlain, pr, iqmp)) { PPK_LOG_ERROR("Failed to read iqmp"); return false; }

    PPK_LOG("RSA key sizes: e=%zu n=%zu d=%zu p=%zu q=%zu iqmp=%zu", e.size(), n.size(), d.size(), p.size(), q.size(), iqmp.size());

    if (algV != std::vector<uint8_t>{'s','s','h','-','r','s','a'}) {
        PPK_LOG_ERROR("Algorithm mismatch");
        return false;
    }

    auto pMinus1 = TrimLeadingZeros(p);
    auto qMinus1 = TrimLeadingZeros(q);
    if (!BigDec1(pMinus1) || !BigDec1(qMinus1)) {
        PPK_LOG_ERROR("BigDec1 failed");
        return false;
    }
    auto dmp1 = BigMod(d, pMinus1);
    auto dmq1 = BigMod(d, qMinus1);
    if (dmp1.empty() || dmq1.empty()) {
        PPK_LOG_ERROR("BigMod failed");
        return false;
    }

    std::vector<uint8_t> body;
    Asn1AppendIntegerU32(body, 0);
    Asn1AppendInteger(body, n);
    Asn1AppendInteger(body, e);
    Asn1AppendInteger(body, d);
    Asn1AppendInteger(body, p);
    Asn1AppendInteger(body, q);
    Asn1AppendInteger(body, dmp1);
    Asn1AppendInteger(body, dmq1);
    Asn1AppendInteger(body, iqmp); // q^-1 mod p

    outDer = Asn1WrapSequence(body);
    PPK_LOG("Generated DER size=%zu", outDer.size());
    return !outDer.empty();
}

static bool GetEcCurveOid(const std::string& alg, const std::vector<uint8_t>*& oidVal)
{
    static const std::vector<uint8_t> oidP256{0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07}; // 1.2.840.10045.3.1.7
    static const std::vector<uint8_t> oidP384{0x2B,0x81,0x04,0x00,0x22};                 // 1.3.132.0.34
    static const std::vector<uint8_t> oidP521{0x2B,0x81,0x04,0x00,0x23};                 // 1.3.132.0.35
    if (alg == "ecdsa-sha2-nistp256") oidVal = &oidP256;
    else if (alg == "ecdsa-sha2-nistp384") oidVal = &oidP384;
    else if (alg == "ecdsa-sha2-nistp521") oidVal = &oidP521;
    else oidVal = nullptr;
    return oidVal != nullptr;
}

static bool BuildTraditionalEcDer(const PpkData& ppk, const std::vector<uint8_t>& privateBlobPlain,
                                  std::vector<uint8_t>& outDer)
{
    size_t po = 0, pr = 0;
    std::vector<uint8_t> algV, curveName, publicPoint, scalar;
    if (!ReadSshStrVec(ppk.publicBlob, po, algV)) return false;
    if (!ReadSshStrVec(ppk.publicBlob, po, curveName)) return false;
    if (!ReadSshStrVec(ppk.publicBlob, po, publicPoint)) return false;
    if (!ReadSshStrVec(privateBlobPlain, pr, scalar)) return false;

    if (algV.size() != ppk.algorithm.size() ||
        memcmp(algV.data(), ppk.algorithm.data(), algV.size()) != 0)
        return false;
    static const std::string nistp256 = "nistp256";
    static const std::string nistp384 = "nistp384";
    static const std::string nistp521 = "nistp521";
    if ((ppk.algorithm == "ecdsa-sha2-nistp256" &&
         (curveName.size() != nistp256.size() || memcmp(curveName.data(), nistp256.data(), nistp256.size()) != 0)) ||
        (ppk.algorithm == "ecdsa-sha2-nistp384" &&
         (curveName.size() != nistp384.size() || memcmp(curveName.data(), nistp384.data(), nistp384.size()) != 0)) ||
        (ppk.algorithm == "ecdsa-sha2-nistp521" &&
         (curveName.size() != nistp521.size() || memcmp(curveName.data(), nistp521.data(), nistp521.size()) != 0)))
        return false;

    const std::vector<uint8_t>* oid = nullptr;
    if (!GetEcCurveOid(ppk.algorithm, oid) || !oid)
        return false;

    std::vector<uint8_t> body;
    Asn1AppendIntegerU32(body, 1);
    Asn1AppendOctetString(body, scalar);

    std::vector<uint8_t> oidObj;
    Asn1AppendTagged(oidObj, 0x06, *oid);
    Asn1AppendTagged(body, 0xA0, oidObj);

    std::vector<uint8_t> pubBitStr;
    Asn1AppendBitString(pubBitStr, publicPoint);
    Asn1AppendTagged(body, 0xA1, pubBitStr);

    outDer = Asn1WrapSequence(body);
    return !outDer.empty();
}

// ---------------------------------------------------------------------------
// PEM output
// ---------------------------------------------------------------------------

static bool WritePem(const char* path, const char* label, const std::vector<uint8_t>& data)
{
    const size_t maxB64 = data.size() * 2 + 16;
    std::vector<char> b64(maxB64, '\0');
    int b64Len = MimeEncodeData(data.data(), data.size(), b64.data(), maxB64);
    if (b64Len <= 0) return false;

    HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;

    bool ok = true;
    auto Write = [&](const void* p, DWORD n) {
        if (!ok) return;
        DWORD w = 0;
        ok = (WriteFile(hf, p, n, &w, nullptr) != FALSE) && (w == n);
    };

    std::array<char, 96> hdr{};
    std::array<char, 96> ftr{};
    snprintf(hdr.data(), hdr.size(), "-----BEGIN %s-----\n", label);
    snprintf(ftr.data(), ftr.size(), "\n-----END %s-----\n", label);
    Write(hdr.data(), static_cast<DWORD>(strlen(hdr.data())));

    const char* p = b64.data();
    int remaining = b64Len;
    bool first = true;
    while (ok && remaining > 0) {
        if (!first) Write("\n", 1);
        first = false;
        int lineLen = min(70, remaining);
        Write(p, static_cast<DWORD>(lineLen));
        p += lineLen;
        remaining -= lineLen;
    }

    Write(ftr.data(), static_cast<DWORD>(strlen(ftr.data())));

    CloseHandle(hf);
    if (!ok) DeleteFileA(path);
    return ok;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

static bool ConvertPpkToOpenSshImpl(const char* ppkPath, const char* passphrase,
                                    char* outPemPath, size_t outPemPathLen,
                                    PpkConvertError& err)
{
    PpkData ppk;
    if (!ParsePpkFile(ppkPath, ppk)) {
        PPK_LOG_ERROR("Failed to parse PPK file: %s", ppkPath);
        err = PpkConvertError::invalid_format;
        return false;
    }

    PPK_LOG("PPK parsed successfully: version=%d algorithm=%s encryption=%s",
            ppk.version, ppk.algorithm.c_str(), ppk.encryption.c_str());

    if (ppk.version != 2 && ppk.version != 3) {
        PPK_LOG_ERROR("Unsupported PPK version: %d", ppk.version);
        err = PpkConvertError::unsupported_version;
        return false;
    }

    // quick algorithm sanity (full parse checked later too)
    if (!(ppk.algorithm == "ssh-rsa" || ppk.algorithm == "ssh-ed25519" ||
          ppk.algorithm == "ecdsa-sha2-nistp256" || ppk.algorithm == "ecdsa-sha2-nistp384" ||
          ppk.algorithm == "ecdsa-sha2-nistp521")) {
        PPK_LOG_ERROR("Unsupported algorithm: %s", ppk.algorithm.c_str());
        err = PpkConvertError::unsupported_algorithm;
        return false;
    }

    const bool encrypted = (_stricmp(ppk.encryption.c_str(), "none") != 0);
    PPK_LOG("PPK encryption: %s (encrypted=%d)", ppk.encryption.c_str(), encrypted);
    
    if (encrypted && (!passphrase || passphrase[0] == 0)) {
        PPK_LOG("PPK is encrypted but no passphrase provided");
        err = PpkConvertError::passphrase_required;
        return false;
    }

    std::vector<uint8_t> privatePlain = ppk.privateBlob;

    if (ppk.version == 2) {
        uint8_t cipherKey[32] = {};
        uint8_t cipherIv[16] = {};
        uint8_t macKey[20] = {};
        const char* macPass = encrypted ? passphrase : "";
        if (!DerivePpkV2Material(macPass, cipherKey, cipherIv, macKey)) {
            err = PpkConvertError::crypto_error;
            return false;
        }

        if (encrypted) {
            // v2 MAC is over encrypted blob
            PPK_LOG("Verifying PPK v2 MAC (encrypted key)");
            if (!VerifyPpkV2Mac(ppk, macKey, ppk.privateBlob)) {
                PPK_LOG_ERROR("MAC verification failed for encrypted key");
                err = PpkConvertError::bad_passphrase_or_mac;
                return false;
            }

            if (!DecryptAes256Cbc(privatePlain, cipherKey, cipherIv)) {
                err = PpkConvertError::bad_passphrase_or_mac;
                return false;
            }
        } else {
            // Unencrypted v2 key - no MAC verification needed
            PPK_LOG("Unencrypted PPK v2 key - skipping MAC verification");
        }

        SecureZeroMemory(cipherKey, sizeof(cipherKey));
        SecureZeroMemory(cipherIv, sizeof(cipherIv));
        SecureZeroMemory(macKey, sizeof(macKey));
    } else {
        // PPK v3 handling
        uint8_t cipherKey[32] = {};
        uint8_t cipherIv[16] = {};
        uint8_t macKey[32] = {};
        
        // For encrypted v3 keys: derive key material using Argon2
        // For unencrypted v3 keys: MAC key is empty string (RFC 2104 compliant)
        if (encrypted) {
            if (!DerivePpkV3Material(ppk, passphrase ? passphrase : "", cipherKey, cipherIv, macKey, err)) {
                return false;
            }

            // Decrypt private blob if encrypted
            if (!DecryptAes256Cbc(privatePlain, cipherKey, cipherIv)) {
                err = PpkConvertError::bad_passphrase_or_mac;
                return false;
            }

            // PPK v3 MAC verification for encrypted keys
            // MAC key from Argon2 output (32 bytes at offset 48)
            PPK_LOG("Verifying PPK v3 MAC (encrypted key)");
            if (!VerifyPpkV3Mac(ppk, macKey, sizeof(macKey), privatePlain)) {
                PPK_LOG_ERROR("MAC verification failed for encrypted key");
                err = PpkConvertError::bad_passphrase_or_mac;
                return false;
            }

            // Clear sensitive data
            SecureZeroMemory(cipherKey, sizeof(cipherKey));
            SecureZeroMemory(cipherIv, sizeof(cipherIv));
            SecureZeroMemory(macKey, sizeof(macKey));
        } else {
            // Unencrypted v3 key - MAC verification is still required in v3!
            // The MAC key is the empty string.
            PPK_LOG("Verifying PPK v3 MAC (unencrypted key)");
            if (!VerifyPpkV3Mac(ppk, nullptr, 0, privatePlain)) {
                PPK_LOG_ERROR("MAC verification failed for unencrypted key");
                err = PpkConvertError::bad_passphrase_or_mac;
                return false;
            }
        }
    }

    std::vector<uint8_t> pemDer;
    const char* pemLabel = nullptr;
    if (ppk.algorithm == "ssh-rsa") {
        if (!BuildTraditionalRsaDer(ppk, privatePlain, pemDer)) {
            err = PpkConvertError::unsupported_algorithm;
            return false;
        }
        pemLabel = "RSA PRIVATE KEY";
    } else if (ppk.algorithm == "ecdsa-sha2-nistp256" ||
               ppk.algorithm == "ecdsa-sha2-nistp384" ||
               ppk.algorithm == "ecdsa-sha2-nistp521") {
        if (!BuildTraditionalEcDer(ppk, privatePlain, pemDer)) {
            err = PpkConvertError::unsupported_algorithm;
            return false;
        }
        pemLabel = "EC PRIVATE KEY";
    } else {
        // ssh-ed25519 has no classic "traditional" PEM that old libssh2 consistently accepts.
        err = PpkConvertError::unsupported_algorithm;
        return false;
    }

    std::array<char, MAX_PATH> tempDir{};
    if (!GetTempPathA(static_cast<DWORD>(tempDir.size() - 1), tempDir.data())) {
        err = PpkConvertError::io_error;
        return false;
    }

    std::array<char, MAX_PATH> tempBase{};
    if (!GetTempFileNameA(tempDir.data(), "spp", 0, tempBase.data())) {
        err = PpkConvertError::io_error;
        return false;
    }
    DeleteFileA(tempBase.data());

    strlcpy(outPemPath, tempBase.data(), outPemPathLen - 1);
    strlcat(outPemPath, ".pem", outPemPathLen - 1);

    PPK_LOG("Writing PEM file: %s label=%s derSize=%zu", outPemPath, pemLabel, pemDer.size());
    if (!WritePem(outPemPath, pemLabel, pemDer)) {
        PPK_LOG_ERROR("WritePem failed");
        outPemPath[0] = '\0';
        err = PpkConvertError::io_error;
        return false;
    }
    PPK_LOG("PEM file written successfully");

    err = PpkConvertError::ok;
    return true;
}

bool ConvertPpkToOpenSsh(const char* ppkPath, const char* passphrase,
                         char* outPemPath, size_t outPemPathLen,
                         PpkConvertError* outError) noexcept
{
    if (outError) *outError = PpkConvertError::internal_error;
    if (!ppkPath || !outPemPath || outPemPathLen == 0) {
        if (outError) *outError = PpkConvertError::invalid_format;
        return false;
    }
    outPemPath[0] = '\0';
    try {
        PpkConvertError err = PpkConvertError::internal_error;
        bool ok = ConvertPpkToOpenSshImpl(ppkPath, passphrase, outPemPath, outPemPathLen, err);
        if (outError) *outError = err;
        return ok;
    } catch (...) {
        outPemPath[0] = '\0';
        if (outError) *outError = PpkConvertError::internal_error;
        return false;
    }
}

bool ConvertPpkV2ToOpenSsh(const char* ppkPath, const char* passphrase,
                           char* outPemPath, size_t outPemPathLen) noexcept
{
    return ConvertPpkToOpenSsh(ppkPath, passphrase, outPemPath, outPemPathLen, nullptr);
}


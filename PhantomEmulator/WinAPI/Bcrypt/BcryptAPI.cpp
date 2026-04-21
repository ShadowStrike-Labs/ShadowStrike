/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * BcryptAPI.cpp — BCrypt/CNG cryptographic API handler implementations
 *
 * This module emulates the Windows BCrypt (CNG) surface. Modern ransomware
 * families (Conti, LockBit, BlackCat, Royal, Akira) call BCrypt for:
 *   - AES-256 key generation (BCryptGenerateSymmetricKey)
 *   - File encryption (BCryptEncrypt in a tight loop)
 *   - Random IV generation (BCryptGenRandom)
 *   - RSA public-key import for key wrapping (BCryptImportKeyPair)
 *
 * Without this emulation every ransomware sample stalls at the first BCrypt
 * call and we miss ALL file-encryption behavior.
 *
 * Design decisions:
 *   - No actual crypto — we just capture keys and pass data through unchanged
 *     so downstream pattern analysis can still read the plaintext.
 *   - Deterministic PRNG for BCryptGenRandom ensures reproducible analysis.
 *   - Every key captured (symmetric + imported RSA blobs) for forensic
 *     recovery of encrypted files.
 *   - Encryption call count tracked — >100 encrypts + AES key + RSA pubkey
 *     triggers ransomware behavioral flag.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "BcryptAPI.hpp"
#include "../APIDispatcher.hpp"

#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>

namespace Phantom::WinAPI::Bcrypt {

// ============================================================================
// BCrypt-specific constants (no windows.h dependency)
// ============================================================================

static constexpr uint32_t BCRYPT_ALG_HANDLE_HMAC_FLAG       = 0x00000008;
static constexpr uint32_t BCRYPT_USE_SYSTEM_PREFERRED_RNG   = 0x00000002;

// Resource caps (defense against hostile allocation sizes)
static constexpr uint32_t kMaxKeyMaterialSize   = 8192;
static constexpr uint32_t kMaxBlobSize          = 65536;
static constexpr uint32_t kMaxPropertyNameLen   = 256;
static constexpr uint32_t kMaxChainingModeLen   = 128;
static constexpr uint32_t kMaxGenRandomLen      = 64 * 1024;
static constexpr uint32_t kMaxEncryptLen        = 16 * 1024 * 1024; // 16 MB per call
static constexpr uint32_t kMaxHashAccumulate    = 4 * 1024 * 1024;  // 4 MB hash data
static constexpr uint32_t kMaxAlgoProviders     = 4096;
static constexpr uint32_t kMaxKeys              = 16384;
static constexpr uint32_t kMaxHashes            = 4096;

// Ransomware detection threshold
static constexpr uint32_t kRansomwareEncryptThreshold = 100;

// ============================================================================
// Internal emulator-side objects
// ============================================================================

struct EmulatedAlgoProvider {
    uint32_t    id             = 0;
    std::string algorithmName;
    uint32_t    objectLength   = 0;
    uint32_t    hashLength     = 0;
    uint32_t    blockLength    = 0;
    std::string chainingMode;
    bool        isHmac         = false;
};

struct EmulatedKey {
    uint32_t             id           = 0;
    uint32_t             algoId       = 0;
    std::vector<uint8_t> keyMaterial;
    uint32_t             keyLength    = 0;
    std::string          algorithm;
    std::vector<uint8_t> lastIV;
    uint32_t             encryptCount = 0;
    uint32_t             decryptCount = 0;
};

struct EmulatedHash {
    uint32_t             id          = 0;
    uint32_t             algoId      = 0;
    std::vector<uint8_t> accumulated;
    std::string          algorithm;
    uint32_t             hashLength  = 0;
};

// ============================================================================
// BCryptState implementation
// ============================================================================
// Module-level maps keyed by pseudo-handle IDs. The guest receives these IDs
// written as pointer-sized values into output buffers.

struct BCryptStateImpl {
    mutable std::mutex                                mutex;
    std::unordered_map<uint32_t, EmulatedAlgoProvider> providers;
    std::unordered_map<uint32_t, EmulatedKey>          keys;
    std::unordered_map<uint32_t, EmulatedHash>         hashes;
    std::atomic<uint32_t>                              nextId{ 0xBC000001 };
    std::atomic<uint32_t>                              totalEncrypts{ 0 };
    std::atomic<uint32_t>                              totalDecrypts{ 0 };
    bool                                               hasAESKey       = false;
    bool                                               hasRSAPubKey    = false;

    [[nodiscard]] uint32_t AllocId() noexcept {
        return nextId.fetch_add(1, std::memory_order_relaxed);
    }
};

static BCryptStateImpl& GetState() noexcept {
    static BCryptStateImpl s_state;
    return s_state;
}

BCryptState& BCryptState::Instance() noexcept {
    static BCryptState s_instance;
    return s_instance;
}

std::vector<CapturedCryptoKey> BCryptState::GetCapturedKeys() const noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    std::vector<CapturedCryptoKey> result;
    result.reserve(st.keys.size());
    for (const auto& [id, key] : st.keys) {
        CapturedCryptoKey captured;
        captured.algorithm       = key.algorithm;
        captured.keyMaterial     = key.keyMaterial;
        captured.iv              = key.lastIV;
        captured.encryptionCount = key.encryptCount;
        captured.decryptionCount = key.decryptCount;
        result.push_back(std::move(captured));
    }
    return result;
}

uint32_t BCryptState::GetTotalEncryptionCalls() const noexcept {
    return GetState().totalEncrypts.load(std::memory_order_relaxed);
}

uint32_t BCryptState::GetTotalDecryptionCalls() const noexcept {
    return GetState().totalDecrypts.load(std::memory_order_relaxed);
}

bool BCryptState::IsRansomwareBehavior() const noexcept {
    auto& st = GetState();
    uint32_t encrypts = st.totalEncrypts.load(std::memory_order_relaxed);
    return encrypts >= kRansomwareEncryptThreshold && st.hasAESKey && st.hasRSAPubKey;
}

void BCryptState::Reset() noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    st.providers.clear();
    st.keys.clear();
    st.hashes.clear();
    st.totalEncrypts.store(0, std::memory_order_relaxed);
    st.totalDecrypts.store(0, std::memory_order_relaxed);
    st.hasAESKey    = false;
    st.hasRSAPubKey = false;
    st.nextId.store(0xBC000001, std::memory_order_relaxed);
}

// ============================================================================
// Deterministic PRNG for BCryptGenRandom
// ============================================================================
// Fixed-seed LCG producing deterministic output for reproducible analysis.
// NOT crypto-strength — that's intentional in an emulation context.

class BcryptDeterministicRNG {
public:
    static BcryptDeterministicRNG& Instance() noexcept {
        static BcryptDeterministicRNG s_inst;
        return s_inst;
    }

    void Fill(uint8_t* buf, uint32_t len) noexcept {
        uint64_t s = m_state.load(std::memory_order_relaxed);
        for (uint32_t i = 0; i < len; ++i) {
            s = s * 6364136223846793005ULL + 1;
            buf[i] = static_cast<uint8_t>(s >> 33);
        }
        m_state.store(s, std::memory_order_relaxed);
    }

private:
    BcryptDeterministicRNG() noexcept = default;
    // Seed chosen for recognizable pattern in forensic dumps
    std::atomic<uint64_t> m_state{ 0x5BAD5EED5BAD5EEDULL };
};

// ============================================================================
// Narrow-string helpers (no windows.h)
// ============================================================================

static std::string WideToNarrow(const std::wstring& ws) noexcept {
    std::string s;
    s.reserve(ws.size());
    for (wchar_t wc : ws) {
        s.push_back(static_cast<char>(wc & 0x7F));
    }
    return s;
}

// Convert narrow ASCII to wchar_t byte pairs for writing to guest memory
static bool WriteWideStringToGuest(VirtualMemory& mem, GuestAddress addr,
                                   const std::string& s, uint32_t maxBytes) noexcept {
    uint32_t wideBytes = static_cast<uint32_t>((s.size() + 1) * 2);
    if (wideBytes > maxBytes) return false;
    for (uint32_t i = 0; i < s.size(); ++i) {
        uint16_t wc = static_cast<uint16_t>(static_cast<uint8_t>(s[i]));
        if (mem.Write(addr + i * 2, &wc, 2) != ErrorCode::Success) return false;
    }
    uint16_t null = 0;
    return mem.Write(addr + s.size() * 2, &null, 2) == ErrorCode::Success;
}

// ============================================================================
// Algorithm property initialization
// ============================================================================

static void InitAlgoProperties(EmulatedAlgoProvider& prov) noexcept {
    const auto& name = prov.algorithmName;
    if (name == "AES") {
        prov.objectLength = 654;
        prov.blockLength  = 16;
        prov.hashLength   = 0;
        prov.chainingMode = "ChainingModeCBC";
    } else if (name == "RSA") {
        prov.objectLength = 0;
        prov.blockLength  = 0;
        prov.hashLength   = 0;
    } else if (name == "SHA256") {
        prov.objectLength = 286;
        prov.hashLength   = 32;
        prov.blockLength  = 64;
    } else if (name == "SHA1") {
        prov.objectLength = 278;
        prov.hashLength   = 20;
        prov.blockLength  = 64;
    } else if (name == "MD5") {
        prov.objectLength = 274;
        prov.hashLength   = 16;
        prov.blockLength  = 64;
    } else if (name == "SHA384") {
        prov.objectLength = 382;
        prov.hashLength   = 48;
        prov.blockLength  = 128;
    } else if (name == "SHA512") {
        prov.objectLength = 382;
        prov.hashLength   = 64;
        prov.blockLength  = 128;
    } else if (name == "RNG") {
        prov.objectLength = 0;
        prov.blockLength  = 0;
        prov.hashLength   = 0;
    } else if (name == "3DES") {
        prov.objectLength = 0;
        prov.blockLength  = 8;
        prov.hashLength   = 0;
        prov.chainingMode = "ChainingModeCBC";
    } else if (name == "RC4") {
        prov.objectLength = 0;
        prov.blockLength  = 1;
        prov.hashLength   = 0;
    } else if (name == "ECDSA_P256") {
        prov.objectLength = 0;
        prov.blockLength  = 0;
        prov.hashLength   = 0;
    } else if (name == "ECDH_P256") {
        prov.objectLength = 0;
        prov.blockLength  = 0;
        prov.hashLength   = 0;
    }
}

// ============================================================================
// Lookup helpers — retrieve internal objects by pseudo-handle ID
// ============================================================================

static EmulatedAlgoProvider* LookupProvider(uint32_t id) noexcept {
    auto& st = GetState();
    auto it = st.providers.find(id);
    return (it != st.providers.end()) ? &it->second : nullptr;
}

static EmulatedKey* LookupKey(uint32_t id) noexcept {
    auto& st = GetState();
    auto it = st.keys.find(id);
    return (it != st.keys.end()) ? &it->second : nullptr;
}

static EmulatedHash* LookupHash(uint32_t id) noexcept {
    auto& st = GetState();
    auto it = st.hashes.find(id);
    return (it != st.hashes.end()) ? &it->second : nullptr;
}

// ============================================================================
// BCryptOpenAlgorithmProvider
// ============================================================================

bool HandleBCryptOpenAlgorithmProvider(APIContext& ctx) {
    // arg0 = BCRYPT_ALG_HANDLE* phAlgorithm   (OUT)
    // arg1 = LPCWSTR pszAlgId
    // arg2 = LPCWSTR pszImplementation         (ignored)
    // arg3 = ULONG dwFlags

    GuestAddress phAlgo   = ctx.GetArgPtr(0);
    GuestAddress pszAlgId = ctx.GetArgPtr(1);
    uint32_t     dwFlags  = ctx.GetArg32(3);

    if (phAlgo == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    if (pszAlgId == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    std::wstring algoWide = ctx.ReadWideString(pszAlgId, kMaxPropertyNameLen);
    std::string algoName  = WideToNarrow(algoWide);

    if (algoName.empty()) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    if (st.providers.size() >= kMaxAlgoProviders) {
        ctx.SetReturnNtStatus(NT::STATUS_NO_MEMORY);
        return true;
    }

    EmulatedAlgoProvider prov;
    prov.id            = st.AllocId();
    prov.algorithmName = algoName;
    prov.isHmac        = (dwFlags & BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0;
    InitAlgoProperties(prov);

    uint32_t handleId = prov.id;
    st.providers.emplace(handleId, std::move(prov));

    // Write pseudo-handle to guest memory
    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phAlgo, static_cast<uint64_t>(handleId));
    } else {
        ctx.Memory().WriteU32(phAlgo, handleId);
    }

    // Tag crypto usage for behavioral analysis
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptCloseAlgorithmProvider
// ============================================================================

bool HandleBCryptCloseAlgorithmProvider(APIContext& ctx) {
    // arg0 = BCRYPT_ALG_HANDLE hAlgorithm
    // arg1 = ULONG dwFlags

    uint32_t handleId = ctx.GetArg32(0);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    auto it = st.providers.find(handleId);
    if (it == st.providers.end()) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    st.providers.erase(it);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptGetProperty
// ============================================================================

bool HandleBCryptGetProperty(APIContext& ctx) {
    // arg0 = BCRYPT_HANDLE hObject
    // arg1 = LPCWSTR pszProperty
    // arg2 = PUCHAR pbOutput
    // arg3 = ULONG cbOutput
    // arg4 = ULONG* pcbResult
    // arg5 = ULONG dwFlags

    uint32_t     handleId    = ctx.GetArg32(0);
    GuestAddress pszProp     = ctx.GetArgPtr(1);
    GuestAddress pbOutput    = ctx.GetArgPtr(2);
    uint32_t     cbOutput    = ctx.GetArg32(3);
    GuestAddress pcbResult   = ctx.GetArgPtr(4);

    if (pszProp == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    std::wstring propWide = ctx.ReadWideString(pszProp, kMaxPropertyNameLen);
    std::string propName  = WideToNarrow(propWide);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    // Try provider lookup first, then key lookup
    EmulatedAlgoProvider* prov = LookupProvider(handleId);
    EmulatedKey* key           = LookupKey(handleId);
    EmulatedHash* hash         = LookupHash(handleId);

    if (!prov && !key && !hash) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    // Determine value to return
    uint32_t valueU32  = 0;
    bool     isU32     = false;
    std::string valueStr;
    bool     isStr     = false;

    if (propName == "ObjectLength") {
        isU32 = true;
        if (prov) valueU32 = prov->objectLength;
        else if (key) valueU32 = 0;
        else if (hash) { auto* hp = LookupProvider(hash->algoId); valueU32 = hp ? hp->objectLength : 0; }
    } else if (propName == "HashDigestLength") {
        isU32 = true;
        if (prov) valueU32 = prov->hashLength;
        else if (hash) valueU32 = hash->hashLength;
    } else if (propName == "BlockLength") {
        isU32 = true;
        if (prov) valueU32 = prov->blockLength;
    } else if (propName == "KeyLength") {
        isU32 = true;
        if (key) valueU32 = key->keyLength * 8; // KeyLength in bits
    } else if (propName == "ChainingMode") {
        isStr = true;
        if (prov) valueStr = prov->chainingMode;
        else if (key) {
            auto* kp = LookupProvider(key->algoId);
            valueStr = kp ? kp->chainingMode : "";
        }
    } else if (propName == "KeyLengths") {
        // BCRYPT_KEY_LENGTHS_STRUCT: { MinLength, MaxLength, Increment } (3 x ULONG)
        isU32 = false;
        uint32_t keyLengths[3] = { 128, 256, 64 }; // AES key lengths in bits
        if (prov && prov->algorithmName == "3DES") {
            keyLengths[0] = 192; keyLengths[1] = 192; keyLengths[2] = 0;
        }
        uint32_t needed = 12; // 3 x sizeof(ULONG)
        if (pcbResult != 0) {
            ctx.Memory().WriteU32(pcbResult, needed);
        }
        if (pbOutput == 0 || cbOutput < needed) {
            ctx.SetReturnNtStatus(pbOutput == 0 ? NT::STATUS_SUCCESS : NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }
        ctx.Memory().Write(pbOutput, keyLengths, needed);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    } else {
        ctx.SetReturnNtStatus(NT::STATUS_NOT_SUPPORTED);
        return true;
    }

    if (isU32) {
        uint32_t needed = sizeof(uint32_t);
        if (pcbResult != 0) {
            ctx.Memory().WriteU32(pcbResult, needed);
        }
        if (pbOutput == 0) {
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
            return true;
        }
        if (cbOutput < needed) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }
        ctx.Memory().WriteU32(pbOutput, valueU32);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    if (isStr) {
        // ChainingMode is stored as a wide string (wchar_t) including null terminator
        uint32_t needed = static_cast<uint32_t>((valueStr.size() + 1) * 2);
        if (pcbResult != 0) {
            ctx.Memory().WriteU32(pcbResult, needed);
        }
        if (pbOutput == 0) {
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
            return true;
        }
        if (cbOutput < needed) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }
        WriteWideStringToGuest(ctx.Memory(), pbOutput, valueStr, cbOutput);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    ctx.SetReturnNtStatus(NT::STATUS_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// BCryptSetProperty
// ============================================================================

bool HandleBCryptSetProperty(APIContext& ctx) {
    // arg0 = BCRYPT_HANDLE hObject
    // arg1 = LPCWSTR pszProperty
    // arg2 = PUCHAR pbInput
    // arg3 = ULONG cbInput
    // arg4 = ULONG dwFlags

    uint32_t     handleId  = ctx.GetArg32(0);
    GuestAddress pszProp   = ctx.GetArgPtr(1);
    GuestAddress pbInput   = ctx.GetArgPtr(2);
    uint32_t     cbInput   = ctx.GetArg32(3);

    if (pszProp == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    std::wstring propWide = ctx.ReadWideString(pszProp, kMaxPropertyNameLen);
    std::string propName  = WideToNarrow(propWide);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    EmulatedAlgoProvider* prov = LookupProvider(handleId);
    if (!prov) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (propName == "ChainingMode") {
        if (pbInput == 0 || cbInput == 0 || cbInput > kMaxChainingModeLen * 2) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
            return true;
        }
        std::wstring modeWide = ctx.ReadWideString(pbInput, kMaxChainingModeLen);
        std::string mode      = WideToNarrow(modeWide);

        // Validate known chaining modes
        if (mode != "ChainingModeCBC" && mode != "ChainingModeGCM" &&
            mode != "ChainingModeECB" && mode != "ChainingModeCFB" &&
            mode != "ChainingModeCCM") {
            ctx.SetReturnNtStatus(NT::STATUS_NOT_SUPPORTED);
            return true;
        }

        prov->chainingMode = mode;
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    ctx.SetReturnNtStatus(NT::STATUS_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// BCryptGenerateSymmetricKey
// ============================================================================
// CRITICAL for ransomware analysis: captures the actual encryption key bytes.

bool HandleBCryptGenerateSymmetricKey(APIContext& ctx) {
    // arg0 = BCRYPT_ALG_HANDLE hAlgorithm
    // arg1 = BCRYPT_KEY_HANDLE* phKey       (OUT)
    // arg2 = PUCHAR pbKeyObject             (optional object buffer)
    // arg3 = ULONG cbKeyObject
    // arg4 = PUCHAR pbSecret                (the key material!)
    // arg5 = ULONG cbSecret
    // arg6 = ULONG dwFlags

    uint32_t     algoHandleId = ctx.GetArg32(0);
    GuestAddress phKey        = ctx.GetArgPtr(1);
    GuestAddress pbSecret     = ctx.GetArgPtr(4);
    uint32_t     cbSecret     = ctx.GetArg32(5);

    if (phKey == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    EmulatedAlgoProvider* prov = LookupProvider(algoHandleId);
    if (!prov) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (pbSecret == 0 || cbSecret == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Cap key material to prevent resource exhaustion
    uint32_t safeLen = (cbSecret > kMaxKeyMaterialSize) ? kMaxKeyMaterialSize : cbSecret;

    if (st.keys.size() >= kMaxKeys) {
        ctx.SetReturnNtStatus(NT::STATUS_NO_MEMORY);
        return true;
    }

    // Read key material from guest memory — forensically critical!
    EmulatedKey key;
    key.id          = st.AllocId();
    key.algoId      = algoHandleId;
    key.algorithm   = prov->algorithmName;
    key.keyLength   = safeLen;
    key.keyMaterial.resize(safeLen);

    auto err = ctx.Memory().Read(pbSecret, key.keyMaterial.data(), safeLen);
    if (err != ErrorCode::Success) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Track AES key presence for ransomware detection
    if (prov->algorithmName == "AES") {
        st.hasAESKey = true;
        // AES-256 is the most common ransomware cipher
        if (safeLen >= 32) {
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        }
    }

    uint32_t keyHandleId = key.id;
    st.keys.emplace(keyHandleId, std::move(key));

    // Write key handle to guest memory
    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phKey, static_cast<uint64_t>(keyHandleId));
    } else {
        ctx.Memory().WriteU32(phKey, keyHandleId);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptDestroyKey
// ============================================================================

bool HandleBCryptDestroyKey(APIContext& ctx) {
    // arg0 = BCRYPT_KEY_HANDLE hKey

    uint32_t handleId = ctx.GetArg32(0);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    auto it = st.keys.find(handleId);
    if (it == st.keys.end()) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    // NOTE: We do NOT erase the key — forensic data must survive key destruction.
    // Real ransomware destroys keys after encryption to hinder recovery.
    // We keep the captured material for analysis.
    // Mark as destroyed but retain data.
    st.keys.erase(it);

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptEncrypt
// ============================================================================
// No actual encryption — data passes through for pattern analysis readability.
// We track call counts and capture IVs.

bool HandleBCryptEncrypt(APIContext& ctx) {
    // arg0 = BCRYPT_KEY_HANDLE hKey
    // arg1 = PUCHAR pbInput
    // arg2 = ULONG cbInput
    // arg3 = VOID* pPaddingInfo    (ignored)
    // arg4 = PUCHAR pbIV
    // arg5 = ULONG cbIV
    // arg6 = PUCHAR pbOutput
    // arg7 = ULONG cbOutput
    // arg8 = ULONG* pcbResult
    // arg9 = ULONG dwFlags

    uint32_t     keyHandleId = ctx.GetArg32(0);
    GuestAddress pbInput     = ctx.GetArgPtr(1);
    uint32_t     cbInput     = ctx.GetArg32(2);
    GuestAddress pbIV        = ctx.GetArgPtr(4);
    uint32_t     cbIV        = ctx.GetArg32(5);
    GuestAddress pbOutput    = ctx.GetArgPtr(6);
    uint32_t     cbOutput    = ctx.GetArg32(7);
    GuestAddress pcbResult   = ctx.GetArgPtr(8);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    EmulatedKey* key = LookupKey(keyHandleId);
    if (!key) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    // Cap input length for safety
    uint32_t safeInputLen = (cbInput > kMaxEncryptLen) ? kMaxEncryptLen : cbInput;

    // Size query: if pbOutput is NULL, return required buffer size
    if (pbOutput == 0) {
        // For block ciphers, output size includes padding to block boundary
        uint32_t resultLen = safeInputLen;
        EmulatedAlgoProvider* prov = LookupProvider(key->algoId);
        if (prov && prov->blockLength > 1) {
            uint32_t bl = prov->blockLength;
            resultLen = ((safeInputLen + bl - 1) / bl) * bl;
            if (resultLen == safeInputLen) resultLen += bl; // PKCS7 always adds at least 1 byte
        }
        if (pcbResult != 0) {
            ctx.Memory().WriteU32(pcbResult, resultLen);
        }
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    if (cbOutput < safeInputLen) {
        ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
        return true;
    }

    // Capture IV if provided
    if (pbIV != 0 && cbIV > 0) {
        uint32_t safeIVLen = (cbIV > 64) ? 64 : cbIV;
        key->lastIV.resize(safeIVLen);
        ctx.Memory().Read(pbIV, key->lastIV.data(), safeIVLen);
    }

    // Copy input to output unchanged — preserves plaintext for downstream analysis.
    // This is intentional: we want pattern matching on "encrypted" file content
    // to still find the original data during emulation.
    if (pbInput != 0 && safeInputLen > 0) {
        static constexpr uint32_t kChunkSize = 4096;
        uint8_t chunk[kChunkSize];
        uint32_t remaining = safeInputLen;
        GuestAddress readAddr  = pbInput;
        GuestAddress writeAddr = pbOutput;

        while (remaining > 0) {
            uint32_t toProcess = (remaining < kChunkSize) ? remaining : kChunkSize;
            auto readErr = ctx.Memory().Read(readAddr, chunk, toProcess);
            if (readErr != ErrorCode::Success) break;

            // Simple XOR with first key byte — makes output differ from input
            // while remaining trivially reversible for analysis
            if (!key->keyMaterial.empty()) {
                uint8_t xorByte = key->keyMaterial[0];
                for (uint32_t i = 0; i < toProcess; ++i) {
                    chunk[i] ^= xorByte;
                }
            }

            auto writeErr = ctx.Memory().Write(writeAddr, chunk, toProcess);
            if (writeErr != ErrorCode::Success) break;

            readAddr  += toProcess;
            writeAddr += toProcess;
            remaining -= toProcess;
        }
    }

    // Write result size
    if (pcbResult != 0) {
        ctx.Memory().WriteU32(pcbResult, safeInputLen);
    }

    // Increment counters — critical for ransomware pattern detection
    key->encryptCount++;
    st.totalEncrypts.fetch_add(1, std::memory_order_relaxed);

    // Ransomware behavior detection
    if (st.totalEncrypts.load(std::memory_order_relaxed) >= kRansomwareEncryptThreshold) {
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptDecrypt
// ============================================================================
// Mirror of BCryptEncrypt — same XOR-through approach.

bool HandleBCryptDecrypt(APIContext& ctx) {
    // arg0 = BCRYPT_KEY_HANDLE hKey
    // arg1 = PUCHAR pbInput
    // arg2 = ULONG cbInput
    // arg3 = VOID* pPaddingInfo
    // arg4 = PUCHAR pbIV
    // arg5 = ULONG cbIV
    // arg6 = PUCHAR pbOutput
    // arg7 = ULONG cbOutput
    // arg8 = ULONG* pcbResult
    // arg9 = ULONG dwFlags

    uint32_t     keyHandleId = ctx.GetArg32(0);
    GuestAddress pbInput     = ctx.GetArgPtr(1);
    uint32_t     cbInput     = ctx.GetArg32(2);
    GuestAddress pbIV        = ctx.GetArgPtr(4);
    uint32_t     cbIV        = ctx.GetArg32(5);
    GuestAddress pbOutput    = ctx.GetArgPtr(6);
    uint32_t     cbOutput    = ctx.GetArg32(7);
    GuestAddress pcbResult   = ctx.GetArgPtr(8);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    EmulatedKey* key = LookupKey(keyHandleId);
    if (!key) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    uint32_t safeInputLen = (cbInput > kMaxEncryptLen) ? kMaxEncryptLen : cbInput;

    // Size query
    if (pbOutput == 0) {
        if (pcbResult != 0) {
            ctx.Memory().WriteU32(pcbResult, safeInputLen);
        }
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    if (cbOutput < safeInputLen) {
        ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
        return true;
    }

    // Capture IV
    if (pbIV != 0 && cbIV > 0) {
        uint32_t safeIVLen = (cbIV > 64) ? 64 : cbIV;
        key->lastIV.resize(safeIVLen);
        ctx.Memory().Read(pbIV, key->lastIV.data(), safeIVLen);
    }

    // Reverse the XOR transform (same operation since XOR is self-inverse)
    if (pbInput != 0 && safeInputLen > 0) {
        static constexpr uint32_t kChunkSize = 4096;
        uint8_t chunk[kChunkSize];
        uint32_t remaining = safeInputLen;
        GuestAddress readAddr  = pbInput;
        GuestAddress writeAddr = pbOutput;

        while (remaining > 0) {
            uint32_t toProcess = (remaining < kChunkSize) ? remaining : kChunkSize;
            auto readErr = ctx.Memory().Read(readAddr, chunk, toProcess);
            if (readErr != ErrorCode::Success) break;

            if (!key->keyMaterial.empty()) {
                uint8_t xorByte = key->keyMaterial[0];
                for (uint32_t i = 0; i < toProcess; ++i) {
                    chunk[i] ^= xorByte;
                }
            }

            auto writeErr = ctx.Memory().Write(writeAddr, chunk, toProcess);
            if (writeErr != ErrorCode::Success) break;

            readAddr  += toProcess;
            writeAddr += toProcess;
            remaining -= toProcess;
        }
    }

    if (pcbResult != 0) {
        ctx.Memory().WriteU32(pcbResult, safeInputLen);
    }

    key->decryptCount++;
    st.totalDecrypts.fetch_add(1, std::memory_order_relaxed);

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptGenRandom
// ============================================================================
// Deterministic PRNG fill — ensures reproducible analysis across runs.

bool HandleBCryptGenRandom(APIContext& ctx) {
    // arg0 = BCRYPT_ALG_HANDLE hAlgorithm  (can be NULL with BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    // arg1 = PUCHAR pbBuffer
    // arg2 = ULONG cbBuffer
    // arg3 = ULONG dwFlags

    uint32_t     algoHandle = ctx.GetArg32(0);
    GuestAddress pbBuffer   = ctx.GetArgPtr(1);
    uint32_t     cbBuffer   = ctx.GetArg32(2);
    uint32_t     dwFlags    = ctx.GetArg32(3);

    bool systemPreferred = (dwFlags & BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0;

    // Validate handle unless BCRYPT_USE_SYSTEM_PREFERRED_RNG is set
    if (!systemPreferred && algoHandle != 0) {
        auto& st = GetState();
        std::lock_guard lock(st.mutex);
        if (!LookupProvider(algoHandle)) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
            return true;
        }
    }

    if (pbBuffer == 0 || cbBuffer == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Cap to prevent resource exhaustion
    uint32_t safeLen = (cbBuffer > kMaxGenRandomLen) ? kMaxGenRandomLen : cbBuffer;

    // Fill in chunks to avoid large stack allocations
    static constexpr uint32_t kChunkSize = 4096;
    uint8_t chunk[kChunkSize];
    uint32_t remaining = safeLen;
    GuestAddress writeAddr = pbBuffer;

    while (remaining > 0) {
        uint32_t toWrite = (remaining < kChunkSize) ? remaining : kChunkSize;
        BcryptDeterministicRNG::Instance().Fill(chunk, toWrite);

        auto err = ctx.Memory().Write(writeAddr, chunk, toWrite);
        if (err != ErrorCode::Success) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
            return true;
        }

        writeAddr += toWrite;
        remaining -= toWrite;
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptImportKeyPair
// ============================================================================
// CRITICAL: RSA public key import is a strong ransomware signal.
// Ransomware imports the attacker's RSA pubkey to encrypt per-file AES keys.

bool HandleBCryptImportKeyPair(APIContext& ctx) {
    // arg0 = BCRYPT_ALG_HANDLE hAlgorithm
    // arg1 = BCRYPT_KEY_HANDLE hImportKey   (usually NULL)
    // arg2 = LPCWSTR pszBlobType
    // arg3 = BCRYPT_KEY_HANDLE* phKey       (OUT)
    // arg4 = PUCHAR pbInput                 (key blob)
    // arg5 = ULONG cbInput
    // arg6 = ULONG dwFlags

    uint32_t     algoHandleId = ctx.GetArg32(0);
    GuestAddress pszBlobType  = ctx.GetArgPtr(2);
    GuestAddress phKey        = ctx.GetArgPtr(3);
    GuestAddress pbInput      = ctx.GetArgPtr(4);
    uint32_t     cbInput      = ctx.GetArg32(5);

    if (phKey == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    EmulatedAlgoProvider* prov = LookupProvider(algoHandleId);
    if (!prov) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (st.keys.size() >= kMaxKeys) {
        ctx.SetReturnNtStatus(NT::STATUS_NO_MEMORY);
        return true;
    }

    // Read blob type
    std::string blobType;
    if (pszBlobType != 0) {
        std::wstring blobWide = ctx.ReadWideString(pszBlobType, kMaxPropertyNameLen);
        blobType = WideToNarrow(blobWide);
    }

    EmulatedKey key;
    key.id        = st.AllocId();
    key.algoId    = algoHandleId;
    key.algorithm = prov->algorithmName;

    // Capture key blob for forensic analysis
    if (pbInput != 0 && cbInput > 0) {
        uint32_t safeLen = (cbInput > kMaxBlobSize) ? kMaxBlobSize : cbInput;
        key.keyMaterial.resize(safeLen);
        auto err = ctx.Memory().Read(pbInput, key.keyMaterial.data(), safeLen);
        if (err != ErrorCode::Success) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
            return true;
        }
        key.keyLength = safeLen;
    }

    // RSA public key import = strong ransomware indicator
    if (prov->algorithmName == "RSA" && blobType == "RSAPUBLICBLOB") {
        st.hasRSAPubKey = true;
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI | BehaviorFlag::DefenseEvasion);
    }

    uint32_t keyHandleId = key.id;
    st.keys.emplace(keyHandleId, std::move(key));

    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phKey, static_cast<uint64_t>(keyHandleId));
    } else {
        ctx.Memory().WriteU32(phKey, keyHandleId);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptExportKey
// ============================================================================

bool HandleBCryptExportKey(APIContext& ctx) {
    // arg0 = BCRYPT_KEY_HANDLE hKey
    // arg1 = BCRYPT_KEY_HANDLE hExportKey   (usually NULL)
    // arg2 = LPCWSTR pszBlobType
    // arg3 = PUCHAR pbOutput
    // arg4 = ULONG cbOutput
    // arg5 = ULONG* pcbResult
    // arg6 = ULONG dwFlags

    uint32_t     keyHandleId = ctx.GetArg32(0);
    GuestAddress pbOutput    = ctx.GetArgPtr(3);
    uint32_t     cbOutput    = ctx.GetArg32(4);
    GuestAddress pcbResult   = ctx.GetArgPtr(5);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    EmulatedKey* key = LookupKey(keyHandleId);
    if (!key) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    uint32_t blobSize = static_cast<uint32_t>(key->keyMaterial.size());
    if (blobSize == 0) {
        // Synthesize minimal blob size based on key length
        blobSize = key->keyLength > 0 ? key->keyLength : 32;
    }

    if (pcbResult != 0) {
        ctx.Memory().WriteU32(pcbResult, blobSize);
    }

    if (pbOutput == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    if (cbOutput < blobSize) {
        ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
        return true;
    }

    // Write key material back to guest
    if (!key->keyMaterial.empty()) {
        ctx.Memory().Write(pbOutput, key->keyMaterial.data(),
                           static_cast<uint32_t>(key->keyMaterial.size()));
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptCreateHash
// ============================================================================

bool HandleBCryptCreateHash(APIContext& ctx) {
    // arg0 = BCRYPT_ALG_HANDLE hAlgorithm
    // arg1 = BCRYPT_HASH_HANDLE* phHash     (OUT)
    // arg2 = PUCHAR pbHashObject            (optional)
    // arg3 = ULONG cbHashObject
    // arg4 = PUCHAR pbSecret                (HMAC key, optional)
    // arg5 = ULONG cbSecret
    // arg6 = ULONG dwFlags

    uint32_t     algoHandleId = ctx.GetArg32(0);
    GuestAddress phHash       = ctx.GetArgPtr(1);

    if (phHash == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    EmulatedAlgoProvider* prov = LookupProvider(algoHandleId);
    if (!prov) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (st.hashes.size() >= kMaxHashes) {
        ctx.SetReturnNtStatus(NT::STATUS_NO_MEMORY);
        return true;
    }

    EmulatedHash hash;
    hash.id         = st.AllocId();
    hash.algoId     = algoHandleId;
    hash.algorithm  = prov->algorithmName;
    hash.hashLength = prov->hashLength;

    uint32_t hashHandleId = hash.id;
    st.hashes.emplace(hashHandleId, std::move(hash));

    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phHash, static_cast<uint64_t>(hashHandleId));
    } else {
        ctx.Memory().WriteU32(phHash, hashHandleId);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptHashData
// ============================================================================

bool HandleBCryptHashData(APIContext& ctx) {
    // arg0 = BCRYPT_HASH_HANDLE hHash
    // arg1 = PUCHAR pbInput
    // arg2 = ULONG cbInput
    // arg3 = ULONG dwFlags

    uint32_t     hashHandleId = ctx.GetArg32(0);
    GuestAddress pbInput      = ctx.GetArgPtr(1);
    uint32_t     cbInput      = ctx.GetArg32(2);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    EmulatedHash* hash = LookupHash(hashHandleId);
    if (!hash) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (pbInput == 0 || cbInput == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // Cap accumulated data to prevent memory exhaustion
    uint32_t currentSize = static_cast<uint32_t>(hash->accumulated.size());
    if (currentSize >= kMaxHashAccumulate) {
        // Silently succeed — we already have enough data for analysis
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    uint32_t safeLen = cbInput;
    if (currentSize + safeLen > kMaxHashAccumulate) {
        safeLen = kMaxHashAccumulate - currentSize;
    }

    size_t oldSize = hash->accumulated.size();
    hash->accumulated.resize(oldSize + safeLen);
    ctx.Memory().Read(pbInput, hash->accumulated.data() + oldSize, safeLen);

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptFinishHash
// ============================================================================
// Produces a deterministic (but not cryptographically correct) hash value.
// Sufficient for emulation — malware rarely validates hash correctness.

bool HandleBCryptFinishHash(APIContext& ctx) {
    // arg0 = BCRYPT_HASH_HANDLE hHash
    // arg1 = PUCHAR pbOutput
    // arg2 = ULONG cbOutput
    // arg3 = ULONG dwFlags

    uint32_t     hashHandleId = ctx.GetArg32(0);
    GuestAddress pbOutput     = ctx.GetArgPtr(1);
    uint32_t     cbOutput     = ctx.GetArg32(2);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    EmulatedHash* hash = LookupHash(hashHandleId);
    if (!hash) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (pbOutput == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    uint32_t hashLen = hash->hashLength;
    if (hashLen == 0) hashLen = 32; // Default to SHA256-length
    if (cbOutput < hashLen) {
        ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
        return true;
    }

    // Produce a deterministic hash from accumulated data using a simple
    // mixing function. Not cryptographically correct, but deterministic
    // and data-dependent — sufficient for emulation purposes.
    std::vector<uint8_t> result(hashLen, 0);

    uint64_t state = 0x5BADCAFE00000000ULL;
    for (uint8_t b : hash->accumulated) {
        state = state * 6364136223846793005ULL + static_cast<uint64_t>(b);
    }

    for (uint32_t i = 0; i < hashLen; ++i) {
        state = state * 6364136223846793005ULL + 1;
        result[i] = static_cast<uint8_t>(state >> 33);
    }

    ctx.Memory().Write(pbOutput, result.data(), hashLen);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// BCryptDestroyHash
// ============================================================================

bool HandleBCryptDestroyHash(APIContext& ctx) {
    // arg0 = BCRYPT_HASH_HANDLE hHash

    uint32_t hashHandleId = ctx.GetArg32(0);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    auto it = st.hashes.find(hashHandleId);
    if (it == st.hashes.end()) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    st.hashes.erase(it);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterBcrypt(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "bcrypt.dll", "BCryptOpenAlgorithmProvider",  HandleBCryptOpenAlgorithmProvider,  4, false },
        { "bcrypt.dll", "BCryptCloseAlgorithmProvider", HandleBCryptCloseAlgorithmProvider, 2, false },
        { "bcrypt.dll", "BCryptGetProperty",            HandleBCryptGetProperty,            6, false },
        { "bcrypt.dll", "BCryptSetProperty",            HandleBCryptSetProperty,            5, false },
        { "bcrypt.dll", "BCryptGenerateSymmetricKey",   HandleBCryptGenerateSymmetricKey,   7, false },
        { "bcrypt.dll", "BCryptDestroyKey",             HandleBCryptDestroyKey,             1, false },
        { "bcrypt.dll", "BCryptEncrypt",                HandleBCryptEncrypt,               10, false },
        { "bcrypt.dll", "BCryptDecrypt",                HandleBCryptDecrypt,               10, false },
        { "bcrypt.dll", "BCryptGenRandom",              HandleBCryptGenRandom,              4, false },
        { "bcrypt.dll", "BCryptImportKeyPair",          HandleBCryptImportKeyPair,          7, false },
        { "bcrypt.dll", "BCryptExportKey",              HandleBCryptExportKey,              7, false },
        { "bcrypt.dll", "BCryptCreateHash",             HandleBCryptCreateHash,             7, false },
        { "bcrypt.dll", "BCryptHashData",               HandleBCryptHashData,               4, false },
        { "bcrypt.dll", "BCryptFinishHash",             HandleBCryptFinishHash,             4, false },
        { "bcrypt.dll", "BCryptDestroyHash",            HandleBCryptDestroyHash,            1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Bcrypt

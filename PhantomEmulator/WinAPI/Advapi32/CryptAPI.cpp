/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * CryptAPI.cpp — Advapi32 cryptographic API handler implementations
 *
 * CryptEncrypt/CryptDecrypt are no-ops but tracked as ransomware indicators.
 * CryptGenRandom uses a deterministic LCG for reproducible analysis with
 * non-zero fill patterns.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "CryptAPI.hpp"
#include "../APIDispatcher.hpp"

#include <atomic>
#include <cstring>
#include <string>

namespace Phantom::WinAPI::Advapi32 {

// ============================================================================
// Win32 crypto constants (no windows.h dependency)
// ============================================================================

static constexpr uint32_t ERROR_SUCCESS           = 0;
static constexpr uint32_t ERROR_INVALID_HANDLE    = 6;
static constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
static constexpr uint32_t NTE_BAD_UID             = 0x80090001;

static constexpr uint32_t PROV_RSA_FULL           = 1;
static constexpr uint32_t PROV_RSA_AES            = 24;
static constexpr uint32_t CRYPT_VERIFYCONTEXT     = 0xF0000000;
static constexpr uint32_t CRYPT_NEWKEYSET         = 0x00000008;

// ============================================================================
// Deterministic LCG for CryptGenRandom
// ============================================================================
// Not crypto-strength — intentionally deterministic for reproducible analysis.
// Parameters chosen for full period on 64-bit state with non-zero output bytes.

class DeterministicRNG {
public:
    static DeterministicRNG& Instance() noexcept {
        static DeterministicRNG s_instance;
        return s_instance;
    }

    uint8_t Next() noexcept {
        // Knuth's LCG: state = state * 6364136223846793005 + 1442695040888963407
        uint64_t s = m_state.load(std::memory_order_relaxed);
        uint64_t next = s * 6364136223846793005ULL + 1442695040888963407ULL;
        m_state.store(next, std::memory_order_relaxed);
        // Return bits [32..39] — good distribution from LCG
        return static_cast<uint8_t>(next >> 32);
    }

    void Fill(uint8_t* buf, uint32_t len) noexcept {
        for (uint32_t i = 0; i < len; ++i) {
            buf[i] = Next();
        }
    }

private:
    DeterministicRNG() noexcept = default;
    std::atomic<uint64_t> m_state{ 0xDEADBEEFCAFEBABEULL };
};

// ============================================================================
// Handle helpers: use SyncObjectData with HandleType::Event as surrogate
// for HCRYPTPROV and HCRYPTHASH handles.
// ============================================================================

static std::wstring NarrowToWide(std::string_view s) noexcept {
    std::wstring w;
    w.reserve(s.size());
    for (char c : s) w.push_back(static_cast<wchar_t>(static_cast<uint8_t>(c)));
    return w;
}

// ============================================================================
// CryptAcquireContextA/W
// ============================================================================

static bool CryptAcquireContextImpl(APIContext& ctx, bool isWide) {
    // arg0 = phProv (HCRYPTPROV*)
    // arg1 = szContainer (can be NULL)
    // arg2 = szProvider (can be NULL)
    // arg3 = dwProvType
    // arg4 = dwFlags

    GuestAddress phProv = ctx.GetArgPtr(0);

    if (phProv == 0) {
        ctx.SetLastError(ERROR_INVALID_PARAMETER);
        ctx.SetReturnBool(false);
        return true;
    }

    SyncObjectData provData;
    provData.name     = L"CryptProvider";
    provData.signaled = true;

    GuestHandle provHandle = ctx.Handles().Create(HandleType::Event, std::move(provData));

    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phProv, provHandle);
    } else {
        ctx.Memory().WriteU32(phProv, static_cast<uint32_t>(provHandle));
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

bool HandleCryptAcquireContextA(APIContext& ctx) { return CryptAcquireContextImpl(ctx, false); }
bool HandleCryptAcquireContextW(APIContext& ctx) { return CryptAcquireContextImpl(ctx, true); }

// ============================================================================
// CryptGenRandom
// ============================================================================

bool HandleCryptGenRandom(APIContext& ctx) {
    // arg0 = hProv
    // arg1 = dwLen
    // arg2 = pbBuffer

    GuestHandle hProv    = ctx.GetArg(0);
    uint32_t    dwLen    = ctx.GetArg32(1);
    GuestAddress pbBuf   = ctx.GetArgPtr(2);

    if (!ctx.Handles().IsValid(hProv)) {
        ctx.SetLastError(ERROR_INVALID_HANDLE);
        ctx.SetReturnBool(false);
        return true;
    }

    if (pbBuf == 0 || dwLen == 0) {
        ctx.SetReturnBool(true);
        ctx.SetLastError(ERROR_SUCCESS);
        return true;
    }

    // Cap to prevent resource exhaustion
    static constexpr uint32_t kMaxGenLen = 64 * 1024;
    if (dwLen > kMaxGenLen) dwLen = kMaxGenLen;

    // Fill a host-side buffer then write to guest memory in one shot
    // to minimize memory API calls
    static constexpr uint32_t kChunkSize = 4096;
    uint8_t chunk[kChunkSize];

    uint32_t remaining = dwLen;
    GuestAddress writeAddr = pbBuf;

    while (remaining > 0) {
        uint32_t toWrite = (remaining < kChunkSize) ? remaining : kChunkSize;
        DeterministicRNG::Instance().Fill(chunk, toWrite);
        auto err = ctx.Memory().Write(writeAddr, chunk, toWrite);
        if (err != ErrorCode::Success) {
            ctx.SetLastError(ERROR_INVALID_PARAMETER);
            ctx.SetReturnBool(false);
            return true;
        }
        writeAddr += toWrite;
        remaining -= toWrite;
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// CryptEncrypt — no-op, tracked as ransomware indicator
// ============================================================================

bool HandleCryptEncrypt(APIContext& ctx) {
    // arg0 = hKey
    // arg1 = hHash
    // arg2 = Final
    // arg3 = dwFlags
    // arg4 = pbData
    // arg5 = pdwDataLen
    // arg6 = dwBufLen

    // No actual encryption — we leave the buffer untouched so we can
    // observe what the malware intended to encrypt.
    // The dispatcher flags this call via the APIDatabase behavioral annotation.

    GuestAddress pdwDataLen = ctx.GetArgPtr(5);
    if (pdwDataLen != 0) {
        // Read current data length and leave it unchanged (identity transform)
        uint32_t dataLen = 0;
        ctx.Memory().ReadU32(pdwDataLen, dataLen);
        ctx.Memory().WriteU32(pdwDataLen, dataLen);
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// CryptDecrypt — no-op, tracked as ransomware indicator
// ============================================================================

bool HandleCryptDecrypt(APIContext& ctx) {
    // arg0 = hKey
    // arg1 = hHash
    // arg2 = Final
    // arg3 = dwFlags
    // arg4 = pbData
    // arg5 = pdwDataLen

    GuestAddress pdwDataLen = ctx.GetArgPtr(5);
    if (pdwDataLen != 0) {
        uint32_t dataLen = 0;
        ctx.Memory().ReadU32(pdwDataLen, dataLen);
        ctx.Memory().WriteU32(pdwDataLen, dataLen);
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// CryptCreateHash
// ============================================================================

bool HandleCryptCreateHash(APIContext& ctx) {
    // arg0 = hProv
    // arg1 = Algid
    // arg2 = hKey
    // arg3 = dwFlags
    // arg4 = phHash*

    GuestHandle hProv    = ctx.GetArg(0);
    GuestAddress phHash  = ctx.GetArgPtr(4);

    if (!ctx.Handles().IsValid(hProv)) {
        ctx.SetLastError(ERROR_INVALID_HANDLE);
        ctx.SetReturnBool(false);
        return true;
    }

    if (phHash == 0) {
        ctx.SetLastError(ERROR_INVALID_PARAMETER);
        ctx.SetReturnBool(false);
        return true;
    }

    SyncObjectData hashData;
    hashData.name     = L"CryptHash";
    hashData.signaled = true;

    GuestHandle hashHandle = ctx.Handles().Create(HandleType::Event, std::move(hashData));

    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phHash, hashHandle);
    } else {
        ctx.Memory().WriteU32(phHash, static_cast<uint32_t>(hashHandle));
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// CryptHashData — no-op, return TRUE
// ============================================================================

bool HandleCryptHashData(APIContext& ctx) {
    // arg0 = hHash
    // arg1 = pbData
    // arg2 = dwDataLen
    // arg3 = dwFlags

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// CryptReleaseContext
// ============================================================================

bool HandleCryptReleaseContext(APIContext& ctx) {
    // arg0 = hProv
    // arg1 = dwFlags

    GuestHandle hProv = ctx.GetArg(0);

    if (!ctx.Handles().Close(hProv)) {
        ctx.SetLastError(ERROR_INVALID_HANDLE);
        ctx.SetReturnBool(false);
        return true;
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterCryptAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "advapi32.dll", "CryptAcquireContextA", HandleCryptAcquireContextA, 5, false },
        { "advapi32.dll", "CryptAcquireContextW", HandleCryptAcquireContextW, 5, false },
        { "advapi32.dll", "CryptGenRandom",       HandleCryptGenRandom,       3, false },
        { "advapi32.dll", "CryptEncrypt",         HandleCryptEncrypt,         7, false },
        { "advapi32.dll", "CryptDecrypt",         HandleCryptDecrypt,         6, false },
        { "advapi32.dll", "CryptCreateHash",      HandleCryptCreateHash,      5, false },
        { "advapi32.dll", "CryptHashData",        HandleCryptHashData,        4, false },
        { "advapi32.dll", "CryptReleaseContext",  HandleCryptReleaseContext,  2, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Advapi32

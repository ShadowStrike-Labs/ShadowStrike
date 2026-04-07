/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * BcryptAPI.hpp — BCrypt/CNG cryptographic API emulation handlers
 *
 * Emulates the Windows BCrypt (CNG) cryptographic API surface used
 * extensively by modern ransomware (Conti, LockBit, BlackCat, Royal, Akira)
 * for AES-256 file encryption, RSA public key import, and IV generation.
 *
 * This module does NOT perform real cryptography. Instead, it:
 *   1. Captures all key material for forensic recovery
 *   2. Counts encryption/decryption operations for ransomware detection
 *   3. Produces deterministic "random" output for reproducible analysis
 *   4. Passes data through encrypt/decrypt unchanged for pattern analysis
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Bcrypt {

// ============================================================================
// Forensic Extraction Types
// ============================================================================
// Captured cryptographic keys and operational counters for ransomware analysis.

struct CapturedCryptoKey {
    std::string          algorithm;
    std::vector<uint8_t> keyMaterial;
    std::vector<uint8_t> iv;
    uint32_t             encryptionCount  = 0;
    uint32_t             decryptionCount  = 0;
};

// ============================================================================
// BCryptState — Module-level state for BCrypt emulation
// ============================================================================
// Meyers' singleton holding all emulated algorithm providers, keys, hashes,
// and forensic counters. Thread-safe via internal mutex.

class BCryptState {
public:
    [[nodiscard]] static BCryptState& Instance() noexcept;

    // Forensic extraction
    [[nodiscard]] std::vector<CapturedCryptoKey> GetCapturedKeys() const noexcept;
    [[nodiscard]] uint32_t GetTotalEncryptionCalls() const noexcept;
    [[nodiscard]] uint32_t GetTotalDecryptionCalls() const noexcept;
    [[nodiscard]] bool IsRansomwareBehavior() const noexcept;

    // Reset all state (session cleanup)
    void Reset() noexcept;

    BCryptState(const BCryptState&) = delete;
    BCryptState& operator=(const BCryptState&) = delete;

private:
    BCryptState() noexcept = default;
};

// ============================================================================
// Registration
// ============================================================================

void RegisterBcrypt(APIDispatcher& dispatcher) noexcept;

// ============================================================================
// Individual API Handlers
// ============================================================================
// Each returns true to continue emulation, false to halt.

bool HandleBCryptOpenAlgorithmProvider(APIContext& ctx);
bool HandleBCryptCloseAlgorithmProvider(APIContext& ctx);
bool HandleBCryptGetProperty(APIContext& ctx);
bool HandleBCryptSetProperty(APIContext& ctx);
bool HandleBCryptGenerateSymmetricKey(APIContext& ctx);
bool HandleBCryptDestroyKey(APIContext& ctx);
bool HandleBCryptEncrypt(APIContext& ctx);
bool HandleBCryptDecrypt(APIContext& ctx);
bool HandleBCryptGenRandom(APIContext& ctx);
bool HandleBCryptImportKeyPair(APIContext& ctx);
bool HandleBCryptExportKey(APIContext& ctx);
bool HandleBCryptCreateHash(APIContext& ctx);
bool HandleBCryptHashData(APIContext& ctx);
bool HandleBCryptFinishHash(APIContext& ctx);
bool HandleBCryptDestroyHash(APIContext& ctx);

} // namespace WinAPI::Bcrypt
} // namespace Phantom

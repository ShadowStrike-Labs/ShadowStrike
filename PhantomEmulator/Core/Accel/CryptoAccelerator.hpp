/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * CryptoAccelerator — Hardware-accelerated crypto detection and hashing
 *
 * Uses AES-NI, SHA-NI, and PCLMULQDQ host instructions to accelerate
 * cryptographic artifact detection during emulation. Critical for ransomware
 * identification (AES key schedule detection, high-entropy region analysis)
 * and fast file hashing (SHA-256 at hardware speed).
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace Phantom {

// ============================================================================
// AES Detection Structures
// ============================================================================

struct AESKeyCandidate {
    GuestAddress address = 0;
    uint32_t keySize = 0;           // 128, 192, or 256
    float confidence = 0.0f;
    std::array<uint8_t, 32> keyBytes{};
};

struct AESDetectionResult {
    std::vector<AESKeyCandidate> keyCandidates;
    std::vector<GuestAddress> sboxLocations;
    std::vector<GuestAddress> roundConstantLocations;
    bool hasAESPatterns = false;
    uint32_t encryptedRegionCount = 0;
};

// ============================================================================
// Encryption Analysis Structures
// ============================================================================

struct EncryptedRegion {
    GuestAddress start = 0;
    GuestSize size = 0;
    double entropy = 0.0;
    enum class Type : uint8_t {
        Unknown,
        AES,
        ChaCha,
        XOR,
        Compressed
    } type = Type::Unknown;
};

struct EncryptionAnalysis {
    std::vector<EncryptedRegion> regions;
    double overallEntropy = 0.0;
    uint32_t encryptedBytes = 0;
    uint32_t totalBytes = 0;
    float encryptedRatio = 0.0f;
    bool isLikelyRansomware = false;
};

// ============================================================================
// CryptoAccelerator
// ============================================================================
// Hardware-accelerated cryptographic detection and hashing engine.
// Uses runtime CPUID feature detection with scalar fallbacks for all paths.
//
// Thread-safe: all public methods are const and operate on immutable state
// after construction. The PIMPL holds only immutable feature flags.

class CryptoAccelerator {
public:
    CryptoAccelerator() noexcept;
    ~CryptoAccelerator() noexcept;

    CryptoAccelerator(const CryptoAccelerator&) = delete;
    CryptoAccelerator& operator=(const CryptoAccelerator&) = delete;
    CryptoAccelerator(CryptoAccelerator&&) noexcept;
    CryptoAccelerator& operator=(CryptoAccelerator&&) noexcept;

    // === Feature Detection ===

    [[nodiscard]] bool HasAESNI() const noexcept;
    [[nodiscard]] bool HasSHANI() const noexcept;
    [[nodiscard]] bool HasPCLMUL() const noexcept;
    [[nodiscard]] bool HasSSE42() const noexcept;

    // === Hashing ===

    [[nodiscard]] SHA256Hash SHA256(ByteSpan data) const noexcept;
    [[nodiscard]] uint32_t CRC32(ByteSpan data) const noexcept;

    // === AES Detection ===

    [[nodiscard]] AESDetectionResult DetectAESContent(
        ByteSpan data, GuestAddress baseAddr) const noexcept;

    // === Encryption Analysis ===

    [[nodiscard]] EncryptionAnalysis AnalyzeEncryption(
        ByteSpan data, GuestAddress baseAddr) const noexcept;

    // === Stream Cipher Detection ===

    [[nodiscard]] bool DetectChaChaPattern(ByteSpan data) const noexcept;

    // === RSA Key Detection ===

    [[nodiscard]] std::vector<GuestAddress> FindRSAPublicKeys(
        ByteSpan data, GuestAddress base) const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom

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

/**
 * @brief Candidate AES root key or expanded-key schedule found in guest memory.
 *
 * Thread safety: immutable value type returned by CryptoAccelerator scan APIs.
 * Failure contract: default-initialized when no candidate is available.
 */
struct AESKeyCandidate {
    GuestAddress address = 0;
    uint32_t keySize = 0;           // 128, 192, or 256
    float confidence = 0.0f;
    std::array<uint8_t, 32> keyBytes{};
};

/**
 * @brief Bounded AES artifact scan result.
 *
 * All vectors are capped by the implementation to prevent hostile guest-memory
 * buffers from driving unbounded allocations. Thread safety: immutable after
 * return to the caller.
 */
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

/**
 * @brief High-entropy guest-memory region classified by crypto heuristics.
 *
 * Addresses are guest virtual addresses. If a caller provides a base address
 * close to UINT64_MAX, implementation saturates rather than wrapping.
 */
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

/**
 * @brief Aggregate entropy and ransomware-oriented encryption heuristics.
 *
 * Failure contract: allocation failure or invalid input returns the default
 * object with zero counters and no regions.
 */
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
/**
 * @brief Cryptographic artifact detector and deterministic hashing helper.
 *
 * The class detects host CPU capabilities at construction but every public API
 * has a scalar, CPU-stable fallback. Inputs are caller-owned byte spans; spans
 * must reference readable memory for their full length. Invalid non-empty null
 * spans are rejected with safe empty/default results.
 *
 * Thread safety: all public methods are const and use immutable state after
 * construction. IRQL: user-mode only; scan APIs make no blocking OS calls.
 * Failure contract: public noexcept APIs never throw; bounded scan APIs return
 * partial or empty results if allocation caps cannot be reserved.
 */

class CryptoAccelerator {
public:
    /**
     * @brief Constructs the accelerator and records host CPU feature flags.
     *
     * Failure contract: allocation failure leaves feature flags unavailable and
     * all APIs continue on safe scalar/default paths.
     */
    CryptoAccelerator() noexcept;
    ~CryptoAccelerator() noexcept;

    CryptoAccelerator(const CryptoAccelerator&) = delete;
    CryptoAccelerator& operator=(const CryptoAccelerator&) = delete;
    CryptoAccelerator(CryptoAccelerator&&) noexcept;
    CryptoAccelerator& operator=(CryptoAccelerator&&) noexcept;

    /** @return true when AES-NI was detected during construction. */
    [[nodiscard]] bool HasAESNI() const noexcept;
    /** @return true when SHA-NI was detected during construction. */
    [[nodiscard]] bool HasSHANI() const noexcept;
    /** @return true when PCLMULQDQ was detected during construction. */
    [[nodiscard]] bool HasPCLMUL() const noexcept;
    /** @return true when SSE4.2 was detected during construction. */
    [[nodiscard]] bool HasSSE42() const noexcept;

    /**
     * @brief Computes a FIPS-180-4 SHA-256 digest for the supplied bytes.
     * @param data Readable input bytes. Empty input is valid.
     * @return Digest bytes in canonical big-endian order; zero digest on invalid
     * non-empty null span.
     */
    [[nodiscard]] SHA256Hash SHA256(ByteSpan data) const noexcept;

    /**
     * @brief Computes CPU-stable IEEE CRC32 (polynomial 0xEDB88320).
     * @param data Readable input bytes. Empty input is valid.
     * @return IEEE CRC32 value, or zero for empty/invalid input.
     */
    [[nodiscard]] uint32_t CRC32(ByteSpan data) const noexcept;

    /**
     * @brief Scans guest memory for AES S-box, RCON, key-schedule, and entropy artifacts.
     * @param data Readable guest-memory bytes.
     * @param baseAddr Guest address corresponding to data[0].
     * @return Bounded detection result; addresses saturate on overflow.
     */
    [[nodiscard]] AESDetectionResult DetectAESContent(
        ByteSpan data, GuestAddress baseAddr) const noexcept;

    /**
     * @brief Performs sliding-window entropy analysis for encrypted/compressed regions.
     * @param data Readable guest-memory bytes.
     * @param baseAddr Guest address corresponding to data[0].
     * @return Bounded entropy analysis result.
     */
    [[nodiscard]] EncryptionAnalysis AnalyzeEncryption(
        ByteSpan data, GuestAddress baseAddr) const noexcept;

    /**
     * @brief Detects embedded ChaCha20/Salsa20 constants in guest memory.
     * @param data Readable guest-memory bytes.
     * @return true when a recognized constant layout is found.
     */
    [[nodiscard]] bool DetectChaChaPattern(ByteSpan data) const noexcept;

    /**
     * @brief Finds DER and CryptoAPI RSA public/private key blob signatures.
     * @param data Readable guest-memory bytes.
     * @param base Guest address corresponding to data[0].
     * @return Bounded list of guest addresses for validated key structures.
     */
    [[nodiscard]] std::vector<GuestAddress> FindRSAPublicKeys(
        ByteSpan data, GuestAddress base) const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom

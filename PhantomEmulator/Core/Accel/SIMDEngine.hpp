/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SIMDEngine — Host-CPU SIMD-accelerated primitives for emulation analysis
 *
 * Provides AVX2/SSE4.2/SSE2 optimized routines for entropy calculation,
 * pattern matching, CRC checksumming, and memory analysis. All functions
 * include scalar fallbacks for compatibility.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include "../../Common/Platform.hpp"
#include <array>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace Phantom {

// ============================================================================
// CPU Feature Flags
// ============================================================================

struct CPUFeatures {
    bool sse2       = false;
    bool sse41      = false;
    bool sse42      = false;
    bool avx        = false;
    bool avx2       = false;
    bool aesni      = false;
    bool shani      = false;
    bool pclmulqdq  = false;
    bool bmi1       = false;
    bool bmi2       = false;
};

// ============================================================================
// SIMDEngine — SIMD-Accelerated Analysis Primitives
// ============================================================================
// Instantiated per emulation session. Detects host CPU features at construction
// and dispatches to the best available SIMD path at runtime.
//
// Thread safety: all const methods are safe to call concurrently. The object
// itself is immutable after construction (feature flags are set once).

class SIMDEngine {
public:
    SIMDEngine() noexcept;
    ~SIMDEngine() noexcept;

    SIMDEngine(const SIMDEngine&) = delete;
    SIMDEngine& operator=(const SIMDEngine&) = delete;
    SIMDEngine(SIMDEngine&&) noexcept;
    SIMDEngine& operator=(SIMDEngine&&) noexcept;

    // ========================================================================
    // Feature Queries
    // ========================================================================

    [[nodiscard]] bool HasSSE2()       const noexcept;
    [[nodiscard]] bool HasSSE41()      const noexcept;
    [[nodiscard]] bool HasSSE42()      const noexcept;
    [[nodiscard]] bool HasAVX()        const noexcept;
    [[nodiscard]] bool HasAVX2()       const noexcept;
    [[nodiscard]] bool HasAESNI()      const noexcept;
    [[nodiscard]] bool HasSHANI()      const noexcept;
    [[nodiscard]] bool HasPCLMULQDQ()  const noexcept;
    [[nodiscard]] bool HasBMI1()       const noexcept;
    [[nodiscard]] bool HasBMI2()       const noexcept;

    [[nodiscard]] const CPUFeatures& GetFeatures() const noexcept;

    // ========================================================================
    // Entropy Calculation
    // ========================================================================
    // Shannon entropy of the data buffer, in bits per byte [0.0, 8.0].
    // Uses BuildHistogram internally; SIMD dispatch for the histogram phase.

    [[nodiscard]] double CalculateEntropy(ByteSpan data) const noexcept;

    // ========================================================================
    // Byte Frequency Histogram
    // ========================================================================
    // Populates a 256-bin histogram from the input data.

    void BuildHistogram(ByteSpan data,
                        std::array<uint32_t, 256>& histogram) const noexcept;

    // ========================================================================
    // CRC32C Checksum
    // ========================================================================
    // Uses hardware CRC32C (SSE4.2) when available, otherwise a software LUT.

    [[nodiscard]] uint32_t CRC32C(ByteSpan data) const noexcept;

    // ========================================================================
    // Pattern Search (single pattern)
    // ========================================================================
    // Returns the offset of the first occurrence of needle in haystack,
    // or std::nullopt if not found. AVX2 → SSE2 → scalar dispatch.

    [[nodiscard]] std::optional<size_t> FindPattern(
        ByteSpan haystack, ByteSpan needle) const noexcept;

    // ========================================================================
    // Multi-Pattern Search
    // ========================================================================
    // Returns (offset, pattern_index) pairs for every match of every pattern.
    // Uses first-byte SIMD filtering then scalar verification.

    [[nodiscard]] std::vector<std::pair<size_t, uint32_t>> FindPatterns(
        ByteSpan data,
        std::span<const ByteSpan> patterns) const noexcept;

    // ========================================================================
    // Memory Compare
    // ========================================================================
    // Returns true iff the two spans are identical (same length and content).

    [[nodiscard]] bool MemoryEqual(ByteSpan a, ByteSpan b) const noexcept;

    // ========================================================================
    // Single-Byte XOR Key Detection
    // ========================================================================
    // Tries all 256 XOR keys and returns the most likely one if the decoded
    // result has a strong printable-ASCII bias. Returns std::nullopt if no
    // convincing key is found.

    [[nodiscard]] std::optional<uint8_t> DetectSingleByteXOR(
        ByteSpan data) const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom

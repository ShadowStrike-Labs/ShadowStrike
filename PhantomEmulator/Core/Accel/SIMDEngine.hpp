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

/**
 * @brief Immutable host CPU feature snapshot used for SIMD dispatch.
 */
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
/**
 * @brief Host-CPU SIMD accelerated primitives for emulator analysis.
 *
 * The engine detects CPU/OS feature support at construction and dispatches to
 * AVX2/SSE/scalar implementations at runtime. All byte-span inputs must point
 * to readable memory for their declared length; invalid non-empty null spans
 * return empty/default results. Expensive heuristic scans are capped internally
 * to prevent hostile buffers from driving unbounded CPU or allocation work.
 *
 * Thread safety: const methods are safe to call concurrently. The object is
 * immutable after construction. IRQL: user-mode only. Failure contract: public
 * noexcept APIs do not throw; allocation failure returns empty/default results.
 */
class SIMDEngine {
public:
    /**
     * @brief Constructs the engine and records host SIMD feature flags.
     *
     * Failure contract: allocation failure leaves the engine feature-disabled;
     * public APIs continue to return safe empty/default results.
     */
    SIMDEngine() noexcept;
    ~SIMDEngine() noexcept;

    SIMDEngine(const SIMDEngine&) = delete;
    SIMDEngine& operator=(const SIMDEngine&) = delete;
    SIMDEngine(SIMDEngine&&) noexcept;
    SIMDEngine& operator=(SIMDEngine&&) noexcept;

    /** @return true when SSE2 is available. */
    [[nodiscard]] bool HasSSE2()       const noexcept;
    /** @return true when SSE4.1 is available. */
    [[nodiscard]] bool HasSSE41()      const noexcept;
    /** @return true when SSE4.2 is available. */
    [[nodiscard]] bool HasSSE42()      const noexcept;
    /** @return true when AVX and OS XSAVE support are available. */
    [[nodiscard]] bool HasAVX()        const noexcept;
    /** @return true when AVX2 and required OS state support are available. */
    [[nodiscard]] bool HasAVX2()       const noexcept;
    /** @return true when AES-NI is available. */
    [[nodiscard]] bool HasAESNI()      const noexcept;
    /** @return true when SHA-NI is available. */
    [[nodiscard]] bool HasSHANI()      const noexcept;
    /** @return true when PCLMULQDQ is available. */
    [[nodiscard]] bool HasPCLMULQDQ()  const noexcept;
    /** @return true when BMI1 is available. */
    [[nodiscard]] bool HasBMI1()       const noexcept;
    /** @return true when BMI2 is available. */
    [[nodiscard]] bool HasBMI2()       const noexcept;

    /** @return Immutable feature snapshot; all false if construction failed. */
    [[nodiscard]] const CPUFeatures& GetFeatures() const noexcept;

    /**
     * @brief Calculates Shannon entropy in bits per byte.
     * @param data Readable bytes; empty input returns 0.
     * @return Entropy in [0, 8], or 0 for invalid input.
     */
    [[nodiscard]] double CalculateEntropy(ByteSpan data) const noexcept;

    /**
     * @brief Builds a 256-bin byte-frequency histogram.
     * @param data Readable bytes; internally capped for uint32_t bin safety.
     * @param histogram Output bins; reset to zero before population.
     */
    void BuildHistogram(ByteSpan data,
                        std::array<uint32_t, 256>& histogram) const noexcept;

    /**
     * @brief Computes CRC32C/Castagnoli checksum.
     * @param data Readable bytes; empty or invalid input returns 0.
     * @return CRC32C checksum with hardware SSE4.2 dispatch when available.
     */
    [[nodiscard]] uint32_t CRC32C(ByteSpan data) const noexcept;

    /**
     * @brief Finds the first occurrence of a byte pattern.
     * @param haystack Readable search bytes; internally capped.
     * @param needle Readable pattern bytes; empty needle matches offset 0.
     * @return Offset, or nullopt when not found/invalid.
     */
    [[nodiscard]] std::optional<size_t> FindPattern(
        ByteSpan haystack, ByteSpan needle) const noexcept;

    /**
     * @brief Finds bounded occurrences for multiple byte patterns.
     * @param data Readable search bytes; internally capped.
     * @param patterns Readable pattern span; invalid/empty patterns are skipped.
     * @return Bounded (offset, pattern_index) pairs.
     */
    [[nodiscard]] std::vector<std::pair<size_t, uint32_t>> FindPatterns(
        ByteSpan data,
        std::span<const ByteSpan> patterns) const noexcept;

    /**
     * @brief Constant-result memory equality check with SIMD dispatch.
     * @param a First readable byte span.
     * @param b Second readable byte span.
     * @return true when lengths and bytes match; false for invalid non-empty spans.
     */
    [[nodiscard]] bool MemoryEqual(ByteSpan a, ByteSpan b) const noexcept;

    /**
     * @brief Detects likely single-byte XOR key for ASCII-oriented decoder stubs.
     * @param data Encoded bytes; internally capped for CPU bounds.
     * @return Best key when printable/text score is convincing, otherwise nullopt.
     */
    [[nodiscard]] std::optional<uint8_t> DetectSingleByteXOR(
        ByteSpan data) const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom

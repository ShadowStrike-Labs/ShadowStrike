/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike PhantomCortex - REAL-TIME FEATURE EXTRACTION ENGINE
 * ============================================================================
 *
 * @file FeatureExtractor.hpp
 * @brief Meyers' Singleton for extracting ML feature vectors from live data.
 *
 * Transforms raw telemetry (PE bytes, API sequences, memory dumps, network
 * flows, emulation traces) into fixed-size float vectors suitable for ONNX
 * model inference. Feature encoding MUST match the Python training pipeline
 * exactly — any divergence will silently degrade detection accuracy.
 *
 * FEATURE VECTOR SIZES (must match training):
 * ============================================
 * ┌──────────────┬──────────────────────────────────┐
 * │ Model        │ Feature Count                    │
 * ├──────────────┼──────────────────────────────────┤
 * │ Static (PE)  │ 2381 (EMBER-aligned)             │
 * │ Behavioral   │  512 (API sequence embedding)    │
 * │ Memory       │  256 (byte histogram + entropy)  │
 * │ Network      │  128 (flow statistics + TLS)     │
 * │ Emulation    │  384 (opcode/mem/API sequence)   │
 * └──────────────┴──────────────────────────────────┘
 *
 * SECURITY CONSIDERATIONS:
 * ========================
 * - All input buffers are bounds-checked against hard limits.
 * - Malformed PE files, truncated traces, and adversarial inputs
 *   must never cause undefined behavior — return std::nullopt.
 * - Allocation sizes are capped via CortexConstants.
 *
 * THREAD SAFETY:
 * ==============
 * - All extraction methods are stateless with respect to the Impl
 *   (read-only lookup tables). Concurrent calls are safe.
 * - Internal lookup tables are initialized once during Initialize()
 *   and never mutated afterward.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <memory>
#include <vector>
#include <span>
#include <optional>

// ============================================================================
// SHADOWSTRIKE INCLUDES
// ============================================================================

#include "CortexTypes.hpp"

namespace ShadowStrike {
namespace AI {

/**
 * @brief Meyers' Singleton responsible for converting raw telemetry into
 *        fixed-size feature vectors for ML inference.
 *
 * @note Thread Safety: All public methods are thread-safe.
 *       Extraction routines operate on immutable internal lookup tables
 *       and take only const/span parameters — no shared mutable state.
 */
class FeatureExtractor final {
public:
    // ================================================================
    // Singleton Access
    // ================================================================

    /**
     * @brief Get the singleton instance.
     * @return Reference to the global FeatureExtractor instance.
     *
     * Thread Safety: Thread-safe (C++11 static initialization guarantee).
     */
    static FeatureExtractor& Instance() noexcept;

    // Disable copy and move
    FeatureExtractor(const FeatureExtractor&)            = delete;
    FeatureExtractor& operator=(const FeatureExtractor&) = delete;
    FeatureExtractor(FeatureExtractor&&)                 = delete;
    FeatureExtractor& operator=(FeatureExtractor&&)      = delete;

    // ================================================================
    // Lifecycle
    // ================================================================

    /**
     * @brief Initialize internal lookup tables and normalization parameters.
     * @return true on success; false if resource allocation fails.
     *
     * Must be called once before any Extract*() method. Safe to call
     * multiple times — subsequent calls return true immediately.
     *
     * Thread Safety: Serialized (exclusive lock during first call).
     */
    [[nodiscard]] bool Initialize() noexcept;

    // ================================================================
    // PE Static Feature Extraction
    // ================================================================

    /**
     * @brief Extract static features from raw PE file bytes.
     * @param fileBytes Raw bytes of the PE file (non-owning view).
     * @return Feature vector of size CortexConstants::STATIC_FEATURE_COUNT,
     *         or std::nullopt if the file is not a valid PE, exceeds
     *         MAX_PE_FILE_SIZE, or extraction fails.
     *
     * Extracts header fields, section entropy, import/export histograms,
     * string statistics, and byte n-gram features aligned with the
     * EMBER feature format used during training.
     *
     * Thread Safety: Safe for concurrent calls.
     */
    [[nodiscard]] std::optional<std::vector<float>> ExtractPEFeatures(
        std::span<const uint8_t> fileBytes) noexcept;

    // ================================================================
    // Behavioral Feature Extraction
    // ================================================================

    /**
     * @brief Extract behavioral features from an API call sequence.
     * @param apiCalls Ordered sequence of observed API call records.
     * @return Feature vector of size CortexConstants::BEHAVIORAL_FEATURE_COUNT,
     *         or std::nullopt if the sequence is empty or extraction fails.
     *
     * Encodes API name hashes, call ordering, return value distributions,
     * and temporal patterns. Sequences longer than MAX_API_SEQUENCE_LENGTH
     * are truncated to the most recent calls.
     *
     * Thread Safety: Safe for concurrent calls.
     */
    [[nodiscard]] std::optional<std::vector<float>> ExtractBehavioralFeatures(
        std::span<const APICallRecord> apiCalls) noexcept;

    // ================================================================
    // Memory Region Feature Extraction
    // ================================================================

    /**
     * @brief Extract features from a suspicious memory region.
     * @param region Memory region descriptor with a data view.
     * @return Feature vector of size CortexConstants::MEMORY_FEATURE_COUNT,
     *         or std::nullopt if the region exceeds MAX_MEMORY_REGION_SIZE
     *         or extraction fails.
     *
     * Computes byte histogram, Shannon entropy, opcode density heuristics,
     * ROP gadget statistics, and protection flag encodings.
     *
     * Thread Safety: Safe for concurrent calls.
     */
    [[nodiscard]] std::optional<std::vector<float>> ExtractMemoryFeatures(
        const MemoryRegionInfo& region) noexcept;

    // ================================================================
    // Network Flow Feature Extraction
    // ================================================================

    /**
     * @brief Extract features from a network flow record.
     * @param flow Aggregated network flow metadata.
     * @return Feature vector of size CortexConstants::NETWORK_FEATURE_COUNT,
     *         or std::nullopt if extraction fails.
     *
     * Encodes volume ratios, timing statistics, TLS fingerprints,
     * DNS query characteristics, and payload entropy.
     *
     * Thread Safety: Safe for concurrent calls.
     */
    [[nodiscard]] std::optional<std::vector<float>> ExtractNetworkFeatures(
        const NetworkFlowInfo& flow) noexcept;

    // ================================================================
    // Emulation Trace Feature Extraction
    // ================================================================

    /**
     * @brief Extract features from an emulation trace.
     * @param events Ordered sequence of emulation events.
     * @return Feature vector of size CortexConstants::EMULATION_FEATURE_COUNT,
     *         or std::nullopt if the trace is empty or extraction fails.
     *
     * Encodes instruction category n-grams, memory access patterns,
     * API call sequences observed during emulation, and EFLAGS
     * transition statistics.
     *
     * Thread Safety: Safe for concurrent calls.
     */
    [[nodiscard]] std::optional<std::vector<float>> ExtractEmulationFeatures(
        std::span<const EmulationEvent> events) noexcept;

private:
    FeatureExtractor() = default;
    ~FeatureExtractor() = default;

    /// @brief Opaque implementation — hides lookup tables and normalization state.
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace AI
}  // namespace ShadowStrike

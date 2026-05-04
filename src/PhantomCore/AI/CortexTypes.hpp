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
 * ShadowStrike PhantomCortex - SHARED TYPES AND ENUMERATIONS
 * ============================================================================
 *
 * @file CortexTypes.hpp
 * @brief Core type definitions for the PhantomCortex AI/ML inference engine.
 *
 * Defines all shared enumerations, structures, and configuration types used
 * across the PhantomCortex subsystem. These types form the contract between
 * feature extraction, model inference, and the orchestrator.
 *
 * Enum categories are aligned 1:1 with the Python training pipeline label
 * encodings to ensure inference parity between training and production.
 *
 * DESIGN PRINCIPLES:
 * ==================
 * - All enums are scoped (enum class) for type safety
 * - All structs are trivially copyable where possible for cache efficiency
 * - std::span used for zero-copy buffer views (no ownership)
 * - std::chrono used for all time measurements (no raw integers)
 * - std::filesystem::path used for all file system paths
 *
 * @note Thread Safety: All types defined here are value types.
 *       They are safe to copy, move, and use concurrently without
 *       synchronization unless explicitly noted otherwise.
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
#include <cstddef>
#include <string>
#include <array>
#include <span>
#include <optional>
#include <chrono>
#include <filesystem>

namespace ShadowStrike {
namespace AI {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace CortexConstants {

    /// @brief Number of distinct model types in the ensemble
    inline constexpr size_t MODEL_COUNT = 5;

    /// @brief Feature vector size for the static PE model (EMBER 2024 aligned)
    inline constexpr size_t STATIC_FEATURE_COUNT = 2568;

    /// @brief Maximum API call sequence length for the behavioral model
    inline constexpr size_t MAX_API_SEQUENCE_LENGTH = 2048;

    /// @brief Behavioral model: number of timesteps in the API call sequence
    inline constexpr size_t BEHAVIORAL_SEQ_LENGTH = 512;

    /// @brief Behavioral model: features per timestep (apiHash, argHash, retVal, deltaMs)
    inline constexpr size_t BEHAVIORAL_FEATURES_PER_STEP = 4;

    /// @brief Total flat feature count for the behavioral model (SEQ_LENGTH × FEATURES_PER_STEP)
    inline constexpr size_t BEHAVIORAL_FEATURE_COUNT = BEHAVIORAL_SEQ_LENGTH * BEHAVIORAL_FEATURES_PER_STEP;

    /// @brief Feature vector size for the memory scanner model (CIC-MalMem-2022 aligned)
    inline constexpr size_t MEMORY_FEATURE_COUNT = 128;

    /// @brief Feature vector size for the network flow model (UNSW-NB15 aligned)
    inline constexpr size_t NETWORK_FEATURE_COUNT = 64;

    /// @brief Emulation model: number of timesteps in the event trace
    inline constexpr size_t EMULATION_SEQ_LENGTH = 1024;

    /// @brief Emulation model: features per timestep (opcodeCategory, memAccessType, apiCallId, eflagsChange)
    inline constexpr size_t EMULATION_FEATURES_PER_STEP = 4;

    /// @brief Total flat feature count for the emulation trace model (SEQ_LENGTH × FEATURES_PER_STEP)
    inline constexpr size_t EMULATION_FEATURE_COUNT = EMULATION_SEQ_LENGTH * EMULATION_FEATURES_PER_STEP;

    /// @brief Maximum batch size for inference requests
    inline constexpr uint32_t MAX_BATCH_SIZE = 128;

    /// @brief Maximum model file size (500 MB)
    inline constexpr size_t MAX_MODEL_FILE_SIZE = 500ULL * 1024 * 1024;

    /// @brief Maximum memory region size for scanning (64 MB)
    inline constexpr size_t MAX_MEMORY_REGION_SIZE = 64ULL * 1024 * 1024;

    /// @brief Maximum PE file size for static analysis (256 MB)
    inline constexpr size_t MAX_PE_FILE_SIZE = 256ULL * 1024 * 1024;

    /// @brief Confidence value indicating uninitialized / not computed
    inline constexpr float CONFIDENCE_UNSET = -1.0f;

    /// @brief Default inference timeout in milliseconds
    inline constexpr uint32_t DEFAULT_INFERENCE_TIMEOUT_MS = 100;

    /// @brief Maximum allowed inference timeout in milliseconds (30 seconds)
    inline constexpr uint32_t MAX_INFERENCE_TIMEOUT_MS = 30000;

    // ------------------------------------------------------------------
    // Compile-time training-parity guards
    // ------------------------------------------------------------------
    // These constants form the binding contract between the Python
    // training pipeline and the production inference path. A silent
    // numeric drift here will not produce a runtime error — it will
    // produce systematically wrong verdicts. Pin the derived values at
    // compile time so any edit to the source constants breaks the build.
    static_assert(BEHAVIORAL_FEATURE_COUNT == 2048,
                  "BEHAVIORAL_FEATURE_COUNT diverged from training pipeline (512 x 4)");
    static_assert(EMULATION_FEATURE_COUNT  == 4096,
                  "EMULATION_FEATURE_COUNT diverged from training pipeline (1024 x 4)");
    static_assert(MAX_BATCH_SIZE > 0,
                  "MAX_BATCH_SIZE must be positive");
    static_assert(MAX_INFERENCE_TIMEOUT_MS >= DEFAULT_INFERENCE_TIMEOUT_MS,
                  "MAX_INFERENCE_TIMEOUT_MS must dominate DEFAULT_INFERENCE_TIMEOUT_MS");

}  // namespace CortexConstants

// ============================================================================
// MODEL TYPE ENUMERATION
// ============================================================================

/**
 * @brief Identifies which ML model produced a verdict.
 *
 * Each model targets a distinct telemetry source. The ordinal values
 * serve as indices into the ensemble verdict array.
 */
enum class CortexModelType : uint8_t {
    Static      = 0,    ///< Pre-execution PE feature analysis
    Behavioral  = 1,    ///< Runtime API call sequence classification
    Memory      = 2,    ///< Suspicious memory region analysis
    Network     = 3,    ///< Network flow classification
    Emulation   = 4     ///< Post-emulation trace classification
};

// Lock the ensemble verdict array width to the number of model types.
// Adding a new CortexModelType without bumping MODEL_COUNT would cause
// the ensemble aggregator to silently drop the new model's verdict.
static_assert(static_cast<size_t>(CortexModelType::Emulation) + 1
              == CortexConstants::MODEL_COUNT,
              "CortexConstants::MODEL_COUNT must equal the cardinality of CortexModelType");

// ============================================================================
// VERDICT ENUMERATIONS
// ============================================================================

/**
 * @brief Top-level threat classification produced by any model.
 */
enum class ThreatVerdict : uint8_t {
    Benign      = 0,    ///< No threat detected
    Suspicious  = 1,    ///< Below conviction threshold — monitor closely
    Malicious   = 2     ///< High-confidence threat — take action
};

/**
 * @brief Behavioral threat category labels.
 *
 * These 20 categories are aligned 1:1 with the Python training pipeline
 * label encoding. Changing the ordinal values will break inference parity.
 */
enum class BehaviorCategory : uint8_t {
    ProcessInjection    = 0,
    Ransomware          = 1,
    InfoStealer         = 2,
    Backdoor            = 3,
    Rootkit             = 4,
    Downloader          = 5,
    Dropper             = 6,
    Worm                = 7,
    Miner               = 8,
    Adware              = 9,
    Keylogger           = 10,
    RAT                 = 11,
    BankTrojan          = 12,
    Spyware             = 13,
    Fileless            = 14,
    LateralMovement     = 15,
    Exfiltration        = 16,
    Persistence         = 17,
    PrivEsc             = 18,
    Benign              = 19
};

/**
 * @brief Memory region threat classification.
 *
 * Aligned with CIC-MalMem-2022 + MemMal-D2024 training taxonomy.
 * 4-class: Benign / Trojan / Ransomware / Spyware.
 */
enum class MemoryThreatType : uint8_t {
    Benign      = 0,
    Trojan      = 1,
    Ransomware  = 2,
    Spyware     = 3
};

/**
 * @brief Network flow threat classification.
 */
enum class NetworkThreatType : uint8_t {
    Normal          = 0,
    C2Beacon        = 1,
    Exfiltration    = 2,
    LateralMovement = 3,
    Scanning        = 4,
    DGADomain       = 5,
    DNSTunnel       = 6,
    CryptoMining    = 7
};

// ============================================================================
// VERDICT STRUCTURES
// ============================================================================

/**
 * @brief Result produced by a single model inference pass.
 *
 * Contains the verdict, confidence, model source, sub-classification
 * (where applicable), and timing metadata.
 */
struct CortexVerdict {
    ThreatVerdict       verdict             = ThreatVerdict::Benign;
    float               confidence          = 0.0f;
    CortexModelType     source              = CortexModelType::Static;
    BehaviorCategory    behaviorCategory    = BehaviorCategory::Benign;
    MemoryThreatType    memoryThreat        = MemoryThreatType::Benign;
    NetworkThreatType   networkThreat       = NetworkThreatType::Normal;
    std::wstring        details;
    std::chrono::microseconds inferenceTime{0};
};

/**
 * @brief Combined result from the full model ensemble.
 *
 * Aggregates verdicts from all available models into a unified
 * decision with an ensemble confidence score.
 */
struct CortexEnsembleVerdict {
    ThreatVerdict       finalVerdict        = ThreatVerdict::Benign;
    float               ensembleConfidence  = 0.0f;
    std::array<CortexVerdict, CortexConstants::MODEL_COUNT> modelVerdicts{};
    std::chrono::microseconds totalInferenceTime{0};
};

// ============================================================================
// INPUT DATA STRUCTURES
// ============================================================================

/**
 * @brief A single observed API call record for behavioral analysis.
 *
 * Fields are hashed at collection time to avoid storing sensitive strings
 * and to match the feature encoding used during training.
 */
struct APICallRecord {
    uint32_t    apiNameHash         = 0;    ///< CRC32/FNV-1a hash of API name
    uint32_t    argSummaryHash      = 0;    ///< Hash of argument summary
    int32_t     returnValue         = 0;    ///< NTSTATUS / HRESULT / int
    float       timestampDeltaMs    = 0.0f; ///< Delta from previous call (ms)
};

/**
 * @brief Describes a memory region to be analysed by the memory model.
 *
 * @warning The `data` span is a non-owning view. The caller must ensure
 *          the backing memory remains valid for the duration of analysis.
 *
 * @note `size` records the *original* VAS region size as observed by the
 *       sensor. When the sensor caps a large region, `data.size()` is the
 *       captured slice while `size` retains the full region length, allowing
 *       downstream models to reason about truncation. Callers MUST treat
 *       `data.size()` (not `size`) as the authoritative byte count of the
 *       captured payload.
 */
struct MemoryRegionInfo {
    std::span<const uint8_t>    data;           ///< Captured region bytes (non-owning)
    uintptr_t                   baseAddress = 0;
    size_t                      size        = 0; ///< Original (pre-capture) region size; may exceed data.size()
    uint32_t                    protection  = 0; ///< PAGE_EXECUTE_READWRITE, etc.
};

/**
 * @brief Aggregated network flow metadata for the network model.
 *
 * All fields are populated from the ShadowStrike network sensor
 * and normalized to match training feature expectations.
 */
struct NetworkFlowInfo {
    // --- Addressing ---
    uint32_t    srcIPv4         = 0;        ///< Source IPv4 (network byte order)
    uint32_t    dstIPv4         = 0;        ///< Dest IPv4 (network byte order)
    uint16_t    srcPort         = 0;
    uint16_t    dstPort         = 0;
    uint8_t     protocol        = 0;        ///< IPPROTO_TCP / UDP / etc.

    // --- Volume ---
    uint64_t    bytesSent       = 0;
    uint64_t    bytesReceived   = 0;
    uint32_t    packetsSent     = 0;
    uint32_t    packetsReceived = 0;

    // --- Timing ---
    float       durationMs          = 0.0f;
    float       avgInterArrivalMs   = 0.0f;
    float       stdInterArrivalMs   = 0.0f;
    float       minInterArrivalMs   = 0.0f;
    float       maxInterArrivalMs   = 0.0f;

    // --- TLS / DNS fingerprinting ---
    uint32_t    ja3Hash         = 0;        ///< JA3 hash of TLS client hello
    uint32_t    ja3sHash        = 0;        ///< JA3S hash of TLS server hello
    uint32_t    dnsQueryHash    = 0;        ///< Hash of first DNS query
    uint16_t    dnsQueryCount   = 0;
    uint16_t    tlsVersion      = 0;        ///< TLS version (0x0303 = TLS 1.2)

    // --- Payload statistics ---
    float       payloadEntropy  = 0.0f;     ///< Shannon entropy of payload
    uint32_t    uniquePayloadBytes = 0;     ///< Count of distinct byte values
};

/**
 * @brief A single event from the PhantomEmulator trace log.
 *
 * Compact representation designed for efficient batched inference.
 */
struct EmulationEvent {
    uint16_t    opcodeCategory      = 0;    ///< Instruction category (e.g., branch, mem, arith)
    uint8_t     memoryAccessType    = 0;    ///< 0=none, 1=read, 2=write, 3=exec
    uint16_t    apiCallId           = 0;    ///< Resolved API ordinal (0 = no API call)
    uint8_t     eflagsChange        = 0;    ///< Bitmask of changed EFLAGS bits
};

// ============================================================================
// MODEL VERSIONING
// ============================================================================

/**
 * @brief Semantic version and provenance metadata for a loaded ONNX model.
 */
struct ModelVersion {
    uint32_t    major       = 0;
    uint32_t    minor       = 0;
    uint32_t    patch       = 0;
    std::wstring modelHash;                 ///< SHA-256 hex digest of the .onnx file
    std::chrono::system_clock::time_point trainedAt{};
};

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * @brief Runtime configuration for the PhantomCortex engine.
 *
 * Sane defaults are provided for all fields. Thresholds are applied
 * per-model: a confidence score below the threshold maps to Benign,
 * between threshold and (threshold + 0.2) maps to Suspicious, and
 * above maps to Malicious.
 */
struct CortexConfig {
    std::filesystem::path   modelDirectory;

    // --- Per-model confidence thresholds ---
    float   staticThreshold         = 0.5f;
    float   behavioralThreshold     = 0.6f;
    float   memoryThreshold         = 0.7f;
    float   networkThreshold        = 0.8f;
    float   emulationThreshold      = 0.6f;
    float   ensembleThreshold       = 0.5f;

    // --- Hardware acceleration ---
    bool    useGPU                  = true;     ///< Prefer DirectML; auto-fallback to CPU
    bool    useAVX512               = true;     ///< Auto-fallback to AVX2 / SSE4.2

    // --- Batching and timeout ---
    uint32_t maxBatchSize           = 32;
    uint32_t inferenceTimeoutMs     = CortexConstants::DEFAULT_INFERENCE_TIMEOUT_MS;
};

}  // namespace AI
}  // namespace ShadowStrike

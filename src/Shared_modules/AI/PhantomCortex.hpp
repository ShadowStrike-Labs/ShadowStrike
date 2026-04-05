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
 * ShadowStrike PhantomCortex - AI/ML MALWARE DETECTION ORCHESTRATOR
 * ============================================================================
 *
 * @file PhantomCortex.hpp
 * @brief Top-level API for PhantomCortex, the AI-driven detection engine.
 *
 * PhantomCortex is the unified entry point that other ShadowStrike modules
 * call to obtain ML-based verdicts. It coordinates feature extraction,
 * model inference, and ensemble decision-making across five model types:
 *
 * DETECTION PIPELINE:
 * ===================
 *
 *   Raw Telemetry
 *       │
 *       ▼
 *  ┌────────────────┐
 *  │ FeatureExtract │ ─── Converts raw data to float vectors
 *  └───────┬────────┘
 *          │
 *          ▼
 *  ┌────────────────┐
 *  │ ModelInference  │ ─── Runs ONNX model, returns probabilities
 *  └───────┬────────┘
 *          │
 *          ▼
 *  ┌────────────────┐
 *  │   Threshold    │ ─── Applies per-model confidence thresholds
 *  └───────┬────────┘
 *          │
 *          ▼
 *  ┌────────────────┐
 *  │   Ensemble     │ ─── Combines multi-model verdicts
 *  └───────┬────────┘
 *          │
 *          ▼
 *     CortexVerdict / CortexEnsembleVerdict
 *
 * MODEL ENSEMBLE ARCHITECTURE:
 * ============================
 * ┌─────────┬────────────┬────────┬─────────┬───────────┐
 * │ Static  │ Behavioral │ Memory │ Network │ Emulation │
 * │  (PE)   │  (API seq) │ (scan) │ (flows) │  (traces) │
 * └────┬────┴─────┬──────┴───┬────┴────┬────┴─────┬─────┘
 *      │          │          │         │          │
 *      └──────────┴──────────┼─────────┴──────────┘
 *                            │
 *                    Weighted Ensemble
 *                            │
 *                     Final Verdict
 *
 * THREAD SAFETY:
 * ==============
 * - All Analyze*() methods are safe for concurrent calls.
 * - EnsembleVerdict() is a pure computation — no shared state.
 * - UpdateModels() acquires exclusive locks and serializes against
 *   inference. In-flight inference calls complete before the swap.
 * - Statistics counters use std::atomic for lock-free updates.
 *
 * LOCK HIERARCHY:
 * ===============
 * 1. m_operationalMutex (for Initialize/Shutdown/UpdateModels)
 * 2. ModelInference::m_modelMutex (delegated to ModelInference)
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
#include <array>
#include <span>
#include <optional>
#include <atomic>
#include <filesystem>

// ============================================================================
// SHADOWSTRIKE INCLUDES
// ============================================================================

#include "CortexTypes.hpp"

namespace ShadowStrike {
namespace AI {

/**
 * @brief Top-level Meyers' Singleton orchestrating the PhantomCortex
 *        AI/ML detection pipeline.
 *
 * @note Thread Safety: All public methods are thread-safe.
 *       See LOCK HIERARCHY in the file header for ordering details.
 */
class PhantomCortex final {
public:
    // ================================================================
    // Singleton Access
    // ================================================================

    /**
     * @brief Get the singleton instance.
     * @return Reference to the global PhantomCortex instance.
     *
     * Thread Safety: Thread-safe (C++11 static initialization guarantee).
     */
    static PhantomCortex& Instance() noexcept;

    // Disable copy and move
    PhantomCortex(const PhantomCortex&)                 = delete;
    PhantomCortex& operator=(const PhantomCortex&)      = delete;
    PhantomCortex(PhantomCortex&&)                      = delete;
    PhantomCortex& operator=(PhantomCortex&&)           = delete;

    // ================================================================
    // Lifecycle Management
    // ================================================================

    /**
     * @brief Initialize the full PhantomCortex pipeline.
     * @param config Engine configuration (paths, thresholds, hardware prefs).
     * @return true on success; false if any sub-component fails to initialize.
     *
     * Initializes FeatureExtractor, ModelInference, and loads all model
     * files found in config.modelDirectory. Safe to call after Shutdown().
     *
     * Thread Safety: Serialized (exclusive lock).
     */
    [[nodiscard]] bool Initialize(const CortexConfig& config) noexcept;

    /**
     * @brief Gracefully shut down the engine and release all resources.
     *
     * In-flight inference calls will complete before resources are freed.
     * Safe to call multiple times.
     *
     * Thread Safety: Serialized (exclusive lock).
     */
    void Shutdown() noexcept;

    /**
     * @brief Query whether the engine is fully initialized and ready.
     * @return true if Initialize() succeeded and Shutdown() has not been called.
     */
    [[nodiscard]] bool IsOperational() const noexcept;

    // ================================================================
    // Single-Model Analysis
    // ================================================================

    /**
     * @brief Pre-execution: classify a PE file from raw bytes.
     * @param fileBytes Raw PE file contents (non-owning view).
     * @return Verdict from the static model.
     *
     * If the engine is not operational or the file cannot be parsed,
     * returns a Benign verdict with confidence 0 and an error in details.
     *
     * Thread Safety: Safe for concurrent calls.
     */
    [[nodiscard]] CortexVerdict AnalyzeFile(
        std::span<const uint8_t> fileBytes) noexcept;

    /**
     * @brief Runtime: classify a process by its API call sequence.
     * @param apiCalls Ordered API call records from the ShadowStrike hook engine.
     * @return Verdict from the behavioral model.
     *
     * Thread Safety: Safe for concurrent calls.
     */
    [[nodiscard]] CortexVerdict AnalyzeBehavior(
        std::span<const APICallRecord> apiCalls) noexcept;

    /**
     * @brief On-demand: classify a suspicious memory region.
     * @param region Memory region descriptor with data view.
     * @return Verdict from the memory model.
     *
     * Thread Safety: Safe for concurrent calls.
     */
    [[nodiscard]] CortexVerdict AnalyzeMemory(
        const MemoryRegionInfo& region) noexcept;

    /**
     * @brief Network: classify a captured traffic flow.
     * @param flow Aggregated network flow metadata.
     * @return Verdict from the network model.
     *
     * Thread Safety: Safe for concurrent calls.
     */
    [[nodiscard]] CortexVerdict AnalyzeNetwork(
        const NetworkFlowInfo& flow) noexcept;

    /**
     * @brief Post-emulation: classify an emulation trace.
     * @param events Ordered emulation events from PhantomEmulator.
     * @return Verdict from the emulation model.
     *
     * Thread Safety: Safe for concurrent calls.
     */
    [[nodiscard]] CortexVerdict AnalyzeEmulationTrace(
        std::span<const EmulationEvent> events) noexcept;

    // ================================================================
    // Ensemble Verdict
    // ================================================================

    /**
     * @brief Combine per-model verdicts into a unified ensemble decision.
     * @param staticV      Optional static model verdict.
     * @param behavioralV  Optional behavioral model verdict.
     * @param memoryV      Optional memory model verdict.
     * @param networkV     Optional network model verdict.
     * @param emulationV   Optional emulation model verdict.
     * @return Ensemble verdict with weighted confidence aggregation.
     *
     * At least one verdict must be provided. Models that produced no
     * verdict are excluded from the ensemble weight calculation.
     *
     * Thread Safety: Pure computation — no shared mutable state.
     */
    [[nodiscard]] CortexEnsembleVerdict EnsembleVerdict(
        std::optional<CortexVerdict> staticV,
        std::optional<CortexVerdict> behavioralV,
        std::optional<CortexVerdict> memoryV,
        std::optional<CortexVerdict> networkV     = std::nullopt,
        std::optional<CortexVerdict> emulationV   = std::nullopt) noexcept;

    // ================================================================
    // Model Management
    // ================================================================

    /**
     * @brief Hot-swap all models from a new directory without downtime.
     * @param newModelDir Directory containing updated .onnx model files.
     * @return true if at least one model was successfully updated.
     *
     * Models are loaded into shadow sessions, verified, then atomically
     * swapped. If a model fails to load, the previous version remains
     * active for that slot.
     *
     * Thread Safety: Serialized (exclusive lock). In-flight inferences
     * complete against the old sessions before the swap.
     */
    [[nodiscard]] bool UpdateModels(
        const std::filesystem::path& newModelDir) noexcept;

    /**
     * @brief Get semantic version metadata for all loaded models.
     * @return Array of optional ModelVersion, indexed by CortexModelType ordinal.
     *         Slots without a loaded model contain std::nullopt.
     */
    [[nodiscard]] std::array<std::optional<ModelVersion>,
                             CortexConstants::MODEL_COUNT> GetModelVersions() const noexcept;

    // ================================================================
    // Runtime Statistics
    // ================================================================

    /**
     * @brief Aggregate statistics counters for the PhantomCortex engine.
     *
     * All counters are std::atomic for lock-free concurrent updates.
     *
     * @note This struct is NOT copyable or movable due to atomic members.
     *       Use GetStats() which returns a snapshot copy.
     */
    struct CortexStats {
        uint64_t totalInferences            = 0;
        uint64_t totalMaliciousDetections   = 0;
        uint64_t totalSuspiciousDetections  = 0;
        uint64_t totalBenignClassifications = 0;
        uint64_t averageInferenceTimeUs     = 0;
        uint64_t modelLoadErrors            = 0;
    };

    /**
     * @brief Retrieve a point-in-time snapshot of engine statistics.
     * @return CortexStats with values read from internal atomic counters.
     *
     * Thread Safety: Lock-free (atomic loads).
     */
    [[nodiscard]] CortexStats GetStats() const noexcept;

private:
    PhantomCortex() = default;
    ~PhantomCortex();

    /// @brief Opaque implementation — hides orchestration state and locks.
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace AI
}  // namespace ShadowStrike

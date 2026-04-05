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
 * ShadowStrike PhantomCortex - ONNX RUNTIME INFERENCE WRAPPER
 * ============================================================================
 *
 * @file ModelInference.hpp
 * @brief Meyers' Singleton wrapping the ONNX Runtime C API for ML inference.
 *
 * Provides a thread-safe interface for loading ONNX models, running single
 * and batched inference, querying hardware capabilities, and performing
 * hot-swap model updates with zero downtime.
 *
 * PIMPL PATTERN:
 * ==============
 * All ONNX Runtime types (OrtEnv, OrtSession, OrtValue, etc.) are
 * confined to the Impl struct defined in ModelInference.cpp. This header
 * exposes zero ORT dependencies, preserving ABI stability and allowing
 * the ORT SDK version to change without recompiling consumers.
 *
 * HARDWARE ACCELERATION:
 * ======================
 * - DirectML (GPU) — preferred when available
 * - AVX-512 / AVX2 / SSE4.2 — auto-detected, best available used
 * - Fallback to reference CPU kernels when no SIMD is present
 *
 * THREAD SAFETY:
 * ==============
 * - ORT sessions are inherently thread-safe for concurrent Infer() calls.
 * - Model loading/unloading acquires an exclusive lock and serializes
 *   against inference.
 * - All public methods are safe to call from any thread.
 *
 * LOCK HIERARCHY:
 * ===============
 * 1. m_modelMutex (shared for Infer, exclusive for Load/Unload)
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
#include <filesystem>

// ============================================================================
// SHADOWSTRIKE INCLUDES
// ============================================================================

#include "CortexTypes.hpp"

namespace ShadowStrike {
namespace AI {

/**
 * @brief Meyers' Singleton wrapping the ONNX Runtime C API.
 *
 * Manages the ORT environment, per-model sessions, and inference
 * execution. All ORT types are hidden behind the PIMPL firewall.
 *
 * @note Thread Safety: All public methods are thread-safe.
 *       Inference calls share a reader lock; model load/unload
 *       operations acquire an exclusive writer lock.
 */
class ModelInference final {
public:
    // ================================================================
    // Singleton Access
    // ================================================================

    /**
     * @brief Get the singleton instance.
     * @return Reference to the global ModelInference instance.
     *
     * Thread Safety: Thread-safe (C++11 static initialization guarantee).
     */
    static ModelInference& Instance() noexcept;

    // Disable copy and move
    ModelInference(const ModelInference&)                = delete;
    ModelInference& operator=(const ModelInference&)     = delete;
    ModelInference(ModelInference&&)                     = delete;
    ModelInference& operator=(ModelInference&&)          = delete;

    // ================================================================
    // Lifecycle Management
    // ================================================================

    /**
     * @brief Initialize the ORT environment and configure execution providers.
     * @param config Engine configuration (GPU/SIMD preferences, timeouts).
     * @return true on success; false if ORT initialization fails.
     *
     * Must be called exactly once before any other method. Repeated calls
     * after successful initialization return true immediately.
     *
     * Thread Safety: Serialized (exclusive lock).
     */
    [[nodiscard]] bool Initialize(const CortexConfig& config) noexcept;

    /**
     * @brief Release all ORT sessions and the environment.
     *
     * Safe to call multiple times. After shutdown, Initialize() may be
     * called again to restart the engine.
     *
     * Thread Safety: Serialized (exclusive lock).
     */
    void Shutdown() noexcept;

    /**
     * @brief Query whether the ORT environment is ready.
     * @return true if Initialize() has completed successfully.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    // ================================================================
    // Model Loading
    // ================================================================

    /**
     * @brief Load an ONNX model for the specified model type.
     * @param type   Which slot to load the model into.
     * @param onnxPath Absolute path to the .onnx file.
     * @return true on success; false on file I/O or ORT parse error.
     *
     * If a model is already loaded for @p type, it is replaced atomically.
     * Ongoing inference calls against the old session will complete before
     * the session object is destroyed.
     *
     * Thread Safety: Serialized (exclusive lock on the target model slot).
     */
    [[nodiscard]] bool LoadModel(CortexModelType type,
                                 const std::filesystem::path& onnxPath) noexcept;

    /**
     * @brief Unload the model for the specified type.
     * @param type Model slot to clear.
     *
     * No-op if the slot is already empty.
     *
     * Thread Safety: Serialized (exclusive lock on the target model slot).
     */
    void UnloadModel(CortexModelType type) noexcept;

    // ================================================================
    // Inference
    // ================================================================

    /**
     * @brief Run single-sample inference on the specified model.
     * @param type       Which model to use.
     * @param inputData  Flat feature vector (row-major).
     * @param inputShape Tensor shape (e.g., {1, featureCount}).
     * @return Output tensor as a flat float vector, or std::nullopt on error.
     *
     * Thread Safety: Concurrent calls to Infer() on the same or different
     * model types are safe (shared lock per model slot).
     */
    [[nodiscard]] std::optional<std::vector<float>> Infer(
        CortexModelType type,
        std::span<const float> inputData,
        std::span<const int64_t> inputShape) noexcept;

    /**
     * @brief Run batched inference on the specified model.
     * @param type       Which model to use.
     * @param batchData  Flat feature matrix (batch × features, row-major).
     * @param batchShape Tensor shape (e.g., {batchSize, featureCount}).
     * @return Vector of per-sample output vectors, or std::nullopt on error.
     *
     * The batch size dimension is derived from batchShape[0]. The caller
     * must ensure batchData.size() == product(batchShape).
     *
     * Thread Safety: Same as Infer().
     */
    [[nodiscard]] std::optional<std::vector<std::vector<float>>> InferBatch(
        CortexModelType type,
        std::span<const float> batchData,
        std::span<const int64_t> batchShape) noexcept;

    // ================================================================
    // Model Metadata
    // ================================================================

    /**
     * @brief Retrieve version metadata for a loaded model.
     * @param type Model slot to query.
     * @return ModelVersion if the model is loaded, std::nullopt otherwise.
     */
    [[nodiscard]] std::optional<ModelVersion> GetModelVersion(
        CortexModelType type) const noexcept;

    /**
     * @brief Check whether a model is currently loaded.
     * @param type Model slot to query.
     * @return true if a valid session exists for the slot.
     */
    [[nodiscard]] bool IsModelLoaded(CortexModelType type) const noexcept;

    // ================================================================
    // Hardware Capability Detection
    // ================================================================

    /**
     * @brief Check if the host CPU supports AVX2 instructions.
     * @return true if AVX2 is available.
     */
    [[nodiscard]] bool HasAVX2() const noexcept;

    /**
     * @brief Check if the host CPU supports AVX-512 instructions.
     * @return true if AVX-512F is available.
     */
    [[nodiscard]] bool HasAVX512() const noexcept;

    /**
     * @brief Check if a DirectML-capable GPU is available.
     * @return true if DirectML execution provider can be used.
     */
    [[nodiscard]] bool HasDirectML() const noexcept;

private:
    ModelInference();
    ~ModelInference();

    /// @brief Opaque implementation — hides all ONNX Runtime types.
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace AI
}  // namespace ShadowStrike

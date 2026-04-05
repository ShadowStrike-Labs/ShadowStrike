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
 * ShadowStrike PhantomCortex - MODEL FILE CACHE AND INTEGRITY MANAGER
 * ============================================================================
 *
 * @file ModelCache.hpp
 * @brief Meyers' Singleton managing ONNX model files on disk.
 *
 * Handles model versioning, integrity verification (SHA-256), atomic
 * file swaps, rollback support, and coordinated updates from a remote
 * manifest. Ensures that a corrupt or tampered model file never reaches
 * the inference engine.
 *
 * FILE LAYOUT (per model type):
 * =============================
 *   <cacheDir>/
 *   ├── static/
 *   │   ├── current.onnx          ← active model
 *   │   ├── previous.onnx         ← rollback target
 *   │   └── manifest.json         ← version + SHA-256
 *   ├── behavioral/
 *   │   └── ...
 *   ├── memory/
 *   │   └── ...
 *   ├── network/
 *   │   └── ...
 *   └── emulation/
 *       └── ...
 *
 * ATOMIC SWAP PROTOCOL:
 * =====================
 * 1. Stage: Write new model to <slot>/staging.onnx
 * 2. Verify: Compute SHA-256 and compare with expected hash
 * 3. Backup: Rename current.onnx → previous.onnx
 * 4. Activate: Rename staging.onnx → current.onnx
 * 5. Commit: Update manifest.json
 *
 * If any step fails, the previous model remains active.
 *
 * SECURITY:
 * =========
 * - All downloaded files are verified against SHA-256 before activation.
 * - Model paths are validated against directory traversal attacks.
 * - File sizes are capped at CortexConstants::MAX_MODEL_FILE_SIZE.
 *
 * THREAD SAFETY:
 * ==============
 * - Read-only queries (GetModelPath, VerifyIntegrity) use a shared lock.
 * - Mutating operations (Download, Swap, Rollback) use an exclusive lock.
 * - Each model slot has an independent lock for maximum concurrency.
 *
 * LOCK HIERARCHY:
 * ===============
 * 1. m_slotMutex[type] (per-slot reader/writer lock)
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
#include <string>
#include <optional>
#include <filesystem>

// ============================================================================
// SHADOWSTRIKE INCLUDES
// ============================================================================

#include "CortexTypes.hpp"

namespace ShadowStrike {
namespace AI {

/**
 * @brief Meyers' Singleton managing ONNX model files, integrity, and updates.
 *
 * @note Thread Safety: All public methods are thread-safe.
 *       See LOCK HIERARCHY in the file header for ordering details.
 */
class ModelCache final {
public:
    // ================================================================
    // Singleton Access
    // ================================================================

    /**
     * @brief Get the singleton instance.
     * @return Reference to the global ModelCache instance.
     *
     * Thread Safety: Thread-safe (C++11 static initialization guarantee).
     */
    static ModelCache& Instance() noexcept;

    // Disable copy and move
    ModelCache(const ModelCache&)                = delete;
    ModelCache& operator=(const ModelCache&)     = delete;
    ModelCache(ModelCache&&)                     = delete;
    ModelCache& operator=(ModelCache&&)          = delete;

    // ================================================================
    // Lifecycle
    // ================================================================

    /**
     * @brief Initialize the cache, creating the directory structure if needed.
     * @param cacheDir Root directory for model storage.
     * @return true on success; false if the directory cannot be created or accessed.
     *
     * Thread Safety: Serialized (exclusive lock).
     */
    [[nodiscard]] bool Initialize(const std::filesystem::path& cacheDir) noexcept;

    // ================================================================
    // Remote Update Coordination
    // ================================================================

    /**
     * @brief Check a remote manifest for available model updates.
     * @param manifestUrl HTTPS URL of the model manifest JSON.
     * @return true if one or more models have a newer version available.
     *
     * Compares SHA-256 hashes in the remote manifest against the local
     * manifest for each model slot. Does NOT download any files.
     *
     * Thread Safety: Shared lock (read-only comparison).
     */
    [[nodiscard]] bool CheckForUpdates(const std::wstring& manifestUrl) noexcept;

    /**
     * @brief Download a model file and verify its integrity.
     * @param type            Model slot to update.
     * @param url             HTTPS URL to download from.
     * @param expectedSha256  Expected SHA-256 hex digest of the file.
     * @return true if the download succeeded and the hash matched.
     *
     * The file is written to a staging location first. If verification
     * fails, the staging file is deleted and no swap occurs.
     *
     * Thread Safety: Exclusive lock on the target model slot.
     */
    [[nodiscard]] bool DownloadModel(CortexModelType type,
                                     const std::wstring& url,
                                     const std::wstring& expectedSha256) noexcept;

    // ================================================================
    // Local Model Queries
    // ================================================================

    /**
     * @brief Get the filesystem path to the active model for a slot.
     * @param type Model slot to query.
     * @return Absolute path to current.onnx, or std::nullopt if no model exists.
     *
     * Thread Safety: Shared lock on the target model slot.
     */
    [[nodiscard]] std::optional<std::filesystem::path> GetModelPath(
        CortexModelType type) const noexcept;

    // ================================================================
    // Atomic Model Swap
    // ================================================================

    /**
     * @brief Atomically swap the active model with a new file.
     * @param type     Model slot to update.
     * @param newModel Path to the verified replacement .onnx file.
     * @return true if the swap completed successfully.
     *
     * Follows the five-step atomic swap protocol documented in the
     * file header. The previous model is preserved for rollback.
     *
     * Thread Safety: Exclusive lock on the target model slot.
     */
    [[nodiscard]] bool SwapModel(CortexModelType type,
                                 const std::filesystem::path& newModel) noexcept;

    // ================================================================
    // Rollback
    // ================================================================

    /**
     * @brief Rollback the active model to the previous version.
     * @param type Model slot to rollback.
     * @return true if the rollback succeeded; false if no previous version exists.
     *
     * Thread Safety: Exclusive lock on the target model slot.
     */
    [[nodiscard]] bool Rollback(CortexModelType type) noexcept;

    // ================================================================
    // Integrity Verification
    // ================================================================

    /**
     * @brief Verify the on-disk integrity of the active model file.
     * @param type Model slot to verify.
     * @return true if the file exists and its SHA-256 matches the manifest.
     *
     * Thread Safety: Shared lock on the target model slot.
     */
    [[nodiscard]] bool VerifyIntegrity(CortexModelType type) const noexcept;

private:
    ModelCache() = default;
    ~ModelCache() = default;

    /// @brief Opaque implementation — hides file I/O, hashing, and lock state.
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace AI
}  // namespace ShadowStrike

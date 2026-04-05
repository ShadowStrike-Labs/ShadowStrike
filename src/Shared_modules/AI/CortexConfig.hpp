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
 * ShadowStrike PhantomCortex - CONFIGURATION MANAGER
 * ============================================================================
 *
 * @file CortexConfig.hpp
 * @brief Meyers' Singleton for loading, validating, and persisting
 *        PhantomCortex configuration.
 *
 * Supports two configuration sources:
 * 1. JSON file on disk (portable, human-editable)
 * 2. Windows Registry (enterprise deployment via GPO)
 *
 * CONFIGURATION VALIDATION:
 * =========================
 * - All thresholds are clamped to [0.0, 1.0]
 * - maxBatchSize is capped at CortexConstants::MAX_BATCH_SIZE
 * - modelDirectory existence is verified on load
 * - Invalid values are replaced with defaults and logged as warnings
 *
 * REGISTRY PATH:
 * ==============
 * HKLM\SOFTWARE\ShadowStrike\PhantomCortex
 *   ├── ModelDirectory     (REG_SZ)
 *   ├── StaticThreshold    (REG_SZ, float as string)
 *   ├── BehavioralThreshold(REG_SZ)
 *   ├── MemoryThreshold    (REG_SZ)
 *   ├── NetworkThreshold   (REG_SZ)
 *   ├── EmulationThreshold (REG_SZ)
 *   ├── EnsembleThreshold  (REG_SZ)
 *   ├── UseGPU             (REG_DWORD, 0 or 1)
 *   ├── UseAVX512          (REG_DWORD, 0 or 1)
 *   ├── MaxBatchSize       (REG_DWORD)
 *   └── InferenceTimeoutMs (REG_DWORD)
 *
 * THREAD SAFETY:
 * ==============
 * - GetConfig() returns a const reference protected by a shared lock.
 *   The reference remains valid as long as no concurrent LoadConfig()
 *   or LoadFromRegistry() call is in progress.
 * - LoadConfig() and LoadFromRegistry() acquire an exclusive lock.
 * - SaveConfig() acquires a shared lock (read-only on internal state).
 *
 * LOCK HIERARCHY:
 * ===============
 * 1. m_configMutex (single reader/writer lock)
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
#include <filesystem>

// ============================================================================
// SHADOWSTRIKE INCLUDES
// ============================================================================

#include "CortexTypes.hpp"

namespace ShadowStrike {
namespace AI {

/**
 * @brief Meyers' Singleton for managing PhantomCortex runtime configuration.
 *
 * @note Thread Safety: All public methods are thread-safe.
 *       See LOCK HIERARCHY in the file header for details.
 */
class CortexConfigManager final {
public:
    // ================================================================
    // Singleton Access
    // ================================================================

    /**
     * @brief Get the singleton instance.
     * @return Reference to the global CortexConfigManager instance.
     *
     * Thread Safety: Thread-safe (C++11 static initialization guarantee).
     */
    static CortexConfigManager& Instance() noexcept;

    // Disable copy and move
    CortexConfigManager(const CortexConfigManager&)             = delete;
    CortexConfigManager& operator=(const CortexConfigManager&)  = delete;
    CortexConfigManager(CortexConfigManager&&)                  = delete;
    CortexConfigManager& operator=(CortexConfigManager&&)       = delete;

    // ================================================================
    // Configuration Loading
    // ================================================================

    /**
     * @brief Load configuration from a JSON file on disk.
     * @param configPath Absolute path to the JSON configuration file.
     * @return true if the file was read and parsed successfully.
     *
     * Invalid or missing fields fall back to CortexConfig defaults.
     * Validation errors are logged at WARN level but do not fail the load.
     *
     * Thread Safety: Serialized (exclusive lock).
     */
    [[nodiscard]] bool LoadConfig(const std::filesystem::path& configPath) noexcept;

    /**
     * @brief Load configuration from the Windows Registry.
     * @return true if the registry key was read successfully.
     *
     * Reads from HKLM\SOFTWARE\ShadowStrike\PhantomCortex.
     * Missing values fall back to CortexConfig defaults.
     *
     * Thread Safety: Serialized (exclusive lock).
     */
    [[nodiscard]] bool LoadFromRegistry() noexcept;

    // ================================================================
    // Configuration Access
    // ================================================================

    /**
     * @brief Get the current configuration.
     * @return Const reference to the active CortexConfig.
     *
     * @warning The returned reference is invalidated if a concurrent
     *          LoadConfig() or LoadFromRegistry() call begins. Callers
     *          operating in multi-threaded contexts should copy the
     *          struct if they need a stable snapshot.
     *
     * Thread Safety: Shared lock (concurrent reads are safe).
     */
    [[nodiscard]] const CortexConfig& GetConfig() const noexcept;

    // ================================================================
    // Configuration Persistence
    // ================================================================

    /**
     * @brief Save the current configuration to a JSON file.
     * @param configPath Absolute path for the output JSON file.
     * @return true if the file was written successfully.
     *
     * Thread Safety: Shared lock (reads internal state only).
     */
    [[nodiscard]] bool SaveConfig(
        const std::filesystem::path& configPath) const noexcept;

private:
    CortexConfigManager() = default;
    ~CortexConfigManager() = default;

    /// @brief Opaque implementation — hides JSON parsing, registry I/O, and lock state.
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace AI
}  // namespace ShadowStrike

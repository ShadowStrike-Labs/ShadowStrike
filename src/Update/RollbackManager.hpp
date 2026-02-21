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
 * ShadowStrike NGAV - ROLLBACK MANAGER MODULE
 * ============================================================================
 *
 * @file RollbackManager.hpp
 * @brief Enterprise-grade update recovery and rollback management with
 *        boot loop detection, health validation, and emergency recovery.
 *
 * Provides comprehensive rollback capabilities for safe recovery from
 * failed updates including automatic detection and user-initiated rollback.
 *
 * ROLLBACK CAPABILITIES:
 * ======================
 *
 * 1. SNAPSHOT MANAGEMENT
 *    - Pre-update snapshots
 *    - Incremental snapshots
 *    - Version tracking
 *    - Space management
 *    - Cleanup policies
 *
 * 2. BOOT LOOP DETECTION
 *    - Crash counting
 *    - Time window analysis
 *    - Auto-rollback trigger
 *    - Safe mode integration
 *    - Recovery boot
 *
 * 3. HEALTH VALIDATION
 *    - Service status check
 *    - Component verification
 *    - Database integrity
 *    - Network connectivity
 *    - Self-test execution
 *
 * 4. RECOVERY MECHANISMS
 *    - File rollback
 *    - Registry restore
 *    - Service reconfiguration
 *    - Driver rollback
 *    - Emergency repair
 *
 * 5. ENTERPRISE FEATURES
 *    - Group policy backup
 *    - Configuration export
 *    - Audit logging
 *    - Remote rollback
 *    - Compliance reporting
 *
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <filesystem>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/SystemUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Update {
    class RollbackManagerImpl;
}

namespace ShadowStrike {
namespace Update {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace RollbackConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum snapshots to keep
    inline constexpr uint32_t MAX_SNAPSHOTS = 5;
    
    /// @brief Boot loop crash threshold
    inline constexpr uint32_t BOOT_LOOP_THRESHOLD = 3;
    
    /// @brief Boot loop time window (minutes)
    inline constexpr uint32_t BOOT_LOOP_WINDOW_MINUTES = 5;
    
    /// @brief Health check timeout (seconds)
    inline constexpr uint32_t HEALTH_CHECK_TIMEOUT_SECONDS = 30;
    
    /// @brief Snapshot directory
    inline constexpr const wchar_t* SNAPSHOT_DIR = L"Backup\\Snapshots";

}  // namespace RollbackConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Snapshot type
 */
enum class SnapshotType : uint8_t {
    Full            = 0,    ///< Full backup
    Incremental     = 1,    ///< Incremental changes
    Configuration   = 2,    ///< Config only
    Database        = 3,    ///< Databases only
    Drivers         = 4,    ///< Drivers only
    Emergency       = 5     ///< Emergency snapshot
};

/**
 * @brief Rollback state
 */
enum class RollbackState : uint8_t {
    Idle            = 0,
    Preparing       = 1,
    StoppingServices = 2,
    RestoringFiles  = 3,
    RestoringConfig = 4,
    RestoringDrivers = 5,
    StartingServices = 6,
    Verifying       = 7,
    Completed       = 8,
    Failed          = 9
};

/**
 * @brief Health status
 */
enum class HealthStatus : uint8_t {
    Unknown         = 0,
    Healthy         = 1,
    Degraded        = 2,
    Unhealthy       = 3,
    Critical        = 4,
    BootLoop        = 5
};

/**
 * @brief Component status
 */
enum class ComponentHealth : uint8_t {
    Unknown         = 0,
    Running         = 1,
    Stopped         = 2,
    Error           = 3,
    Missing         = 4,
    Corrupted       = 5
};

/**
 * @brief Module status
 */
enum class RollbackManagerStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    RollingBack     = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Snapshot info
 */
struct SnapshotInfo {
    /// @brief Snapshot ID
    std::string snapshotId;
    
    /// @brief Snapshot type
    SnapshotType type = SnapshotType::Full;
    
    /// @brief Created time
    SystemTimePoint createdTime;
    
    /// @brief Version info
    std::string versionString;
    
    /// @brief Description
    std::string description;
    
    /// @brief Size (bytes)
    uint64_t sizeBytes = 0;
    
    /// @brief File count
    uint32_t fileCount = 0;
    
    /// @brief Snapshot path
    fs::path snapshotPath;
    
    /// @brief Is current (last known good)
    bool isCurrent = false;
    
    /// @brief Is valid
    bool isValid = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Health check result
 */
struct HealthCheckResult {
    /// @brief Overall status
    HealthStatus overallStatus = HealthStatus::Unknown;
    
    /// @brief Component statuses
    std::map<std::string, ComponentHealth> componentStatuses;
    
    /// @brief Service running
    bool serviceRunning = false;
    
    /// @brief GUI accessible
    bool guiAccessible = false;
    
    /// @brief Databases valid
    bool databasesValid = false;
    
    /// @brief Network connected
    bool networkConnected = false;
    
    /// @brief Self-test passed
    bool selfTestPassed = false;
    
    /// @brief Boot count (since last update)
    uint32_t bootCount = 0;
    
    /// @brief Crash count (in window)
    uint32_t crashCount = 0;
    
    /// @brief Last crash time
    std::optional<SystemTimePoint> lastCrashTime;
    
    /// @brief Check time
    SystemTimePoint checkTime;
    
    /// @brief Issues found
    std::vector<std::string> issues;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Rollback progress
 */
struct RollbackProgress {
    /// @brief State
    RollbackState state = RollbackState::Idle;
    
    /// @brief Progress (0-100)
    uint8_t progressPercent = 0;
    
    /// @brief Current operation
    std::string currentOperation;
    
    /// @brief Files restored
    uint32_t filesRestored = 0;
    
    /// @brief Files total
    uint32_t filesTotal = 0;
    
    /// @brief Error message
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Rollback result
 */
struct RollbackResult {
    /// @brief Success
    bool success = false;
    
    /// @brief Snapshot used
    std::string snapshotId;
    
    /// @brief Version restored
    std::string restoredVersion;
    
    /// @brief Files restored
    uint32_t filesRestored = 0;
    
    /// @brief Duration (seconds)
    uint32_t durationSeconds = 0;
    
    /// @brief Reboot required
    bool rebootRequired = false;
    
    /// @brief Error message
    std::string errorMessage;
    
    /// @brief Completion time
    SystemTimePoint completionTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct RollbackStatistics {
    std::atomic<uint64_t> snapshotsCreated{0};
    std::atomic<uint64_t> snapshotsDeleted{0};
    std::atomic<uint64_t> rollbacksPerformed{0};
    std::atomic<uint64_t> rollbacksFailed{0};
    std::atomic<uint64_t> bootLoopsDetected{0};
    std::atomic<uint64_t> autoRollbacks{0};
    std::atomic<uint64_t> healthChecks{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct RollbackManagerConfiguration {
    /// @brief Enable rollback
    bool enabled = true;
    
    /// @brief Enable boot loop detection
    bool enableBootLoopDetection = true;
    
    /// @brief Boot loop threshold
    uint32_t bootLoopThreshold = RollbackConstants::BOOT_LOOP_THRESHOLD;
    
    /// @brief Boot loop window (minutes)
    uint32_t bootLoopWindowMinutes = RollbackConstants::BOOT_LOOP_WINDOW_MINUTES;
    
    /// @brief Auto-rollback on boot loop
    bool autoRollbackOnBootLoop = true;
    
    /// @brief Max snapshots
    uint32_t maxSnapshots = RollbackConstants::MAX_SNAPSHOTS;
    
    /// @brief Snapshot directory
    fs::path snapshotDirectory;
    
    /// @brief Auto-create snapshot before update
    bool autoSnapshotBeforeUpdate = true;
    
    /// @brief Health check timeout (seconds)
    uint32_t healthCheckTimeoutSeconds = RollbackConstants::HEALTH_CHECK_TIMEOUT_SECONDS;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using RollbackProgressCallback = std::function<void(const RollbackProgress&)>;
using RollbackCompletionCallback = std::function<void(const RollbackResult&)>;
using HealthChangeCallback = std::function<void(HealthStatus)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// ROLLBACK MANAGER CLASS
// ============================================================================

/**
 * @class RollbackManager
 * @brief Enterprise rollback management
 */
class RollbackManager final {
public:
    [[nodiscard]] static RollbackManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    RollbackManager(const RollbackManager&) = delete;
    RollbackManager& operator=(const RollbackManager&) = delete;
    RollbackManager(RollbackManager&&) = delete;
    RollbackManager& operator=(RollbackManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const RollbackManagerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] RollbackManagerStatus GetStatus() const noexcept;

    // ========================================================================
    // SNAPSHOT MANAGEMENT
    // ========================================================================
    
    /// @brief Backup current version as "Last Known Good"
    void BackupCurrentVersion();
    
    /// @brief Create snapshot
    [[nodiscard]] std::string CreateSnapshot(
        SnapshotType type = SnapshotType::Full,
        const std::string& description = "");
    
    /// @brief Get available snapshots
    [[nodiscard]] std::vector<SnapshotInfo> GetSnapshots() const;
    
    /// @brief Get snapshot info
    [[nodiscard]] std::optional<SnapshotInfo> GetSnapshot(const std::string& snapshotId) const;
    
    /// @brief Delete snapshot
    [[nodiscard]] bool DeleteSnapshot(const std::string& snapshotId);
    
    /// @brief Cleanup old snapshots
    [[nodiscard]] uint32_t CleanupSnapshots(uint32_t keepCount = 0);
    
    /// @brief Get last known good snapshot
    [[nodiscard]] std::optional<SnapshotInfo> GetLastKnownGood() const;

    // ========================================================================
    // ROLLBACK OPERATIONS
    // ========================================================================
    
    /// @brief Trigger rollback to last known good
    [[nodiscard]] bool TriggerRollback();
    
    /// @brief Rollback to specific snapshot
    [[nodiscard]] bool RollbackTo(const std::string& snapshotId);
    
    /// @brief Can rollback
    [[nodiscard]] bool CanRollback() const;
    
    /// @brief Is rollback in progress
    [[nodiscard]] bool IsRollbackInProgress() const noexcept;
    
    /// @brief Get rollback progress
    [[nodiscard]] RollbackProgress GetProgress() const;
    
    /// @brief Cancel rollback
    void CancelRollback();

    // ========================================================================
    // HEALTH VALIDATION
    // ========================================================================
    
    /// @brief Verify system stability
    [[nodiscard]] bool VerifyStability();
    
    /// @brief Perform health check
    [[nodiscard]] HealthCheckResult PerformHealthCheck();
    
    /// @brief Get current health status
    [[nodiscard]] HealthStatus GetHealthStatus() const noexcept;
    
    /// @brief Is boot loop detected
    [[nodiscard]] bool IsBootLoopDetected() const;
    
    /// @brief Record boot/crash for boot loop detection
    void RecordBoot();
    void RecordCrash();
    
    /// @brief Clear boot loop counter
    void ClearBootLoopCounter();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterProgressCallback(RollbackProgressCallback callback);
    void RegisterCompletionCallback(RollbackCompletionCallback callback);
    void RegisterHealthChangeCallback(HealthChangeCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] RollbackStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    RollbackManager();
    ~RollbackManager();
    
    std::unique_ptr<RollbackManagerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetSnapshotTypeName(SnapshotType type) noexcept;
[[nodiscard]] std::string_view GetRollbackStateName(RollbackState state) noexcept;
[[nodiscard]] std::string_view GetHealthStatusName(HealthStatus status) noexcept;
[[nodiscard]] std::string_view GetComponentHealthName(ComponentHealth health) noexcept;

/// @brief Generate snapshot ID
[[nodiscard]] std::string GenerateSnapshotId();

/// @brief Calculate snapshot size
[[nodiscard]] uint64_t CalculateSnapshotSize(const fs::path& directory);

}  // namespace Update
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_CREATE_SNAPSHOT() \
    ::ShadowStrike::Update::RollbackManager::Instance().CreateSnapshot()

#define SS_TRIGGER_ROLLBACK() \
    ::ShadowStrike::Update::RollbackManager::Instance().TriggerRollback()

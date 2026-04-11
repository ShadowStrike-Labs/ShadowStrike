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
 * ShadowStrike Ransomware Protection - VOLUME SNAPSHOT SERVICE WRAPPER
 * ============================================================================
 *
 * @file VolumeSnapshotService.hpp
 * @brief Enterprise-grade wrapper for Windows VSS API enabling programmatic
 *        creation, management, and restoration of volume shadow copies.
 *
 * This module provides a high-level interface to the Windows Volume Shadow
 * Copy Service (VSS) for backup and recovery operations without relying
 * on external command-line tools.
 *
 * INTEGRATION:
 *   - ShadowCopyProtector: notified of every snapshot ID for tamper protection
 *   - RansomwareDetector:  triggers CreateEmergencySnapshot on detection
 *   - RansomwareDecryptor: queries GetRecoveryPoints for file restoration
 *   - PhantomSensor:       kernel storage-pressure events trigger pre-snapshots
 *
 * @note Requires SeBackupPrivilege, SeRestorePrivilege, SeSecurityPrivilege.
 * @note Uses VSS COM interfaces directly (IVssBackupComponents).
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
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
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <map>

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

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Ransomware {
    class VolumeSnapshotServiceImpl;
}

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace VSSConstants {
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 1;
    inline constexpr uint32_t VERSION_PATCH = 0;

    inline constexpr size_t   MAX_SNAPSHOTS_PER_VOLUME      = 64;
    inline constexpr uint32_t SNAPSHOT_TIMEOUT_MS            = 300000;  // 5 minutes
    inline constexpr uint32_t DEFAULT_STORAGE_LIMIT_PERCENT  = 10;
    inline constexpr uint32_t DEFAULT_MONITORING_INTERVAL_S  = 300;     // 5 minutes
    inline constexpr uint32_t DEFAULT_MAX_SNAPSHOT_AGE_DAYS  = 30;
    inline constexpr size_t   MAX_VOLUME_PATH_LEN            = 260;
    inline constexpr uint32_t EMERGENCY_SNAPSHOT_TIMEOUT_MS  = 60000;   // 1 minute
}

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock           = std::chrono::steady_clock;
using TimePoint       = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/// @brief Snapshot type (maps to VSS backup context flags)
enum class SnapshotType : uint8_t {
    Standard        = 0,    ///< VSS_BT_COPY — non-intrusive snapshot
    AppConsistent   = 1,    ///< Full writer coordination
    CrashConsistent = 2,    ///< No writer coordination
    Transportable   = 3     ///< Transportable snapshot set
};

/// @brief Snapshot lifecycle state (mirrors VSS_SNAPSHOT_STATE)
enum class SnapshotState : uint8_t {
    Unknown     = 0,
    Preparing   = 1,
    Processing  = 2,
    Prepared    = 3,
    Committed   = 4,
    Created     = 5
};

/// @brief VSS writer state
enum class WriterState : uint8_t {
    Unknown              = 0,
    Stable               = 1,
    WaitingForFreeze     = 2,
    WaitingForThaw       = 3,
    WaitingForCompletion = 4,
    Failed               = 5
};

/// @brief Operation result codes (exhaustive VSS HRESULT mapping)
enum class VSSResult : uint8_t {
    Success              = 0,
    NotInitialized       = 1,
    AlreadyInitialized   = 2,
    InvalidParameter     = 3,
    AccessDenied         = 4,
    OutOfMemory          = 5,
    NotFound             = 6,
    BadState             = 7,
    ProviderError        = 8,
    VolumeNotSupported   = 9,
    InsufficientStorage  = 10,
    ProviderVeto         = 11,
    MaxSnapshotsReached  = 12,
    WriterFailed         = 13,
    Timeout              = 14,
    MountFailed          = 15,
    RestoreFailed        = 16,
    IntegrityCheckFailed = 17,
    PrivilegeError       = 18,
    UnknownError         = 255
};

/// @brief Module lifecycle status
#ifndef SHADOWSTRIKE_RANSOMWARE_MODULE_STATUS_DEFINED
#define SHADOWSTRIKE_RANSOMWARE_MODULE_STATUS_DEFINED
enum class ModuleStatus : uint8_t {
    Uninitialized = 0,
    Initializing  = 1,
    Running       = 2,
    Degraded      = 3,
    Paused        = 4,
    Stopping      = 5,
    Stopped       = 6,
    Error         = 7
};
#endif // SHADOWSTRIKE_RANSOMWARE_MODULE_STATUS_DEFINED

/// @brief Snapshot operation type (for tracking active operations)
enum class OperationType : uint8_t {
    Create  = 0,
    Delete  = 1,
    Mount   = 2,
    Restore = 3
};

/// @brief Snapshot operation state
enum class OperationState : uint8_t {
    Pending    = 0,
    InProgress = 1,
    Completed  = 2,
    Failed     = 3,
    Cancelled  = 4
};

// ============================================================================
// STRUCTURES
// ============================================================================

/// @brief Snapshot information
struct SnapshotInfo {
    std::wstring    snapshotId;
    std::wstring    snapshotSetId;
    std::wstring    volumeName;
    std::wstring    deviceName;
    SystemTimePoint creationTime;
    SnapshotType    type       = SnapshotType::Standard;
    SnapshotState   state      = SnapshotState::Unknown;
    uint32_t        attributes = 0;
    uint64_t        sizeBytes  = 0;
    bool            isExposed  = false;
    std::wstring    exposePath;

    [[nodiscard]] std::string ToJson() const;
};

/// @brief Volume information
struct VolumeInfo {
    std::wstring volumeName;
    std::wstring mountPoint;
    std::wstring fileSystem;
    std::wstring label;
    uint64_t     totalSize        = 0;
    uint64_t     freeSpace        = 0;
    uint64_t     shadowStorageMax = 0;
    uint64_t     shadowStorageUsed= 0;
    uint32_t     snapshotCount    = 0;
    bool         vssSupported     = false;

    [[nodiscard]] std::string ToJson() const;
};

/// @brief VSS writer information
struct WriterInfo {
    std::wstring writerId;
    std::wstring writerName;
    std::wstring instanceId;
    WriterState  state     = WriterState::Unknown;
    HRESULT      lastError = S_OK;

    [[nodiscard]] std::string ToJson() const;
};

/// @brief Active operation tracking
struct SnapshotOperation {
    std::wstring    operationId;
    OperationType   type  = OperationType::Create;
    OperationState  state = OperationState::Pending;
    std::wstring    volumeName;
    std::wstring    snapshotId;
    uint32_t        progressPercent = 0;
    TimePoint       startTime;
    TimePoint       endTime;
    std::string     errorMessage;

    [[nodiscard]] std::string ToJson() const;
};

/// @brief Snapshot creation options
struct SnapshotOptions {
    SnapshotType type            = SnapshotType::Standard;
    bool         includeWriters  = true;
    bool         autoCleanup     = false;
    uint32_t     timeoutMs       = VSSConstants::SNAPSHOT_TIMEOUT_MS;
    std::wstring description;
};

/// @brief Service configuration
struct VolumeSnapshotConfiguration {
    bool     enabled                    = true;
    uint32_t maxSnapshotsPerVolume      = VSSConstants::MAX_SNAPSHOTS_PER_VOLUME;
    uint32_t defaultStorageLimitPercent = VSSConstants::DEFAULT_STORAGE_LIMIT_PERCENT;
    uint32_t monitoringIntervalSeconds = VSSConstants::DEFAULT_MONITORING_INTERVAL_S;
    bool     enableMonitoring          = true;
    bool     autoCleanupSnapshots      = false;
    uint32_t maxSnapshotAgeDays        = VSSConstants::DEFAULT_MAX_SNAPSHOT_AGE_DAYS;
    bool     monitorWriters            = true;
    bool     verboseLogging            = false;

    [[nodiscard]] bool IsValid() const noexcept;
};

/// @brief Service statistics
struct VolumeSnapshotStatistics {
    std::atomic<uint64_t> snapshotsCreated{0};
    std::atomic<uint64_t> snapshotsDeleted{0};
    std::atomic<uint64_t> snapshotsMounted{0};
    std::atomic<uint64_t> filesRestored{0};
    std::atomic<uint64_t> directoriesRestored{0};
    std::atomic<uint64_t> operationsFailed{0};
    std::atomic<uint64_t> totalCreationTimeMs{0};
    std::atomic<uint64_t> totalDeletionTimeMs{0};
    std::atomic<uint64_t> totalRestorationTimeMs{0};
    std::atomic<uint64_t> currentOperations{0};
    std::atomic<uint64_t> emergencySnapshotsCreated{0};

    static constexpr size_t kTypeCount   = 4;
    static constexpr size_t kResultCount = 19;
    std::array<std::atomic<uint64_t>, kTypeCount>   byType{};
    std::array<std::atomic<uint64_t>, kResultCount> byResult{};

    TimePoint startTime = Clock::now();

    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Thread-safe snapshot of VSS statistics (non-atomic, copyable)
 */
struct VolumeSnapshotStatisticsSnapshot {
    uint64_t snapshotsCreated        = 0;
    uint64_t snapshotsDeleted        = 0;
    uint64_t snapshotsMounted        = 0;
    uint64_t filesRestored           = 0;
    uint64_t directoriesRestored     = 0;
    uint64_t operationsFailed        = 0;
    uint64_t totalCreationTimeMs     = 0;
    uint64_t totalDeletionTimeMs     = 0;
    uint64_t totalRestorationTimeMs  = 0;
    uint64_t currentOperations       = 0;
    uint64_t emergencySnapshotsCreated = 0;
    std::array<uint64_t, 4>  byType{};
    std::array<uint64_t, 19> byResult{};
    uint64_t uptimeSeconds           = 0;

    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ProgressCallback   = std::function<void(const std::wstring& operationId, uint32_t percent)>;
using CompletionCallback = std::function<void(const std::wstring& operationId, VSSResult result)>;
using ErrorCallback      = std::function<void(const std::string& message, int code)>;

// ============================================================================
// VOLUME SNAPSHOT SERVICE CLASS
// ============================================================================

/**
 * @class VolumeSnapshotService
 * @brief Enterprise-grade VSS wrapper for shadow copy management.
 *
 * Provides programmatic access to Windows VSS for backup and recovery.
 * Uses PIMPL pattern for ABI stability and Meyers' Singleton.
 *
 * THREAD SAFETY: All public methods are thread-safe via std::shared_mutex.
 */
class VolumeSnapshotService final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    [[nodiscard]] static VolumeSnapshotService& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;

    VolumeSnapshotService(const VolumeSnapshotService&)            = delete;
    VolumeSnapshotService& operator=(const VolumeSnapshotService&) = delete;
    VolumeSnapshotService(VolumeSnapshotService&&)                 = delete;
    VolumeSnapshotService& operator=(VolumeSnapshotService&&)      = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool Initialize(const VolumeSnapshotConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    [[nodiscard]] bool UpdateConfiguration(const VolumeSnapshotConfiguration& config);
    [[nodiscard]] VolumeSnapshotConfiguration GetConfiguration() const;

    // ========================================================================
    // SNAPSHOT CREATION
    // ========================================================================

    [[nodiscard]] VSSResult CreateSnapshot(
        const std::wstring& volumeName,
        std::wstring& outSnapshotId,
        SnapshotType type = SnapshotType::Standard);

    [[nodiscard]] VSSResult CreateSnapshotEx(
        const std::wstring& volumeName,
        std::wstring& outSnapshotId,
        const SnapshotOptions& options = {});

    [[nodiscard]] VSSResult CreateSnapshotSet(
        const std::vector<std::wstring>& volumes,
        std::vector<std::wstring>& outSnapshotIds,
        SnapshotType type = SnapshotType::Standard);

    /// @brief Emergency snapshot triggered by RansomwareDetector.
    /// Uses reduced timeout, skips writers, notifies ShadowCopyProtector.
    [[nodiscard]] VSSResult CreateEmergencySnapshot(
        const std::wstring& volumeName,
        std::wstring& outSnapshotId);

    // ========================================================================
    // SNAPSHOT QUERY
    // ========================================================================

    [[nodiscard]] std::vector<SnapshotInfo> EnumerateSnapshots();
    [[nodiscard]] std::vector<SnapshotInfo> EnumerateSnapshotsForVolume(
        const std::wstring& volumeName);
    [[nodiscard]] std::optional<SnapshotInfo> GetSnapshotInfo(const std::wstring& snapshotId);

    /// @brief Recovery-point query for RansomwareDecryptor integration.
    [[nodiscard]] std::vector<SnapshotInfo> GetRecoveryPoints(const std::wstring& volumeName);

    // ========================================================================
    // SNAPSHOT DELETION
    // ========================================================================

    [[nodiscard]] VSSResult DeleteSnapshot(const std::wstring& snapshotId, bool force = false);
    [[nodiscard]] VSSResult DeleteSnapshotsForVolume(const std::wstring& volumeName);
    [[nodiscard]] VSSResult DeleteOldestSnapshot(const std::wstring& volumeName);
    [[nodiscard]] uint32_t  DeleteSnapshotsOlderThan(const SystemTimePoint& cutoffTime);

    // ========================================================================
    // SNAPSHOT MOUNTING & RESTORATION
    // ========================================================================

    [[nodiscard]] VSSResult MountSnapshot(
        const std::wstring& snapshotId,
        const std::wstring& mountPoint);
    [[nodiscard]] VSSResult UnmountSnapshot(const std::wstring& snapshotId);
    [[nodiscard]] bool IsSnapshotMounted(const std::wstring& snapshotId);
    [[nodiscard]] std::optional<std::wstring> GetMountPoint(const std::wstring& snapshotId);

    [[nodiscard]] VSSResult RestoreFile(
        const std::wstring& snapshotId,
        const std::wstring& sourceFile,
        const std::wstring& destinationFile);
    [[nodiscard]] VSSResult RestoreDirectory(
        const std::wstring& snapshotId,
        const std::wstring& sourceDir,
        const std::wstring& destinationDir,
        bool recursive = true);
    [[nodiscard]] VSSResult RestoreToOriginalLocation(
        const std::wstring& snapshotId,
        const std::wstring& filePath);

    // ========================================================================
    // SNAPSHOT INTEGRITY
    // ========================================================================

    /// @brief Verify snapshot is accessible and not corrupted.
    [[nodiscard]] bool VerifySnapshotIntegrity(const std::wstring& snapshotId);

    // ========================================================================
    // VOLUME INFORMATION
    // ========================================================================

    [[nodiscard]] std::vector<VolumeInfo> GetVSSVolumes();
    [[nodiscard]] std::optional<VolumeInfo> GetVolumeInfo(const std::wstring& volumeName);
    [[nodiscard]] bool IsVSSSupported(const std::wstring& volumeName);
    [[nodiscard]] std::wstring GetVolumeFromPath(const std::wstring& path);

    // ========================================================================
    // STORAGE MANAGEMENT
    // ========================================================================

    [[nodiscard]] VSSResult SetStorageLimit(const std::wstring& volumeName, uint64_t maxSizeBytes);
    [[nodiscard]] VSSResult SetStorageLimitPercent(const std::wstring& volumeName, uint32_t percent);
    [[nodiscard]] std::optional<uint64_t> GetStorageLimit(const std::wstring& volumeName);
    [[nodiscard]] std::optional<uint64_t> GetStorageUsage(const std::wstring& volumeName);
    [[nodiscard]] VSSResult CleanupOldSnapshots(const std::wstring& volumeName, uint32_t keepCount);

    // ========================================================================
    // WRITER MANAGEMENT
    // ========================================================================

    [[nodiscard]] std::vector<WriterInfo> GetWriters();
    [[nodiscard]] bool AreWritersStable();
    [[nodiscard]] VSSResult WaitForWriters(uint32_t timeoutMs = 30000);

    // ========================================================================
    // OPERATION TRACKING
    // ========================================================================

    [[nodiscard]] std::vector<SnapshotOperation> GetActiveOperations();
    [[nodiscard]] std::optional<SnapshotOperation> GetOperation(const std::wstring& operationId);
    [[nodiscard]] bool CancelOperation(const std::wstring& operationId);

    // ========================================================================
    // MONITORING
    // ========================================================================

    [[nodiscard]] bool StartMonitoring();
    void StopMonitoring();
    [[nodiscard]] bool IsMonitoring() const noexcept;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterCompletionCallback(CompletionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] VolumeSnapshotStatisticsSnapshot GetStatistics() const;
    void ResetStatistics();

    // ========================================================================
    // UTILITY
    // ========================================================================

    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

    // ========================================================================
    // KERNEL BRIDGE — IPC integration with PhantomSensor kernel driver
    // ========================================================================

    void OnKernelProcessNotify(uint32_t pid, uint32_t parentPid,
                               std::wstring_view imagePath, bool isCreate);
    void OnKernelImageLoad(uint32_t pid, std::wstring_view imagePath, uintptr_t imageBase);
    [[nodiscard]] bool RequestKernelProcessBlock(uint32_t pid, std::wstring_view reason);

    // ========================================================================
    // CROSS-MODULE WIRING — AlertSystem & TelemetryCollector
    // ========================================================================

    void ReportSnapshotEventToAlertSystem(const std::string& event,
                                          const std::string& detail);
    void ReportSnapshotTelemetry(const std::string& eventName,
                                  const std::map<std::string, std::string>& fields);

private:
    VolumeSnapshotService();
    ~VolumeSnapshotService();

    std::unique_ptr<VolumeSnapshotServiceImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetSnapshotTypeName(SnapshotType type) noexcept;
[[nodiscard]] std::string_view GetSnapshotStateName(SnapshotState state) noexcept;
[[nodiscard]] std::string_view GetVSSResultName(VSSResult result) noexcept;
[[nodiscard]] std::string_view GetWriterStateName(WriterState state) noexcept;

}  // namespace Ransomware
}  // namespace ShadowStrike

// ============================================================================
// CONVENIENCE MACROS
// ============================================================================

#define SS_VSS_CREATE_SNAPSHOT(volume, outId) \
    ::ShadowStrike::Ransomware::VolumeSnapshotService::Instance().CreateSnapshot((volume), (outId))

#define SS_VSS_EMERGENCY_SNAPSHOT(volume, outId) \
    ::ShadowStrike::Ransomware::VolumeSnapshotService::Instance().CreateEmergencySnapshot((volume), (outId))

#define SS_VSS_ENUM_SNAPSHOTS() \
    ::ShadowStrike::Ransomware::VolumeSnapshotService::Instance().EnumerateSnapshots()

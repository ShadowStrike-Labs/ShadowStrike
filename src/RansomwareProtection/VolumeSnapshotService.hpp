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
 * VSS CAPABILITIES:
 * =================
 *
 * 1. SNAPSHOT CREATION
 *    - Per-volume snapshots
 *    - Multi-volume snapshots
 *    - Application-consistent snapshots
 *    - Crash-consistent snapshots
 *    - Transportable snapshots
 *
 * 2. SNAPSHOT MANAGEMENT
 *    - Enumeration
 *    - Deletion
 *    - Retention policies
 *    - Storage management
 *    - Provider selection
 *
 * 3. RESTORATION
 *    - File-level restore
 *    - Directory restore
 *    - Volume restore
 *    - Point-in-time recovery
 *
 * 4. MONITORING
 *    - Storage usage tracking
 *    - Provider health checks
 *    - Event logging
 *    - Quota management
 *
 * 5. WRITER COORDINATION
 *    - Application writer notification
 *    - Consistent state capture
 *    - Pre/post snapshot hooks
 *
 * @note Requires administrative privileges for most operations.
 * @note Uses VSS COM interfaces directly.
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
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>

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
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;
    
    /// @brief Maximum snapshots per volume
    inline constexpr size_t MAX_SNAPSHOTS_PER_VOLUME = 64;
    
    /// @brief Snapshot creation timeout (milliseconds)
    inline constexpr uint32_t SNAPSHOT_TIMEOUT_MS = 300000;  // 5 minutes
    
    /// @brief Default storage percentage
    inline constexpr uint32_t DEFAULT_STORAGE_PERCENT = 10;
}

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using GUID = std::array<uint8_t, 16>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Snapshot type
 */
enum class SnapshotType : uint8_t {
    Standard        = 0,    ///< Standard snapshot
    AppConsistent   = 1,    ///< Application-consistent
    CrashConsistent = 2,    ///< Crash-consistent
    Transportable   = 3     ///< Transportable snapshot
};

/**
 * @brief Snapshot state
 */
enum class SnapshotState : uint8_t {
    Unknown     = 0,
    Creating    = 1,
    Ready       = 2,
    Mounted     = 3,
    Deleting    = 4,
    Deleted     = 5,
    Error       = 6
};

/**
 * @brief Operation result
 */
enum class VSSResult : uint8_t {
    Success             = 0,
    AccessDenied        = 1,
    ServiceUnavailable  = 2,
    VolumeNotFound      = 3,
    SnapshotNotFound    = 4,
    InsufficientSpace   = 5,
    Timeout             = 6,
    WriterError         = 7,
    ProviderError       = 8,
    UnknownError        = 255
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Snapshot information
 */
struct SnapshotInfo {
    /// @brief Snapshot ID (GUID as string)
    std::wstring snapshotId;
    
    /// @brief Snapshot set ID
    std::wstring snapshotSetId;
    
    /// @brief Volume name (e.g., "C:\")
    std::wstring volumeName;
    
    /// @brief Volume display name
    std::wstring volumeDisplayName;
    
    /// @brief Snapshot device object name
    std::wstring deviceName;
    
    /// @brief Provider ID
    std::wstring providerId;
    
    /// @brief Provider name
    std::wstring providerName;
    
    /// @brief Creation time
    SystemTimePoint creationTime;
    
    /// @brief Snapshot type
    SnapshotType type = SnapshotType::Standard;
    
    /// @brief State
    SnapshotState state = SnapshotState::Unknown;
    
    /// @brief Attributes
    uint32_t attributes = 0;
    
    /// @brief Is exposed (mounted)
    bool isExposed = false;
    
    /// @brief Expose path (if mounted)
    std::wstring exposePath;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Volume information
 */
struct VolumeInfo {
    /// @brief Volume name (e.g., "\\?\Volume{GUID}\")
    std::wstring volumeName;
    
    /// @brief Mount point (e.g., "C:\")
    std::wstring mountPoint;
    
    /// @brief File system
    std::wstring fileSystem;
    
    /// @brief Volume label
    std::wstring label;
    
    /// @brief Total size
    uint64_t totalSize = 0;
    
    /// @brief Free space
    uint64_t freeSpace = 0;
    
    /// @brief Shadow storage max size
    uint64_t shadowStorageMax = 0;
    
    /// @brief Shadow storage used
    uint64_t shadowStorageUsed = 0;
    
    /// @brief Number of snapshots
    uint32_t snapshotCount = 0;
    
    /// @brief VSS supported
    bool vssSupported = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Writer information
 */
struct WriterInfo {
    /// @brief Writer ID (GUID)
    std::wstring writerId;
    
    /// @brief Writer name
    std::wstring writerName;
    
    /// @brief Instance ID
    std::wstring instanceId;
    
    /// @brief State
    uint32_t state = 0;
    
    /// @brief Last error
    uint32_t lastError = 0;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Snapshot creation options
 */
struct SnapshotOptions {
    /// @brief Snapshot type
    SnapshotType type = SnapshotType::Standard;
    
    /// @brief Include writers
    bool includeWriters = true;
    
    /// @brief Wait for completion
    bool waitForCompletion = true;
    
    /// @brief Timeout (milliseconds)
    uint32_t timeoutMs = VSSConstants::SNAPSHOT_TIMEOUT_MS;
    
    /// @brief Auto-delete after timeout
    bool autoDeleteOnTimeout = true;
    
    /// @brief Description
    std::wstring description;
};

/**
 * @brief VSS configuration
 */
struct VolumeSnapshotServiceConfiguration {
    /// @brief Enable service
    bool enabled = true;
    
    /// @brief Default snapshot type
    SnapshotType defaultType = SnapshotType::Standard;
    
    /// @brief Default timeout (milliseconds)
    uint32_t defaultTimeoutMs = VSSConstants::SNAPSHOT_TIMEOUT_MS;
    
    /// @brief Auto-cleanup old snapshots
    bool autoCleanup = false;
    
    /// @brief Maximum snapshots per volume
    size_t maxSnapshotsPerVolume = VSSConstants::MAX_SNAPSHOTS_PER_VOLUME;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief VSS statistics
 */
struct VSSStatistics {
    /// @brief Snapshots created
    std::atomic<uint64_t> snapshotsCreated{0};
    
    /// @brief Snapshots deleted
    std::atomic<uint64_t> snapshotsDeleted{0};
    
    /// @brief Files restored
    std::atomic<uint64_t> filesRestored{0};
    
    /// @brief Creation failures
    std::atomic<uint64_t> creationFailures{0};
    
    /// @brief Total bytes in snapshots
    std::atomic<uint64_t> totalSnapshotBytes{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using SnapshotProgressCallback = std::function<void(
    const std::wstring& volume, uint32_t percentComplete)>;
using SnapshotCompleteCallback = std::function<void(
    const SnapshotInfo& snapshot, VSSResult result)>;

// ============================================================================
// VOLUME SNAPSHOT SERVICE CLASS
// ============================================================================

/**
 * @class VolumeSnapshotService
 * @brief Enterprise-grade VSS wrapper for shadow copy management
 *
 * Provides programmatic access to Windows VSS for backup and recovery.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 */
class VolumeSnapshotService final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    [[nodiscard]] static VolumeSnapshotService& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    VolumeSnapshotService(const VolumeSnapshotService&) = delete;
    VolumeSnapshotService& operator=(const VolumeSnapshotService&) = delete;
    VolumeSnapshotService(VolumeSnapshotService&&) = delete;
    VolumeSnapshotService& operator=(VolumeSnapshotService&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const VolumeSnapshotServiceConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    // ========================================================================
    // SNAPSHOT CREATION
    // ========================================================================
    
    /**
     * @brief Create snapshot of a drive
     */
    [[nodiscard]] bool CreateSnapshot(const std::wstring& driveLetter);
    
    /**
     * @brief Create snapshot with options
     */
    [[nodiscard]] std::optional<std::wstring> CreateSnapshotEx(
        std::wstring_view volume, const SnapshotOptions& options = {});
    
    /**
     * @brief Create snapshots of multiple volumes
     */
    [[nodiscard]] std::vector<std::wstring> CreateSnapshotSet(
        std::span<const std::wstring> volumes, const SnapshotOptions& options = {});
    
    // ========================================================================
    // SNAPSHOT MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Enumerate all snapshots
     */
    [[nodiscard]] std::vector<std::wstring> EnumSnapshots();
    
    /**
     * @brief Enumerate with full details
     */
    [[nodiscard]] std::vector<SnapshotInfo> EnumerateSnapshots();
    
    /**
     * @brief Enumerate for specific volume
     */
    [[nodiscard]] std::vector<SnapshotInfo> EnumerateSnapshotsForVolume(
        std::wstring_view volume);
    
    /**
     * @brief Get snapshot info
     */
    [[nodiscard]] std::optional<SnapshotInfo> GetSnapshot(std::wstring_view snapshotId);
    
    /**
     * @brief Delete snapshot
     */
    [[nodiscard]] VSSResult DeleteSnapshot(std::wstring_view snapshotId);
    
    /**
     * @brief Delete all snapshots for volume
     */
    [[nodiscard]] size_t DeleteSnapshotsForVolume(std::wstring_view volume);
    
    // ========================================================================
    // SNAPSHOT ACCESS
    // ========================================================================
    
    /**
     * @brief Mount snapshot (expose)
     */
    [[nodiscard]] std::optional<std::wstring> MountSnapshot(
        std::wstring_view snapshotId, std::wstring_view mountPoint);
    
    /**
     * @brief Unmount snapshot
     */
    [[nodiscard]] VSSResult UnmountSnapshot(std::wstring_view snapshotId);
    
    /**
     * @brief Get file from snapshot
     */
    [[nodiscard]] bool RestoreFile(std::wstring_view snapshotId,
                                   std::wstring_view relativePath,
                                   std::wstring_view destinationPath);
    
    /**
     * @brief Get directory from snapshot
     */
    [[nodiscard]] bool RestoreDirectory(std::wstring_view snapshotId,
                                        std::wstring_view relativePath,
                                        std::wstring_view destinationPath);
    
    // ========================================================================
    // VOLUME INFORMATION
    // ========================================================================
    
    /**
     * @brief Get volumes supporting VSS
     */
    [[nodiscard]] std::vector<VolumeInfo> GetVSSVolumes();
    
    /**
     * @brief Get volume info
     */
    [[nodiscard]] std::optional<VolumeInfo> GetVolumeInfo(std::wstring_view volume);
    
    /**
     * @brief Check if VSS supported
     */
    [[nodiscard]] bool IsVSSSupported(std::wstring_view volume);
    
    // ========================================================================
    // STORAGE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Set shadow storage limit
     */
    [[nodiscard]] VSSResult SetStorageLimit(std::wstring_view volume,
                                            uint64_t maxBytes);
    
    /**
     * @brief Set storage limit as percentage
     */
    [[nodiscard]] VSSResult SetStorageLimitPercent(std::wstring_view volume,
                                                   uint32_t percent);
    
    /**
     * @brief Get storage usage
     */
    [[nodiscard]] std::pair<uint64_t, uint64_t> GetStorageUsage(
        std::wstring_view volume);  // (used, max)
    
    // ========================================================================
    // WRITER INFORMATION
    // ========================================================================
    
    /**
     * @brief Get VSS writers
     */
    [[nodiscard]] std::vector<WriterInfo> GetWriters();
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void SetProgressCallback(SnapshotProgressCallback callback);
    void SetCompleteCallback(SnapshotCompleteCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] VSSStatistics GetStatistics() const;
    void ResetStatistics();
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

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

}  // namespace Ransomware
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_CREATE_SNAPSHOT(drive) \
    ::ShadowStrike::Ransomware::VolumeSnapshotService::Instance().CreateSnapshot(drive)

#define SS_ENUM_SNAPSHOTS() \
    ::ShadowStrike::Ransomware::VolumeSnapshotService::Instance().EnumSnapshots()

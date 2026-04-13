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
 * ShadowStrike NGAV - RESTORE MANAGER MODULE
 * ============================================================================
 *
 * @file RestoreManager.hpp
 * @brief Enterprise-grade data restoration with point-in-time recovery,
 *        conflict resolution, and NTFS permissions preservation.
 *
 * Provides comprehensive restore capabilities including granular file recovery,
 * full system restore, and intelligent conflict handling.
 *
 * RESTORE CAPABILITIES:
 * =====================
 *
 * 1. RESTORE MODES
 *    - Full restore
 *    - Selective file restore
 *    - Directory restore
 *    - Point-in-time restore
 *    - Bare metal restore
 *
 * 2. CONFLICT RESOLUTION
 *    - Overwrite existing
 *    - Keep both (rename)
 *    - Skip existing
 *    - Overwrite if newer
 *    - Prompt user
 *
 * 3. METADATA RESTORE
 *    - NTFS ACLs
 *    - File attributes
 *    - Timestamps
 *    - Extended attributes
 *    - Alternate data streams
 *
 * 4. VERIFICATION
 *    - Integrity check
 *    - Hash verification
 *    - Permission validation
 *    - Size verification
 *
 * 5. ROLLBACK
 *    - Restore rollback
 *    - Partial restore undo
 *    - Pre-restore snapshot
 *
 * @note Requires elevated privileges for full ACL restore.
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
#include <unordered_map>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
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
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Backup {
    class RestoreManagerImpl;
    struct BackupPoint;
}

namespace ShadowStrike {
namespace Backup {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace RestoreConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum concurrent restore operations
    inline constexpr size_t MAX_CONCURRENT_RESTORES = 4;
    
    /// @brief Default buffer size
    inline constexpr size_t DEFAULT_BUFFER_SIZE = 4 * 1024 * 1024;  // 4MB

}  // namespace RestoreConstants

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
 * @brief Restore mode
 */
enum class RestoreMode : uint8_t {
    Full            = 0,
    Selective       = 1,
    Directory       = 2,
    PointInTime     = 3,
    BareMetal       = 4
};

/**
 * @brief Conflict resolution
 */
enum class ConflictResolution : uint8_t {
    Overwrite       = 0,
    KeepBoth        = 1,
    Skip            = 2,
    OverwriteNewer  = 3,
    OverwriteOlder  = 4,
    Prompt          = 5
};

/**
 * @brief Restore status
 */
enum class RestoreStatus : uint8_t {
    Pending         = 0,
    InProgress      = 1,
    Completed       = 2,
    Failed          = 3,
    Cancelled       = 4,
    Partial         = 5,
    Verifying       = 6,
    RollingBack     = 7,
    Paused          = 8
};

/**
 * @brief Metadata restore options
 */
enum class MetadataOption : uint32_t {
    None            = 0,
    Timestamps      = 1 << 0,
    Attributes      = 1 << 1,
    ACLs            = 1 << 2,
    Owner           = 1 << 3,
    ADS             = 1 << 4,
    Extended        = 1 << 5,
    All             = 0xFFFFFFFF
};

/// @brief Bitwise OR for MetadataOption
[[nodiscard]] inline constexpr MetadataOption operator|(MetadataOption a, MetadataOption b) noexcept {
    return static_cast<MetadataOption>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/// @brief Bitwise AND for MetadataOption
[[nodiscard]] inline constexpr MetadataOption operator&(MetadataOption a, MetadataOption b) noexcept {
    return static_cast<MetadataOption>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * @brief Module status
 */
enum class RestoreModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Ready           = 2,
    Restoring       = 3,
    Verifying       = 4,
    Paused          = 5,
    Stopping        = 6,
    Stopped         = 7,
    Error           = 8
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Restore target
 */
struct RestoreTarget {
    /// @brief Source path in backup
    fs::path sourcePath;
    
    /// @brief Target path on disk
    fs::path targetPath;
    
    /// @brief Is directory
    bool isDirectory = false;
    
    /// @brief Restore subdirectories
    bool recursive = true;
    
    /// @brief Include patterns
    std::vector<std::string> includePatterns;
    
    /// @brief Exclude patterns
    std::vector<std::string> excludePatterns;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Restore options
 */
struct RestoreOptions {
    /// @brief Restore mode
    RestoreMode mode = RestoreMode::Selective;
    
    /// @brief Conflict resolution
    ConflictResolution conflictResolution = ConflictResolution::Prompt;
    
    /// @brief Metadata options (bitmask)
    MetadataOption metadataOptions = MetadataOption::All;
    
    /// @brief Verify after restore
    bool verifyAfterRestore = true;
    
    /// @brief Create pre-restore snapshot
    bool createSnapshot = true;
    
    /// @brief Preserve directory structure
    bool preserveStructure = true;
    
    /// @brief Overwrite read-only files
    bool overwriteReadOnly = true;
    
    /// @brief Continue on error
    bool continueOnError = true;
    
    /// @brief Max errors before abort
    uint32_t maxErrors = 100;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Restore conflict
 */
struct RestoreConflict {
    /// @brief Source file (in backup)
    fs::path sourcePath;
    
    /// @brief Target file (on disk)
    fs::path targetPath;
    
    /// @brief Source size
    uint64_t sourceSize = 0;
    
    /// @brief Target size
    uint64_t targetSize = 0;
    
    /// @brief Source modified time
    SystemTimePoint sourceModified;
    
    /// @brief Target modified time
    SystemTimePoint targetModified;
    
    /// @brief Resolution used
    ConflictResolution resolution = ConflictResolution::Prompt;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief File entry in backup
 */
struct BackupFileEntry {
    /// @brief Path in backup
    fs::path path;
    
    /// @brief Is directory
    bool isDirectory = false;
    
    /// @brief Size (uncompressed)
    uint64_t size = 0;
    
    /// @brief Size (compressed)
    uint64_t compressedSize = 0;
    
    /// @brief Modified time
    SystemTimePoint modifiedTime;
    
    /// @brief Created time
    SystemTimePoint createdTime;
    
    /// @brief Attributes
    uint32_t attributes = 0;
    
    /// @brief Hash (SHA256)
    std::string hash;
    
    /// @brief Has ACLs
    bool hasACLs = false;
    
    /// @brief Has ADS
    bool hasADS = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Restore progress
 */
struct RestoreProgress {
    /// @brief Restore operation ID
    std::string restoreId;
    
    /// @brief Status
    RestoreStatus status = RestoreStatus::Pending;
    
    /// @brief Current phase
    std::string phase;
    
    /// @brief Current file
    fs::path currentFile;
    
    /// @brief Percent complete
    int percentComplete = 0;
    
    /// @brief Files restored
    uint64_t filesRestored = 0;
    
    /// @brief Total files
    uint64_t totalFiles = 0;
    
    /// @brief Bytes restored
    uint64_t bytesRestored = 0;
    
    /// @brief Total bytes
    uint64_t totalBytes = 0;
    
    /// @brief Files skipped
    uint64_t filesSkipped = 0;
    
    /// @brief Files failed
    uint64_t filesFailed = 0;
    
    /// @brief Conflicts encountered
    uint32_t conflictsEncountered = 0;
    
    /// @brief Transfer rate (bytes/sec)
    uint64_t transferRate = 0;
    
    /// @brief Estimated time remaining
    uint32_t estimatedTimeRemaining = 0;
    
    /// @brief Errors
    std::vector<std::string> errors;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Restore result
 */
struct RestoreResult {
    /// @brief Restore ID
    std::string restoreId;
    
    /// @brief Backup ID used
    std::string backupId;
    
    /// @brief Status
    RestoreStatus status = RestoreStatus::Completed;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief End time
    SystemTimePoint endTime;
    
    /// @brief Duration
    std::chrono::seconds duration{0};
    
    /// @brief Files restored
    uint64_t filesRestored = 0;
    
    /// @brief Bytes restored
    uint64_t bytesRestored = 0;
    
    /// @brief Files skipped
    uint64_t filesSkipped = 0;
    
    /// @brief Files failed
    uint64_t filesFailed = 0;
    
    /// @brief Conflicts resolved
    std::vector<RestoreConflict> conflicts;
    
    /// @brief Verification passed
    bool verificationPassed = false;
    
    /// @brief Errors
    std::vector<std::string> errors;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct RestoreStatistics {
    std::atomic<uint64_t> totalRestores{0};
    std::atomic<uint64_t> successfulRestores{0};
    std::atomic<uint64_t> failedRestores{0};
    std::atomic<uint64_t> totalFilesRestored{0};
    std::atomic<uint64_t> totalBytesRestored{0};
    std::atomic<uint64_t> conflictsResolved{0};
    std::atomic<uint64_t> filesSkipped{0};
    std::atomic<uint64_t> aclsRestored{0};
    std::atomic<uint64_t> verificationsPerformed{0};
    std::atomic<uint64_t> rollbacksPerformed{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using RestoreProgressCallback = std::function<void(const RestoreProgress&)>;
using RestoreCompletionCallback = std::function<void(const RestoreResult&)>;
using RestoreConflictCallback = std::function<ConflictResolution(const RestoreConflict&)>;
using RestoreFileCallback = std::function<bool(const BackupFileEntry&)>;
using RestoreErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// RESTORE MANAGER CLASS
// ============================================================================

/**
 * @class RestoreManager
 * @brief Enterprise data restoration
 */
class RestoreManager final {
public:
    [[nodiscard]] static RestoreManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;

    RestoreManager(const RestoreManager&) = delete;
    RestoreManager& operator=(const RestoreManager&) = delete;
    RestoreManager(RestoreManager&&) = delete;
    RestoreManager& operator=(RestoreManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] RestoreModuleStatus GetStatus() const noexcept;

    // ========================================================================
    // RESTORE OPERATIONS
    // ========================================================================
    
    /// @brief Restore from backup point
    [[nodiscard]] bool Restore(
        const std::wstring& backupId,
        const std::wstring& targetPath);
    
    /// @brief Restore with options
    [[nodiscard]] std::string Restore(
        const std::string& backupId,
        const std::vector<RestoreTarget>& targets,
        const RestoreOptions& options = {});
    
    /// @brief Restore single file
    [[nodiscard]] bool RestoreFile(
        const std::string& backupId,
        const fs::path& sourcePath,
        const fs::path& targetPath,
        const RestoreOptions& options = {});
    
    /// @brief Cancel restore
    [[nodiscard]] bool CancelRestore(const std::string& restoreId);
    
    /// @brief Pause restore
    [[nodiscard]] bool PauseRestore(const std::string& restoreId);
    
    /// @brief Resume restore
    [[nodiscard]] bool ResumeRestore(const std::string& restoreId);

    // ========================================================================
    // POINT-IN-TIME RESTORE
    // ========================================================================
    
    /// @brief Restore to point in time
    [[nodiscard]] std::string RestoreToPointInTime(
        const SystemTimePoint& timestamp,
        const std::vector<RestoreTarget>& targets,
        const RestoreOptions& options = {});
    
    /// @brief Get file version history
    [[nodiscard]] std::vector<BackupFileEntry> GetFileVersions(
        const fs::path& filePath);
    
    /// @brief Restore specific file version
    [[nodiscard]] bool RestoreFileVersion(
        const fs::path& filePath,
        const SystemTimePoint& versionTimestamp,
        const fs::path& targetPath);

    // ========================================================================
    // BROWSE BACKUP
    // ========================================================================
    
    /// @brief List files in backup
    [[nodiscard]] std::vector<BackupFileEntry> ListBackupFiles(
        const std::string& backupId,
        const fs::path& directory = L"");
    
    /// @brief Search files in backup
    [[nodiscard]] std::vector<BackupFileEntry> SearchBackupFiles(
        const std::string& backupId,
        const std::string& pattern);
    
    /// @brief Preview file from backup
    [[nodiscard]] std::vector<uint8_t> PreviewFile(
        const std::string& backupId,
        const fs::path& filePath,
        size_t maxBytes = 1024 * 1024);

    // ========================================================================
    // VERIFICATION
    // ========================================================================
    
    /// @brief Verify restore
    [[nodiscard]] bool VerifyRestore(const std::string& restoreId);
    
    /// @brief Verify file integrity
    [[nodiscard]] bool VerifyFileIntegrity(
        const fs::path& filePath,
        const std::string& expectedHash);

    // ========================================================================
    // ROLLBACK
    // ========================================================================
    
    /// @brief Rollback restore
    [[nodiscard]] bool RollbackRestore(const std::string& restoreId);
    
    /// @brief Is rollback available
    [[nodiscard]] bool IsRollbackAvailable(const std::string& restoreId) const;

    // ========================================================================
    // PROGRESS & STATUS
    // ========================================================================
    
    /// @brief Get restore progress
    [[nodiscard]] std::optional<RestoreProgress> GetProgress(
        const std::string& restoreId);
    
    /// @brief Get restore result
    [[nodiscard]] std::optional<RestoreResult> GetResult(
        const std::string& restoreId);
    
    /// @brief Get active restores
    [[nodiscard]] std::vector<std::string> GetActiveRestores();

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterProgressCallback(RestoreProgressCallback callback);
    void RegisterCompletionCallback(RestoreCompletionCallback callback);
    void RegisterConflictCallback(RestoreConflictCallback callback);
    void RegisterFileCallback(RestoreFileCallback callback);
    void RegisterErrorCallback(RestoreErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] RestoreStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    RestoreManager();
    ~RestoreManager();
    
    std::unique_ptr<RestoreManagerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetRestoreModeName(RestoreMode mode) noexcept;
[[nodiscard]] std::string_view GetConflictResolutionName(ConflictResolution resolution) noexcept;
[[nodiscard]] std::string_view GetRestoreStatusName(RestoreStatus status) noexcept;

/// @brief Generate restore ID
[[nodiscard]] std::string GenerateRestoreId();

/// @brief Compare file timestamps
[[nodiscard]] bool IsNewer(
    const SystemTimePoint& a,
    const SystemTimePoint& b);

}  // namespace Backup
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_RESTORE(backupId, path) \
    ::ShadowStrike::Backup::RestoreManager::Instance().Restore(backupId, path)

#define SS_RESTORE_FILE(backupId, src, dst) \
    ::ShadowStrike::Backup::RestoreManager::Instance().RestoreFile(backupId, src, dst)

#define SS_RESTORE_LIST(backupId) \
    ::ShadowStrike::Backup::RestoreManager::Instance().ListBackupFiles(backupId)

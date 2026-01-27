/**
 * ============================================================================
 * ShadowStrike Ransomware Protection - FILE BACKUP MANAGER (JIT Backup)
 * ============================================================================
 *
 * @file FileBackupManager.hpp
 * @brief Enterprise-grade Just-In-Time backup system for ransomware mitigation
 *        enabling file restoration after suspicious modification attempts.
 *
 * This module provides intelligent file backup before potentially destructive
 * modifications, enabling rollback if the modifying process is later confirmed
 * as ransomware.
 *
 * JIT BACKUP WORKFLOW:
 * ====================
 *
 * 1. Suspicious activity detected (but not confirmed)
 * 2. Pause the write operation
 * 3. Copy original file to secure cache
 * 4. Allow the write to proceed
 * 5. If process confirmed as ransomware → restore from cache
 * 6. If process exits cleanly → discard cache
 *
 * BACKUP CAPABILITIES:
 * ====================
 *
 * 1. STORAGE OPTIONS
 *    - RAM cache (fastest, limited size)
 *    - Protected folder (hidden/system)
 *    - Encrypted storage
 *    - Network backup
 *    - Volume shadow copy
 *
 * 2. BACKUP POLICIES
 *    - Size-based (small files to RAM)
 *    - Type-based (by extension)
 *    - Location-based (protected folders)
 *    - Risk-based (process risk level)
 *
 * 3. DEDUPLICATION
 *    - Content hashing
 *    - Block-level dedup
 *    - Delta storage
 *    - Compression
 *
 * 4. LIFECYCLE MANAGEMENT
 *    - Auto-cleanup on safe exit
 *    - Retention policies
 *    - Space management
 *    - Priority eviction
 *
 * 5. RESTORATION
 *    - Single file restore
 *    - Process rollback (all files)
 *    - Selective restore
 *    - Integrity verification
 *
 * 6. PERFORMANCE
 *    - Asynchronous backup
 *    - Memory-mapped I/O
 *    - Write-ahead logging
 *    - Batch operations
 *
 * INTEGRATION:
 * ============
 * - Ransomware::RansomwareDetector for triggering
 * - Utils::FileUtils for file operations
 * - Security::CryptoManager for encryption
 *
 * @note Minimal latency impact is critical for user experience.
 * @note Storage space should be monitored and managed.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, GDPR (data protection)
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
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <queue>

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
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/HashUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Ransomware {
    class FileBackupManagerImpl;
}

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace BackupConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum RAM cache size (bytes)
    inline constexpr uint64_t MAX_RAM_CACHE_SIZE = 512ULL * 1024 * 1024;  // 512MB
    
    /// @brief Maximum disk cache size (bytes)
    inline constexpr uint64_t MAX_DISK_CACHE_SIZE = 10ULL * 1024 * 1024 * 1024;  // 10GB
    
    /// @brief Maximum file size for RAM cache
    inline constexpr uint64_t MAX_RAM_FILE_SIZE = 10 * 1024 * 1024;  // 10MB
    
    /// @brief Maximum file size for backup
    inline constexpr uint64_t MAX_BACKUP_FILE_SIZE = 1ULL * 1024 * 1024 * 1024;  // 1GB
    
    /// @brief Maximum backups per process
    inline constexpr size_t MAX_BACKUPS_PER_PROCESS = 10000;
    
    /// @brief Maximum concurrent backup operations
    inline constexpr size_t MAX_CONCURRENT_BACKUPS = 16;

    // ========================================================================
    // TIMING
    // ========================================================================
    
    /// @brief Backup timeout (milliseconds)
    inline constexpr uint32_t BACKUP_TIMEOUT_MS = 30000;  // 30 seconds
    
    /// @brief Cleanup interval (seconds)
    inline constexpr uint32_t CLEANUP_INTERVAL_SECS = 300;  // 5 minutes
    
    /// @brief Default retention period (seconds)
    inline constexpr uint32_t DEFAULT_RETENTION_SECS = 3600;  // 1 hour

}  // namespace BackupConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Backup storage type
 */
enum class BackupStorageType : uint8_t {
    RAM         = 0,    ///< In-memory cache
    Disk        = 1,    ///< Protected disk folder
    Encrypted   = 2,    ///< Encrypted disk storage
    VSS         = 3,    ///< Volume shadow copy
    Network     = 4     ///< Network location
};

/**
 * @brief Backup status
 */
enum class BackupStatus : uint8_t {
    Pending     = 0,    ///< Backup pending
    InProgress  = 1,    ///< Backup in progress
    Completed   = 2,    ///< Backup completed
    Failed      = 3,    ///< Backup failed
    Restored    = 4,    ///< File restored from backup
    Committed   = 5,    ///< Changes committed (backup deleted)
    Expired     = 6     ///< Backup expired
};

/**
 * @brief Restore status
 */
enum class RestoreStatus : uint8_t {
    Success         = 0,
    PartialSuccess  = 1,
    Failed          = 2,
    NotFound        = 3,
    Corrupted       = 4,
    InUse           = 5,
    AccessDenied    = 6
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
 * @brief Backup entry
 */
struct BackupEntry {
    /// @brief Backup ID
    std::string backupId;
    
    /// @brief Original file path
    std::wstring originalPath;
    
    /// @brief Backup path/location
    std::wstring backupPath;
    
    /// @brief Original file size
    uint64_t originalSize = 0;
    
    /// @brief Backup size (may differ due to compression)
    uint64_t backupSize = 0;
    
    /// @brief Modifying process ID
    uint32_t modifyingPid = 0;
    
    /// @brief Modifying process name
    std::wstring processName;
    
    /// @brief Storage type
    BackupStorageType storageType = BackupStorageType::Disk;
    
    /// @brief Status
    BackupStatus status = BackupStatus::Pending;
    
    /// @brief Creation timestamp
    SystemTimePoint timestamp;
    
    /// @brief Expiration time
    TimePoint expirationTime;
    
    /// @brief Original file hash
    Hash256 originalHash{};
    
    /// @brief Backup hash
    Hash256 backupHash{};
    
    /// @brief Original file attributes
    uint32_t originalAttributes = 0;
    
    /// @brief Original creation time
    uint64_t originalCreationTime = 0;
    
    /// @brief Original modification time
    uint64_t originalModificationTime = 0;
    
    /// @brief Is compressed
    bool isCompressed = false;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
    
    /// @brief In-memory data (for RAM cache)
    std::shared_ptr<std::vector<uint8_t>> memoryData;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Restore result
 */
struct RestoreResult {
    /// @brief Original path
    std::wstring originalPath;
    
    /// @brief Backup ID used
    std::string backupId;
    
    /// @brief Status
    RestoreStatus status = RestoreStatus::Failed;
    
    /// @brief Duration (milliseconds)
    uint64_t durationMs = 0;
    
    /// @brief Bytes restored
    uint64_t bytesRestored = 0;
    
    /// @brief Error message
    std::string errorMessage;
    
    /// @brief Integrity verified
    bool integrityVerified = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Rollback result
 */
struct RollbackResult {
    /// @brief Process ID
    uint32_t pid = 0;
    
    /// @brief Files attempted
    uint64_t filesAttempted = 0;
    
    /// @brief Files restored
    uint64_t filesRestored = 0;
    
    /// @brief Files failed
    uint64_t filesFailed = 0;
    
    /// @brief Bytes restored
    uint64_t bytesRestored = 0;
    
    /// @brief Duration (milliseconds)
    uint64_t durationMs = 0;
    
    /// @brief Individual results
    std::vector<RestoreResult> results;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Backup policy
 */
struct BackupPolicy {
    /// @brief Policy name
    std::string policyName;
    
    /// @brief Enabled
    bool enabled = true;
    
    /// @brief Maximum file size
    uint64_t maxFileSize = BackupConstants::MAX_BACKUP_FILE_SIZE;
    
    /// @brief Storage type preference
    BackupStorageType preferredStorage = BackupStorageType::Disk;
    
    /// @brief Use RAM for files under this size
    uint64_t ramThreshold = BackupConstants::MAX_RAM_FILE_SIZE;
    
    /// @brief Compress backups
    bool compress = false;
    
    /// @brief Encrypt backups
    bool encrypt = false;
    
    /// @brief Retention period (seconds)
    uint32_t retentionSecs = BackupConstants::DEFAULT_RETENTION_SECS;
    
    /// @brief File extensions to include (empty = all)
    std::vector<std::wstring> includeExtensions;
    
    /// @brief File extensions to exclude
    std::vector<std::wstring> excludeExtensions;
    
    /// @brief Directories to include
    std::vector<std::wstring> includeDirectories;
    
    /// @brief Directories to exclude
    std::vector<std::wstring> excludeDirectories;
    
    /**
     * @brief Check if file matches policy
     */
    [[nodiscard]] bool ShouldBackup(std::wstring_view filePath, uint64_t fileSize) const;
};

/**
 * @brief Backup manager configuration
 */
struct FileBackupManagerConfiguration {
    /// @brief Enable backup system
    bool enabled = true;
    
    /// @brief Cache directory
    std::wstring cacheDirectory;
    
    /// @brief Maximum RAM cache size
    uint64_t maxRamCacheSize = BackupConstants::MAX_RAM_CACHE_SIZE;
    
    /// @brief Maximum disk cache size
    uint64_t maxDiskCacheSize = BackupConstants::MAX_DISK_CACHE_SIZE;
    
    /// @brief Default backup policy
    BackupPolicy defaultPolicy;
    
    /// @brief Additional policies
    std::vector<BackupPolicy> policies;
    
    /// @brief Async backup (non-blocking)
    bool asyncBackup = true;
    
    /// @brief Verify backup integrity
    bool verifyBackups = true;
    
    /// @brief Auto-cleanup expired backups
    bool autoCleanup = true;
    
    /// @brief Cleanup interval (seconds)
    uint32_t cleanupIntervalSecs = BackupConstants::CLEANUP_INTERVAL_SECS;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Backup statistics
 */
struct BackupStatistics {
    /// @brief Files backed up
    std::atomic<uint64_t> filesBackedUp{0};
    
    /// @brief Files restored
    std::atomic<uint64_t> filesRestored{0};
    
    /// @brief Files committed
    std::atomic<uint64_t> filesCommitted{0};
    
    /// @brief Backup failures
    std::atomic<uint64_t> backupFailures{0};
    
    /// @brief Restore failures
    std::atomic<uint64_t> restoreFailures{0};
    
    /// @brief Bytes backed up
    std::atomic<uint64_t> bytesBackedUp{0};
    
    /// @brief Bytes restored
    std::atomic<uint64_t> bytesRestored{0};
    
    /// @brief Current RAM usage
    std::atomic<uint64_t> currentRamUsage{0};
    
    /// @brief Current disk usage
    std::atomic<uint64_t> currentDiskUsage{0};
    
    /// @brief Active backups
    std::atomic<uint64_t> activeBackups{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Backup complete callback
using BackupCompleteCallback = std::function<void(const BackupEntry&)>;

/// @brief Restore complete callback
using RestoreCompleteCallback = std::function<void(const RestoreResult&)>;

/// @brief Progress callback
using BackupProgressCallback = std::function<void(
    std::wstring_view file, uint64_t bytesProcessed, uint64_t totalBytes)>;

// ============================================================================
// FILE BACKUP MANAGER CLASS
// ============================================================================

/**
 * @class FileBackupManager
 * @brief Enterprise-grade JIT backup system for ransomware mitigation
 *
 * Provides intelligent file backup before suspicious modifications,
 * enabling rollback if malicious activity is confirmed.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& backup = FileBackupManager::Instance();
 *     backup.Initialize();
 *     
 *     // Backup before suspicious modification
 *     if (backup.BackupFile(filePath, pid)) {
 *         // Allow modification
 *     }
 *     
 *     // Later, if ransomware confirmed
 *     backup.RollbackChanges(pid);
 * @endcode
 */
class FileBackupManager final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    [[nodiscard]] static FileBackupManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    FileBackupManager(const FileBackupManager&) = delete;
    FileBackupManager& operator=(const FileBackupManager&) = delete;
    FileBackupManager(FileBackupManager&&) = delete;
    FileBackupManager& operator=(FileBackupManager&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const FileBackupManagerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    // ========================================================================
    // BACKUP OPERATIONS
    // ========================================================================
    
    /**
     * @brief Create a JIT backup of a file
     * @param filePath File to backup
     * @param pid Process requesting the modification
     * @return True if backup successful
     */
    [[nodiscard]] bool BackupFile(const std::wstring& filePath, uint32_t pid);
    
    /**
     * @brief Backup with explicit policy
     */
    [[nodiscard]] std::optional<std::string> BackupFileEx(
        std::wstring_view filePath, uint32_t pid, const BackupPolicy& policy);
    
    /**
     * @brief Backup to specific storage
     */
    [[nodiscard]] std::optional<std::string> BackupFileTo(
        std::wstring_view filePath, uint32_t pid, BackupStorageType storage);
    
    /**
     * @brief Check if file is already backed up
     */
    [[nodiscard]] bool IsBackedUp(std::wstring_view filePath, uint32_t pid) const;
    
    /**
     * @brief Get backup for file
     */
    [[nodiscard]] std::optional<BackupEntry> GetBackup(
        std::wstring_view filePath, uint32_t pid) const;
    
    // ========================================================================
    // RESTORATION
    // ========================================================================
    
    /**
     * @brief Restore all files modified by a process
     */
    RollbackResult RollbackChanges(uint32_t pid);
    
    /**
     * @brief Restore single file
     */
    [[nodiscard]] RestoreResult RestoreFile(const std::string& backupId);
    
    /**
     * @brief Restore file by path
     */
    [[nodiscard]] RestoreResult RestoreFile(std::wstring_view filePath, uint32_t pid);
    
    /**
     * @brief Restore multiple files
     */
    [[nodiscard]] std::vector<RestoreResult> RestoreFiles(
        std::span<const std::string> backupIds);
    
    // ========================================================================
    // COMMIT (DISCARD BACKUPS)
    // ========================================================================
    
    /**
     * @brief Commit changes for a safe process
     */
    void CommitChanges(uint32_t pid);
    
    /**
     * @brief Commit single backup
     */
    void CommitBackup(const std::string& backupId);
    
    /**
     * @brief Commit all expired backups
     */
    void CommitExpired();
    
    // ========================================================================
    // QUERIES
    // ========================================================================
    
    /**
     * @brief Get all backups for process
     */
    [[nodiscard]] std::vector<BackupEntry> GetBackupsForProcess(uint32_t pid) const;
    
    /**
     * @brief Get all active backups
     */
    [[nodiscard]] std::vector<BackupEntry> GetActiveBackups() const;
    
    /**
     * @brief Get backup count for process
     */
    [[nodiscard]] size_t GetBackupCount(uint32_t pid) const;
    
    /**
     * @brief Get total backup count
     */
    [[nodiscard]] size_t GetTotalBackupCount() const noexcept;
    
    // ========================================================================
    // STORAGE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Get RAM cache usage
     */
    [[nodiscard]] uint64_t GetRamCacheUsage() const noexcept;
    
    /**
     * @brief Get disk cache usage
     */
    [[nodiscard]] uint64_t GetDiskCacheUsage() const noexcept;
    
    /**
     * @brief Cleanup old backups
     */
    void Cleanup();
    
    /**
     * @brief Force cleanup to free space
     */
    void FreeSpace(uint64_t bytesNeeded);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void SetBackupCompleteCallback(BackupCompleteCallback callback);
    void SetRestoreCompleteCallback(RestoreCompleteCallback callback);
    void SetProgressCallback(BackupProgressCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] BackupStatistics GetStatistics() const;
    void ResetStatistics();
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    FileBackupManager();
    ~FileBackupManager();
    
    std::unique_ptr<FileBackupManagerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetStorageTypeName(BackupStorageType type) noexcept;
[[nodiscard]] std::string_view GetBackupStatusName(BackupStatus status) noexcept;
[[nodiscard]] std::string_view GetRestoreStatusName(RestoreStatus status) noexcept;

}  // namespace Ransomware
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_BACKUP_FILE(path, pid) \
    ::ShadowStrike::Ransomware::FileBackupManager::Instance().BackupFile((path), (pid))

#define SS_ROLLBACK_CHANGES(pid) \
    ::ShadowStrike::Ransomware::FileBackupManager::Instance().RollbackChanges(pid)

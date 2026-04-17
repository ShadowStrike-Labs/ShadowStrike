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
 * ShadowStrike NGAV - BACKUP MANAGER MODULE
 * ============================================================================
 *
 * @file BackupManager.hpp
 * @brief Enterprise-grade secure backup management with encrypted vault,
 *        ransomware-protected storage, and VSS integration.
 *
 * Provides comprehensive backup management including secure vault creation,
 * minifilter-protected storage, versioning, and intelligent backup scheduling.
 *
 * BACKUP CAPABILITIES:
 * ====================
 *
 * 1. SECURE VAULT
 *    - AES-256 encrypted storage
 *    - Hidden backup location
 *    - Minifilter-protected access
 *    - Locked partition support
 *    - Ransomware immunity
 *
 * 2. BACKUP TYPES
 *    - Full backup
 *    - Incremental backup
 *    - Differential backup
 *    - Mirror backup
 *    - Continuous data protection
 *
 * 3. STORAGE OPTIONS
 *    - Local disk vault
 *    - Network share (SMB/NFS)
 *    - Cloud storage (S3, Azure, GCS)
 *    - External USB drives
 *    - NAS devices
 *
 * 4. DATA PROTECTION
 *    - Encryption at rest
 *    - Encryption in transit
 *    - Deduplication
 *    - Compression
 *    - Integrity verification
 *
 * 5. VSS INTEGRATION
 *    - Shadow copy management
 *    - Application-consistent backups
 *    - Open file backup
 *    - System state backup
 *
 * 6. SELF-DEFENSE
 *    - Protected vault access
 *    - Anti-tamper protection
 *    - Kernel-level isolation
 *    - Process whitelisting
 *
 * @note Requires minifilter driver for full protection.
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
#include <unordered_set>
#include <set>
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
#include "../Utils/CryptoUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Backup {
    class BackupManagerImpl;
}

namespace ShadowStrike {
namespace Backup {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace BackupConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default vault name
    inline constexpr const wchar_t* DEFAULT_VAULT_NAME = L".ShadowStrikeVault";
    
    /// @brief Maximum backup points
    inline constexpr size_t MAX_BACKUP_POINTS = 1000;
    
    /// @brief Default block size for backup
    inline constexpr size_t DEFAULT_BLOCK_SIZE = 4 * 1024 * 1024;  // 4MB
    
    /// @brief Encryption algorithm
    inline constexpr const char* ENCRYPTION_ALGORITHM = "AES-256-GCM";
    
    /// @brief Compression algorithm
    inline constexpr const char* COMPRESSION_ALGORITHM = "ZSTD";
    
    /// @brief Maximum concurrent backup operations
    inline constexpr size_t MAX_CONCURRENT_OPERATIONS = 4;

}  // namespace BackupConstants

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
 * @brief Backup type
 */
enum class BackupType : uint8_t {
    Full            = 0,    ///< Complete backup of all data
    Incremental     = 1,    ///< Only changed since last backup
    Differential    = 2,    ///< Only changed since last full backup
    Mirror          = 3,    ///< Exact mirror copy
    CDP             = 4,    ///< Continuous data protection
    Snapshot        = 5     ///< Point-in-time snapshot
};

/**
 * @brief Storage type
 */
enum class StorageType : uint8_t {
    LocalDisk       = 0,    ///< Local disk vault
    NetworkShare    = 1,    ///< SMB/NFS share
    CloudS3         = 2,    ///< Amazon S3
    CloudAzure      = 3,    ///< Azure Blob Storage
    CloudGCS        = 4,    ///< Google Cloud Storage
    USB             = 5,    ///< USB external drive
    NAS             = 6     ///< NAS device
};

/**
 * @brief Backup status
 */
enum class BackupStatus : uint8_t {
    Pending         = 0,
    InProgress      = 1,
    Completed       = 2,
    Failed          = 3,
    Cancelled       = 4,
    Partial         = 5,    ///< Partially completed
    Verifying       = 6,
    Verified        = 7
};

/**
 * @brief Vault status
 */
enum class VaultStatus : uint8_t {
    NotInitialized  = 0,
    Initializing    = 1,
    Ready           = 2,
    Locked          = 3,
    Unlocked        = 4,
    Corrupted       = 5,
    Full            = 6,
    Error           = 7
};

/**
 * @brief Compression level
 */
enum class CompressionLevel : uint8_t {
    None            = 0,
    Fast            = 1,
    Normal          = 2,
    Maximum         = 3
};

/**
 * @brief Encryption mode
 */
enum class EncryptionMode : uint8_t {
    None            = 0,
    AES128          = 1,
    AES256          = 2,
    ChaCha20        = 3
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Backing         = 3,
    Restoring       = 4,
    Paused          = 5,
    Stopping        = 6,
    Stopped         = 7,
    Error           = 8
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Vault configuration
 */
struct VaultConfiguration {
    /// @brief Vault path
    fs::path vaultPath;
    
    /// @brief Maximum size (bytes, 0 = unlimited)
    uint64_t maxSize = 0;
    
    /// @brief Encryption mode
    EncryptionMode encryption = EncryptionMode::AES256;
    
    /// @brief Encryption key (derived from password)
    std::vector<uint8_t> encryptionKey;
    
    /// @brief Compression level
    CompressionLevel compression = CompressionLevel::Normal;
    
    /// @brief Enable deduplication
    bool enableDeduplication = true;
    
    /// @brief Enable minifilter protection
    bool enableMinifilterProtection = true;
    
    /// @brief Hide vault folder
    bool hideVault = true;
    
    /// @brief Max backup points to keep
    size_t maxBackupPoints = BackupConstants::MAX_BACKUP_POINTS;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Vault info
 */
struct VaultInfo {
    /// @brief Vault ID
    std::string vaultId;
    
    /// @brief Vault path
    fs::path path;
    
    /// @brief Status
    VaultStatus status = VaultStatus::NotInitialized;
    
    /// @brief Total size
    uint64_t totalSize = 0;
    
    /// @brief Used size
    uint64_t usedSize = 0;
    
    /// @brief Available size
    uint64_t availableSize = 0;
    
    /// @brief Backup count
    uint32_t backupCount = 0;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
    
    /// @brief Is protected
    bool isProtected = false;
    
    /// @brief Is hidden
    bool isHidden = false;
    
    /// @brief Creation time
    SystemTimePoint creationTime;
    
    /// @brief Last backup time
    SystemTimePoint lastBackupTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Backup source
 */
struct BackupSource {
    /// @brief Source path
    fs::path path;
    
    /// @brief Is directory
    bool isDirectory = true;
    
    /// @brief Include patterns (glob)
    std::vector<std::string> includePatterns;
    
    /// @brief Exclude patterns (glob)
    std::vector<std::string> excludePatterns;
    
    /// @brief Recursive
    bool recursive = true;
    
    /// @brief Follow symlinks
    bool followSymlinks = false;
    
    /// @brief Use VSS for open files
    bool useVSS = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Backup point
 */
struct BackupPoint {
    /// @brief Backup ID
    std::string backupId;
    
    /// @brief Parent backup ID (for incremental)
    std::string parentBackupId;
    
    /// @brief Backup type
    BackupType type = BackupType::Full;
    
    /// @brief Status
    BackupStatus status = BackupStatus::Pending;
    
    /// @brief Sources
    std::vector<BackupSource> sources;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief End time
    SystemTimePoint endTime;
    
    /// @brief Duration
    std::chrono::seconds duration{0};
    
    /// @brief Total files
    uint64_t totalFiles = 0;
    
    /// @brief Total size (uncompressed)
    uint64_t totalSize = 0;
    
    /// @brief Backed up size (compressed/deduped)
    uint64_t backedUpSize = 0;
    
    /// @brief Files backed up
    uint64_t filesBackedUp = 0;
    
    /// @brief Files skipped
    uint64_t filesSkipped = 0;
    
    /// @brief Files failed
    uint64_t filesFailed = 0;
    
    /// @brief Compression ratio
    double compressionRatio = 1.0;
    
    /// @brief Deduplication ratio
    double deduplicationRatio = 1.0;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
    
    /// @brief Is verified
    bool isVerified = false;
    
    /// @brief Label
    std::string label;
    
    /// @brief Notes
    std::string notes;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Backup job
 */
struct BackupJob {
    /// @brief Job ID
    std::string jobId;
    
    /// @brief Job name
    std::string name;
    
    /// @brief Backup type
    BackupType type = BackupType::Incremental;
    
    /// @brief Sources
    std::vector<BackupSource> sources;
    
    /// @brief Target vault ID
    std::string vaultId;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Last run
    SystemTimePoint lastRun;
    
    /// @brief Next run (scheduled)
    SystemTimePoint nextRun;
    
    /// @brief Retention days
    uint32_t retentionDays = 30;
    
    /// @brief Max versions
    uint32_t maxVersions = 10;
    
    /// @brief Pre-backup command
    std::string preBackupCommand;
    
    /// @brief Post-backup command
    std::string postBackupCommand;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Backup progress
 */
struct BackupProgress {
    /// @brief Backup ID
    std::string backupId;
    
    /// @brief Current phase
    std::string phase;
    
    /// @brief Current file
    fs::path currentFile;
    
    /// @brief Percent complete (0-100)
    int percentComplete = 0;
    
    /// @brief Files processed
    uint64_t filesProcessed = 0;
    
    /// @brief Total files
    uint64_t totalFiles = 0;
    
    /// @brief Bytes processed
    uint64_t bytesProcessed = 0;
    
    /// @brief Total bytes
    uint64_t totalBytes = 0;
    
    /// @brief Transfer rate (bytes/sec)
    uint64_t transferRate = 0;
    
    /// @brief Estimated time remaining (seconds)
    uint32_t estimatedTimeRemaining = 0;
    
    /// @brief Errors
    std::vector<std::string> errors;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct BackupStatistics {
    std::atomic<uint64_t> totalBackups{0};
    std::atomic<uint64_t> successfulBackups{0};
    std::atomic<uint64_t> failedBackups{0};
    std::atomic<uint64_t> totalBytesBackedUp{0};
    std::atomic<uint64_t> totalFilesBackedUp{0};
    std::atomic<uint64_t> totalRestores{0};
    std::atomic<uint64_t> successfulRestores{0};
    std::atomic<uint64_t> bytesSavedByDedup{0};
    std::atomic<uint64_t> bytesSavedByCompression{0};
    std::atomic<uint64_t> vssSnapshotsCreated{0};
    std::atomic<uint64_t> ransomwareBlockedAttempts{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;

    struct Snapshot {
        uint64_t totalBackups{0};
        uint64_t successfulBackups{0};
        uint64_t failedBackups{0};
        uint64_t totalBytesBackedUp{0};
        uint64_t totalFilesBackedUp{0};
        uint64_t totalRestores{0};
        uint64_t successfulRestores{0};
        uint64_t bytesSavedByDedup{0};
        uint64_t bytesSavedByCompression{0};
        uint64_t vssSnapshotsCreated{0};
        uint64_t ransomwareBlockedAttempts{0};
        TimePoint startTime{Clock::now()};

        [[nodiscard]] std::string ToJson() const;
    };

    [[nodiscard]] Snapshot TakeSnapshot() const noexcept {
        Snapshot s;
        s.totalBackups = totalBackups.load(std::memory_order_relaxed);
        s.successfulBackups = successfulBackups.load(std::memory_order_relaxed);
        s.failedBackups = failedBackups.load(std::memory_order_relaxed);
        s.totalBytesBackedUp = totalBytesBackedUp.load(std::memory_order_relaxed);
        s.totalFilesBackedUp = totalFilesBackedUp.load(std::memory_order_relaxed);
        s.totalRestores = totalRestores.load(std::memory_order_relaxed);
        s.successfulRestores = successfulRestores.load(std::memory_order_relaxed);
        s.bytesSavedByDedup = bytesSavedByDedup.load(std::memory_order_relaxed);
        s.bytesSavedByCompression = bytesSavedByCompression.load(std::memory_order_relaxed);
        s.vssSnapshotsCreated = vssSnapshotsCreated.load(std::memory_order_relaxed);
        s.ransomwareBlockedAttempts = ransomwareBlockedAttempts.load(std::memory_order_relaxed);
        s.startTime = startTime;
        return s;
    }
};

/**
 * @brief Configuration
 */
struct BackupConfiguration {
    /// @brief Enable backup manager
    bool enabled = true;
    
    /// @brief Default vault configuration
    VaultConfiguration defaultVault;
    
    /// @brief Enable VSS integration
    bool enableVSS = true;
    
    /// @brief VSS timeout (seconds)
    uint32_t vssTimeoutSeconds = 300;
    
    /// @brief Enable minifilter protection
    bool enableMinifilterProtection = true;
    
    /// @brief Block size
    size_t blockSize = BackupConstants::DEFAULT_BLOCK_SIZE;
    
    /// @brief Max concurrent operations
    size_t maxConcurrentOperations = BackupConstants::MAX_CONCURRENT_OPERATIONS;
    
    /// @brief Verify after backup
    bool verifyAfterBackup = true;
    
    /// @brief Send notification on completion
    bool notifyOnCompletion = true;
    
    /// @brief Backup jobs
    std::vector<BackupJob> jobs;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ProgressCallback = std::function<void(const BackupProgress&)>;
using CompletionCallback = std::function<void(const BackupPoint&)>;
using FileCallback = std::function<bool(const fs::path&)>;  // Return false to skip
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// BACKUP MANAGER CLASS
// ============================================================================

/**
 * @class BackupManager
 * @brief Enterprise backup management
 */
class BackupManager final {
public:
    [[nodiscard]] static BackupManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    BackupManager(const BackupManager&) = delete;
    BackupManager& operator=(const BackupManager&) = delete;
    BackupManager(BackupManager&&) = delete;
    BackupManager& operator=(BackupManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const std::wstring& vaultPath);
    [[nodiscard]] bool Initialize(const BackupConfiguration& config);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const BackupConfiguration& config);
    [[nodiscard]] BackupConfiguration GetConfiguration() const;

    // ========================================================================
    // VAULT MANAGEMENT
    // ========================================================================
    
    /// @brief Create new vault
    [[nodiscard]] bool CreateVault(const VaultConfiguration& config);
    
    /// @brief Open existing vault
    [[nodiscard]] bool OpenVault(const fs::path& vaultPath, const std::string& password);
    
    /// @brief Close vault
    void CloseVault();
    
    /// @brief Lock vault
    [[nodiscard]] bool LockVault();
    
    /// @brief Unlock vault
    [[nodiscard]] bool UnlockVault(const std::string& password);
    
    /// @brief Get vault info
    [[nodiscard]] VaultInfo GetVaultInfo() const;
    
    /// @brief Is vault open
    [[nodiscard]] bool IsVaultOpen() const noexcept;
    
    /// @brief Is vault locked
    [[nodiscard]] bool IsVaultLocked() const noexcept;
    
    /// @brief Change vault password
    [[nodiscard]] bool ChangeVaultPassword(
        const std::string& oldPassword,
        const std::string& newPassword);

    // ========================================================================
    // BACKUP OPERATIONS
    // ========================================================================
    
    /// @brief Create backup
    [[nodiscard]] bool CreateBackup(const std::wstring& sourcePath);
    
    /// @brief Create backup with options
    [[nodiscard]] std::string CreateBackup(
        const std::vector<BackupSource>& sources,
        BackupType type = BackupType::Incremental,
        const std::string& label = "");
    
    /// @brief Cancel backup
    [[nodiscard]] bool CancelBackup(const std::string& backupId);
    
    /// @brief Pause backup
    [[nodiscard]] bool PauseBackup(const std::string& backupId);
    
    /// @brief Resume backup
    [[nodiscard]] bool ResumeBackup(const std::string& backupId);
    
    /// @brief Verify backup
    [[nodiscard]] bool VerifyBackup(const std::string& backupId);
    
    /// @brief Delete backup
    [[nodiscard]] bool DeleteBackup(const std::string& backupId);

    // ========================================================================
    // BACKUP POINTS
    // ========================================================================
    
    /// @brief Get backup points
    [[nodiscard]] std::vector<std::wstring> GetBackupPoints();
    
    /// @brief Get backup points (detailed)
    [[nodiscard]] std::vector<BackupPoint> GetBackupPointsDetailed();
    
    /// @brief Get backup point by ID
    [[nodiscard]] std::optional<BackupPoint> GetBackupPoint(const std::string& backupId);
    
    /// @brief Get latest backup point
    [[nodiscard]] std::optional<BackupPoint> GetLatestBackupPoint();
    
    /// @brief Get backup progress
    [[nodiscard]] std::optional<BackupProgress> GetBackupProgress(const std::string& backupId);

    // ========================================================================
    // JOB MANAGEMENT
    // ========================================================================
    
    /// @brief Create backup job
    [[nodiscard]] bool CreateJob(const BackupJob& job);
    
    /// @brief Update backup job
    [[nodiscard]] bool UpdateJob(const BackupJob& job);
    
    /// @brief Delete backup job
    [[nodiscard]] bool DeleteJob(const std::string& jobId);
    
    /// @brief Get backup jobs
    [[nodiscard]] std::vector<BackupJob> GetJobs() const;
    
    /// @brief Run backup job
    [[nodiscard]] std::string RunJob(const std::string& jobId);

    // ========================================================================
    // VSS INTEGRATION
    // ========================================================================
    
    /// @brief Create VSS snapshot
    [[nodiscard]] bool CreateVSSSnapshot(const std::wstring& volumePath);
    
    /// @brief Delete VSS snapshot
    [[nodiscard]] bool DeleteVSSSnapshot(const std::string& snapshotId);
    
    /// @brief Get VSS snapshots
    [[nodiscard]] std::vector<std::string> GetVSSSnapshots(const std::wstring& volumePath);

    // ========================================================================
    // RETENTION
    // ========================================================================
    
    /// @brief Apply retention policy
    [[nodiscard]] uint32_t ApplyRetentionPolicy();
    
    /// @brief Set retention days
    void SetRetentionDays(uint32_t days);
    
    /// @brief Get retention days
    [[nodiscard]] uint32_t GetRetentionDays() const noexcept;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterCompletionCallback(CompletionCallback callback);
    void RegisterFileCallback(FileCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] BackupStatistics::Snapshot GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    BackupManager();
    ~BackupManager();
    
    std::unique_ptr<BackupManagerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetBackupTypeName(BackupType type) noexcept;
[[nodiscard]] std::string_view GetStorageTypeName(StorageType type) noexcept;
[[nodiscard]] std::string_view GetBackupStatusName(BackupStatus status) noexcept;
[[nodiscard]] std::string_view GetVaultStatusName(VaultStatus status) noexcept;
[[nodiscard]] std::string_view GetCompressionLevelName(CompressionLevel level) noexcept;
[[nodiscard]] std::string_view GetEncryptionModeName(EncryptionMode mode) noexcept;

/// @brief Generate backup ID
[[nodiscard]] std::string GenerateBackupId();

/// @brief Calculate backup size estimate
[[nodiscard]] uint64_t EstimateBackupSize(const std::vector<BackupSource>& sources);

/// @brief Format bytes to human readable
[[nodiscard]] std::string FormatBytes(uint64_t bytes);

}  // namespace Backup
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_BACKUP_CREATE(path) \
    ::ShadowStrike::Backup::BackupManager::Instance().CreateBackup(path)

#define SS_BACKUP_VERIFY(id) \
    ::ShadowStrike::Backup::BackupManager::Instance().VerifyBackup(id)

#define SS_BACKUP_LIST() \
    ::ShadowStrike::Backup::BackupManager::Instance().GetBackupPointsDetailed()

#define SS_VAULT_LOCK() \
    ::ShadowStrike::Backup::BackupManager::Instance().LockVault()

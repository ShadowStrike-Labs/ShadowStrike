/**
 * ============================================================================
 * ShadowStrike Core FileSystem - FILE LOCK MANAGER (The Keymaster)
 * ============================================================================
 *
 * @file FileLockManager.hpp
 * @brief Enterprise-grade file lock detection and handle management.
 *
 * This module provides comprehensive capabilities to identify processes
 * holding file locks and safely release them when necessary for malware
 * remediation and quarantine operations.
 *
 * Key Capabilities:
 * =================
 * 1. LOCK DETECTION
 *    - Process handle enumeration
 *    - File mapping detection
 *    - Section object detection
 *    - DLL load locks
 *
 * 2. HANDLE MANAGEMENT
 *    - Handle duplication
 *    - Handle closure
 *    - Safe handle termination
 *    - Kernel driver integration
 *
 * 3. PROCESS MANAGEMENT
 *    - Locking process identification
 *    - Process tree analysis
 *    - Safe process termination
 *    - Restart Manager integration
 *
 * 4. REMEDIATION
 *    - Force unlock
 *    - Delete-on-reboot scheduling
 *    - Move-pending operations
 *    - Quarantine support
 *
 * Lock Management Architecture:
 * =============================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                       FileLockManager                               │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │HandleDetector│  │ProcessAnalyzer│ │    RestartManager        │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Enumerate  │  │ - Identify   │  │ - Session start          │  │
 *   │  │ - Filter     │  │ - Tree       │  │ - Resource reg           │  │
 *   │  │ - Validate   │  │ - Rights     │  │ - Shutdown               │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │HandleCloser  │  │ RebootScheduler│ │   KernelIntegration     │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Duplicate  │  │ - MoveFileEx │  │ - Driver comm            │  │
 *   │  │ - Close      │  │ - Schedule   │  │ - Kernel close           │  │
 *   │  │ - Terminate  │  │ - Track      │  │ - Force unlock           │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Integration Points:
 * ===================
 * - Quarantine: File isolation
 * - Kernel Driver: Force unlock
 * - Process Monitor: Process identification
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see QuarantineManager.hpp for file isolation
 * @see ProcessMonitor.hpp for process tracking
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/FileUtils.hpp"          // File operations
#include "../../Utils/ProcessUtils.hpp"       // Process handle enumeration
#include "../../Utils/SystemUtils.hpp"        // System operations

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class FileLockManagerImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace FileLockManagerConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Limits
    constexpr uint32_t MAX_LOCK_OWNERS = 1000;
    constexpr uint32_t MAX_HANDLES_PER_PROCESS = 10000;
    constexpr uint32_t UNLOCK_TIMEOUT_MS = 5000;

    // Retry settings
    constexpr uint32_t DEFAULT_RETRY_COUNT = 3;
    constexpr uint32_t DEFAULT_RETRY_DELAY_MS = 500;

}  // namespace FileLockManagerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum LockType
 * @brief Type of file lock.
 */
enum class LockType : uint8_t {
    Unknown = 0,
    Read = 1,                      // Shared read access
    Write = 2,                     // Exclusive write access
    ReadWrite = 3,                 // Both read and write
    Delete = 4,                    // Delete share violation
    Exclusive = 5,                 // No sharing
    Mapping = 6,                   // Memory-mapped file
    Section = 7,                   // Section object
    Module = 8                     // Loaded as DLL/EXE
};

/**
 * @enum UnlockMethod
 * @brief Method used to unlock file.
 */
enum class UnlockMethod : uint8_t {
    None = 0,
    HandleClose = 1,               // Close duplicate handle
    ProcessTerminate = 2,          // Terminate process
    RestartManager = 3,            // Use Restart Manager
    KernelDriver = 4,              // Use kernel driver
    DeleteOnReboot = 5             // Schedule for reboot
};

/**
 * @enum UnlockResult
 * @brief Result of unlock operation.
 */
enum class UnlockResult : uint8_t {
    Success = 0,
    PartialSuccess = 1,            // Some handles closed
    Failed = 2,
    AccessDenied = 3,
    ProcessCritical = 4,           // Cannot terminate critical process
    RequiresReboot = 5,
    InUseBySystem = 6,
    NotLocked = 7
};

/**
 * @enum ProcessRole
 * @brief Role of process in file lock.
 */
enum class ProcessRole : uint8_t {
    Unknown = 0,
    Application = 1,               // Normal application
    Service = 2,                   // Windows service
    System = 3,                    // System process
    Antivirus = 4,                 // AV software
    Explorer = 5,                  // Windows Explorer
    Malware = 6                    // Suspected malware
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct LockOwner
 * @brief Process owning a file lock.
 */
struct alignas(128) LockOwner {
    // Process info
    uint32_t pid{ 0 };
    uint32_t parentPid{ 0 };
    std::wstring processName;
    std::wstring processPath;
    std::wstring commandLine;

    // Lock info
    LockType lockType{ LockType::Unknown };
    uint64_t handleValue{ 0 };
    uint32_t accessMask{ 0 };
    uint32_t shareMode{ 0 };

    // Process classification
    ProcessRole role{ ProcessRole::Unknown };
    bool isSystemProcess{ false };
    bool isCriticalProcess{ false };
    bool isElevated{ false };
    bool isSigned{ false };
    std::wstring signerName;

    // Additional context
    std::wstring sessionName;
    uint32_t sessionId{ 0 };
    std::wstring userName;

    // Timestamps
    std::chrono::system_clock::time_point processStart;
    std::chrono::system_clock::time_point handleCreated;
};

/**
 * @struct FileLockInfo
 * @brief Complete file lock information.
 */
struct alignas(64) FileLockInfo {
    std::wstring filePath;
    bool isLocked{ false };
    uint32_t lockCount{ 0 };

    std::vector<LockOwner> owners;

    // Aggregated info
    bool hasSystemLock{ false };
    bool hasCriticalLock{ false };
    bool canForceUnlock{ true };

    // File metadata
    uint64_t fileSize{ 0 };
    bool fileExists{ true };
    bool isDirectory{ false };
};

/**
 * @struct UnlockOperation
 * @brief Result of unlock operation.
 */
struct alignas(128) UnlockOperation {
    std::wstring filePath;
    UnlockResult result{ UnlockResult::Failed };
    UnlockMethod method{ UnlockMethod::None };

    // Details
    uint32_t handlesClosed{ 0 };
    uint32_t processesTerminated{ 0 };
    std::vector<std::string> errors;
    std::vector<std::string> warnings;

    // Tracking
    bool requiresReboot{ false };
    std::wstring pendingOperation;

    // Timing
    std::chrono::milliseconds duration{ 0 };
};

/**
 * @struct PendingOperation
 * @brief Scheduled reboot operation.
 */
struct alignas(64) PendingOperation {
    std::wstring sourcePath;
    std::wstring destinationPath;          // Empty for delete
    bool isDelete{ false };
    bool isMove{ false };

    std::chrono::system_clock::time_point scheduledTime;
    std::string reason;
};

/**
 * @struct FileLockManagerConfig
 * @brief Configuration for file lock manager.
 */
struct alignas(32) FileLockManagerConfig {
    // Operation settings
    bool allowProcessTermination{ false };
    bool allowKernelUnlock{ true };
    bool allowRestartManager{ true };
    uint32_t unlockTimeoutMs{ FileLockManagerConstants::UNLOCK_TIMEOUT_MS };

    // Retry settings
    uint32_t retryCount{ FileLockManagerConstants::DEFAULT_RETRY_COUNT };
    uint32_t retryDelayMs{ FileLockManagerConstants::DEFAULT_RETRY_DELAY_MS };

    // Safety settings
    bool protectSystemProcesses{ true };
    bool protectCriticalProcesses{ true };
    bool protectServices{ true };

    // Factory methods
    static FileLockManagerConfig CreateDefault() noexcept;
    static FileLockManagerConfig CreateAggressive() noexcept;
    static FileLockManagerConfig CreateSafe() noexcept;
};

/**
 * @struct FileLockManagerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) FileLockManagerStatistics {
    std::atomic<uint64_t> locksDetected{ 0 };
    std::atomic<uint64_t> successfulUnlocks{ 0 };
    std::atomic<uint64_t> failedUnlocks{ 0 };
    std::atomic<uint64_t> processesTerminated{ 0 };
    std::atomic<uint64_t> handlesClosed{ 0 };
    std::atomic<uint64_t> rebootScheduled{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for process termination confirmation.
 */
using TerminateCallback = std::function<bool(const LockOwner& owner)>;

/**
 * @brief Callback for unlock progress.
 */
using UnlockProgressCallback = std::function<void(const std::wstring& status, uint32_t percent)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class FileLockManager
 * @brief Enterprise-grade file lock management.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& lockMgr = FileLockManager::Instance();
 * 
 * // Check who is locking a file
 * auto lockInfo = lockMgr.GetLockInfo(L"C:\\malware.exe");
 * 
 * if (lockInfo.isLocked) {
 *     for (const auto& owner : lockInfo.owners) {
 *         LOG_INFO << "Locked by: " << owner.processName 
 *                  << " (PID: " << owner.pid << ")";
 *     }
 *     
 *     // Try to unlock
 *     auto result = lockMgr.UnlockFile(L"C:\\malware.exe");
 *     
 *     if (result.result == UnlockResult::Success) {
 *         // File is now unlocked, can delete/quarantine
 *         quarantine.Add(L"C:\\malware.exe");
 *     } else if (result.requiresReboot) {
 *         LOG_WARNING << "File scheduled for deletion on reboot";
 *     }
 * }
 * @endcode
 */
class FileLockManager {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static FileLockManager& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the lock manager.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const FileLockManagerConfig& config);

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    // ========================================================================
    // LOCK DETECTION
    // ========================================================================

    /**
     * @brief Gets processes locking a file.
     * @param filePath Path to file.
     * @return Vector of lock owners.
     */
    [[nodiscard]] std::vector<LockOwner> GetLockingProcesses(const std::wstring& filePath) const;

    /**
     * @brief Gets complete lock information.
     * @param filePath Path to file.
     * @return File lock info.
     */
    [[nodiscard]] FileLockInfo GetLockInfo(const std::wstring& filePath) const;

    /**
     * @brief Checks if file is locked.
     * @param filePath Path to file.
     * @return True if locked.
     */
    [[nodiscard]] bool IsFileLocked(const std::wstring& filePath) const;

    /**
     * @brief Checks if file can be deleted.
     * @param filePath Path to file.
     * @return True if deletable.
     */
    [[nodiscard]] bool CanDeleteFile(const std::wstring& filePath) const;

    /**
     * @brief Gets lock type for file.
     * @param filePath Path to file.
     * @return Lock type.
     */
    [[nodiscard]] LockType GetLockType(const std::wstring& filePath) const;

    // ========================================================================
    // UNLOCK OPERATIONS
    // ========================================================================

    /**
     * @brief Attempts to unlock a file.
     * @param filePath Path to file.
     * @return Unlock operation result.
     */
    [[nodiscard]] UnlockOperation UnlockFile(const std::wstring& filePath);

    /**
     * @brief Attempts to unlock with specific method.
     * @param filePath Path to file.
     * @param method Unlock method to use.
     * @return Unlock operation result.
     */
    [[nodiscard]] UnlockOperation UnlockFile(const std::wstring& filePath, UnlockMethod method);

    /**
     * @brief Force unlocks a file using all available methods.
     * @param filePath Path to file.
     * @return Unlock operation result.
     */
    [[nodiscard]] UnlockOperation ForceUnlockFile(const std::wstring& filePath);

    /**
     * @brief Closes specific handle.
     * @param owner Lock owner.
     * @return True if closed.
     */
    bool CloseHandle(const LockOwner& owner);

    /**
     * @brief Terminates locking process.
     * @param owner Lock owner.
     * @param force Force termination.
     * @return True if terminated.
     */
    bool TerminateProcess(const LockOwner& owner, bool force = false);

    // ========================================================================
    // RESTART MANAGER
    // ========================================================================

    /**
     * @brief Uses Restart Manager to unlock file.
     * @param filePath Path to file.
     * @return True if successful.
     */
    bool UseRestartManager(const std::wstring& filePath);

    /**
     * @brief Gets applications using file via Restart Manager.
     * @param filePath Path to file.
     * @return Vector of application names.
     */
    [[nodiscard]] std::vector<std::wstring> GetApplicationsUsingFile(const std::wstring& filePath) const;

    // ========================================================================
    // REBOOT OPERATIONS
    // ========================================================================

    /**
     * @brief Schedules file deletion on reboot.
     * @param filePath Path to file.
     * @return True if scheduled.
     */
    bool ScheduleDeleteOnReboot(const std::wstring& filePath);

    /**
     * @brief Schedules file move on reboot.
     * @param sourcePath Source path.
     * @param destPath Destination path.
     * @return True if scheduled.
     */
    bool ScheduleMoveOnReboot(const std::wstring& sourcePath, const std::wstring& destPath);

    /**
     * @brief Gets pending reboot operations.
     * @return Vector of pending operations.
     */
    [[nodiscard]] std::vector<PendingOperation> GetPendingOperations() const;

    /**
     * @brief Cancels pending operation.
     * @param sourcePath Source path.
     * @return True if cancelled.
     */
    bool CancelPendingOperation(const std::wstring& sourcePath);

    // ========================================================================
    // KERNEL INTEGRATION
    // ========================================================================

    /**
     * @brief Uses kernel driver to unlock file.
     * @param filePath Path to file.
     * @return True if successful.
     */
    bool KernelUnlockFile(const std::wstring& filePath);

    /**
     * @brief Checks if kernel driver is available.
     * @return True if available.
     */
    [[nodiscard]] bool IsKernelDriverAvailable() const noexcept;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetTerminateCallback(TerminateCallback callback);
    void SetProgressCallback(UnlockProgressCallback callback);

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    void SetAllowProcessTermination(bool allow) noexcept;
    void SetProtectSystemProcesses(bool protect) noexcept;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const FileLockManagerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    FileLockManager();
    ~FileLockManager();

    FileLockManager(const FileLockManager&) = delete;
    FileLockManager& operator=(const FileLockManager&) = delete;

    std::unique_ptr<FileLockManagerImpl> m_impl;
};

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike

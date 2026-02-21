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
 * ShadowStrike Core Process - PROCESS KILLER (The Executioner)
 * ============================================================================
 *
 * @file ProcessKiller.hpp
 * @brief Enterprise-grade robust process termination engine.
 *
 * Terminating malware is challenging. Sophisticated threats employ multiple
 * defensive mechanisms to survive termination attempts:
 *
 * - API hooking to intercept TerminateProcess
 * - Watchdog processes that restart each other
 * - Protected Process Light (PPL) status
 * - Running as SYSTEM with SeDebugPrivilege blocking
 * - Critical process flagging (BSOD on termination)
 * - Thread resurrection via APC
 * - PsSetCreateThreadNotifyRoutine abuse
 *
 * This module implements robust, escalating termination techniques to
 * reliably neutralize threats while minimizing system impact.
 *
 * ============================================================================
 * TERMINATION METHODS (Escalation Order)
 * ============================================================================
 *
 * | Level | Method                  | Description                           |
 * |-------|-------------------------|---------------------------------------|
 * | 1     | Standard                | TerminateProcess() API                |
 * | 2     | Privileged              | Enable SeDebugPrivilege + Terminate   |
 * | 3     | Freeze-Kill             | Suspend all threads, then terminate   |
 * | 4     | Job Object              | Assign to job, terminate via job      |
 * | 5     | Token Manipulation      | Modify token, then terminate          |
 * | 6     | Kernel Direct           | Driver IOCTL for kernel termination   |
 * | 7     | Force Kernel            | ZwTerminateProcess from kernel        |
 * | 8     | Nuclear                 | Kernel memory manipulation            |
 *
 * ============================================================================
 * ENTERPRISE FEATURES
 * ============================================================================
 *
 * 1. PROCESS TREE TERMINATION
 *    - Kill parent with all children
 *    - Prevent orphan resurrection
 *    - Handle multi-generation trees
 *    - Cycle detection (mutual watchdogs)
 *
 * 2. WATCHDOG DEFEAT
 *    - Detect watchdog relationships
 *    - Synchronized termination
 *    - Service dependency analysis
 *    - Scheduled task removal
 *
 * 3. SELF-PROTECTION BYPASS
 *    - Handle protected processes
 *    - PPL level analysis
 *    - Critical process handling
 *    - Anti-tamper circumvention
 *
 * 4. PERSISTENCE CLEANUP
 *    - Service removal
 *    - Registry persistence cleanup
 *    - Scheduled task removal
 *    - Startup item removal
 *
 * 5. AUDIT TRAIL
 *    - Complete termination logging
 *    - Forensic evidence preservation
 *    - Rollback capability
 *    - Compliance reporting
 *
 * ============================================================================
 * SAFETY FEATURES
 * ============================================================================
 *
 * - System process protection (csrss, smss, lsass)
 * - User confirmation for critical processes
 * - Rollback capability
 * - Impact assessment before termination
 * - Dependency analysis
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

// ============================================================================
// INCLUDES
// ============================================================================

// Internal infrastructure
#include "ProcessMonitor.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/ErrorUtils.hpp"
#include "../../Whitelist/WhiteListStore.hpp" // Protected process list

// Standard library
#include <string>
#include <string_view>
#include <vector>
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
#include <future>
#include <cstdint>

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ProcessKillerImpl;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace KillerConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 4;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Timeouts
    constexpr uint32_t DEFAULT_KILL_TIMEOUT_MS = 5000;
    constexpr uint32_t SUSPEND_TIMEOUT_MS = 3000;
    constexpr uint32_t TREE_KILL_TIMEOUT_MS = 30000;
    constexpr uint32_t VERIFICATION_DELAY_MS = 100;
    constexpr uint32_t MAX_RETRY_ATTEMPTS = 3;
    constexpr uint32_t RETRY_DELAY_MS = 500;

    // Process tree limits
    constexpr uint32_t MAX_TREE_DEPTH = 64;
    constexpr uint32_t MAX_TREE_SIZE = 1024;
    constexpr uint32_t MAX_WATCHDOG_GROUPS = 256;

    // Thread limits
    constexpr uint32_t MAX_THREADS_PER_PROCESS = 10000;

    // Exit codes
    constexpr uint32_t EXIT_CODE_KILLED = 0xDEAD;
    constexpr uint32_t EXIT_CODE_SECURITY = 0xBAD;
    constexpr uint32_t EXIT_CODE_FORCE = 0xF0CE;

    // Protected process levels
    constexpr uint8_t PROTECTION_NONE = 0;
    constexpr uint8_t PROTECTION_PPL_AUTHENTICODE = 1;
    constexpr uint8_t PROTECTION_PPL_CODEGEN = 2;
    constexpr uint8_t PROTECTION_PPL_ANTIMALWARE = 3;
    constexpr uint8_t PROTECTION_PPL_LSA = 4;
    constexpr uint8_t PROTECTION_PPL_WINDOWS = 5;
    constexpr uint8_t PROTECTION_PP_WINTCB = 6;

    // Critical Windows processes (DO NOT TERMINATE)
    constexpr std::wstring_view CRITICAL_PROCESSES[] = {
        L"System", L"smss.exe", L"csrss.exe", L"wininit.exe",
        L"services.exe", L"lsass.exe", L"winlogon.exe"
    };

    // System processes (terminate with caution)
    constexpr std::wstring_view SYSTEM_PROCESSES[] = {
        L"svchost.exe", L"dwm.exe", L"fontdrvhost.exe",
        L"sihost.exe", L"taskhostw.exe", L"ctfmon.exe",
        L"explorer.exe", L"RuntimeBroker.exe"
    };

} // namespace KillerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum KillMethod
 * @brief Termination method to use.
 */
enum class KillMethod : uint8_t {
    Auto = 0,             ///< Automatically escalate through methods
    Standard = 1,         ///< TerminateProcess only
    Privileged = 2,       ///< Enable debug privilege first
    Freeze = 3,           ///< Suspend all threads, then terminate
    JobObject = 4,        ///< Assign to job and terminate
    TokenManipulation = 5,///< Manipulate token first
    Kernel = 6,           ///< Use kernel driver
    ForceKernel = 7,      ///< Aggressive kernel termination
    Nuclear = 8           ///< Last resort - kernel memory manipulation
};

/**
 * @enum KillResult
 * @brief Result of a termination attempt.
 */
enum class KillResult : uint8_t {
    Success = 0,          ///< Process terminated successfully
    AlreadyDead = 1,      ///< Process was already terminated
    AccessDenied = 2,     ///< Insufficient privileges
    Protected = 3,        ///< Protected process (PPL)
    Critical = 4,         ///< Critical process, refused
    NotFound = 5,         ///< Process doesn't exist
    Timeout = 6,          ///< Termination timed out
    PartialSuccess = 7,   ///< Some processes in tree killed
    Failed = 8,           ///< General failure
    Blocked = 9,          ///< Blocked by policy
    Resurrected = 10,     ///< Process was restarted
    InsufficientPriv = 11 ///< Cannot elevate privileges
};

/**
 * @enum SuspendResult
 * @brief Result of a suspension attempt.
 */
enum class SuspendResult : uint8_t {
    Success = 0,
    PartialSuccess = 1,   ///< Some threads suspended
    AccessDenied = 2,
    NotFound = 3,
    Failed = 4,
    AlreadySuspended = 5
};

/**
 * @enum ProtectionLevel
 * @brief Process protection level.
 */
enum class ProtectionLevel : uint8_t {
    None = 0,
    Light = 1,            ///< PPL - Protected Process Light
    Full = 2,             ///< PP - Full Protected Process
    Unknown = 3
};

/**
 * @enum ProcessCriticality
 * @brief How critical a process is to system stability.
 */
enum class ProcessCriticality : uint8_t {
    Normal = 0,           ///< Can be terminated freely
    SystemService = 1,    ///< May affect system features
    SecuritySoftware = 2, ///< Security product
    Critical = 3,         ///< Termination causes BSOD
    Forbidden = 4         ///< Never terminate (csrss, smss)
};

/**
 * @enum TreeKillStrategy
 * @brief Strategy for killing process trees.
 */
enum class TreeKillStrategy : uint8_t {
    BottomUp = 0,         ///< Kill children first, then parent
    TopDown = 1,          ///< Kill parent first
    Simultaneous = 2,     ///< Kill all at once (for watchdogs)
    Selective = 3         ///< Only kill malicious processes
};

/**
 * @enum WatchdogType
 * @brief Type of watchdog mechanism detected.
 */
enum class WatchdogType : uint8_t {
    None = 0,
    MutualProcess = 1,    ///< Two processes watching each other
    ParentChild = 2,      ///< Parent restarts child
    ServiceMonitor = 3,   ///< Service recovery mechanism
    ScheduledTask = 4,    ///< Scheduled task restarts process
    RegistryRun = 5,      ///< Registry run key restoration
    WMISubscription = 6   ///< WMI event subscription
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct ProcessProtectionInfo
 * @brief Information about process protection status.
 */
struct ProcessProtectionInfo {
    ProtectionLevel level = ProtectionLevel::None;
    uint8_t signerType = 0;                   ///< PS_PROTECTED_SIGNER
    uint8_t protectionType = 0;               ///< PS_PROTECTED_TYPE
    bool isCritical = false;                  ///< Process is marked critical
    bool isBreakOnTermination = false;        ///< BSOD on termination
    bool isSecure = false;                    ///< Secure process (VBS)
    bool canTerminate = true;                 ///< Assessment if we can terminate
    std::wstring protectionDescription;
};

/**
 * @struct ThreadKillInfo
 * @brief Information about killing a specific thread.
 */
struct ThreadKillInfo {
    uint32_t threadId = 0;
    bool wasSuspended = false;
    bool wasTerminated = false;
    uint32_t suspendCount = 0;
    std::wstring status;
};

/**
 * @struct ProcessKillInfo
 * @brief Information about a terminated process.
 */
struct ProcessKillInfo {
    uint32_t processId = 0;
    std::wstring processName;
    std::wstring processPath;
    std::wstring commandLine;
    uint32_t parentPid = 0;
    std::wstring userName;
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point killTime;
    KillMethod methodUsed = KillMethod::Standard;
    KillResult result = KillResult::Failed;
    uint32_t exitCode = 0;
    ProcessProtectionInfo protectionInfo;
    std::vector<ThreadKillInfo> threadResults;
    std::wstring errorMessage;
    uint32_t attemptCount = 0;
};

/**
 * @struct TreeKillInfo
 * @brief Information about killing a process tree.
 */
struct TreeKillInfo {
    uint32_t rootPid = 0;
    std::wstring rootName;
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    TreeKillStrategy strategy = TreeKillStrategy::BottomUp;
    uint32_t totalProcesses = 0;
    uint32_t killedProcesses = 0;
    uint32_t failedProcesses = 0;
    uint32_t skippedProcesses = 0;
    std::vector<ProcessKillInfo> processResults;
    KillResult overallResult = KillResult::Failed;
    std::vector<std::wstring> errors;
    std::vector<std::wstring> warnings;
};

/**
 * @struct WatchdogInfo
 * @brief Information about detected watchdog mechanism.
 */
struct WatchdogInfo {
    WatchdogType type = WatchdogType::None;
    uint32_t watcherPid = 0;
    uint32_t watchedPid = 0;
    std::wstring watcherName;
    std::wstring watchedName;
    std::wstring mechanism;                   ///< How they're connected
    std::wstring persistenceLocation;         ///< Registry, service, etc.
    bool canDisable = false;
};

/**
 * @struct WatchdogGroup
 * @brief Group of processes that watch each other.
 */
struct WatchdogGroup {
    std::vector<uint32_t> processIds;
    std::vector<WatchdogInfo> relationships;
    std::vector<std::wstring> persistenceLocations;
    bool requiresSimultaneousKill = false;
};

/**
 * @struct KillOptions
 * @brief Options for process termination.
 */
struct KillOptions {
    KillMethod preferredMethod = KillMethod::Auto;
    uint32_t timeoutMs = KillerConstants::DEFAULT_KILL_TIMEOUT_MS;
    uint32_t maxRetries = KillerConstants::MAX_RETRY_ATTEMPTS;
    bool escalateOnFailure = true;            ///< Try harder methods on failure
    bool killTree = false;                    ///< Kill entire process tree
    TreeKillStrategy treeStrategy = TreeKillStrategy::BottomUp;
    bool defeatWatchdogs = true;              ///< Detect and handle watchdogs
    bool cleanPersistence = false;            ///< Remove persistence mechanisms
    bool verifyTermination = true;            ///< Verify process is actually dead
    bool preserveEvidence = true;             ///< Collect forensic info before kill
    bool allowCritical = false;               ///< Allow killing critical processes
    uint32_t exitCode = KillerConstants::EXIT_CODE_KILLED;
    
    /**
     * @brief Create options for standard termination.
     */
    static KillOptions CreateStandard() noexcept;

    /**
     * @brief Create options for aggressive termination.
     */
    static KillOptions CreateAggressive() noexcept;

    /**
     * @brief Create options for malware termination.
     */
    static KillOptions CreateMalwareKill() noexcept;

    /**
     * @brief Create options for forensic-safe termination.
     */
    static KillOptions CreateForensic() noexcept;
};

/**
 * @struct SuspendOptions
 * @brief Options for process suspension.
 */
struct SuspendOptions {
    uint32_t timeoutMs = KillerConstants::SUSPEND_TIMEOUT_MS;
    bool suspendAllThreads = true;
    bool includeFrozenThreads = false;
    bool verifyFreeze = true;
};

/**
 * @struct KillerStatistics
 * @brief Runtime statistics for the process killer.
 */
struct alignas(64) KillerStatistics {
    // Termination counts
    std::atomic<uint64_t> totalKillAttempts{0};
    std::atomic<uint64_t> successfulKills{0};
    std::atomic<uint64_t> failedKills{0};
    std::atomic<uint64_t> escalatedKills{0};

    // Method usage
    std::atomic<uint64_t> standardKills{0};
    std::atomic<uint64_t> privilegedKills{0};
    std::atomic<uint64_t> freezeKills{0};
    std::atomic<uint64_t> jobObjectKills{0};
    std::atomic<uint64_t> kernelKills{0};

    // Tree operations
    std::atomic<uint64_t> treeKillAttempts{0};
    std::atomic<uint64_t> processesInTreesKilled{0};

    // Suspension
    std::atomic<uint64_t> suspendAttempts{0};
    std::atomic<uint64_t> successfulSuspends{0};
    std::atomic<uint64_t> resumeAttempts{0};

    // Watchdog handling
    std::atomic<uint64_t> watchdogsDetected{0};
    std::atomic<uint64_t> watchdogsDefeated{0};

    // Protection handling
    std::atomic<uint64_t> protectedProcessesEncountered{0};
    std::atomic<uint64_t> criticalProcessesBlocked{0};

    // Errors
    std::atomic<uint64_t> accessDeniedErrors{0};
    std::atomic<uint64_t> timeoutErrors{0};
    std::atomic<uint64_t> resurrectionsDetected{0};

    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept;

    /**
     * @brief Get kill success rate.
     */
    [[nodiscard]] double GetSuccessRate() const noexcept;
};

// ============================================================================
// CALLBACK DEFINITIONS
// ============================================================================

/**
 * @brief Callback before process termination.
 * @param pid Process ID
 * @param options Kill options
 * @return True to proceed, false to abort
 */
using PreKillCallback = std::function<bool(
    uint32_t pid,
    const KillOptions& options
)>;

/**
 * @brief Callback after process termination.
 * @param result Kill result information
 */
using PostKillCallback = std::function<void(
    const ProcessKillInfo& result
)>;

/**
 * @brief Callback for tree kill progress.
 * @param current Current process being killed
 * @param total Total processes in tree
 * @param result Result of current kill
 */
using TreeProgressCallback = std::function<void(
    uint32_t current,
    uint32_t total,
    const ProcessKillInfo& result
)>;

/**
 * @brief Callback when watchdog is detected.
 * @param watchdog Watchdog information
 */
using WatchdogDetectedCallback = std::function<void(
    const WatchdogInfo& watchdog
)>;

// ============================================================================
// PROCESS KILLER CLASS
// ============================================================================

/**
 * @class ProcessKiller
 * @brief Enterprise-grade process termination engine.
 *
 * Thread-safety: All public methods are thread-safe.
 * This class uses a combination of static methods (for simple operations)
 * and instance methods (for complex scenarios requiring state).
 *
 * Usage:
 * @code
 * // Simple termination
 * auto result = ProcessKiller::Terminate(targetPid);
 * if (result != KillResult::Success) {
 *     // Handle failure...
 * }
 * 
 * // Complex malware termination
 * auto& killer = ProcessKiller::Instance();
 * auto options = KillOptions::CreateMalwareKill();
 * options.killTree = true;
 * options.defeatWatchdogs = true;
 * auto treeResult = killer.TerminateTree(rootPid, options);
 * @endcode
 */
class ProcessKiller {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance.
     * @return Reference to the singleton instance.
     */
    [[nodiscard]] static ProcessKiller& Instance();

    // ========================================================================
    // STATIC TERMINATION METHODS (Simple API)
    // ========================================================================

    /**
     * @brief Terminate a process by any means necessary.
     * @param pid Process ID.
     * @param method Termination method.
     * @return Kill result.
     */
    [[nodiscard]] static KillResult Terminate(
        uint32_t pid,
        KillMethod method = KillMethod::Auto
    );

    /**
     * @brief Terminate a process tree (parent + all children).
     * @param rootPid Root process ID.
     * @return Kill result.
     */
    [[nodiscard]] static KillResult TerminateTree(uint32_t rootPid);

    /**
     * @brief Suspend all threads in a process.
     * @param pid Process ID.
     * @return True if suspended.
     */
    [[nodiscard]] static bool SuspendProcess(uint32_t pid);

    /**
     * @brief Resume a suspended process.
     * @param pid Process ID.
     * @return True if resumed.
     */
    [[nodiscard]] static bool ResumeProcess(uint32_t pid);

    /**
     * @brief Check if a process can be terminated.
     * @param pid Process ID.
     * @return True if can be terminated.
     */
    [[nodiscard]] static bool CanTerminate(uint32_t pid);

    /**
     * @brief Check if a process is a critical system process.
     * @param pid Process ID.
     * @return True if critical.
     */
    [[nodiscard]] static bool IsCriticalProcess(uint32_t pid);

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize the killer with kernel driver support.
     * @return True if initialization succeeded.
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Shutdown and cleanup.
     */
    void Shutdown();

    /**
     * @brief Check if initialized.
     * @return True if ready.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Check if kernel mode is available.
     * @return True if kernel driver is loaded.
     */
    [[nodiscard]] bool IsKernelModeAvailable() const noexcept;

    // ========================================================================
    // ADVANCED TERMINATION
    // ========================================================================

    /**
     * @brief Terminate a process with full options.
     * @param pid Process ID.
     * @param options Termination options.
     * @return Detailed kill information.
     */
    [[nodiscard]] ProcessKillInfo TerminateEx(
        uint32_t pid,
        const KillOptions& options = KillOptions::CreateStandard()
    );

    /**
     * @brief Terminate a process tree with full options.
     * @param rootPid Root process ID.
     * @param options Termination options.
     * @return Detailed tree kill information.
     */
    [[nodiscard]] TreeKillInfo TerminateTreeEx(
        uint32_t rootPid,
        const KillOptions& options = KillOptions::CreateStandard()
    );

    /**
     * @brief Terminate multiple processes.
     * @param pids Process IDs to terminate.
     * @param options Termination options.
     * @return Results for each process.
     */
    [[nodiscard]] std::vector<ProcessKillInfo> TerminateMultiple(
        const std::vector<uint32_t>& pids,
        const KillOptions& options = KillOptions::CreateStandard()
    );

    /**
     * @brief Terminate processes by name.
     * @param processName Process name.
     * @param options Termination options.
     * @return Results for each process.
     */
    [[nodiscard]] std::vector<ProcessKillInfo> TerminateByName(
        const std::wstring& processName,
        const KillOptions& options = KillOptions::CreateStandard()
    );

    /**
     * @brief Terminate processes by path.
     * @param processPath Process path.
     * @param options Termination options.
     * @return Results for each process.
     */
    [[nodiscard]] std::vector<ProcessKillInfo> TerminateByPath(
        const std::wstring& processPath,
        const KillOptions& options = KillOptions::CreateStandard()
    );

    // ========================================================================
    // SUSPENSION OPERATIONS
    // ========================================================================

    /**
     * @brief Suspend a process with options.
     * @param pid Process ID.
     * @param options Suspension options.
     * @return Suspend result.
     */
    [[nodiscard]] SuspendResult SuspendProcessEx(
        uint32_t pid,
        const SuspendOptions& options = SuspendOptions{}
    );

    /**
     * @brief Resume a process.
     * @param pid Process ID.
     * @return True if resumed.
     */
    bool ResumeProcessEx(uint32_t pid);

    /**
     * @brief Freeze a process (deep suspend).
     * @param pid Process ID.
     * @return True if frozen.
     *
     * This performs a deeper freeze that prevents the process from
     * executing any code, including kernel APCs.
     */
    [[nodiscard]] bool FreezeProcess(uint32_t pid);

    /**
     * @brief Thaw a frozen process.
     * @param pid Process ID.
     * @return True if thawed.
     */
    bool ThawProcess(uint32_t pid);

    /**
     * @brief Check if a process is suspended.
     * @param pid Process ID.
     * @return True if all threads are suspended.
     */
    [[nodiscard]] bool IsSuspended(uint32_t pid) const;

    // ========================================================================
    // PROCESS TREE OPERATIONS
    // ========================================================================

    /**
     * @brief Get process tree for a root PID.
     * @param rootPid Root process ID.
     * @param maxDepth Maximum tree depth.
     * @return Process IDs in the tree (root first).
     */
    [[nodiscard]] std::vector<uint32_t> GetProcessTree(
        uint32_t rootPid,
        uint32_t maxDepth = KillerConstants::MAX_TREE_DEPTH
    );

    /**
     * @brief Get children of a process.
     * @param pid Parent process ID.
     * @param recursive Include all descendants.
     * @return Child process IDs.
     */
    [[nodiscard]] std::vector<uint32_t> GetChildren(
        uint32_t pid,
        bool recursive = false
    );

    /**
     * @brief Suspend an entire process tree.
     * @param rootPid Root process ID.
     * @return True if all processes suspended.
     */
    [[nodiscard]] bool SuspendTree(uint32_t rootPid);

    /**
     * @brief Resume an entire process tree.
     * @param rootPid Root process ID.
     * @return True if all processes resumed.
     */
    bool ResumeTree(uint32_t rootPid);

    // ========================================================================
    // WATCHDOG DETECTION AND HANDLING
    // ========================================================================

    /**
     * @brief Detect watchdog mechanisms for a process.
     * @param pid Process ID.
     * @return Vector of detected watchdog info.
     */
    [[nodiscard]] std::vector<WatchdogInfo> DetectWatchdogs(uint32_t pid);

    /**
     * @brief Detect watchdog groups (mutual watchdogs).
     * @param pids Process IDs to analyze.
     * @return Watchdog groups.
     */
    [[nodiscard]] std::vector<WatchdogGroup> DetectWatchdogGroups(
        const std::vector<uint32_t>& pids
    );

    /**
     * @brief Defeat watchdog mechanisms.
     * @param group Watchdog group to defeat.
     * @return True if defeated.
     */
    bool DefeatWatchdogGroup(const WatchdogGroup& group);

    /**
     * @brief Kill a process and its watchdogs together.
     * @param pid Process ID.
     * @param options Kill options.
     * @return Tree kill info.
     */
    [[nodiscard]] TreeKillInfo KillWithWatchdogs(
        uint32_t pid,
        const KillOptions& options = KillOptions::CreateMalwareKill()
    );

    // ========================================================================
    // PROTECTION ANALYSIS
    // ========================================================================

    /**
     * @brief Get protection information for a process.
     * @param pid Process ID.
     * @return Protection information.
     */
    [[nodiscard]] ProcessProtectionInfo GetProtectionInfo(uint32_t pid);

    /**
     * @brief Get criticality level for a process.
     * @param pid Process ID.
     * @return Criticality level.
     */
    [[nodiscard]] ProcessCriticality GetCriticality(uint32_t pid);

    /**
     * @brief Check if process is protected (PPL).
     * @param pid Process ID.
     * @return True if protected.
     */
    [[nodiscard]] bool IsProtectedProcess(uint32_t pid);

    /**
     * @brief Attempt to remove PPL protection (requires driver).
     * @param pid Process ID.
     * @return True if protection removed.
     */
    [[nodiscard]] bool RemoveProtection(uint32_t pid);

    // ========================================================================
    // PERSISTENCE CLEANUP
    // ========================================================================

    /**
     * @brief Remove persistence mechanisms for a process.
     * @param pid Process ID.
     * @return True if persistence removed.
     */
    bool CleanPersistence(uint32_t pid);

    /**
     * @brief Remove service associated with process.
     * @param pid Process ID.
     * @return True if service removed.
     */
    bool RemoveService(uint32_t pid);

    /**
     * @brief Remove scheduled tasks associated with process.
     * @param pid Process ID.
     * @return True if tasks removed.
     */
    bool RemoveScheduledTasks(uint32_t pid);

    /**
     * @brief Remove registry persistence.
     * @param pid Process ID.
     * @return True if registry entries removed.
     */
    bool RemoveRegistryPersistence(uint32_t pid);

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Register pre-kill callback.
     * @param callback Callback function.
     * @return Callback ID.
     */
    uint64_t RegisterPreKillCallback(PreKillCallback callback);

    /**
     * @brief Register post-kill callback.
     * @param callback Callback function.
     * @return Callback ID.
     */
    uint64_t RegisterPostKillCallback(PostKillCallback callback);

    /**
     * @brief Register tree progress callback.
     * @param callback Callback function.
     * @return Callback ID.
     */
    uint64_t RegisterTreeProgressCallback(TreeProgressCallback callback);

    /**
     * @brief Register watchdog detection callback.
     * @param callback Callback function.
     * @return Callback ID.
     */
    uint64_t RegisterWatchdogCallback(WatchdogDetectedCallback callback);

    /**
     * @brief Unregister a callback.
     * @param callbackId Callback ID.
     */
    void UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // VERIFICATION
    // ========================================================================

    /**
     * @brief Verify a process is truly terminated.
     * @param pid Process ID.
     * @param timeoutMs Maximum time to wait.
     * @return True if process is dead.
     */
    [[nodiscard]] bool VerifyTermination(
        uint32_t pid,
        uint32_t timeoutMs = KillerConstants::DEFAULT_KILL_TIMEOUT_MS
    );

    /**
     * @brief Check if process was resurrected after kill.
     * @param name Process name.
     * @param path Process path.
     * @param sinceTime Check only processes started after this time.
     * @return New PID if resurrected, 0 otherwise.
     */
    [[nodiscard]] uint32_t CheckResurrection(
        const std::wstring& name,
        const std::wstring& path,
        std::chrono::system_clock::time_point sinceTime
    );

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /**
     * @brief Get killer statistics.
     * @return Current statistics.
     */
    [[nodiscard]] KillerStatistics GetStatistics() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStatistics();

    /**
     * @brief Get version string.
     * @return Version.
     */
    [[nodiscard]] static std::wstring GetVersion() noexcept;

    // ========================================================================
    // UTILITY
    // ========================================================================

    /**
     * @brief Convert kill result to string.
     * @param result Kill result.
     * @return String representation.
     */
    [[nodiscard]] static std::wstring ResultToString(KillResult result) noexcept;

    /**
     * @brief Convert kill method to string.
     * @param method Kill method.
     * @return String representation.
     */
    [[nodiscard]] static std::wstring MethodToString(KillMethod method) noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================

    ProcessKiller();
    ~ProcessKiller();

    ProcessKiller(const ProcessKiller&) = delete;
    ProcessKiller& operator=(const ProcessKiller&) = delete;

    // ========================================================================
    // IMPLEMENTATION
    // ========================================================================

    std::unique_ptr<ProcessKillerImpl> m_impl;
};

} // namespace Process
} // namespace Core
} // namespace ShadowStrike

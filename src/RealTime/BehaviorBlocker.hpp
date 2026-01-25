/**
 * ============================================================================
 * ShadowStrike Real-Time - BEHAVIOR BLOCKER (The Warden)
 * ============================================================================
 *
 * @file BehaviorBlocker.hpp
 * @brief Enterprise-grade real-time threat blocking and remediation.
 *
 * This module connects behavioral analysis verdicts to enforcement actions,
 * providing automated threat neutralization with rollback capabilities.
 *
 * =============================================================================
 * CORE CAPABILITIES
 * =============================================================================
 *
 * 1. **Threat Neutralization**
 *    - Process termination (graceful and forced)
 *    - Process suspension (analysis mode)
 *    - Child process termination
 *    - Thread termination
 *    - Handle revocation
 *
 * 2. **Rollback & Recovery**
 *    - File change rollback via FileBackupManager
 *    - Registry change rollback
 *    - Service restoration
 *    - Scheduled task removal
 *    - Persistence mechanism cleanup
 *
 * 3. **Quarantine Integration**
 *    - Automatic malware quarantine
 *    - Process artifacts collection
 *    - Memory dump capture
 *    - Evidence preservation
 *
 * 4. **Policy Enforcement**
 *    - Score-based blocking thresholds
 *    - Rule-based blocking decisions
 *    - Whitelist exceptions
 *    - Grace periods for critical processes
 *
 * =============================================================================
 * BLOCKING DECISION FLOW
 * =============================================================================
 *
 * ```
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                        THREAT DETECTION SOURCES                             │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
 * │  │ BehaviorAnalyzer│  │ MemoryProtection│  │      ThreatDetector         │  │
 * │  │   (scores)      │  │ (injections)    │  │    (correlated events)      │  │
 * │  └────────┬────────┘  └────────┬────────┘  └─────────────┬───────────────┘  │
 * │           │                    │                         │                  │
 * │           └────────────────────┼─────────────────────────┘                  │
 * │                                │                                            │
 * │                                ▼                                            │
 * └────────────────────────────────┼────────────────────────────────────────────┘
 *                                  │
 * ┌────────────────────────────────▼────────────────────────────────────────────┐
 * │                         BEHAVIOR BLOCKER                                    │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                     Decision Engine                                  │   │
 * │  │                                                                       │   │
 * │  │  1. Check whitelist → Exempt? → ALLOW                                │   │
 * │  │  2. Check critical process → Grace period? → DELAY                   │   │
 * │  │  3. Evaluate score thresholds:                                        │   │
 * │  │     - score < 50  → MONITOR                                          │   │
 * │  │     - score >= 50 → SUSPEND (if enabled)                             │   │
 * │  │     - score >= 70 → ALERT                                            │   │
 * │  │     - score >= 90 → TERMINATE                                        │   │
 * │  │  4. Apply policy rules                                                │   │
 * │  │  5. Execute blocking action                                           │   │
 * │  │                                                                       │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────────┐   │
 * │  │ Termination      │  │ Quarantine       │  │ Rollback               │   │
 * │  │ Module           │  │ Integration      │  │ Coordinator            │   │
 * │  │                  │  │                  │  │                        │   │
 * │  │ - Kill process   │  │ - Vault binary   │  │ - File changes         │   │
 * │  │ - Kill children  │  │ - Capture memory │  │ - Registry changes     │   │
 * │  │ - Close handles  │  │ - Save artifacts │  │ - Service changes      │   │
 * │  │ - Suspend first  │  │ - Forensics      │  │ - Task changes         │   │
 * │  └──────────────────┘  └──────────────────┘  └────────────────────────┘   │
 * │                                                                              │
 * └──────────────────────────────────────────────────────────────────────────────┘
 * ```
 *
 * =============================================================================
 * BLOCKING ACTIONS BY SEVERITY
 * =============================================================================
 *
 * | Score Range | Action                      | Description                       |
 * |-------------|-----------------------------|------------------------------------|
 * | 0-29        | None                        | Normal monitoring                  |
 * | 30-49       | Monitor                     | Enhanced monitoring, log events    |
 * | 50-69       | Suspend (optional)          | Pause for analysis                 |
 * | 70-89       | Alert + Suspend             | Alert SOC, suspend process         |
 * | 90-100      | Terminate + Quarantine      | Kill process, vault binary         |
 *
 * =============================================================================
 * CRITICAL PROCESS HANDLING
 * =============================================================================
 *
 * Some processes require special handling to avoid system instability:
 *
 * | Process               | Strategy                                           |
 * |-----------------------|---------------------------------------------------|
 * | csrss.exe             | Never terminate, alert only                        |
 * | lsass.exe             | Credential protection mode                         |
 * | services.exe          | Grace period, controlled termination               |
 * | svchost.exe           | Service-specific handling                          |
 * | explorer.exe          | UI warning before termination                      |
 * | winlogon.exe          | Never terminate                                    |
 * | System (PID 4)        | Never terminate                                    |
 *
 * =============================================================================
 * MITRE ATT&CK COVERAGE (Response)
 * =============================================================================
 *
 * | Technique | Description                     | Response Action              |
 * |-----------|---------------------------------|------------------------------|
 * | T1055     | Process Injection               | Terminate attacker+victim    |
 * | T1059     | Command Interpreter             | Terminate shell, block cmd   |
 * | T1486     | Data Encrypted for Impact       | Terminate, rollback          |
 * | T1547     | Boot/Logon Autostart            | Remove persistence           |
 * | T1053     | Scheduled Task                  | Remove task                  |
 * | T1543     | System Services                 | Revert service               |
 *
 * @note Thread-safe for all public methods
 * @note Requires elevated privileges for process termination
 *
 * @see BehaviorAnalyzer for behavioral scoring
 * @see QuarantineManager for malware isolation
 * @see FileBackupManager for rollback
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/ProcessUtils.hpp"          // Process termination
#include "../Utils/FileUtils.hpp"             // File rollback
#include "../Utils/RegistryUtils.hpp"         // Registry rollback
#include "../Whitelist/WhiteListStore.hpp"    // Critical process list

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// Forward declarations
namespace ShadowStrike {
    namespace Utils {
        class ThreadPool;
    }
    namespace Core {
        namespace Engine {
            class BehaviorAnalyzer;
            class ThreatDetector;
            class QuarantineManager;
        }
    }
    namespace Whitelist {
        class WhitelistStore;
    }
    namespace Backup {
        class FileBackupManager;
    }
}

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class BehaviorBlocker;
struct BlockingDecision;
struct BlockedProcessInfo;
struct RollbackOperation;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace BehaviorBlockerConstants {
    // -------------------------------------------------------------------------
    // Score Thresholds
    // -------------------------------------------------------------------------
    
    /// @brief Threshold for enhanced monitoring
    constexpr double MONITOR_THRESHOLD = 30.0;
    
    /// @brief Threshold for suspension
    constexpr double SUSPEND_THRESHOLD = 50.0;
    
    /// @brief Threshold for alert
    constexpr double ALERT_THRESHOLD = 70.0;
    
    /// @brief Threshold for termination
    constexpr double TERMINATE_THRESHOLD = 90.0;
    
    // -------------------------------------------------------------------------
    // Timing
    // -------------------------------------------------------------------------
    
    /// @brief Default grace period for critical processes (ms)
    constexpr uint32_t DEFAULT_GRACE_PERIOD_MS = 5000;
    
    /// @brief Maximum suspension time before decision (ms)
    constexpr uint32_t MAX_SUSPENSION_TIME_MS = 30000;
    
    /// @brief Termination timeout (ms)
    constexpr uint32_t TERMINATION_TIMEOUT_MS = 10000;
    
    // -------------------------------------------------------------------------
    // Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum blocked processes to track
    constexpr size_t MAX_BLOCKED_HISTORY = 10000;
    
    /// @brief Maximum pending rollback operations
    constexpr size_t MAX_PENDING_ROLLBACKS = 1000;
    
    /// @brief Maximum children to terminate per process
    constexpr size_t MAX_CHILD_TERMINATIONS = 100;
    
    // -------------------------------------------------------------------------
    // Retry
    // -------------------------------------------------------------------------
    
    /// @brief Maximum termination retries
    constexpr size_t MAX_TERMINATION_RETRIES = 3;
    
    /// @brief Retry interval (ms)
    constexpr uint32_t TERMINATION_RETRY_INTERVAL_MS = 1000;
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Blocking action type.
 */
enum class BlockingAction : uint8_t {
    /// @brief No action
    None = 0,
    
    /// @brief Monitor only
    Monitor = 1,
    
    /// @brief Suspend process
    Suspend = 2,
    
    /// @brief Alert (suspend + notify)
    Alert = 3,
    
    /// @brief Terminate process
    Terminate = 4,
    
    /// @brief Terminate and quarantine
    TerminateAndQuarantine = 5,
    
    /// @brief Terminate with rollback
    TerminateWithRollback = 6,
    
    /// @brief Full remediation (terminate + quarantine + rollback)
    FullRemediation = 7
};

/**
 * @brief Termination method.
 */
enum class TerminationMethod : uint8_t {
    /// @brief TerminateProcess API
    Standard = 0,
    
    /// @brief NtTerminateProcess
    Native = 1,
    
    /// @brief Terminate threads first
    ThreadBased = 2,
    
    /// @brief Suspend first, then terminate
    SuspendThenTerminate = 3,
    
    /// @brief Close all handles, starve resources
    ResourceStarvation = 4,
    
    /// @brief Kernel-level termination (driver)
    KernelLevel = 5
};

/**
 * @brief Blocking result.
 */
enum class BlockingResult : uint8_t {
    /// @brief Success
    Success = 0,
    
    /// @brief Process already terminated
    AlreadyTerminated = 1,
    
    /// @brief Process is whitelisted
    Whitelisted = 2,
    
    /// @brief Process is critical (not blocked)
    CriticalProcess = 3,
    
    /// @brief Access denied
    AccessDenied = 4,
    
    /// @brief Timeout
    Timeout = 5,
    
    /// @brief Failed
    Failed = 6,
    
    /// @brief Pending (in grace period)
    Pending = 7,
    
    /// @brief Suspended (awaiting decision)
    Suspended = 8
};

/**
 * @brief Process criticality level.
 */
enum class ProcessCriticality : uint8_t {
    /// @brief Normal process
    Normal = 0,
    
    /// @brief Important but terminable
    Important = 1,
    
    /// @brief System service
    Service = 2,
    
    /// @brief Critical system process
    Critical = 3,
    
    /// @brief Never terminate
    Protected = 4
};

/**
 * @brief Rollback type.
 */
enum class RollbackType : uint8_t {
    /// @brief No rollback
    None = 0,
    
    /// @brief File changes
    FileChanges = 1,
    
    /// @brief Registry changes
    RegistryChanges = 2,
    
    /// @brief Service changes
    ServiceChanges = 3,
    
    /// @brief Scheduled task changes
    ScheduledTaskChanges = 4,
    
    /// @brief All changes
    All = 5
};

/**
 * @brief Get string for BlockingAction.
 */
[[nodiscard]] constexpr const char* BlockingActionToString(BlockingAction action) noexcept;

/**
 * @brief Get string for BlockingResult.
 */
[[nodiscard]] constexpr const char* BlockingResultToString(BlockingResult result) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Blocking decision request.
 */
struct BlockingRequest {
    /// @brief Request ID
    uint64_t requestId = 0;
    
    /// @brief Request timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Thread ID (if thread-specific)
    uint32_t threadId = 0;
    
    /// @brief Process image path
    std::wstring imagePath;
    
    /// @brief Process image name
    std::wstring imageName;
    
    /// @brief Process command line
    std::wstring commandLine;
    
    /// @brief Parent process ID
    uint32_t parentProcessId = 0;
    
    /// @brief Risk/malice score
    double riskScore = 0.0;
    
    /// @brief Source of request
    std::string source;  // "BehaviorAnalyzer", "MemoryProtection", etc.
    
    /// @brief Blocking reason
    std::wstring reason;
    
    /// @brief MITRE techniques
    std::vector<std::string> mitreTechniques;
    
    /// @brief Suggested action
    BlockingAction suggestedAction = BlockingAction::None;
    
    /// @brief Is urgent (bypass grace period)
    bool urgent = false;
    
    /// @brief Kill children too
    bool terminateChildren = true;
    
    /// @brief Perform rollback
    bool rollback = true;
    
    /// @brief Quarantine binary
    bool quarantine = true;
    
    /// @brief Capture memory dump
    bool captureMemoryDump = false;
    
    /// @brief Additional context
    std::map<std::string, std::wstring> context;
};

/**
 * @brief Blocking decision result.
 */
struct BlockingDecision {
    /// @brief Request that triggered decision
    uint64_t requestId = 0;
    
    /// @brief Decision timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Decided action
    BlockingAction action = BlockingAction::None;
    
    /// @brief Result
    BlockingResult result = BlockingResult::Failed;
    
    /// @brief Decision reason
    std::wstring reason;
    
    /// @brief Process was whitelisted
    bool wasWhitelisted = false;
    
    /// @brief Grace period applied
    bool gracePeriodApplied = false;
    
    /// @brief Grace period end time
    std::chrono::system_clock::time_point gracePeriodEnd{};
    
    /// @brief Children terminated
    uint32_t childrenTerminated = 0;
    
    /// @brief Quarantine successful
    bool quarantineSuccessful = false;
    
    /// @brief Quarantine entry ID
    std::string quarantineEntryId;
    
    /// @brief Rollback initiated
    bool rollbackInitiated = false;
    
    /// @brief Files rolled back
    uint32_t filesRolledBack = 0;
    
    /// @brief Memory dump path (if captured)
    std::wstring memoryDumpPath;
    
    /// @brief Processing time (microseconds)
    uint64_t processingTimeUs = 0;
};

/**
 * @brief Information about a blocked process.
 */
struct BlockedProcessInfo {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring imageName;
    
    /// @brief Process path
    std::wstring imagePath;
    
    /// @brief Command line
    std::wstring commandLine;
    
    /// @brief User name
    std::wstring userName;
    
    /// @brief Parent PID
    uint32_t parentProcessId = 0;
    
    /// @brief Risk score at blocking
    double riskScore = 0.0;
    
    /// @brief Blocking action taken
    BlockingAction action = BlockingAction::None;
    
    /// @brief Blocking result
    BlockingResult result = BlockingResult::Failed;
    
    /// @brief Blocking reason
    std::wstring reason;
    
    /// @brief MITRE techniques
    std::vector<std::string> mitreTechniques;
    
    /// @brief Block timestamp
    std::chrono::system_clock::time_point blockTime{};
    
    /// @brief Termination timestamp
    std::chrono::system_clock::time_point terminationTime{};
    
    /// @brief Was quarantined
    bool wasQuarantined = false;
    
    /// @brief Was rolled back
    bool wasRolledBack = false;
    
    /// @brief Files rolled back
    std::vector<std::wstring> rolledBackFiles;
    
    /// @brief Child PIDs terminated
    std::vector<uint32_t> terminatedChildren;
    
    /// @brief Memory dump captured
    bool memoryDumpCaptured = false;
    
    /// @brief Memory dump path
    std::wstring memoryDumpPath;
    
    /// @brief Image hash
    std::string imageHash;
};

/**
 * @brief Rollback operation descriptor.
 */
struct RollbackOperation {
    /// @brief Operation ID
    uint64_t operationId = 0;
    
    /// @brief Process ID that caused changes
    uint32_t processId = 0;
    
    /// @brief Rollback type
    RollbackType rollbackType = RollbackType::None;
    
    /// @brief Files to rollback
    std::vector<std::wstring> files;
    
    /// @brief Registry keys to rollback
    std::vector<std::wstring> registryKeys;
    
    /// @brief Services to restore
    std::vector<std::wstring> services;
    
    /// @brief Scheduled tasks to remove
    std::vector<std::wstring> scheduledTasks;
    
    /// @brief Startup entries to remove
    std::vector<std::wstring> startupEntries;
    
    /// @brief Status
    std::string status;
    
    /// @brief Errors encountered
    std::vector<std::wstring> errors;
    
    /// @brief Items rolled back
    uint32_t itemsRolledBack = 0;
    
    /// @brief Items failed
    uint32_t itemsFailed = 0;
};

/**
 * @brief Critical process definition.
 */
struct CriticalProcessDef {
    /// @brief Process image name (lowercase)
    std::wstring imageName;
    
    /// @brief Criticality level
    ProcessCriticality criticality = ProcessCriticality::Normal;
    
    /// @brief Grace period (ms)
    uint32_t gracePeriodMs = 0;
    
    /// @brief Can terminate
    bool canTerminate = true;
    
    /// @brief Requires confirmation
    bool requiresConfirmation = false;
    
    /// @brief Custom handling notes
    std::wstring notes;
};

/**
 * @brief Configuration for behavior blocker.
 */
struct BehaviorBlockerConfig {
    // -------------------------------------------------------------------------
    // General Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable blocking
    bool enabled = true;
    
    /// @brief Enable automatic termination
    bool autoTerminate = true;
    
    /// @brief Enable automatic quarantine
    bool autoQuarantine = true;
    
    /// @brief Enable automatic rollback
    bool autoRollback = true;
    
    // -------------------------------------------------------------------------
    // Score Thresholds
    // -------------------------------------------------------------------------
    
    /// @brief Monitor threshold
    double monitorThreshold = BehaviorBlockerConstants::MONITOR_THRESHOLD;
    
    /// @brief Suspend threshold
    double suspendThreshold = BehaviorBlockerConstants::SUSPEND_THRESHOLD;
    
    /// @brief Alert threshold
    double alertThreshold = BehaviorBlockerConstants::ALERT_THRESHOLD;
    
    /// @brief Terminate threshold
    double terminateThreshold = BehaviorBlockerConstants::TERMINATE_THRESHOLD;
    
    // -------------------------------------------------------------------------
    // Behavior Settings
    // -------------------------------------------------------------------------
    
    /// @brief Terminate child processes
    bool terminateChildren = true;
    
    /// @brief Capture memory dump before termination
    bool captureMemoryDump = false;
    
    /// @brief Suspend before terminate (allows analysis)
    bool suspendBeforeTerminate = true;
    
    /// @brief Preferred termination method
    TerminationMethod terminationMethod = TerminationMethod::SuspendThenTerminate;
    
    // -------------------------------------------------------------------------
    // Protection Settings
    // -------------------------------------------------------------------------
    
    /// @brief Respect critical process protections
    bool respectCriticalProcesses = true;
    
    /// @brief Default grace period for critical processes (ms)
    uint32_t defaultGracePeriodMs = BehaviorBlockerConstants::DEFAULT_GRACE_PERIOD_MS;
    
    /// @brief Maximum suspension time (ms)
    uint32_t maxSuspensionTimeMs = BehaviorBlockerConstants::MAX_SUSPENSION_TIME_MS;
    
    // -------------------------------------------------------------------------
    // Rollback Settings
    // -------------------------------------------------------------------------
    
    /// @brief Rollback file changes
    bool rollbackFileChanges = true;
    
    /// @brief Rollback registry changes
    bool rollbackRegistryChanges = true;
    
    /// @brief Remove persistence mechanisms
    bool removePersistence = true;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static BehaviorBlockerConfig CreateDefault() noexcept {
        return BehaviorBlockerConfig{};
    }
    
    /**
     * @brief Create aggressive configuration.
     */
    [[nodiscard]] static BehaviorBlockerConfig CreateAggressive() noexcept {
        BehaviorBlockerConfig config;
        config.terminateThreshold = 80.0;
        config.alertThreshold = 60.0;
        config.suspendThreshold = 40.0;
        config.captureMemoryDump = true;
        config.terminationMethod = TerminationMethod::KernelLevel;
        return config;
    }
    
    /**
     * @brief Create conservative configuration.
     */
    [[nodiscard]] static BehaviorBlockerConfig CreateConservative() noexcept {
        BehaviorBlockerConfig config;
        config.terminateThreshold = 95.0;
        config.alertThreshold = 85.0;
        config.autoTerminate = false;  // Alert only
        config.respectCriticalProcesses = true;
        config.defaultGracePeriodMs = 10000;
        return config;
    }
    
    /**
     * @brief Create monitor-only configuration.
     */
    [[nodiscard]] static BehaviorBlockerConfig CreateMonitorOnly() noexcept {
        BehaviorBlockerConfig config;
        config.autoTerminate = false;
        config.autoQuarantine = false;
        config.autoRollback = false;
        config.terminateThreshold = 100.0;  // Never auto-terminate
        return config;
    }
};

/**
 * @brief Statistics for behavior blocker.
 */
struct BehaviorBlockerStats {
    /// @brief Total blocking requests received
    std::atomic<uint64_t> totalRequests{ 0 };
    
    /// @brief Processes terminated
    std::atomic<uint64_t> processesTerminated{ 0 };
    
    /// @brief Processes suspended
    std::atomic<uint64_t> processesSuspended{ 0 };
    
    /// @brief Processes monitored
    std::atomic<uint64_t> processesMonitored{ 0 };
    
    /// @brief Whitelist exemptions
    std::atomic<uint64_t> whitelistExemptions{ 0 };
    
    /// @brief Critical process exemptions
    std::atomic<uint64_t> criticalExemptions{ 0 };
    
    /// @brief Child processes terminated
    std::atomic<uint64_t> childrenTerminated{ 0 };
    
    /// @brief Quarantine operations
    std::atomic<uint64_t> quarantineOperations{ 0 };
    
    /// @brief Rollback operations
    std::atomic<uint64_t> rollbackOperations{ 0 };
    
    /// @brief Files rolled back
    std::atomic<uint64_t> filesRolledBack{ 0 };
    
    /// @brief Memory dumps captured
    std::atomic<uint64_t> memoryDumps{ 0 };
    
    /// @brief Termination failures
    std::atomic<uint64_t> terminationFailures{ 0 };
    
    /// @brief Average decision time (microseconds)
    std::atomic<uint64_t> avgDecisionTimeUs{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalRequests.store(0, std::memory_order_relaxed);
        processesTerminated.store(0, std::memory_order_relaxed);
        processesSuspended.store(0, std::memory_order_relaxed);
        processesMonitored.store(0, std::memory_order_relaxed);
        whitelistExemptions.store(0, std::memory_order_relaxed);
        criticalExemptions.store(0, std::memory_order_relaxed);
        childrenTerminated.store(0, std::memory_order_relaxed);
        quarantineOperations.store(0, std::memory_order_relaxed);
        rollbackOperations.store(0, std::memory_order_relaxed);
        filesRolledBack.store(0, std::memory_order_relaxed);
        memoryDumps.store(0, std::memory_order_relaxed);
        terminationFailures.store(0, std::memory_order_relaxed);
        avgDecisionTimeUs.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types.
 */
using BlockingDecisionCallback = std::function<bool(const BlockingRequest&, BlockingDecision&)>;
using BlockCompleteCallback = std::function<void(const BlockedProcessInfo&)>;
using RollbackCompleteCallback = std::function<void(const RollbackOperation&)>;
using TerminationAttemptCallback = std::function<void(uint32_t pid, TerminationMethod method, bool success)>;

// ============================================================================
// MAIN BEHAVIOR BLOCKER CLASS
// ============================================================================

/**
 * @brief Enterprise-grade real-time threat blocking and remediation.
 *
 * Connects behavioral analysis verdicts to enforcement actions including
 * process termination, quarantine, and rollback.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& blocker = BehaviorBlocker::Instance();
 * 
 * // Initialize
 * BehaviorBlockerConfig config = BehaviorBlockerConfig::CreateDefault();
 * blocker.Initialize(threadPool, config);
 * 
 * // Set integrations
 * blocker.SetQuarantineManager(&QuarantineManager::Instance());
 * blocker.SetWhitelistStore(&WhitelistStore::Instance());
 * blocker.SetFileBackupManager(&FileBackupManager::Instance());
 * 
 * // Register callbacks
 * blocker.RegisterBlockCompleteCallback([](const BlockedProcessInfo& info) {
 *     LOG_INFO(L"Blocked process: {} (PID: {}) - Score: {:.1f}",
 *              info.imageName, info.processId, info.riskScore);
 * });
 * 
 * // Start blocking
 * blocker.Start();
 * 
 * // Manual blocking request
 * BlockingRequest request;
 * request.processId = suspiciousPid;
 * request.riskScore = 95.0;
 * request.reason = L"Ransomware behavior detected";
 * request.urgent = true;
 * 
 * auto decision = blocker.Block(request);
 * if (decision.result == BlockingResult::Success) {
 *     LOG_INFO("Process terminated successfully");
 * }
 * 
 * // Check blocked history
 * auto history = blocker.GetBlockedHistory(100);
 * for (const auto& blocked : history) {
 *     LOG_INFO(L"Blocked: {} at {}", blocked.imageName, blocked.blockTime);
 * }
 * 
 * blocker.Stop();
 * blocker.Shutdown();
 * @endcode
 */
class BehaviorBlocker {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     */
    [[nodiscard]] static BehaviorBlocker& Instance();

    // Non-copyable, non-movable
    BehaviorBlocker(const BehaviorBlocker&) = delete;
    BehaviorBlocker& operator=(const BehaviorBlocker&) = delete;
    BehaviorBlocker(BehaviorBlocker&&) = delete;
    BehaviorBlocker& operator=(BehaviorBlocker&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the blocker.
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Initialize with thread pool.
     */
    [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

    /**
     * @brief Initialize with configuration.
     */
    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const BehaviorBlockerConfig& config
    );

    /**
     * @brief Shutdown the blocker.
     */
    void Shutdown();

    /**
     * @brief Start blocking.
     */
    void Start();

    /**
     * @brief Stop blocking.
     */
    void Stop();

    /**
     * @brief Check if blocker is running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Update configuration.
     */
    void UpdateConfig(const BehaviorBlockerConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] BehaviorBlockerConfig GetConfig() const;

    // =========================================================================
    // Blocking Operations
    // =========================================================================

    /**
     * @brief Block a process (full request).
     */
    [[nodiscard]] BlockingDecision Block(const BlockingRequest& request);

    /**
     * @brief Block a process (simplified).
     * @param pid Process ID.
     * @param reason Blocking reason.
     * @return Decision.
     */
    [[nodiscard]] BlockingDecision BlockProcess(uint32_t pid, const std::wstring& reason);

    /**
     * @brief Block a process (with score).
     */
    [[nodiscard]] BlockingDecision BlockProcess(
        uint32_t pid,
        double riskScore,
        const std::wstring& reason
    );

    /**
     * @brief Suspend a process (for analysis).
     */
    [[nodiscard]] BlockingResult SuspendProcess(uint32_t pid);

    /**
     * @brief Resume a suspended process.
     */
    [[nodiscard]] BlockingResult ResumeProcess(uint32_t pid);

    /**
     * @brief Terminate a process directly.
     */
    [[nodiscard]] BlockingResult TerminateProcess(
        uint32_t pid,
        TerminationMethod method = TerminationMethod::Standard
    );

    /**
     * @brief Terminate process and all children.
     */
    [[nodiscard]] BlockingResult TerminateProcessTree(uint32_t pid);

    // =========================================================================
    // Decision Logic
    // =========================================================================

    /**
     * @brief Determine action for score.
     */
    [[nodiscard]] BlockingAction DetermineAction(double riskScore) const;

    /**
     * @brief Check if process should be blocked.
     */
    [[nodiscard]] bool ShouldBlock(const BlockingRequest& request) const;

    /**
     * @brief Check if process is whitelisted.
     */
    [[nodiscard]] bool IsWhitelisted(uint32_t pid) const;

    /**
     * @brief Get process criticality.
     */
    [[nodiscard]] ProcessCriticality GetProcessCriticality(const std::wstring& imageName) const;

    // =========================================================================
    // Rollback Operations
    // =========================================================================

    /**
     * @brief Initiate rollback for process.
     */
    [[nodiscard]] RollbackOperation InitiateRollback(
        uint32_t pid,
        RollbackType rollbackType = RollbackType::All
    );

    /**
     * @brief Rollback file changes.
     */
    [[nodiscard]] bool RollbackFileChanges(uint32_t pid);

    /**
     * @brief Rollback registry changes.
     */
    [[nodiscard]] bool RollbackRegistryChanges(uint32_t pid);

    /**
     * @brief Remove persistence mechanisms.
     */
    [[nodiscard]] bool RemovePersistenceMechanisms(uint32_t pid);

    /**
     * @brief Get pending rollback operations.
     */
    [[nodiscard]] std::vector<RollbackOperation> GetPendingRollbacks() const;

    // =========================================================================
    // Quarantine Operations
    // =========================================================================

    /**
     * @brief Quarantine process binary.
     */
    [[nodiscard]] bool QuarantineProcess(uint32_t pid);

    /**
     * @brief Capture memory dump.
     */
    [[nodiscard]] std::wstring CaptureMemoryDump(uint32_t pid);

    /**
     * @brief Collect process artifacts.
     */
    [[nodiscard]] std::vector<std::wstring> CollectArtifacts(uint32_t pid);

    // =========================================================================
    // Query
    // =========================================================================

    /**
     * @brief Get blocked process info.
     */
    [[nodiscard]] std::optional<BlockedProcessInfo> GetBlockedInfo(uint32_t pid) const;

    /**
     * @brief Get blocked history.
     */
    [[nodiscard]] std::vector<BlockedProcessInfo> GetBlockedHistory(size_t count = 100) const;

    /**
     * @brief Get processes in grace period.
     */
    [[nodiscard]] std::vector<std::pair<uint32_t, std::chrono::system_clock::time_point>> 
        GetPendingBlocks() const;

    /**
     * @brief Get suspended processes.
     */
    [[nodiscard]] std::vector<uint32_t> GetSuspendedProcesses() const;

    /**
     * @brief Check if process was blocked.
     */
    [[nodiscard]] bool WasBlocked(uint32_t pid) const;

    // =========================================================================
    // Critical Process Management
    // =========================================================================

    /**
     * @brief Add critical process definition.
     */
    void AddCriticalProcess(const CriticalProcessDef& def);

    /**
     * @brief Remove critical process definition.
     */
    void RemoveCriticalProcess(const std::wstring& imageName);

    /**
     * @brief Get critical process definitions.
     */
    [[nodiscard]] std::vector<CriticalProcessDef> GetCriticalProcesses() const;

    /**
     * @brief Load critical processes from file.
     */
    bool LoadCriticalProcessesFromFile(const std::wstring& filePath);

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get statistics.
     */
    [[nodiscard]] BehaviorBlockerStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register decision callback (can modify decision).
     */
    [[nodiscard]] uint64_t RegisterDecisionCallback(BlockingDecisionCallback callback);

    /**
     * @brief Unregister decision callback.
     */
    bool UnregisterDecisionCallback(uint64_t callbackId);

    /**
     * @brief Register block complete callback.
     */
    [[nodiscard]] uint64_t RegisterBlockCompleteCallback(BlockCompleteCallback callback);

    /**
     * @brief Unregister block complete callback.
     */
    bool UnregisterBlockCompleteCallback(uint64_t callbackId);

    /**
     * @brief Register rollback complete callback.
     */
    [[nodiscard]] uint64_t RegisterRollbackCallback(RollbackCompleteCallback callback);

    /**
     * @brief Unregister rollback callback.
     */
    bool UnregisterRollbackCallback(uint64_t callbackId);

    /**
     * @brief Register termination attempt callback.
     */
    [[nodiscard]] uint64_t RegisterTerminationCallback(TerminationAttemptCallback callback);

    /**
     * @brief Unregister termination callback.
     */
    bool UnregisterTerminationCallback(uint64_t callbackId);

    // =========================================================================
    // External Integration
    // =========================================================================

    /**
     * @brief Set quarantine manager.
     */
    void SetQuarantineManager(Core::Engine::QuarantineManager* manager);

    /**
     * @brief Set behavior analyzer.
     */
    void SetBehaviorAnalyzer(Core::Engine::BehaviorAnalyzer* analyzer);

    /**
     * @brief Set threat detector.
     */
    void SetThreatDetector(Core::Engine::ThreatDetector* detector);

    /**
     * @brief Set whitelist store.
     */
    void SetWhitelistStore(Whitelist::WhitelistStore* store);

    /**
     * @brief Set file backup manager.
     */
    void SetFileBackupManager(Backup::FileBackupManager* manager);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    BehaviorBlocker();
    ~BehaviorBlocker();

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /**
     * @brief Execute blocking decision.
     */
    BlockingResult ExecuteBlock(const BlockingRequest& request, BlockingDecision& decision);

    /**
     * @brief Terminate process with retries.
     */
    bool TerminateWithRetry(uint32_t pid, TerminationMethod method);

    /**
     * @brief Get child processes.
     */
    std::vector<uint32_t> GetChildProcesses(uint32_t pid);

    /**
     * @brief Check grace period.
     */
    bool IsInGracePeriod(uint32_t pid) const;

    /**
     * @brief Handle grace period expiry.
     */
    void OnGracePeriodExpired(uint32_t pid);

    /**
     * @brief Grace period timer thread.
     */
    void GracePeriodTimerThread();

    /**
     * @brief Invoke decision callbacks.
     */
    bool InvokeDecisionCallbacks(const BlockingRequest& request, BlockingDecision& decision);

    /**
     * @brief Invoke block complete callbacks.
     */
    void InvokeBlockCompleteCallbacks(const BlockedProcessInfo& info);

    /**
     * @brief Invoke rollback callbacks.
     */
    void InvokeRollbackCallbacks(const RollbackOperation& op);

    // =========================================================================
    // Internal Data (PIMPL)
    // =========================================================================

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Suspend all threads in a process.
 */
[[nodiscard]] bool SuspendAllThreads(uint32_t pid) noexcept;

/**
 * @brief Resume all threads in a process.
 */
[[nodiscard]] bool ResumeAllThreads(uint32_t pid) noexcept;

/**
 * @brief Get all process child PIDs (recursive).
 */
[[nodiscard]] std::vector<uint32_t> GetProcessTreePIDs(uint32_t rootPid) noexcept;

/**
 * @brief Check if process is a critical system process.
 */
[[nodiscard]] bool IsCriticalSystemProcess(const std::wstring& imageName) noexcept;

/**
 * @brief Create memory dump for process.
 */
[[nodiscard]] bool CreateProcessDump(uint32_t pid, const std::wstring& outputPath) noexcept;

} // namespace RealTime
} // namespace ShadowStrike

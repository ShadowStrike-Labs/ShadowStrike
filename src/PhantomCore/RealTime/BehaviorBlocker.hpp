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
 * ShadowStrike Real-Time - BEHAVIOR BLOCKER (The Enforcer)
 * ============================================================================
 *
 * @file BehaviorBlocker.hpp
 * @brief Chief behavior blocking orchestrator for real-time threat response.
 *
 * This module is the central decision engine that evaluates observed process
 * behaviors against a prioritized rule set and enforces blocking actions in
 * real time. It ingests events from both user-mode sensors and the kernel
 * minifilter/ETW pipeline, correlates them into attack chains, and takes
 * graduated enforcement actions ranging from logging through process
 * termination.
 *
 * =============================================================================
 * CORE CAPABILITIES
 * =============================================================================
 *
 * 1. **Behavior Analysis**
 *    - Evaluates 19 behavior categories against prioritized rule sets
 *    - Regex-based target matching with ReDoS-safe input capping
 *    - Risk-level thresholding for graduated response
 *    - MITRE ATT&CK technique mapping per rule
 *
 * 2. **Kernel Integration**
 *    - Receives behavioral alerts from ShadowStrike minifilter driver
 *    - Deserializes kernel message payloads into ProcessBehavior events
 *    - Pushes compiled rule sets to kernel for early filtering
 *
 * 3. **Temporal Correlation**
 *    - Links related events into behavior chains via correlationId
 *    - Auto-escalates response when chain score exceeds threshold
 *    - Configurable chain timeout window (default 5 minutes)
 *
 * 4. **Graduated Enforcement**
 *    - 8-level action hierarchy: Allow → LogOnly → AlertOnly →
 *      BlockOperation → QuarantineFile → SuspendProcess →
 *      IsolateNetwork → TerminateProcess
 *    - TerminateProcess is the highest-priority actionable response
 *
 * 5. **Exclusion Engine**
 *    - Process path, behavior type, command line, and target regex matching
 *    - Time-bounded exclusions with auto-expiry
 *    - Fast-path bypass before rule evaluation
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ```
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          KERNEL MODE                                        │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │  ┌──────────────────────────────────────────────────────────────────────┐   │
 * │  │  Minifilter / ETW Provider / PsSetCreateProcessNotifyRoutineEx2     │   │
 * │  │  ─ Emits behavioral alerts for 19 categories                       │   │
 * │  └──────────────────────────┬───────────────────────────────────────────┘   │
 * │                             │ FilterSendMessage / shared ring buffer       │
 * └─────────────────────────────┼───────────────────────────────────────────────┘
 *                               │
 * ══════════════════════════════╪═══════════════════════════════════════════════
 *                               │ Kernel Boundary
 * ══════════════════════════════╪═══════════════════════════════════════════════
 *                               │
 * ┌─────────────────────────────┼───────────────────────────────────────────────┐
 * │                             ▼                                               │
 * │  ┌──────────────────────────────────────────────────────────────────────┐   │
 * │  │                     BehaviorBlocker                                  │   │
 * │  │                                                                      │   │
 * │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐   │   │
 * │  │  │  Rule Engine │  │  Exclusion   │  │  Temporal Correlation    │   │   │
 * │  │  │  (Priority   │  │  Engine      │  │  Engine                  │   │   │
 * │  │  │   Ordered)   │  │  (Fast Path) │  │  (Chain Tracking)        │   │   │
 * │  │  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────────┘   │   │
 * │  │         │                 │                      │                   │   │
 * │  │         └─────────────────┴──────────────────────┘                   │   │
 * │  │                           │                                          │   │
 * │  │                           ▼                                          │   │
 * │  │  ┌──────────────────────────────────────────────────────────────┐   │   │
 * │  │  │                  Enforcement Layer                           │   │   │
 * │  │  │  - ProcessUtils::TerminateProcess                           │   │   │
 * │  │  │  - ProcessUtils::SuspendProcess                             │   │   │
 * │  │  │  - QuarantineManager (file isolation)                       │   │   │
 * │  │  │  - NetworkIsolator (endpoint isolation)                     │   │   │
 * │  │  └──────────────────────────────────────────────────────────────┘   │   │
 * │  │                                                                      │   │
 * │  │  Callbacks ────► RealTimeProtection, ThreatDetector, UI, Telemetry  │   │
 * │  └──────────────────────────────────────────────────────────────────────┘   │
 * │                          USER MODE                                          │
 * └─────────────────────────────────────────────────────────────────────────────┘
 * ```
 *
 * =============================================================================
 * LIFECYCLE STATE MACHINE
 * =============================================================================
 *
 * ```
 * NotInitialized ──Initialize()──► Initializing ──(success)──► Stopped
 *                                       │                         │
 *                                    (fail)                   Start()
 *                                       │                         │
 *                                       ▼                         ▼
 *                                     Error                   Running
 *                                                            /       \
 *                                                       Pause()    Stop()
 *                                                          │         │
 *                                                          ▼         ▼
 *                                                       Paused    Stopping ──► Stopped
 *                                                          │
 *                                                      Resume()
 *                                                          │
 *                                                          ▼
 *                                                       Running
 *
 * Any state ──Shutdown()──► NotInitialized
 * ```
 *
 * =============================================================================
 * LOCK ORDERING (deadlock prevention)
 * =============================================================================
 *
 * When acquiring multiple locks, always follow this order:
 *   1. m_stateMutex       (lifecycle state transitions)
 *   2. m_ruleMutex        (rule set reads/writes)
 *   3. m_exclusionMutex   (exclusion set reads/writes)
 *   4. m_blockedMutex     (blocked PID set)
 *   5. m_historyMutex     (event history ring)
 *   6. m_callbackMutex    (callback registry)
 *
 * Never acquire a higher-numbered lock while holding a lower-numbered one
 * in reverse order. The hot path (AnalyzeBehavior) acquires only m_ruleMutex
 * and m_exclusionMutex as shared locks; enforcement acquires m_blockedMutex
 * and m_historyMutex as exclusive locks.
 *
 * =============================================================================
 * HOT PATH PERFORMANCE CONTRACT
 * =============================================================================
 *
 * AnalyzeBehavior() is called on every behavioral event from sensors and the
 * kernel pipeline. It MUST complete within the configured analysisTimeoutMs
 * (default 5ms) for p99 latency. Requirements:
 *   - Exclusion check is the fast path (evaluated first, shared lock only)
 *   - Rules are pre-compiled (regex compiled at AddRule time, not eval time)
 *   - No heap allocation on the common Allow path
 *   - Regex input is capped at regexMaxInputLength to prevent ReDoS
 *   - Statistics use std::atomic internally (no lock contention)
 *
 * =============================================================================
 * THREAD SAFETY
 * =============================================================================
 *
 * - All public methods are thread-safe
 * - Uses std::shared_mutex for read-heavy workloads (rule/exclusion eval)
 * - Write operations (AddRule, RemoveRule, etc.) take exclusive locks
 * - Statistics tracked with std::atomic in PIMPL (exposed as plain snapshot)
 * - Callbacks invoked outside any lock to prevent deadlocks
 *
 * MITRE ATT&CK Coverage:
 * =======================
 * - T1059: Command and Scripting Interpreter (ScriptExecution)
 * - T1055: Process Injection (ProcessInjection)
 * - T1547: Boot or Logon Autostart Execution (RegistryModification)
 * - T1574: Hijack Execution Flow (DLLSideloading)
 * - T1003: OS Credential Dumping (CredentialAccess)
 * - T1486: Data Encrypted for Impact (RansomwareActivity)
 * - T1490: Inhibit System Recovery (ShadowCopyDeletion)
 * - T1548: Abuse Elevation Control Mechanism (PrivilegeEscalation)
 * - T1562: Impair Defenses (DefenseEvasion)
 * - T1021: Remote Services (LateralMovement)
 * - T1047: Windows Management Instrumentation (WMIActivity)
 *
 * @see BehaviorBlocker.cpp for PIMPL implementation
 * @see RealTimeProtection.hpp for lifecycle orchestration
 * @see ProcessCreationMonitor.hpp for process event sourcing
 */
#pragma once

// Standard library
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ShadowStrike::RealTime {

// =============================================================================
// ENUMERATIONS
// =============================================================================

/**
 * @brief Categorization of observed system behaviors.
 *
 * Aligned with the kernel driver's 19 behavioral alert categories.
 * Each category maps to one or more MITRE ATT&CK techniques.
 */
enum class BehaviorType : uint8_t {
    Unknown             = 0,   ///< Unclassified or parse failure
    FileModification    = 1,   ///< Rename, Delete, Write to monitored paths
    NetworkConnection   = 2,   ///< Outbound connect, inbound listen, DNS query
    ProcessInjection    = 3,   ///< Remote thread creation, APC injection, atom bombing
    RegistryModification = 4,  ///< ASEP keys, service registration, COM hijack
    DriverLoading       = 5,   ///< Kernel driver load via NtLoadDriver or SCM
    ShadowCopyDeletion  = 6,   ///< vssadmin delete, WMIC shadowcopy delete
    RansomwareActivity  = 7,   ///< High-entropy writes, known ransom extensions
    PrivilegeEscalation = 8,   ///< Token manipulation, named pipe impersonation
    DefenseEvasion      = 9,   ///< Disable AV, tamper with ETW, kill log services
    ScriptExecution     = 10,  ///< PowerShell, WScript, CScript, mshta, cmstp
    WMIActivity         = 11,  ///< WMI event subscriptions, process creation via WMI
    LateralMovement     = 12,  ///< PsExec, WinRM, RDP, SMB named pipe access
    MemoryManipulation  = 13,  ///< VirtualAllocEx, WriteProcessMemory, NtMapViewOfSection
    DLLSideloading      = 14,  ///< DLL search-order hijack, phantom DLL loading
    NamedPipeCreation   = 15,  ///< C2 named pipes, impersonation pipes
    DataExfiltration    = 16,  ///< Large outbound transfers, clipboard monitoring
    CredentialAccess    = 17,  ///< LSASS access, SAM hive read, credential file access
    ProcessExecution    = 18,  ///< General process creation (non-injection)
    Discovery           = 19,  ///< System enumeration, network scanning, AD queries
};

/**
 * @brief Risk assessment level assigned by the detection pipeline.
 *
 * Ordered by severity; rules specify a minimum risk threshold.
 */
enum class RiskLevel : uint8_t {
    Safe     = 0,  ///< Known-good or whitelisted
    Low      = 1,  ///< Informational, unlikely malicious
    Medium   = 2,  ///< Suspicious, warrants logging
    High     = 3,  ///< Likely malicious, warrants blocking
    Critical = 4,  ///< Confirmed malicious or active attack
};

/**
 * @brief Enforcement action to take when a rule matches.
 *
 * Ordered by escalation severity. TerminateProcess (7) is the highest
 * actionable response, fixing the prior bug where QuarantineFile (5)
 * had a higher numeric value than TerminateProcess (4).
 *
 * The rule engine selects the action with the highest numeric value
 * among all matching rules, so ordering is critical for correctness.
 */
enum class BlockAction : uint8_t {
    Allow            = 0,  ///< Permit the operation unconditionally
    LogOnly          = 1,  ///< Permit but record in event history
    AlertOnly        = 2,  ///< Permit but raise alert to callbacks
    BlockOperation   = 3,  ///< Deny the specific I/O operation
    QuarantineFile   = 4,  ///< Move the executable to quarantine vault
    SuspendProcess   = 5,  ///< Freeze all threads in the process
    IsolateNetwork   = 6,  ///< Cut network access for the endpoint
    TerminateProcess = 7,  ///< Kill the process tree immediately
};

/**
 * @brief Lifecycle state of the BehaviorBlocker component.
 *
 * @see The state machine diagram in the file-level documentation.
 */
enum class ComponentState : uint8_t {
    NotInitialized = 0,  ///< Constructed but Initialize() not yet called
    Initializing   = 1,  ///< Initialize() in progress
    Running        = 2,  ///< Start() completed, actively processing events
    Paused         = 3,  ///< Pause() called, events buffered but not analyzed
    Stopping       = 4,  ///< Stop() in progress, draining queues
    Stopped        = 5,  ///< Stop() completed or Initialize() succeeded
    Error          = 6,  ///< Unrecoverable error; Shutdown() required
};

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/**
 * @brief Input event: context about an observed process behavior.
 *
 * Populated by sensors (ProcessCreationMonitor, FileSystemFilter, kernel
 * alerts) and passed to AnalyzeBehavior() for rule evaluation.
 *
 * All path fields use std::wstring for native Windows UTF-16 representation.
 */
struct ProcessBehavior {
    uint32_t processId{0};             ///< Windows PID of the acting process
    uint32_t parentPid{0};             ///< Parent PID for genealogy tracking
    std::wstring processPath;          ///< Full NT or Win32 path to the executable
    std::wstring commandLine;          ///< Full command line (may be spoofed; validated)
    BehaviorType type{BehaviorType::Unknown}; ///< Behavioral category
    std::wstring target;               ///< Context-dependent: file path, IP, reg key, etc.
    RiskLevel risk{RiskLevel::Safe};   ///< Risk level assigned by detection pipeline
    uint32_t sessionId{0};            ///< Windows session ID (for RDP/terminal tracking)
    uint32_t integrityLevel{0};        ///< SECURITY_MANDATORY_LEVEL value
    std::string correlationId;         ///< Links related events in an attack chain
    int64_t timestamp{0};              ///< Event time in epoch milliseconds (Unix)

    /// @brief Serialize to JSON for logging and telemetry.
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Output event: record of an enforcement action taken.
 *
 * Stored in the event history ring buffer and dispatched to registered
 * callbacks. Used for audit trail, telemetry, and UI display.
 */
struct BlockEvent {
    int64_t timestamp{0};              ///< When the action was taken (epoch milliseconds)
    uint32_t processId{0};             ///< PID of the target process
    std::wstring processPath;          ///< Path of the target executable
    BehaviorType behaviorType{BehaviorType::Unknown}; ///< What behavior triggered this
    BlockAction actionTaken{BlockAction::Allow};       ///< What we did about it
    std::string ruleId;                ///< Which rule matched (empty if manual action)
    std::string details;               ///< Human-readable description of the match
    std::string correlationId;         ///< Links to the originating attack chain
    bool actionSucceeded{true};        ///< Whether enforcement actually worked

    /// @brief Serialize to JSON for logging and telemetry.
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Rule definition for matching behaviors to enforcement actions.
 *
 * Rules are evaluated in descending priority order. The highest-action
 * match wins. Rules can be toggled, expired, and mapped to MITRE ATT&CK.
 */
struct BehaviorRule {
    std::string ruleId;                ///< Unique identifier (e.g., "BB-RANSOM-001")
    std::string description;           ///< Human-readable description for audit
    BehaviorType targetType{BehaviorType::Unknown}; ///< Which behavior category to match
    std::string targetPattern;         ///< Regex pattern matched against ProcessBehavior::target
    RiskLevel minRiskLevel{RiskLevel::Low};          ///< Minimum risk to trigger
    BlockAction action{BlockAction::LogOnly};        ///< Action when matched
    int32_t priority{0};               ///< Evaluation order: higher = evaluated first
    bool enabled{true};                ///< Toggle without removing from rule set
    std::optional<int64_t> expiryTimestamp; ///< Auto-expire after this time (epoch ms); nullopt = permanent
    std::string mitreAttackId;         ///< MITRE ATT&CK technique ID (e.g., "T1059.001")
};

/**
 * @brief Exclusion definition to bypass rule evaluation for trusted processes.
 *
 * Exclusions are checked before rules on the hot path. If any exclusion
 * matches, AnalyzeBehavior() returns Allow immediately without rule eval.
 * All pattern fields are optional; omitted fields match everything.
 */
struct BehaviorExclusion {
    std::string exclusionId;           ///< Unique identifier for management
    std::string processPathPattern;    ///< Regex matched against ProcessBehavior::processPath
    std::optional<BehaviorType> behaviorType; ///< If set, only exclude this category
    std::string commandLinePattern;    ///< Regex matched against ProcessBehavior::commandLine
    std::string targetPattern;         ///< Regex matched against ProcessBehavior::target
    std::string description;           ///< Human-readable justification for audit trail
    std::optional<int64_t> expiryTimestamp; ///< Auto-expire (epoch ms); nullopt = permanent
};

/**
 * @brief Configuration for the BehaviorBlocker component.
 *
 * Passed to Initialize(). Immutable after initialization; to change
 * configuration, Shutdown() and re-Initialize() with new config.
 */
struct BehaviorBlockerConfig {
    bool enableBlocking{true};                ///< Master switch for enforcement actions
    bool enableKernelIntegration{true};       ///< Receive events from kernel pipeline
    bool enableTemporalCorrelation{true};     ///< Link events into attack chains
    uint32_t maxRules{1000};                  ///< Maximum rules before AddRule fails
    uint32_t maxExclusions{500};              ///< Maximum exclusions before AddExclusion fails
    uint32_t maxHistoryEvents{10000};         ///< Event history ring buffer capacity
    uint32_t analysisTimeoutMs{5};            ///< p99 budget per AnalyzeBehavior call
    uint32_t regexMaxInputLength{32768};      ///< Cap input length to prevent ReDoS
    uint32_t behaviorChainTimeoutSec{300};    ///< Chain window before auto-expiry (5 min)
    float escalationThreshold{0.7f};          ///< Chain score threshold for auto-escalation

    /// @brief Create a config suitable for development and testing.
    [[nodiscard]] static BehaviorBlockerConfig CreateDefault();

    /// @brief Create a hardened config for production deployment.
    [[nodiscard]] static BehaviorBlockerConfig CreateEnterprise();
};

/**
 * @brief Non-atomic snapshot of BehaviorBlocker runtime statistics.
 *
 * Returned by GetStatistics() as a point-in-time copy. Internal counters
 * are std::atomic in the PIMPL; this struct uses plain types to avoid
 * deleted copy constructors (C2280) and is safe to pass by value.
 *
 * @note Values are eventually consistent: individual fields may reflect
 *       slightly different moments if read under contention.
 */
struct BehaviorBlockerStats {
    uint64_t behaviorsAnalyzed{0};     ///< Total events passed to AnalyzeBehavior
    uint64_t threatsBlocked{0};        ///< Events that resulted in action ≥ BlockOperation
    uint64_t processesTerminated{0};   ///< Successful TerminateProcess calls
    uint64_t processesSuspended{0};    ///< Successful SuspendProcess calls
    uint64_t rulesEvaluated{0};        ///< Total individual rule checks performed
    uint64_t analysisFailures{0};      ///< Regex or evaluation errors
    uint64_t exclusionsMatched{0};     ///< Events bypassed via exclusion match
    uint64_t totalAnalysisTimeUs{0};   ///< Cumulative analysis time in microseconds
    uint64_t kernelEventsReceived{0};  ///< Events ingested from kernel pipeline
    uint64_t behaviorChainsActive{0};  ///< Currently open correlation chains
    uint32_t activeRuleCount{0};       ///< Number of enabled rules loaded
    uint32_t activeExclusionCount{0};  ///< Number of active exclusions
};

// =============================================================================
// FORWARD DECLARATION
// =============================================================================

class BehaviorBlockerImpl;

// =============================================================================
// CLASS: BehaviorBlocker
// =============================================================================

/**
 * @brief Chief behavior blocking orchestrator for ShadowStrike real-time protection.
 *
 * Thread-safe Meyers' Singleton with PIMPL idiom. All mutable state is
 * encapsulated in BehaviorBlockerImpl to preserve ABI stability and keep
 * implementation details (mutexes, atomics, containers) out of the header.
 *
 * Lifecycle is managed by RealTimeProtection:
 *   Initialize(config) → Start() → [AnalyzeBehavior()...] → Stop() → Shutdown()
 *
 * @see BehaviorBlocker.cpp for the full PIMPL implementation.
 */
class BehaviorBlocker final {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance (Meyers' Singleton).
     * @return Reference to the global BehaviorBlocker instance.
     * @note Thread-safe per C++11 §6.7 static local initialization guarantee.
     */
    [[nodiscard]] static BehaviorBlocker& Instance() noexcept;

    // Non-copyable, non-movable
    BehaviorBlocker(const BehaviorBlocker&) = delete;
    BehaviorBlocker& operator=(const BehaviorBlocker&) = delete;
    BehaviorBlocker(BehaviorBlocker&&) = delete;
    BehaviorBlocker& operator=(BehaviorBlocker&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the behavior blocker with the given configuration.
     *
     * Allocates internal structures, compiles default rules, and optionally
     * connects to the kernel pipeline. Must be called before Start().
     * Transitions: NotInitialized → Initializing → Stopped (or Error).
     *
     * @param config Configuration parameters. Defaults to CreateDefault().
     * @return true if initialization succeeded and state is now Stopped.
     */
    [[nodiscard]] bool Initialize(
        const BehaviorBlockerConfig& config = BehaviorBlockerConfig::CreateDefault());

    /**
     * @brief Begin processing behavioral events.
     *
     * Transitions: Stopped → Running. Begins accepting AnalyzeBehavior calls
     * and kernel event ingestion.
     *
     * @return true if the component is now Running.
     */
    [[nodiscard]] bool Start();

    /**
     * @brief Stop processing events and drain pending work.
     *
     * Transitions: Running|Paused → Stopping → Stopped. Blocks until all
     * in-flight AnalyzeBehavior calls complete and pending callbacks are
     * delivered. Rules and exclusions are preserved.
     */
    void Stop();

    /**
     * @brief Temporarily suspend event processing.
     *
     * Transitions: Running → Paused. Events received while paused are
     * discarded (not buffered) to avoid unbounded memory growth.
     */
    void Pause();

    /**
     * @brief Resume event processing after a Pause.
     *
     * Transitions: Paused → Running.
     */
    void Resume();

    /**
     * @brief Release all resources and return to uninitialized state.
     *
     * Transitions: Any → NotInitialized. Calls Stop() if currently Running
     * or Paused. Clears all rules, exclusions, history, and statistics.
     * The component can be re-initialized after Shutdown().
     */
    void Shutdown();

    /**
     * @brief Check whether the component is actively processing events.
     * @return true if current state is Running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Check whether the component is in the Paused state.
     * @return true if current state is Paused.
     */
    [[nodiscard]] bool IsPaused() const noexcept;

    /**
     * @brief Get the current lifecycle state.
     * @return The ComponentState value representing the current state.
     */
    [[nodiscard]] ComponentState GetState() const noexcept;

    // =========================================================================
    // Core Analysis (HOT PATH)
    // =========================================================================

    /**
     * @brief Evaluate a behavioral event against the rule set and enforce.
     *
     * This is the primary hot path called by sensors and the kernel event
     * ingestion thread. It MUST complete within analysisTimeoutMs (default
     * 5ms) for p99 latency. The evaluation order is:
     *   1. Validate input (PID != 0, state == Running)
     *   2. Check blocked PID set (fast-path reject)
     *   3. Check exclusions (fast-path allow)
     *   4. Evaluate rules in priority order
     *   5. Enforce the highest-severity matching action
     *   6. Record event and notify callbacks (async)
     *
     * @param behavior The behavioral event to analyze.
     * @return The enforcement action taken (or Allow if no rule matched).
     */
    [[nodiscard]] BlockAction AnalyzeBehavior(const ProcessBehavior& behavior);

    // =========================================================================
    // Kernel Event Ingestion
    // =========================================================================

    /**
     * @brief Process a raw behavioral alert from the kernel driver.
     *
     * Called by the kernel communication thread when a behavioral alert
     * message is received via FilterGetMessage. Deserializes the payload
     * into a ProcessBehavior and feeds it to AnalyzeBehavior().
     *
     * @param messageType The kernel message type identifier.
     * @param payload Raw bytes from the kernel message buffer.
     */
    void OnKernelBehavioralAlert(uint32_t messageType, std::span<const std::byte> payload);

    // =========================================================================
    // Process Control
    // =========================================================================

    /**
     * @brief Add a process to the blocked set and terminate it.
     *
     * Used for manual blocking from the UI, API, or other modules.
     * The PID is added to the blocked set so all subsequent operations
     * by this process are denied.
     *
     * @param pid Windows process ID to block.
     * @param reason Human-readable justification for audit trail.
     * @return true if the process was successfully blocked and terminated.
     */
    [[nodiscard]] bool BlockProcess(uint32_t pid, const std::wstring& reason);

    /**
     * @brief Terminate a process tree immediately.
     *
     * Refuses to terminate critical system processes (PID 0, 4, csrss, etc.).
     * Uses ProcessUtils::TerminateProcessTree for complete cleanup.
     *
     * @param pid Windows process ID to terminate.
     * @return true if the process was successfully terminated.
     */
    [[nodiscard]] bool TerminateProcess(uint32_t pid);

    /**
     * @brief Suspend all threads in a process.
     *
     * Useful for forensic preservation before termination.
     * Uses NtSuspendProcess via ProcessUtils.
     *
     * @param pid Windows process ID to suspend.
     * @return true if the process was successfully suspended.
     */
    [[nodiscard]] bool SuspendProcess(uint32_t pid);

    /**
     * @brief Check whether a process is in the blocked set.
     * @param pid Windows process ID to check.
     * @return true if the process is currently blocked.
     */
    [[nodiscard]] bool IsBlocked(uint32_t pid) const noexcept;

    // =========================================================================
    // Rule Management
    // =========================================================================

    /**
     * @brief Add a behavior rule to the active rule set.
     *
     * The rule's targetPattern is compiled to a regex at insertion time.
     * If compilation fails, the rule is rejected. Rules are stored in
     * priority-descending order for evaluation efficiency.
     *
     * @param rule The rule to add. ruleId must be unique.
     * @return true if the rule was accepted and compiled successfully.
     */
    [[nodiscard]] bool AddRule(const BehaviorRule& rule);

    /**
     * @brief Remove a rule by its unique identifier.
     * @param ruleId The rule to remove.
     * @return true if the rule existed and was removed.
     */
    [[nodiscard]] bool RemoveRule(const std::string& ruleId);

    /**
     * @brief Enable a previously disabled rule.
     * @param ruleId The rule to enable.
     * @return true if the rule existed and was enabled.
     */
    [[nodiscard]] bool EnableRule(const std::string& ruleId);

    /**
     * @brief Disable a rule without removing it from the set.
     * @param ruleId The rule to disable.
     * @return true if the rule existed and was disabled.
     */
    [[nodiscard]] bool DisableRule(const std::string& ruleId);

    /**
     * @brief Remove all rules from the active set.
     * @return true if the operation completed successfully.
     */
    [[nodiscard]] bool ClearRules();

    /**
     * @brief Load the built-in default rule set.
     *
     * Replaces the current rule set with the compiled-in defaults
     * covering common threat patterns (ransomware, injection, etc.).
     *
     * @return true if default rules were loaded successfully.
     */
    [[nodiscard]] bool LoadDefaultRules();

    /**
     * @brief Load rules from an external JSON file.
     *
     * Parses the file and adds all valid rules. Invalid rules are
     * skipped with a warning log. Does not clear existing rules.
     *
     * @param path Path to the JSON rule definition file.
     * @return true if the file was parsed and at least one rule loaded.
     */
    [[nodiscard]] bool LoadRulesFromFile(const std::filesystem::path& path);

    /**
     * @brief Push the current user-mode rule set to the kernel driver.
     *
     * Serializes enabled rules into a kernel-compatible format and
     * sends them via the minifilter communication port for early
     * kernel-side filtering.
     *
     * @return true if rules were successfully pushed to kernel.
     */
    [[nodiscard]] bool PushRulesToKernel();

    // =========================================================================
    // Exclusion Management
    // =========================================================================

    /**
     * @brief Add a behavior exclusion to the active exclusion set.
     *
     * Pattern fields are compiled to regex at insertion time. If any
     * pattern fails to compile, the exclusion is rejected.
     *
     * @param exclusion The exclusion to add. exclusionId must be unique.
     * @return true if the exclusion was accepted and compiled successfully.
     */
    [[nodiscard]] bool AddExclusion(const BehaviorExclusion& exclusion);

    /**
     * @brief Remove an exclusion by its unique identifier.
     * @param exclusionId The exclusion to remove.
     * @return true if the exclusion existed and was removed.
     */
    [[nodiscard]] bool RemoveExclusion(const std::string& exclusionId);

    // =========================================================================
    // Callback Registration
    // =========================================================================

    /// @brief Callback type invoked when an enforcement action is taken.
    using BlockEventCallback = std::function<void(const BlockEvent&)>;

    /**
     * @brief Register a callback for block event notifications.
     *
     * Callbacks are invoked asynchronously after enforcement, outside
     * of any internal lock. Registration is thread-safe.
     *
     * @param callback The function to invoke on each block event.
     * @return A unique callback ID for later unregistration.
     */
    [[nodiscard]] uint64_t RegisterBlockCallback(BlockEventCallback callback);

    /**
     * @brief Unregister a previously registered callback.
     * @param callbackId The ID returned by RegisterBlockCallback.
     */
    void UnregisterBlockCallback(uint64_t callbackId);

    // =========================================================================
    // Monitoring & Statistics
    // =========================================================================

    /**
     * @brief Retrieve recent enforcement events from the history ring buffer.
     *
     * Returns a thread-safe copy of the most recent events, ordered
     * newest-first. The ring buffer capacity is set by maxHistoryEvents.
     *
     * @param limit Maximum number of events to return (default 100).
     * @return Vector of recent BlockEvent records.
     */
    [[nodiscard]] std::vector<BlockEvent> GetRecentEvents(size_t limit = 100) const;

    /**
     * @brief Get a point-in-time snapshot of runtime statistics.
     * @return BehaviorBlockerStats with current counter values.
     */
    [[nodiscard]] BehaviorBlockerStats GetStatistics() const noexcept;

    /**
     * @brief Get runtime statistics serialized as a JSON string.
     * @return JSON object string with all statistic fields.
     */
    [[nodiscard]] std::string GetStatisticsJson() const;

    // =========================================================================
    // Diagnostics
    // =========================================================================

    /**
     * @brief Run a self-test to verify module integrity.
     *
     * Exercises the rule engine, exclusion engine, and enforcement
     * paths with synthetic events. Logs results and returns overall
     * pass/fail status. Intended for startup validation and health
     * checks.
     *
     * @return true if all diagnostic checks passed.
     */
    [[nodiscard]] bool SelfTest();

private:
    BehaviorBlocker();
    ~BehaviorBlocker();

    /// @brief PIMPL: all mutable state lives here for ABI stability.
    std::unique_ptr<BehaviorBlockerImpl> m_impl;
};

} // namespace ShadowStrike::RealTime

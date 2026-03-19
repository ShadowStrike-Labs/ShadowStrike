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
 * ShadowStrike Core Process - PROCESS MONITOR (The Census Taker)
 * ============================================================================
 *
 * @file ProcessMonitor.hpp
 * @brief Enterprise-grade real-time process lifecycle tracking system.
 *
 * This module is the single source of truth for "who is running" on the system.
 * It maintains a live, consistent view of all processes with their full metadata,
 * ancestry relationships, and security contexts. Built for extreme scalability
 * to handle systems with thousands of concurrent processes and rapid turnover.
 *
 * ============================================================================
 * ENTERPRISE CAPABILITIES
 * ============================================================================
 *
 * 1. PROCESS CACHE SYSTEM
 *    - O(1) hash-based lookup for PIDs
 *    - O(log n) range queries for path-based lookups
 *    - Cache-line aligned storage for maximum performance
 *    - Lock-free reads for common paths
 *    - Automatic cache eviction with configurable TTL
 *    - Memory-efficient storage with deduplication
 *
 * 2. ANCESTRY TRACKING
 *    - Full parent-child relationship graphs
 *    - Process tree reconstruction
 *    - Orphan process detection
 *    - PPID spoofing detection
 *    - Cross-session spawn tracking
 *    - Real-time tree updates
 *
 * 3. EVENT INGESTION
 *    - Kernel callback integration (PsSetCreateProcessNotifyRoutine)
 *    - ETW (Event Tracing for Windows) provider
 *    - Filter Manager minifilter notifications
 *    - WMI event subscription fallback
 *    - Atomic cache updates with versioning
 *    - Event ordering guarantees
 *
 * 4. PID REUSE HANDLING
 *    - Process start time tracking (FILETIME)
 *    - Unique process identification (PID + StartTime)
 *    - Stale reference detection
 *    - Race condition mitigation
 *    - Historical PID lookup
 *
 * 5. SECURITY CONTEXT TRACKING
 *    - Token information (SID, integrity, privileges)
 *    - Session isolation verification
 *    - User account tracking
 *    - Protected process status
 *    - Elevation status
 *
 * 6. PERFORMANCE OPTIMIZATIONS
 *    - Reader-writer locks for massive concurrent reads
 *    - Batched event processing
 *    - Lazy metadata resolution
 *    - Differential updates
 *    - Memory pooling
 *
 * ============================================================================
 * INTEGRATION ARCHITECTURE
 * ============================================================================
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                           ProcessMonitor                                │
 * │                    (Single Source of Process Truth)                     │
 * └───────────────┬──────────────────┬──────────────────┬──────────────────┘
 *                 │                  │                  │
 *     ┌───────────┴──────┐  ┌───────┴───────┐  ┌──────┴────────┐
 *     ▼                  ▼  ▼               ▼  ▼              ▼
 * ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
 * │   Kernel   │  │    ETW     │  │   Filter   │  │    WMI     │
 * │  Callback  │  │  Provider  │  │  Manager   │  │  Events    │
 * └────────────┘  └────────────┘  └────────────┘  └────────────┘
 *                 │
 *     ┌───────────┼───────────────────────────────────┐
 *     ▼           ▼                                   ▼
 * ┌────────────────────┐  ┌────────────────┐  ┌──────────────────┐
 * │   ProcessUtils     │  │   Whitelist    │  │   ThreatIntel    │
 * │   (Enumeration)    │  │    Store       │  │    Manager       │
 * └────────────────────┘  └────────────────┘  └──────────────────┘
 *
 * ============================================================================
 * CONSUMERS
 * ============================================================================
 *
 * - ThreatDetector: Subscribes to process events for real-time analysis
 * - BehaviorAnalyzer: Uses ancestry for behavioral context
 * - ProcessAnalyzer: Queries cache for on-demand inspection
 * - QuarantineManager: Looks up process info for quarantine operations
 * - ScanEngine: Gets process paths for scheduled scans
 * - All RealTime modules: ProcessCreationMonitor, MemoryProtection, etc.
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
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/ErrorUtils.hpp"
#include "../../Whitelist/WhitelistStore.hpp"
#include "../../ThreatIntel/ThreatIntelManager.hpp"

// Standard library
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <thread>
#include <queue>
#include <span>
#include <array>
#include <bitset>
#include <cstdint>

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ProcessMonitorImpl;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace MonitorConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 4;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Cache limits
    constexpr size_t MAX_CACHED_PROCESSES = 65536;
    constexpr size_t MAX_CACHED_TERMINATED = 16384;
    constexpr size_t MAX_ANCESTRY_DEPTH = 64;
    constexpr size_t MAX_CHILDREN_PER_PROCESS = 4096;
    constexpr size_t MAX_HISTORICAL_ENTRIES = 32768;

    // Event processing
    constexpr size_t EVENT_QUEUE_SIZE = 16384;
    constexpr uint32_t EVENT_BATCH_SIZE = 256;
    constexpr uint32_t EVENT_PROCESS_INTERVAL_MS = 10;
    constexpr uint32_t MAX_EVENT_LAG_MS = 1000;

    // Timeouts and intervals
    constexpr uint32_t SNAPSHOT_INTERVAL_MS = 60000;          ///< Full refresh interval
    constexpr uint32_t DEAD_PROCESS_CLEANUP_INTERVAL_MS = 30000;
    constexpr uint32_t METADATA_REFRESH_INTERVAL_MS = 300000;
    constexpr uint32_t STARTUP_SCAN_TIMEOUT_MS = 30000;
    constexpr uint32_t PROCESS_INFO_CACHE_TTL_MS = 5000;

    // PID reuse protection
    constexpr uint32_t PID_REUSE_WINDOW_MS = 60000;           ///< Time before PID can be considered reused
    constexpr uint64_t INVALID_START_TIME = 0;

    // String deduplication pool
    constexpr size_t STRING_POOL_SIZE = 1024 * 1024;          ///< 1MB string pool
    constexpr size_t MAX_UNIQUE_PATHS = 32768;
    constexpr size_t MAX_UNIQUE_NAMES = 8192;

    // Performance thresholds
    constexpr uint32_t HIGH_TURNOVER_THRESHOLD = 100;         ///< Processes/second
    constexpr uint32_t LOOKUP_LATENCY_WARNING_US = 100;       ///< Microseconds

    // Callback limits
    constexpr size_t MAX_CALLBACKS = 256;

} // namespace MonitorConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ProcessState
 * @brief Current state of a monitored process.
 */
enum class ProcessState : uint8_t {
    Unknown = 0,
    Starting = 1,         ///< Create notification received, not yet fully initialized
    Running = 2,          ///< Active and running
    Suspended = 3,        ///< All threads suspended
    Terminating = 4,      ///< Exit initiated, not yet complete
    Terminated = 5,       ///< Process has exited
    Zombie = 6            ///< Terminated but handle still open somewhere
};

/**
 * @enum ProcessEventType
 * @brief Types of process lifecycle events.
 */
enum class ProcessEventType : uint8_t {
    Unknown = 0,
    Created = 1,              ///< New process created
    Started = 2,              ///< Process initialization complete
    Terminated = 3,           ///< Process exited
    Suspended = 4,            ///< Process suspended
    Resumed = 5,              ///< Process resumed
    ImageLoaded = 6,          ///< Main image loaded
    ModuleLoaded = 7,         ///< Additional module loaded
    ModuleUnloaded = 8,       ///< Module unloaded
    PrivilegeChanged = 9,     ///< Token privileges changed
    TokenChanged = 10,        ///< Token replaced/modified
    IntegrityChanged = 11,    ///< Integrity level changed
    SessionChanged = 12,      ///< Session change
    NameChanged = 13          ///< Process name changed (rare, via debug APIs)
};

/**
 * @enum EventSource
 * @brief Source of process events.
 */
enum class EventSource : uint8_t {
    Unknown = 0,
    KernelCallback = 1,       ///< PsSetCreateProcessNotifyRoutine
    ETWProvider = 2,          ///< Microsoft-Windows-Kernel-Process
    FilterManager = 3,        ///< Minifilter callback
    WMI = 4,                  ///< Win32_ProcessStartTrace
    Snapshot = 5,             ///< Periodic snapshot discovery
    Manual = 6,               ///< API call (GetProcessInfo)
    APIHook = 7               ///< User-mode API hooking
};

/**
 * @enum ProcessCreationMethod
 * @brief How the process was created.
 */
enum class ProcessCreationMethod : uint8_t {
    Unknown = 0,
    NtCreateProcess = 1,
    NtCreateProcessEx = 2,
    NtCreateUserProcess = 3,
    CreateProcessInternal = 4,
    ShellExecute = 5,
    WMI = 6,
    DCOM = 7,
    ScheduledTask = 8,
    ServiceControlManager = 9,
    RemoteProcedureCall = 10,
    PSExec = 11,
    WinRM = 12,
    PowerShell = 13,
    COMObject = 14
};

/**
 * @enum ProcessCategory
 * @brief Categorization of process type.
 */
enum class ProcessCategory : uint8_t {
    Unknown = 0,
    SystemCritical = 1,       ///< Cannot be terminated (csrss, smss, etc.)
    SystemCore = 2,           ///< Core Windows processes
    SystemService = 3,        ///< Windows services
    SecuritySoftware = 4,     ///< AV/EDR/Firewall
    UserApplication = 5,      ///< Standard user app
    Browser = 6,
    Office = 7,
    ScriptHost = 8,           ///< powershell, cscript, python
    SystemUtility = 9,        ///< cmd, certutil, bitsadmin
    LOLBin = 10,              ///< Living-off-the-land binary
    Installer = 11,
    Game = 12,
    Media = 13,
    Developer = 14,
    Network = 15,
    Suspicious = 16,
    Malicious = 17
};

/**
 * @enum CacheUpdatePolicy
 * @brief Policy for cache updates.
 */
enum class CacheUpdatePolicy : uint8_t {
    Immediate = 0,            ///< Update cache immediately
    Batched = 1,              ///< Batch updates
    Lazy = 2                  ///< Update on next access
};

/**
 * @enum LookupResult
 * @brief Result of a cache lookup operation.
 */
enum class LookupResult : uint8_t {
    Found = 0,                ///< Entry found in cache
    NotFound = 1,             ///< Entry not in cache
    Stale = 2,                ///< Entry found but stale (PID reused)
    Expired = 3,              ///< Entry TTL expired
    FetchedLive = 4,          ///< Not in cache, fetched from system
    Error = 5                 ///< Lookup failed
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct ProcessUniqueId
 * @brief Unique identifier for a process (handles PID reuse).
 */
struct ProcessUniqueId {
    uint32_t pid = 0;
    uint64_t startTime = 0;               ///< FILETIME when process started

    bool operator==(const ProcessUniqueId& other) const noexcept {
        return pid == other.pid && startTime == other.startTime;
    }

    bool operator<(const ProcessUniqueId& other) const noexcept {
        return (pid < other.pid) || (pid == other.pid && startTime < other.startTime);
    }

    /**
     * @brief Check if this ID matches a PID (ignoring start time).
     */
    [[nodiscard]] bool MatchesPid(uint32_t targetPid) const noexcept {
        return pid == targetPid;
    }

    /**
     * @brief Generate hash for use in hash maps.
     */
    [[nodiscard]] size_t Hash() const noexcept {
        return std::hash<uint64_t>{}(
            (static_cast<uint64_t>(pid) << 32) | (startTime & 0xFFFFFFFF)
        );
    }
};

/**
 * @struct ProcessUniqueIdHash
 * @brief Hash functor for ProcessUniqueId.
 */
struct ProcessUniqueIdHash {
    size_t operator()(const ProcessUniqueId& id) const noexcept {
        return id.Hash();
    }
};

/**
 * @struct ExtendedProcessInfo
 * @brief Comprehensive process information stored in cache.
 */
struct alignas(64) ExtendedProcessInfo {
    // ========================================================================
    // IDENTIFICATION
    // ========================================================================

    ProcessUniqueId uniqueId;
    std::wstring processName;                 ///< Just the executable name
    std::wstring processPath;                 ///< Full path to executable
    std::wstring commandLine;                 ///< Full command line
    std::wstring workingDirectory;            ///< Initial working directory

    // ========================================================================
    // ANCESTRY
    // ========================================================================

    uint32_t parentPid = 0;
    uint64_t parentStartTime = 0;             ///< For parent unique ID
    uint32_t creatorPid = 0;                  ///< May differ from parent
    uint32_t sessionId = 0;
    std::vector<uint32_t> childPids;          ///< Direct children

    // ========================================================================
    // SECURITY CONTEXT
    // ========================================================================

    std::wstring userName;
    std::wstring domainName;
    std::wstring sidString;
    uint32_t integrityLevel = 0;              ///< SECURITY_MANDATORY_*
    bool isElevated = false;
    bool isProtectedProcess = false;
    bool isProtectedProcessLight = false;
    bool isAppContainer = false;
    bool isWow64 = false;                     ///< 32-bit on 64-bit Windows

    // ========================================================================
    // TIMESTAMPS
    // ========================================================================

    std::chrono::system_clock::time_point createTime;
    std::chrono::system_clock::time_point exitTime;
    std::chrono::system_clock::time_point lastSeenTime;
    std::chrono::system_clock::time_point lastUpdateTime;

    // ========================================================================
    // STATE
    // ========================================================================

    ProcessState state = ProcessState::Unknown;
    uint32_t exitCode = 0;
    bool isTerminated = false;

    // ========================================================================
    // CLASSIFICATION
    // ========================================================================

    ProcessCategory category = ProcessCategory::Unknown;
    bool isSystemProcess = false;
    bool isCriticalProcess = false;
    bool isWhitelisted = false;
    bool isLOLBin = false;

    // ========================================================================
    // CREATION CONTEXT
    // ========================================================================

    ProcessCreationMethod creationMethod = ProcessCreationMethod::Unknown;
    EventSource discoverySource = EventSource::Unknown;

    // ========================================================================
    // HASHES (for quick lookup)
    // ========================================================================

    std::array<uint8_t, 32> imageSha256{};
    bool hashComputed = false;

    // ========================================================================
    // CACHE METADATA
    // ========================================================================

    uint64_t cacheVersion = 0;                ///< For change detection
    bool metadataComplete = false;            ///< Full info fetched

    // ========================================================================
    // METHODS
    // ========================================================================

    /**
     * @brief Convert to basic ProcessInfo (Utils structure).
     */
    [[nodiscard]] Utils::ProcessUtils::ProcessInfo ToProcessInfo() const;

    /**
     * @brief Convert to ProcessBasicInfo (Utils structure).
     */
    [[nodiscard]] Utils::ProcessUtils::ProcessBasicInfo ToBasicInfo() const;

    /**
     * @brief Check if process is still valid (not reused PID).
     */
    [[nodiscard]] bool IsValid() const noexcept {
        return uniqueId.startTime != MonitorConstants::INVALID_START_TIME;
    }

    /**
     * @brief Check if cache entry is stale.
     */
    [[nodiscard]] bool IsStale(std::chrono::milliseconds maxAge) const noexcept;
};

/**
 * @struct ProcessEvent
 * @brief Event representing a process lifecycle change.
 */
struct ProcessEvent {
    ProcessEventType type = ProcessEventType::Unknown;
    EventSource source = EventSource::Unknown;
    ProcessUniqueId processId;
    ProcessUniqueId parentId;

    // Event-specific data
    std::wstring processName;
    std::wstring processPath;
    std::wstring commandLine;
    std::wstring userName;
    uint32_t sessionId = 0;
    uint32_t exitCode = 0;

    // For module events
    std::wstring modulePath;
    uintptr_t moduleBase = 0;
    size_t moduleSize = 0;

    // Timestamp
    std::chrono::system_clock::time_point timestamp;
    uint64_t sequenceNumber = 0;             ///< For ordering

    // Flags
    bool isElevated = false;
    bool isWow64 = false;
};

/**
 * @struct ProcessTreeNode
 * @brief Node in the process tree structure.
 */
struct ProcessTreeNode {
    ProcessUniqueId processId;
    std::wstring processName;
    std::wstring processPath;
    ProcessState state = ProcessState::Unknown;
    std::chrono::system_clock::time_point createTime;

    ProcessTreeNode* parent = nullptr;
    std::vector<std::unique_ptr<ProcessTreeNode>> children;

    uint32_t depth = 0;                      ///< Depth in tree
};

/**
 * @struct ProcessSnapshot
 * @brief Point-in-time snapshot of all processes.
 */
struct ProcessSnapshot {
    std::chrono::system_clock::time_point timestamp;
    uint32_t processCount = 0;
    std::vector<ExtendedProcessInfo> processes;
    uint64_t snapshotVersion = 0;
};

/**
 * @struct AncestryChain
 * @brief Complete ancestry information for a process.
 */
struct AncestryChain {
    ProcessUniqueId targetProcess;
    std::vector<ExtendedProcessInfo> ancestors;     ///< From target up to root
    std::vector<std::wstring> ancestorNames;        ///< Quick access to names
    uint32_t depth = 0;
    bool isComplete = false;                         ///< Reached system root
    bool hasOrphan = false;                          ///< Missing parent in chain
    uint32_t orphanAtDepth = 0;                      ///< Where chain breaks
};

/**
 * @struct ProcessTreeStatistics
 * @brief Statistics about the process tree.
 */
struct ProcessTreeStatistics {
    uint32_t totalProcesses = 0;
    uint32_t runningProcesses = 0;
    uint32_t suspendedProcesses = 0;
    uint32_t systemProcesses = 0;
    uint32_t userProcesses = 0;
    uint32_t elevatedProcesses = 0;
    uint32_t protectedProcesses = 0;
    uint32_t wow64Processes = 0;
    uint32_t orphanProcesses = 0;
    uint32_t maxTreeDepth = 0;
    std::unordered_map<ProcessCategory, uint32_t> countByCategory;
    std::unordered_map<uint32_t, uint32_t> countBySession;
};

/**
 * @struct MonitorConfig
 * @brief Configuration for the process monitor.
 */
struct MonitorConfig {
    // Event sources
    bool useKernelCallback = true;
    bool useETWProvider = true;
    bool useFilterManager = true;
    bool useWMI = false;                          ///< Fallback only
    bool useAPIHooks = false;                     ///< User-mode hooks

    // Cache settings
    size_t maxCachedProcesses = MonitorConstants::MAX_CACHED_PROCESSES;
    size_t maxCachedTerminated = MonitorConstants::MAX_CACHED_TERMINATED;
    uint32_t cacheEntryTTLMs = MonitorConstants::PROCESS_INFO_CACHE_TTL_MS;
    CacheUpdatePolicy updatePolicy = CacheUpdatePolicy::Immediate;

    // Event processing
    size_t eventQueueSize = MonitorConstants::EVENT_QUEUE_SIZE;
    uint32_t eventBatchSize = MonitorConstants::EVENT_BATCH_SIZE;
    uint32_t eventProcessIntervalMs = MonitorConstants::EVENT_PROCESS_INTERVAL_MS;

    // Snapshot settings
    bool enablePeriodicSnapshots = true;
    uint32_t snapshotIntervalMs = MonitorConstants::SNAPSHOT_INTERVAL_MS;
    bool enableHistoricalTracking = true;
    size_t maxHistoricalEntries = MonitorConstants::MAX_HISTORICAL_ENTRIES;

    // Metadata collection
    bool collectCommandLine = true;
    bool collectWorkingDirectory = true;
    bool collectUserInfo = true;
    bool collectIntegrity = true;
    bool computeImageHash = false;                ///< Expensive, disabled by default
    bool lazyMetadataFetch = true;                ///< Fetch on demand

    // Ancestry
    bool trackAncestry = true;
    uint32_t maxAncestryDepth = MonitorConstants::MAX_ANCESTRY_DEPTH;
    bool detectPPIDSpoofing = true;

    // Cleanup
    uint32_t deadProcessCleanupIntervalMs = MonitorConstants::DEAD_PROCESS_CLEANUP_INTERVAL_MS;
    uint32_t terminatedProcessRetentionMs = 60000;  ///< How long to keep terminated

    // Integration
    bool enableWhitelistIntegration = true;
    bool enableThreatIntelIntegration = true;

    // Callbacks
    bool enableEventCallbacks = true;

    // Performance
    uint32_t maxConcurrentLookups = 16;

    /**
     * @brief Create default configuration.
     */
    static MonitorConfig CreateDefault() noexcept;

    /**
     * @brief Create minimal configuration for low-resource systems.
     */
    static MonitorConfig CreateMinimal() noexcept;

    /**
     * @brief Create comprehensive configuration for forensic use.
     */
    static MonitorConfig CreateForensic() noexcept;
};

/**
 * @struct MonitorStatistics
 * @brief Runtime statistics for the process monitor.
 */
struct alignas(64) MonitorStatistics {
    // Process tracking
    std::atomic<uint64_t> totalProcessesTracked{0};
    std::atomic<uint64_t> currentActiveProcesses{0};
    std::atomic<uint64_t> processCreations{0};
    std::atomic<uint64_t> processTerminations{0};
    std::atomic<uint64_t> processesDiscoveredBySnapshot{0};

    // Event processing
    std::atomic<uint64_t> eventsReceived{0};
    std::atomic<uint64_t> eventsProcessed{0};
    std::atomic<uint64_t> eventsDropped{0};
    std::atomic<uint64_t> eventQueueHighWatermark{0};

    // Cache performance
    std::atomic<uint64_t> cacheLookups{0};
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};
    std::atomic<uint64_t> cacheFetchedLive{0};
    std::atomic<uint64_t> cacheEvictions{0};
    std::atomic<uint64_t> staleEntryDetections{0};

    // Lookup performance (microseconds)
    std::atomic<uint64_t> totalLookupTimeUs{0};
    std::atomic<uint64_t> minLookupTimeUs{UINT64_MAX};
    std::atomic<uint64_t> maxLookupTimeUs{0};

    // Ancestry tracking
    std::atomic<uint64_t> ancestryLookups{0};
    std::atomic<uint64_t> orphanProcessesDetected{0};
    std::atomic<uint64_t> ppidSpoofingDetected{0};

    // Errors
    std::atomic<uint64_t> lookupErrors{0};
    std::atomic<uint64_t> accessDeniedErrors{0};
    std::atomic<uint64_t> eventProcessingErrors{0};

    // Callbacks
    std::atomic<uint64_t> callbacksInvoked{0};
    std::atomic<uint64_t> callbackErrors{0};

    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept;

    /**
     * @brief Get cache hit ratio.
     */
    [[nodiscard]] double GetCacheHitRatio() const noexcept;

    /**
     * @brief Get average lookup time in microseconds.
     */
    [[nodiscard]] double GetAverageLookupTimeUs() const noexcept;

    /**
     * @brief Get events per second (recent).
     */
    [[nodiscard]] double GetEventsPerSecond() const noexcept;
};

// ============================================================================
// CALLBACK DEFINITIONS
// ============================================================================

/**
 * @brief Callback for process create/terminate events.
 * @param info Process information
 * @param created True if created, false if terminated
 */
using ProcessCallback = std::function<void(
    const ExtendedProcessInfo& info,
    bool created
)>;

/**
 * @brief Callback for detailed process events.
 * @param event The process event
 */
using ProcessEventCallback = std::function<void(
    const ProcessEvent& event
)>;

/**
 * @brief Callback for suspicious activity detection.
 * @param processId Process unique ID
 * @param description Description of suspicious activity
 */
using SuspiciousActivityCallback = std::function<void(
    const ProcessUniqueId& processId,
    const std::wstring& description
)>;

/**
 * @brief Callback for ancestry anomaly detection.
 * @param processId Child process
 * @param parentId Claimed parent
 * @param anomalyType Description of anomaly
 */
using AncestryAnomalyCallback = std::function<void(
    const ProcessUniqueId& processId,
    const ProcessUniqueId& parentId,
    const std::wstring& anomalyType
)>;

// ============================================================================
// PROCESS MONITOR CLASS
// ============================================================================

/**
 * @class ProcessMonitor
 * @brief Enterprise-grade process lifecycle monitoring system.
 *
 * Thread-safety: All public methods are thread-safe.
 * Pattern: Singleton with PIMPL for ABI stability.
 *
 * Usage:
 * @code
 * auto& monitor = ProcessMonitor::Instance();
 * 
 * // Initialize
 * auto config = MonitorConfig::CreateDefault();
 * monitor.Initialize(config);
 * 
 * // Register callbacks
 * monitor.RegisterCallback([](const ExtendedProcessInfo& info, bool created) {
 *     if (created) {
 *         std::wcout << L"New process: " << info.processName << std::endl;
 *     }
 * });
 * 
 * // Query processes
 * auto procInfo = monitor.GetProcessInfo(targetPid);
 * if (procInfo) {
 *     // Use process info...
 * }
 * @endcode
 */
class ProcessMonitor {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance.
     * @return Reference to the singleton instance.
     */
    [[nodiscard]] static ProcessMonitor& Instance();

    /**
     * @brief Delete copy constructor.
     */
    ProcessMonitor(const ProcessMonitor&) = delete;

    /**
     * @brief Delete copy assignment.
     */
    ProcessMonitor& operator=(const ProcessMonitor&) = delete;

    /**
     * @brief Delete move constructor.
     */
    ProcessMonitor(ProcessMonitor&&) = delete;

    /**
     * @brief Delete move assignment.
     */
    ProcessMonitor& operator=(ProcessMonitor&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize the monitor and populate initial snapshot.
     * @param config Configuration settings.
     * @return True on success.
     */
    [[nodiscard]] bool Initialize(const MonitorConfig& config = MonitorConfig::CreateDefault());

    /**
     * @brief Shutdown the monitor and release resources.
     */
    void Shutdown();

    /**
     * @brief Check if monitor is initialized.
     * @return True if initialized and running.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Update configuration (hot reload).
     * @param config New configuration.
     * @return True if configuration was applied.
     */
    bool UpdateConfig(const MonitorConfig& config);

    /**
     * @brief Get current configuration.
     * @return Current configuration.
     */
    [[nodiscard]] MonitorConfig GetConfig() const;

    // ========================================================================
    // PROCESS LOOKUP
    // ========================================================================

    /**
     * @brief Get detailed info for a process.
     * @param pid Process ID.
     * @return Process info if found, nullopt otherwise.
     *
     * Thread-safe with O(1) average lookup from cache.
     * If not in cache, attempts to fetch live from system.
     */
    [[nodiscard]] std::optional<ExtendedProcessInfo> GetProcessInfo(uint32_t pid) const;

    /**
     * @brief Get detailed info for a process with explicit start time.
     * @param uniqueId Unique process identifier (PID + start time).
     * @return Process info if found.
     *
     * This handles PID reuse correctly by matching start time.
     */
    [[nodiscard]] std::optional<ExtendedProcessInfo> GetProcessInfo(
        const ProcessUniqueId& uniqueId
    ) const;

    /**
     * @brief Get basic info for a process (faster).
     * @param pid Process ID.
     * @return Basic info if found.
     */
    [[nodiscard]] std::optional<Utils::ProcessUtils::ProcessBasicInfo> GetBasicInfo(
        uint32_t pid
    ) const;

    /**
     * @brief Get processes by name.
     * @param processName Process name (case-insensitive).
     * @return Vector of matching processes.
     */
    [[nodiscard]] std::vector<ExtendedProcessInfo> GetProcessesByName(
        const std::wstring& processName
    ) const;

    /**
     * @brief Get processes by path.
     * @param processPath Full path to executable.
     * @return Vector of matching processes.
     */
    [[nodiscard]] std::vector<ExtendedProcessInfo> GetProcessesByPath(
        const std::wstring& processPath
    ) const;

    /**
     * @brief Get processes by user.
     * @param userName User name.
     * @param domainName Domain name (optional).
     * @return Vector of matching processes.
     */
    [[nodiscard]] std::vector<ExtendedProcessInfo> GetProcessesByUser(
        const std::wstring& userName,
        const std::wstring& domainName = L""
    ) const;

    /**
     * @brief Get processes by session.
     * @param sessionId Session ID.
     * @return Vector of processes in session.
     */
    [[nodiscard]] std::vector<ExtendedProcessInfo> GetProcessesBySession(
        uint32_t sessionId
    ) const;

    /**
     * @brief Get processes by category.
     * @param category Process category.
     * @return Vector of matching processes.
     */
    [[nodiscard]] std::vector<ExtendedProcessInfo> GetProcessesByCategory(
        ProcessCategory category
    ) const;

    /**
     * @brief Get all currently tracked processes.
     * @return Vector of all process info.
     */
    [[nodiscard]] std::vector<ExtendedProcessInfo> GetAllProcesses() const;

    /**
     * @brief Check if a process is currently running.
     * @param pid Process ID.
     * @return True if running.
     *
     * Validates against start time to avoid PID reuse confusion.
     */
    [[nodiscard]] bool IsProcessAlive(uint32_t pid) const;

    /**
     * @brief Check if a specific process instance is still running.
     * @param uniqueId Process unique identifier.
     * @return True if still running.
     */
    [[nodiscard]] bool IsProcessAlive(const ProcessUniqueId& uniqueId) const;

    /**
     * @brief Resolve a PID to its executable path.
     * @param pid Process ID.
     * @return Process path, or empty string if not found.
     */
    [[nodiscard]] std::wstring GetProcessPath(uint32_t pid) const;

    /**
     * @brief Get process command line.
     * @param pid Process ID.
     * @return Command line, or empty string if not found.
     */
    [[nodiscard]] std::wstring GetCommandLine(uint32_t pid) const;

    // ========================================================================
    // ANCESTRY OPERATIONS
    // ========================================================================

    /**
     * @brief Get full process ancestry chain.
     * @param pid Process ID.
     * @param maxDepth Maximum ancestry depth.
     * @return Ancestry chain information.
     */
    [[nodiscard]] AncestryChain GetAncestry(
        uint32_t pid,
        uint32_t maxDepth = MonitorConstants::MAX_ANCESTRY_DEPTH
    ) const;

    /**
     * @brief Get parent process info.
     * @param pid Process ID.
     * @return Parent process info if available.
     */
    [[nodiscard]] std::optional<ExtendedProcessInfo> GetParent(uint32_t pid) const;

    /**
     * @brief Get direct children of a process.
     * @param pid Process ID.
     * @return Vector of child process info.
     */
    [[nodiscard]] std::vector<ExtendedProcessInfo> GetChildren(uint32_t pid) const;

    /**
     * @brief Get all descendants of a process (recursive).
     * @param pid Process ID.
     * @param maxDepth Maximum depth.
     * @return Vector of all descendant processes.
     */
    [[nodiscard]] std::vector<ExtendedProcessInfo> GetDescendants(
        uint32_t pid,
        uint32_t maxDepth = MonitorConstants::MAX_ANCESTRY_DEPTH
    ) const;

    /**
     * @brief Get process tree starting from a root PID.
     * @param rootPid Root process ID (0 for full system tree).
     * @return Root node of the process tree.
     */
    [[nodiscard]] std::unique_ptr<ProcessTreeNode> GetProcessTree(
        uint32_t rootPid = 0
    ) const;

    /**
     * @brief Check if one process is an ancestor of another.
     * @param ancestorPid Potential ancestor.
     * @param descendantPid Potential descendant.
     * @return True if ancestor relationship exists.
     */
    [[nodiscard]] bool IsAncestorOf(uint32_t ancestorPid, uint32_t descendantPid) const;

    /**
     * @brief Validate parent-child relationship.
     * @param childPid Child process ID.
     * @return True if parent is valid/expected.
     */
    [[nodiscard]] bool ValidateParent(uint32_t childPid) const;

    /**
     * @brief Detect PPID spoofing.
     * @param pid Process ID.
     * @return True if PPID spoofing is detected.
     */
    [[nodiscard]] bool DetectPPIDSpoofing(uint32_t pid) const;

    // ========================================================================
    // EVENT INGESTION (from kernel/ETW)
    // ========================================================================

    /**
     * @brief Notify monitor of a new process creation.
     * @param event Process event data.
     *
     * Called by kernel callback handler or ETW consumer.
     */
    void OnProcessCreate(const ProcessEvent& event);

    /**
     * @brief Notify monitor of process termination.
     * @param pid Process ID.
     * @param exitCode Exit code.
     */
    void OnProcessTerminate(uint32_t pid, uint32_t exitCode = 0);

    /**
     * @brief Notify monitor of process termination with full event.
     * @param event Process event data.
     */
    void OnProcessTerminate(const ProcessEvent& event);

    /**
     * @brief Notify monitor of module load.
     * @param pid Process ID.
     * @param modulePath Module path.
     * @param moduleBase Base address.
     * @param moduleSize Size.
     */
    void OnModuleLoad(
        uint32_t pid,
        const std::wstring& modulePath,
        uintptr_t moduleBase,
        size_t moduleSize
    );

    /**
     * @brief Batch submit multiple events.
     * @param events Vector of process events.
     */
    void SubmitEvents(std::vector<ProcessEvent> events);

    // ========================================================================
    // SNAPSHOT OPERATIONS
    // ========================================================================

    /**
     * @brief Force a full system process snapshot.
     * @return True if snapshot succeeded.
     */
    bool RefreshSnapshot();

    /**
     * @brief Get a point-in-time snapshot of all processes.
     * @return Process snapshot.
     */
    [[nodiscard]] ProcessSnapshot TakeSnapshot() const;

    /**
     * @brief Compare current state with a previous snapshot.
     * @param previousSnapshot Previous snapshot.
     * @return Processes created and terminated since snapshot.
     */
    [[nodiscard]] std::pair<std::vector<ExtendedProcessInfo>, std::vector<ExtendedProcessInfo>>
    CompareSnapshots(const ProcessSnapshot& previousSnapshot) const;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Register callback for process create/terminate events.
     * @param callback Callback function.
     * @return Callback ID for unregistration.
     */
    uint64_t RegisterCallback(ProcessCallback callback);

    /**
     * @brief Register callback for detailed process events.
     * @param callback Callback function.
     * @return Callback ID for unregistration.
     */
    uint64_t RegisterEventCallback(ProcessEventCallback callback);

    /**
     * @brief Register callback for suspicious activity.
     * @param callback Callback function.
     * @return Callback ID for unregistration.
     */
    uint64_t RegisterSuspiciousCallback(SuspiciousActivityCallback callback);

    /**
     * @brief Register callback for ancestry anomalies.
     * @param callback Callback function.
     * @return Callback ID for unregistration.
     */
    uint64_t RegisterAncestryCallback(AncestryAnomalyCallback callback);

    /**
     * @brief Unregister a callback.
     * @param callbackId ID returned from registration.
     */
    void UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    /**
     * @brief Clear the process cache.
     * @param keepRunning Keep entries for running processes.
     */
    void ClearCache(bool keepRunning = true);

    /**
     * @brief Invalidate cache entry for a process.
     * @param pid Process ID.
     */
    void InvalidateCacheEntry(uint32_t pid);

    /**
     * @brief Force cache refresh for a process.
     * @param pid Process ID.
     * @return Updated process info.
     */
    std::optional<ExtendedProcessInfo> RefreshCacheEntry(uint32_t pid);

    /**
     * @brief Get cache size.
     * @return Number of entries in cache.
     */
    [[nodiscard]] size_t GetCacheSize() const noexcept;

    // ========================================================================
    // STATISTICS & DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Get monitor statistics.
     * @return Current statistics.
     */
    [[nodiscard]] MonitorStatistics GetStatistics() const;

    /**
     * @brief Get process tree statistics.
     * @return Tree statistics.
     */
    [[nodiscard]] ProcessTreeStatistics GetTreeStatistics() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStatistics();

    /**
     * @brief Get monitor version.
     * @return Version string.
     */
    [[nodiscard]] static std::wstring GetVersion() noexcept;

    /**
     * @brief Perform self-diagnostics.
     * @return Vector of diagnostic messages.
     */
    [[nodiscard]] std::vector<std::wstring> RunDiagnostics() const;

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    /**
     * @brief Wait for a process to terminate.
     * @param pid Process ID.
     * @param timeoutMs Timeout in milliseconds.
     * @return True if process terminated, false if timeout.
     */
    bool WaitForTermination(uint32_t pid, uint32_t timeoutMs);

    /**
     * @brief Get process unique ID from PID.
     * @param pid Process ID.
     * @return Unique ID if process exists.
     */
    [[nodiscard]] std::optional<ProcessUniqueId> GetUniqueId(uint32_t pid) const;

    /**
     * @brief Check if PID was recently reused.
     * @param pid Process ID.
     * @return True if PID was reused within reuse window.
     */
    [[nodiscard]] bool WasPidReused(uint32_t pid) const;

    /**
     * @brief Get historical process info (terminated processes).
     * @param uniqueId Process unique identifier.
     * @return Process info if available in history.
     */
    [[nodiscard]] std::optional<ExtendedProcessInfo> GetHistoricalInfo(
        const ProcessUniqueId& uniqueId
    ) const;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (SINGLETON)
    // ========================================================================

    ProcessMonitor();
    ~ProcessMonitor();

    // ========================================================================
    // IMPLEMENTATION
    // ========================================================================

    std::unique_ptr<ProcessMonitorImpl> m_impl;
};

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
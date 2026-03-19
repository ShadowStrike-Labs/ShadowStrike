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
 * ShadowStrike Real-Time Protection - SERVICE MODULE (The Orchestrator)
 * ============================================================================
 *
 * @file RealTimeProtection.hpp
 * @brief Enterprise-grade real-time protection orchestration system.
 *
 * This module serves as the central orchestrator for all real-time protection
 * components. It acts as the "heartbeat" of the active protection system,
 * coordinating kernel driver communication, scan engine integration, policy
 * enforcement, and threat response.
 *
 * Key Responsibilities:
 * =====================
 * 1. KERNEL EVENT COORDINATION
 *    - Initializes and manages communication with the minifilter driver
 *    - Receives file I/O, process, registry, and network events
 *    - Routes events to appropriate analysis modules
 *    - Returns verdicts to kernel for enforcement
 *
 * 2. SCAN ENGINE INTEGRATION
 *    - Coordinates with ScanEngine for file analysis
 *    - Manages scan priorities and queuing
 *    - Handles scan timeouts and failures
 *    - Caches scan results for performance
 *
 * 3. POLICY ENFORCEMENT
 *    - Implements protection policies (block, quarantine, monitor)
 *    - Handles fail-open vs fail-closed decisions
 *    - Manages exclusions and exceptions
 *    - Enforces real-time protection modes
 *
 * 4. COMPONENT ORCHESTRATION
 *    - Coordinates FileSystemFilter, ProcessCreationMonitor, etc.
 *    - Manages component lifecycle and health
 *    - Handles inter-component communication
 *    - Balances load across protection modules
 *
 * 5. THREAT RESPONSE
 *    - Coordinates immediate threat response
 *    - Manages quarantine operations
 *    - Triggers remediation workflows
 *    - Notifies users and administrators
 *
 * 6. TELEMETRY AND MONITORING
 *    - Collects and aggregates protection statistics
 *    - Monitors system health and performance impact
 *    - Detects protection failures and escalates
 *    - Provides real-time status to management console
 *
 * Architecture Position:
 * ======================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                     Kernel Minifilter Driver                        │
 *   │  (ShadowStrikeFlt.sys - File I/O, Process, Registry, Network)       │
 *   └────────────────────────────┬────────────────────────────────────────┘
 *                                │ Filter Communication Port
 *                                ▼
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                         IPCManager                                  │
 *   │        (FilterConnectCommunicationPort, Message Handling)           │
 *   └────────────────────────────┬────────────────────────────────────────┘
 *                                │
 *                                ▼
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                   ┌─────────────────────────┐                       │
 *   │                   │  RealTimeProtection     │                       │
 *   │                   │     (Orchestrator)      │                       │
 *   │                   └────────────┬────────────┘                       │
 *   │                                │                                     │
 *   │     ┌──────────────┬───────────┼───────────┬──────────────┐        │
 *   │     ▼              ▼           ▼           ▼              ▼        │
 *   │ ┌────────┐    ┌────────┐  ┌────────┐  ┌────────┐    ┌────────┐    │
 *   │ │FileSystem│  │Process │  │Memory  │  │Network │    │Behavior│    │
 *   │ │ Filter  │  │Creation│  │Protect │  │Traffic │    │Blocker │    │
 *   │ └────────┘    │Monitor │  └────────┘  │Filter  │    └────────┘    │
 *   │               └────────┘              └────────┘                   │
 *   │                                                                     │
 *   │     ┌──────────────┬───────────┬───────────┬──────────────┐        │
 *   │     ▼              ▼           ▼           ▼              ▼        │
 *   │ ┌────────┐    ┌────────┐  ┌────────┐  ┌────────┐    ┌────────┐    │
 *   │ │Exploit │    │File    │  │Access  │  │ZeroHour│    │Integrity│   │
 *   │ │Prevent │    │Integr  │  │Control │  │Protect │    │Monitor  │   │
 *   │ └────────┘    └────────┘  └────────┘  └────────┘    └────────┘    │
 *   └─────────────────────────────────────────────────────────────────────┘
 *                                │
 *                                ▼
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                          ScanEngine                                 │
 *   │    (Signature, Heuristic, Behavioral, ML Analysis)                  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *                                │
 *         ┌──────────────────────┼──────────────────────┐
 *         ▼                      ▼                      ▼
 *   ┌──────────┐          ┌──────────┐          ┌──────────┐
 *   │HashStore │          │PatternDB │          │ThreatIntel│
 *   └──────────┘          └──────────┘          └──────────┘
 *
 * Workflow Examples:
 * ==================
 *
 * File Access Workflow:
 * ---------------------
 * 1. User opens file → Kernel traps PreCreate
 * 2. IPCManager receives FileScanRequest
 * 3. RealTimeProtection::OnFileAccess() called
 * 4. Check exclusions → If excluded, return ALLOW
 * 5. Check cache → If cached clean, return ALLOW
 * 6. ScanEngine::ScanFile() called
 * 7. Verdict mapped: Clean→ALLOW, Infected→BLOCK
 * 8. If BLOCK: trigger quarantine, notify user
 * 9. Return verdict to kernel
 *
 * Process Creation Workflow:
 * --------------------------
 * 1. Process created → Kernel notifies via PsSetCreateProcessNotifyRoutine
 * 2. IPCManager receives ProcessNotifyRequest
 * 3. RealTimeProtection::OnProcessCreate() called
 * 4. ProcessCreationMonitor validates parent-child relationship
 * 5. ScanEngine scans process image (if not cached)
 * 6. BehaviorMonitor starts tracking if suspicious
 * 7. Verdict returned: ALLOW (with monitoring) or BLOCK
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1059: Command and Scripting Interpreter (Block/Monitor)
 * - T1204: User Execution (Scan on access)
 * - T1566: Phishing (Email attachment scanning)
 * - T1055: Process Injection (Process monitoring)
 * - T1547: Boot/Logon Autostart (Registry monitoring)
 * - T1071: Application Layer Protocol (Network filtering)
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Event handlers may be called concurrently from multiple kernel threads
 * - Component access protected by appropriate synchronization
 * - Statistics use atomic operations
 *
 * Performance Considerations:
 * ===========================
 * - Pre-scan filtering to reduce scan volume
 * - Result caching with configurable TTL
 * - Async scanning for non-blocking operation
 * - Priority queuing for execution attempts
 * - Batch processing for bulk operations
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see Communication/IPCManager.hpp for kernel communication
 * @see Core/Engine/ScanEngine.hpp for scanning infrastructure
 * @see Core/Engine/QuarantineManager.hpp for quarantine operations
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/ProcessUtils.hpp"          // Process context
#include "../Utils/FileUtils.hpp"             // File operations
#include "../Utils/CacheManager.hpp"          // Scan result caching
#include "../ThreatIntel/ThreatIntelLookup.hpp"  // IOC correlation
#include "../Whitelist/WhiteListStore.hpp"    // Exclusions
#include "../HashStore/HashStore.hpp"         // Hash-based blocking

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
#include <map>
#include <set>
#include <queue>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <future>
#include <thread>
#include <condition_variable>
#include <span>

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class RealTimeProtectionImpl;  // PIMPL implementation

// Forward declare other RealTime components
class FileSystemFilter;
class ProcessCreationMonitor;
class MemoryProtection;
class BehaviorBlocker;
class NetworkTrafficFilter;
class ExploitPrevention;
class FileIntegrityMonitor;
class AccessControlManager;
class ZeroHourProtection;

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace RTPConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Timing constants
    constexpr uint32_t DEFAULT_SCAN_TIMEOUT_MS = 60000;          // 1 minute
    constexpr uint32_t QUICK_SCAN_TIMEOUT_MS = 5000;             // 5 seconds
    constexpr uint32_t KERNEL_REPLY_TIMEOUT_MS = 30000;          // 30 seconds
    constexpr uint32_t HEALTH_CHECK_INTERVAL_MS = 60000;         // 1 minute
    constexpr uint32_t STATS_UPDATE_INTERVAL_MS = 5000;          // 5 seconds
    constexpr uint32_t COMPONENT_INIT_TIMEOUT_MS = 30000;        // 30 seconds

    // Cache settings
    constexpr size_t VERDICT_CACHE_SIZE = 100000;                // 100K entries
    constexpr uint32_t VERDICT_CACHE_TTL_CLEAN_MS = 3600000;     // 1 hour for clean
    constexpr uint32_t VERDICT_CACHE_TTL_MALICIOUS_MS = 86400000; // 24 hours for malware
    constexpr size_t PROCESS_CACHE_SIZE = 10000;                 // 10K processes
    constexpr size_t PENDING_SCAN_QUEUE_SIZE = 10000;            // Max pending scans

    // Performance thresholds
    constexpr uint32_t MAX_SCAN_QUEUE_DEPTH = 1000;
    constexpr uint32_t HIGH_CPU_THRESHOLD_PERCENT = 80;
    constexpr uint32_t LOW_MEMORY_THRESHOLD_MB = 512;
    constexpr double MAX_SCAN_LATENCY_MS = 100.0;

    // File size limits
    constexpr uint64_t MAX_REALTIME_SCAN_SIZE = 500ULL * 1024 * 1024;  // 500 MB
    constexpr uint64_t QUICK_SCAN_SIZE_THRESHOLD = 10ULL * 1024 * 1024; // 10 MB

    // Component count
    constexpr size_t MAX_PROTECTION_COMPONENTS = 16;
    constexpr size_t MAX_WORKER_THREADS = 32;

}  // namespace RTPConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ProtectionState
 * @brief Overall state of real-time protection.
 */
enum class ProtectionState : uint8_t {
    UNINITIALIZED = 0,       ///< Not yet initialized
    INITIALIZING = 1,        ///< Initialization in progress
    ACTIVE = 2,              ///< Fully operational
    PAUSED = 3,              ///< Temporarily paused
    DEGRADED = 4,            ///< Partial functionality
    ERROR = 5,               ///< Error state
    SHUTTING_DOWN = 6,       ///< Shutdown in progress
    DISABLED = 7             ///< Disabled by policy/user
};

/**
 * @enum ProtectionMode
 * @brief Operating mode for real-time protection.
 */
enum class ProtectionMode : uint8_t {
    MONITOR_ONLY = 0,        ///< Detect but don't block
    BLOCK_KNOWN = 1,         ///< Block only known threats
    BLOCK_SUSPICIOUS = 2,    ///< Block known + suspicious
    BLOCK_UNKNOWN = 3,       ///< Block all unknowns (paranoid mode)
    CUSTOM = 4               ///< Custom policy
};

/**
 * @enum KernelVerdict
 * @brief Verdict returned to kernel driver.
 */
enum class KernelVerdict : uint8_t {
    ALLOW = 0,               ///< Allow operation to proceed
    BLOCK = 1,               ///< Block operation
    QUARANTINE = 2,          ///< Block and quarantine
    MONITOR = 3,             ///< Allow but monitor closely
    DELAY = 4,               ///< Delay decision (async scan)
    ERROR = 5                ///< Error processing request
};

/**
 * @enum ScanPriority
 * @brief Priority level for scan requests.
 */
enum class ScanPriority : uint8_t {
    LOW = 0,                 ///< Background scan
    NORMAL = 1,              ///< Standard priority
    HIGH = 2,                ///< User-initiated
    CRITICAL = 3,            ///< Execution attempt
    EMERGENCY = 4            ///< Outbreak response
};

/**
 * @enum EventType
 * @brief Type of kernel event.
 */
enum class EventType : uint8_t {
    FILE_CREATE = 0,         ///< File creation
    FILE_OPEN = 1,           ///< File open
    FILE_WRITE = 2,          ///< File write/modify
    FILE_RENAME = 3,         ///< File rename
    FILE_DELETE = 4,         ///< File deletion
    FILE_EXECUTE = 5,        ///< File execution
    PROCESS_CREATE = 6,      ///< Process creation
    PROCESS_TERMINATE = 7,   ///< Process termination
    THREAD_CREATE = 8,       ///< Thread creation
    IMAGE_LOAD = 9,          ///< DLL/module load
    REGISTRY_CREATE_KEY = 10, ///< Registry key creation
    REGISTRY_SET_VALUE = 11, ///< Registry value modification
    REGISTRY_DELETE = 12,    ///< Registry deletion
    NETWORK_CONNECT = 13,    ///< Network connection
    NETWORK_LISTEN = 14,     ///< Network listen
    MEMORY_ALLOCATE = 15,    ///< Memory allocation (RWX)
    MEMORY_PROTECT = 16      ///< Memory protection change
};

/**
 * @enum FailurePolicy
 * @brief Policy for handling failures.
 */
enum class FailurePolicy : uint8_t {
    FAIL_OPEN = 0,           ///< Allow on failure (availability)
    FAIL_CLOSED = 1,         ///< Block on failure (security)
    ASK_USER = 2,            ///< Prompt user on failure
    LOG_ONLY = 3             ///< Log and allow
};

/**
 * @enum ComponentType
 * @brief Types of protection components.
 */
enum class ComponentType : uint8_t {
    FILE_SYSTEM_FILTER = 0,
    PROCESS_MONITOR = 1,
    MEMORY_PROTECTION = 2,
    BEHAVIOR_BLOCKER = 3,
    NETWORK_FILTER = 4,
    EXPLOIT_PREVENTION = 5,
    FILE_INTEGRITY = 6,
    ACCESS_CONTROL = 7,
    ZERO_HOUR = 8,
    SCAN_ENGINE = 9,
    IPC_MANAGER = 10,
    QUARANTINE_MANAGER = 11,
    COMPONENT_COUNT = 12
};

/**
 * @enum ComponentState
 * @brief State of a protection component.
 */
enum class ComponentState : uint8_t {
    UNINITIALIZED = 0,
    INITIALIZING = 1,
    RUNNING = 2,
    PAUSED = 3,
    ERROR = 4,
    STOPPED = 5
};

/**
 * @enum NotificationSeverity
 * @brief Severity level for user notifications.
 */
enum class NotificationSeverity : uint8_t {
    INFO = 0,
    WARNING = 1,
    THREAT_BLOCKED = 2,
    THREAT_DETECTED = 3,
    CRITICAL = 4
};

/**
 * @enum RemediationAction
 * @brief Actions taken for threat remediation.
 */
enum class RemediationAction : uint8_t {
    NONE = 0,
    BLOCKED = 1,
    QUARANTINED = 2,
    DELETED = 3,
    CLEANED = 4,
    PROCESS_TERMINATED = 5,
    NETWORK_BLOCKED = 6,
    REGISTRY_RESTORED = 7,
    ROLLBACK = 8
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct RTPConfig
 * @brief Configuration specific to Real-Time Protection behavior.
 */
struct alignas(64) RTPConfig {
    // Core settings
    bool enabled{ true };
    ProtectionMode mode{ ProtectionMode::BLOCK_KNOWN };
    FailurePolicy failurePolicy{ FailurePolicy::FAIL_OPEN };

    // Scan triggers
    bool scanOnOpen{ true };
    bool scanOnExecute{ true };
    bool scanOnWrite{ false };               ///< High performance impact
    bool scanOnRename{ false };
    bool scanArchives{ true };
    bool scanScripts{ true };
    bool scanDocuments{ true };
    bool scanNetworkFiles{ true };
    bool scanRemovableMedia{ true };

    // Process protection
    bool monitorProcessCreation{ true };
    bool monitorThreadCreation{ false };
    bool monitorImageLoads{ true };
    bool blockSuspiciousProcesses{ true };

    // Memory protection
    bool monitorMemoryAllocation{ true };
    bool blockRWXAllocation{ true };
    bool monitorCodeInjection{ true };

    // Network protection
    bool filterNetworkTraffic{ true };
    bool blockMaliciousConnections{ true };
    bool inspectDNS{ true };
    bool inspectHTTPS{ false };              ///< Requires certificate installation

    // Registry protection
    bool monitorRegistry{ true };
    bool protectAutostart{ true };
    bool protectServices{ true };

    // Behavior
    bool enableBehaviorBlocking{ true };
    bool enableExploitPrevention{ true };
    bool enableFileIntegrity{ true };
    bool enableZeroHourProtection{ true };

    // Performance
    uint32_t scanTimeoutMs{ RTPConstants::DEFAULT_SCAN_TIMEOUT_MS };
    uint32_t maxConcurrentScans{ 4 };
    uint32_t maxPendingScans{ RTPConstants::MAX_SCAN_QUEUE_DEPTH };
    uint64_t maxFileSizeBytes{ RTPConstants::MAX_REALTIME_SCAN_SIZE };
    bool throttleOnHighCPU{ true };
    bool throttleOnLowMemory{ true };

    // Caching
    bool useVerdictCache{ true };
    uint32_t cleanCacheTTLMs{ RTPConstants::VERDICT_CACHE_TTL_CLEAN_MS };
    uint32_t maliciousCacheTTLMs{ RTPConstants::VERDICT_CACHE_TTL_MALICIOUS_MS };
    size_t maxCacheSize{ RTPConstants::VERDICT_CACHE_SIZE };

    // Exclusions
    std::vector<std::wstring> excludedPaths;
    std::vector<std::wstring> excludedExtensions;
    std::vector<std::wstring> excludedProcesses;
    std::vector<uint32_t> excludedPids;
    std::vector<std::wstring> excludedHashes;
    std::vector<std::wstring> excludedPublishers;

    // Notifications
    bool notifyOnThreat{ true };
    bool notifyOnQuarantine{ true };
    bool notifyOnBlock{ true };
    NotificationSeverity minNotificationSeverity{ NotificationSeverity::WARNING };

    // Self-protection
    bool enableSelfProtection{ true };
    bool protectShadowStrikeProcesses{ true };
    bool protectShadowStrikeFiles{ true };
    bool protectShadowStrikeRegistry{ true };

    // Logging
    bool logAllEvents{ false };
    bool logBlockedOnly{ true };
    bool logPerformanceMetrics{ true };

    // Factory methods
    static RTPConfig CreateDefault() noexcept;
    static RTPConfig CreateHighSecurity() noexcept;
    static RTPConfig CreateHighPerformance() noexcept;
    static RTPConfig CreateServerOptimized() noexcept;
    static RTPConfig CreateWorkstationOptimized() noexcept;
};

/**
 * @struct FileScanRequest
 * @brief Request to scan a file from kernel.
 */
struct alignas(64) FileScanRequest {
    // File information
    std::wstring filePath;
    std::wstring dosPath;                    ///< DOS device path from kernel
    uint64_t fileId{ 0 };                    ///< File ID for deduplication
    uint64_t fileSize{ 0 };

    // Hash (may be pre-computed by driver)
    std::array<uint8_t, 32> sha256{ 0 };
    bool hashValid{ false };

    // Operation context
    EventType eventType{ EventType::FILE_OPEN };
    uint32_t desiredAccess{ 0 };
    uint32_t createDisposition{ 0 };
    uint32_t createOptions{ 0 };

    // Process context
    uint32_t pid{ 0 };
    uint32_t tid{ 0 };
    std::wstring processName;
    std::wstring processPath;
    uint64_t processStartTime{ 0 };

    // User context
    std::wstring userSid;
    std::wstring userName;

    // Request metadata
    uint64_t requestId{ 0 };
    uint64_t timestamp{ 0 };
    ScanPriority priority{ ScanPriority::NORMAL };
    bool isBlocking{ true };                 ///< Kernel waiting for reply
    uint32_t timeoutMs{ RTPConstants::KERNEL_REPLY_TIMEOUT_MS };
};

/**
 * @struct ProcessNotifyRequest
 * @brief Process creation/termination notification from kernel.
 */
struct alignas(64) ProcessNotifyRequest {
    // Process information
    uint32_t pid{ 0 };
    uint32_t parentPid{ 0 };
    std::wstring imagePath;
    std::wstring commandLine;
    std::wstring currentDirectory;

    // Hashes
    std::array<uint8_t, 32> imageSha256{ 0 };
    bool hashValid{ false };

    // Creation flags
    bool isCreation{ true };                 ///< True = create, False = terminate
    uint64_t createTime{ 0 };
    uint64_t exitTime{ 0 };
    uint32_t exitCode{ 0 };

    // User context
    std::wstring userSid;
    std::wstring userName;
    uint32_t sessionId{ 0 };
    bool isElevated{ false };

    // Environment
    std::vector<std::pair<std::wstring, std::wstring>> environment;

    // Request metadata
    uint64_t requestId{ 0 };
    uint64_t timestamp{ 0 };
};

/**
 * @struct ImageLoadRequest
 * @brief Image (DLL) load notification from kernel.
 */
struct alignas(64) ImageLoadRequest {
    // Image information
    std::wstring imagePath;
    uint64_t imageBase{ 0 };
    uint64_t imageSize{ 0 };

    // Hashes
    std::array<uint8_t, 32> sha256{ 0 };
    bool hashValid{ false };

    // Process context
    uint32_t pid{ 0 };
    std::wstring processName;

    // Load context
    bool isSystemImage{ false };
    bool isKernelMode{ false };

    // Signature info
    bool isSigned{ false };
    std::wstring publisher;
    bool isValidSignature{ false };

    // Request metadata
    uint64_t requestId{ 0 };
    uint64_t timestamp{ 0 };
};

/**
 * @struct RegistryNotifyRequest
 * @brief Registry operation notification from kernel.
 */
struct alignas(64) RegistryNotifyRequest {
    // Operation
    EventType eventType{ EventType::REGISTRY_SET_VALUE };

    // Key information
    std::wstring keyPath;
    std::wstring valueName;
    uint32_t valueType{ 0 };
    std::vector<uint8_t> valueData;
    std::vector<uint8_t> previousData;

    // Process context
    uint32_t pid{ 0 };
    std::wstring processName;
    std::wstring processPath;

    // Classification
    bool isAutostartLocation{ false };
    bool isServiceLocation{ false };
    bool isSecuritySetting{ false };

    // Request metadata
    uint64_t requestId{ 0 };
    uint64_t timestamp{ 0 };
};

/**
 * @struct NetworkNotifyRequest
 * @brief Network operation notification from kernel.
 */
struct alignas(64) NetworkNotifyRequest {
    // Operation
    EventType eventType{ EventType::NETWORK_CONNECT };

    // Connection information
    std::wstring localAddress;
    uint16_t localPort{ 0 };
    std::wstring remoteAddress;
    uint16_t remotePort{ 0 };
    uint8_t protocol{ 0 };                   ///< TCP=6, UDP=17

    // DNS (if available)
    std::wstring hostName;

    // Process context
    uint32_t pid{ 0 };
    std::wstring processName;
    std::wstring processPath;

    // Classification
    bool isOutbound{ true };
    bool isInbound{ false };

    // Request metadata
    uint64_t requestId{ 0 };
    uint64_t timestamp{ 0 };
};

/**
 * @struct ScanResult
 * @brief Result of a file scan.
 */
struct alignas(64) ScanResult {
    // Primary result
    KernelVerdict verdict{ KernelVerdict::ALLOW };
    bool isThreat{ false };
    std::wstring threatName;
    std::wstring threatCategory;

    // Confidence
    uint8_t confidence{ 0 };                 ///< 0-100

    // Detection sources
    bool detectedBySignature{ false };
    bool detectedByHeuristic{ false };
    bool detectedByBehavior{ false };
    bool detectedByML{ false };
    bool detectedByCloud{ false };

    // Additional info
    std::vector<std::wstring> mitreIds;
    std::wstring description;
    uint8_t severity{ 0 };                   ///< 1-10

    // Remediation
    RemediationAction action{ RemediationAction::NONE };
    std::wstring quarantinePath;
    bool remediationSuccessful{ false };

    // Performance
    std::chrono::microseconds scanDuration{ 0 };
    bool fromCache{ false };

    // Error handling
    uint32_t errorCode{ 0 };
    std::wstring errorMessage;
};

/**
 * @struct ComponentStatus
 * @brief Status of a protection component.
 */
struct alignas(8) ComponentStatus {
    ComponentType type{ ComponentType::COMPONENT_COUNT };
    ComponentState state{ ComponentState::UNINITIALIZED };
    uint32_t errorCode{ 0 };
    std::wstring errorMessage;
    std::chrono::system_clock::time_point lastStateChange;
    uint64_t eventsProcessed{ 0 };
    uint64_t eventsBlocked{ 0 };
    bool isHealthy{ false };
};

/**
 * @struct ProtectionStatus
 * @brief Overall protection status.
 */
struct alignas(64) ProtectionStatus {
    // Overall state
    ProtectionState state{ ProtectionState::UNINITIALIZED };
    ProtectionMode mode{ ProtectionMode::BLOCK_KNOWN };
    bool isProtected{ false };

    // Component status
    std::array<ComponentStatus, static_cast<size_t>(ComponentType::COMPONENT_COUNT)> components;

    // Kernel driver status
    bool driverLoaded{ false };
    bool driverConnected{ false };
    std::wstring driverVersion;

    // Performance metrics
    uint32_t cpuUsagePercent{ 0 };
    uint64_t memoryUsageBytes{ 0 };
    uint32_t pendingScanCount{ 0 };
    double avgScanLatencyMs{ 0 };

    // Timestamps
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point lastUpdate;
    std::chrono::seconds uptime{ 0 };

    // Issues
    std::vector<std::wstring> activeIssues;
    bool hasWarnings{ false };
    bool hasErrors{ false };
};

/**
 * @struct ThreatEvent
 * @brief Record of a threat detection event.
 */
struct alignas(64) ThreatEvent {
    // Event identity
    uint64_t eventId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Threat details
    std::wstring threatName;
    std::wstring threatCategory;
    std::wstring threatFamily;
    uint8_t severity{ 0 };
    std::vector<std::wstring> mitreIds;

    // Target
    std::wstring filePath;
    std::array<uint8_t, 32> fileHash{ 0 };
    uint64_t fileSize{ 0 };

    // Context
    uint32_t pid{ 0 };
    std::wstring processName;
    std::wstring processPath;
    std::wstring userName;
    std::wstring machineName;

    // Response
    RemediationAction action{ RemediationAction::NONE };
    bool actionSuccessful{ false };
    std::wstring quarantinePath;

    // Detection method
    std::wstring detectionMethod;
    uint8_t confidence{ 0 };
};

/**
 * @struct PerformanceMetrics
 * @brief Real-time performance metrics.
 */
struct alignas(64) PerformanceMetrics {
    // Scan performance
    std::atomic<uint64_t> totalScans{ 0 };
    std::atomic<uint64_t> scansPerSecond{ 0 };
    std::atomic<uint64_t> avgScanTimeUs{ 0 };
    std::atomic<uint64_t> maxScanTimeUs{ 0 };
    std::atomic<uint64_t> scanTimeouts{ 0 };

    // Queue metrics
    std::atomic<uint32_t> pendingScanQueue{ 0 };
    std::atomic<uint32_t> maxQueueDepth{ 0 };
    std::atomic<uint64_t> queueWaitTimeUs{ 0 };

    // Cache metrics
    std::atomic<uint64_t> cacheHits{ 0 };
    std::atomic<uint64_t> cacheMisses{ 0 };
    std::atomic<uint32_t> cacheSize{ 0 };
    std::atomic<uint64_t> cacheEvictions{ 0 };

    // Resource usage
    std::atomic<uint32_t> cpuUsagePercent{ 0 };
    std::atomic<uint64_t> memoryUsageBytes{ 0 };
    std::atomic<uint32_t> threadCount{ 0 };
    std::atomic<uint64_t> handleCount{ 0 };

    // Kernel communication
    std::atomic<uint64_t> kernelMessages{ 0 };
    std::atomic<uint64_t> kernelReplies{ 0 };
    std::atomic<uint64_t> kernelTimeouts{ 0 };
    std::atomic<uint64_t> kernelErrors{ 0 };

    void Reset() noexcept;
};

/**
 * @struct RTPStatistics
 * @brief Comprehensive runtime statistics.
 */
struct alignas(64) RTPStatistics {
    // Event counts
    std::atomic<uint64_t> totalEvents{ 0 };
    std::atomic<uint64_t> fileEvents{ 0 };
    std::atomic<uint64_t> processEvents{ 0 };
    std::atomic<uint64_t> registryEvents{ 0 };
    std::atomic<uint64_t> networkEvents{ 0 };
    std::atomic<uint64_t> memoryEvents{ 0 };

    // Scan statistics
    std::atomic<uint64_t> totalScans{ 0 };
    std::atomic<uint64_t> cleanFiles{ 0 };
    std::atomic<uint64_t> infectedFiles{ 0 };
    std::atomic<uint64_t> suspiciousFiles{ 0 };
    std::atomic<uint64_t> puaFiles{ 0 };
    std::atomic<uint64_t> scanErrors{ 0 };

    // Blocking statistics
    std::atomic<uint64_t> filesBlocked{ 0 };
    std::atomic<uint64_t> processesBlocked{ 0 };
    std::atomic<uint64_t> connectionsBlocked{ 0 };
    std::atomic<uint64_t> registryBlocked{ 0 };

    // Remediation statistics
    std::atomic<uint64_t> filesQuarantined{ 0 };
    std::atomic<uint64_t> filesDeleted{ 0 };
    std::atomic<uint64_t> filesCleaned{ 0 };
    std::atomic<uint64_t> processesTerminated{ 0 };

    // Exclusion statistics
    std::atomic<uint64_t> excludedByPath{ 0 };
    std::atomic<uint64_t> excludedByExtension{ 0 };
    std::atomic<uint64_t> excludedByProcess{ 0 };
    std::atomic<uint64_t> excludedByHash{ 0 };

    // Performance metrics
    PerformanceMetrics performance;

    // Timestamps
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point lastReset;

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for file scan requests (can override verdict).
 * @param request The scan request
 * @param result The scan result (can be modified)
 * @return True to use modified result, false to use original
 */
using FileScanCallback = std::function<bool(
    const FileScanRequest& request,
    ScanResult& result
)>;

/**
 * @brief Callback for process creation events.
 * @param request The process notification
 * @param shouldBlock Set to true to block process creation
 */
using ProcessCreateCallback = std::function<void(
    const ProcessNotifyRequest& request,
    bool& shouldBlock
)>;

/**
 * @brief Callback for threat detection events.
 * @param event The threat event details
 */
using ThreatDetectionCallback = std::function<void(
    const ThreatEvent& event
)>;

/**
 * @brief Callback for protection state changes.
 * @param previousState Previous state
 * @param newState New state
 * @param reason Reason for change
 */
using StateChangeCallback = std::function<void(
    ProtectionState previousState,
    ProtectionState newState,
    std::wstring_view reason
)>;

/**
 * @brief Callback for component status changes.
 * @param component The component
 * @param previousState Previous state
 * @param newState New state
 */
using ComponentStatusCallback = std::function<void(
    ComponentType component,
    ComponentState previousState,
    ComponentState newState
)>;

/**
 * @brief Callback for user notifications.
 * @param severity Notification severity
 * @param title Notification title
 * @param message Notification message
 * @param threatEvent Associated threat event (if any)
 */
using UserNotificationCallback = std::function<void(
    NotificationSeverity severity,
    std::wstring_view title,
    std::wstring_view message,
    const std::optional<ThreatEvent>& threatEvent
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class RealTimeProtection
 * @brief Singleton controller for the active protection service.
 *
 * This class serves as the central orchestrator for all real-time protection
 * functionality. It manages the lifecycle of protection components, handles
 * kernel communication, coordinates scanning, and enforces security policies.
 *
 * Thread Safety:
 * All public methods are thread-safe. Event handlers may be called concurrently
 * from multiple kernel threads.
 *
 * Usage Example:
 * @code
 * auto& rtp = RealTimeProtection::Instance();
 * 
 * // Configure with high security settings
 * auto config = RTPConfig::CreateHighSecurity();
 * rtp.UpdateConfig(config);
 * 
 * // Register threat callback
 * rtp.RegisterThreatDetectionCallback([](const ThreatEvent& event) {
 *     LogThreat(event);
 *     NotifySOC(event);
 * });
 * 
 * // Start protection
 * if (!rtp.Start()) {
 *     HandleStartupFailure();
 * }
 * 
 * // Check status periodically
 * auto status = rtp.GetStatus();
 * if (!status.isProtected) {
 *     AlertAdministrators(status);
 * }
 * @endcode
 */
class RealTimeProtection {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Gets the singleton instance of RealTimeProtection.
     * @return Reference to the singleton instance.
     */
    static RealTimeProtection& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Starts the Real-Time Protection service.
     * 
     * This initializes all protection components, connects to the kernel
     * driver, and begins active monitoring.
     * 
     * @return True if protection is active.
     */
    bool Start();

    /**
     * @brief Stops the service and disconnects from the kernel.
     * 
     * Gracefully shuts down all components and releases resources.
     */
    void Stop();

    /**
     * @brief Restarts the protection service.
     * @return True if restart succeeded.
     */
    bool Restart();

    /**
     * @brief Pauses protection temporarily.
     * @param durationMs Duration to pause in milliseconds (0 = indefinite).
     * @param reason Reason for pausing.
     * @return True if pause succeeded.
     */
    bool Pause(uint32_t durationMs = 0, std::wstring_view reason = L"");

    /**
     * @brief Resumes protection after pause.
     * @return True if resume succeeded.
     */
    bool Resume();

    /**
     * @brief Checks if protection is currently active.
     * @return True if fully operational.
     */
    [[nodiscard]] bool IsActive() const noexcept;

    /**
     * @brief Gets the current protection state.
     * @return Current state.
     */
    [[nodiscard]] ProtectionState GetState() const noexcept;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    /**
     * @brief Updates runtime configuration.
     * @param config New configuration settings.
     * @return True if update succeeded.
     * @note Some changes may require restart to take effect.
     */
    bool UpdateConfig(const RTPConfig& config);

    /**
     * @brief Gets the current configuration.
     * @return Current configuration (copy for thread safety).
     */
    [[nodiscard]] RTPConfig GetConfig() const;

    /**
     * @brief Sets the protection mode.
     * @param mode New protection mode.
     */
    void SetProtectionMode(ProtectionMode mode);

    /**
     * @brief Gets the current protection mode.
     * @return Current mode.
     */
    [[nodiscard]] ProtectionMode GetProtectionMode() const noexcept;

    // ========================================================================
    // EXCLUSION MANAGEMENT
    // ========================================================================

    /**
     * @brief Adds a path exclusion.
     * @param path Path to exclude (supports wildcards).
     * @return True if added successfully.
     */
    bool AddPathExclusion(const std::wstring& path);

    /**
     * @brief Removes a path exclusion.
     * @param path Path to remove.
     * @return True if removed.
     */
    bool RemovePathExclusion(const std::wstring& path);

    /**
     * @brief Adds a process exclusion.
     * @param processName Process name or path.
     * @return True if added.
     */
    bool AddProcessExclusion(const std::wstring& processName);

    /**
     * @brief Removes a process exclusion.
     * @param processName Process name or path.
     * @return True if removed.
     */
    bool RemoveProcessExclusion(const std::wstring& processName);

    /**
     * @brief Adds a hash exclusion.
     * @param hash SHA256 hash to exclude.
     * @return True if added.
     */
    bool AddHashExclusion(const std::wstring& hash);

    /**
     * @brief Removes a hash exclusion.
     * @param hash SHA256 hash.
     * @return True if removed.
     */
    bool RemoveHashExclusion(const std::wstring& hash);

    /**
     * @brief Adds a temporary PID exclusion.
     * @param pid Process ID to exclude.
     * @param durationMs Duration in milliseconds.
     * @return True if added.
     */
    bool AddTemporaryPidExclusion(uint32_t pid, uint32_t durationMs);

    /**
     * @brief Clears all exclusions.
     */
    void ClearAllExclusions();

    /**
     * @brief Gets all current exclusions.
     * @return Map of exclusion type to list of exclusions.
     */
    [[nodiscard]] std::unordered_map<std::wstring, std::vector<std::wstring>> GetExclusions() const;

    // ========================================================================
    // STATUS AND MONITORING
    // ========================================================================

    /**
     * @brief Gets comprehensive protection status.
     * @return Current status.
     */
    [[nodiscard]] ProtectionStatus GetStatus() const;

    /**
     * @brief Gets status of a specific component.
     * @param component The component type.
     * @return Component status.
     */
    [[nodiscard]] ComponentStatus GetComponentStatus(ComponentType component) const;

    /**
     * @brief Gets all components' health status.
     * @return Map of component to health status.
     */
    [[nodiscard]] std::unordered_map<ComponentType, bool> GetComponentHealth() const;

    /**
     * @brief Performs a health check on all components.
     * @return True if all components are healthy.
     */
    [[nodiscard]] bool PerformHealthCheck() const;

    /**
     * @brief Gets recent threat events.
     * @param maxEvents Maximum events to return.
     * @param sinceTim Only events after this time.
     * @return Vector of threat events.
     */
    [[nodiscard]] std::vector<ThreatEvent> GetRecentThreats(
        size_t maxEvents = 100,
        std::chrono::system_clock::time_point sinceTime = {}
    ) const;

    // ========================================================================
    // MANUAL OPERATIONS
    // ========================================================================

    /**
     * @brief Manually scans a file.
     * @param filePath Path to file.
     * @param priority Scan priority.
     * @return Scan result.
     */
    [[nodiscard]] ScanResult ScanFile(
        const std::wstring& filePath,
        ScanPriority priority = ScanPriority::HIGH
    );

    /**
     * @brief Manually scans a process.
     * @param pid Process ID.
     * @return Scan result for process image.
     */
    [[nodiscard]] ScanResult ScanProcess(uint32_t pid);

    /**
     * @brief Manually blocks a process.
     * @param pid Process ID.
     * @param terminate Also terminate the process.
     * @return True if blocked successfully.
     */
    bool BlockProcess(uint32_t pid, bool terminate = true);

    /**
     * @brief Manually quarantines a file.
     * @param filePath Path to file.
     * @param threatName Associated threat name.
     * @return True if quarantined successfully.
     */
    bool QuarantineFile(const std::wstring& filePath, std::wstring_view threatName = L"");

    /**
     * @brief Manually blocks a network connection.
     * @param address IP address or hostname.
     * @param port Port number (0 = all ports).
     * @param durationMs Block duration (0 = permanent).
     * @return True if blocked.
     */
    bool BlockNetworkAddress(
        const std::wstring& address,
        uint16_t port = 0,
        uint32_t durationMs = 0
    );

    // ========================================================================
    // VERDICT CACHE MANAGEMENT
    // ========================================================================

    /**
     * @brief Queries the verdict cache.
     * @param hash File hash.
     * @return Cached result, or nullopt if not cached.
     */
    [[nodiscard]] std::optional<ScanResult> QueryVerdictCache(
        const std::array<uint8_t, 32>& hash
    ) const;

    /**
     * @brief Invalidates a specific cache entry.
     * @param hash File hash.
     */
    void InvalidateCacheEntry(const std::array<uint8_t, 32>& hash);

    /**
     * @brief Clears the entire verdict cache.
     */
    void ClearVerdictCache();

    /**
     * @brief Gets the current cache size.
     * @return Number of cached entries.
     */
    [[nodiscard]] size_t GetCacheSize() const noexcept;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Registers a callback for file scan events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterFileScanCallback(FileScanCallback callback);

    /**
     * @brief Registers a callback for process creation events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterProcessCreateCallback(ProcessCreateCallback callback);

    /**
     * @brief Registers a callback for threat detection events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterThreatDetectionCallback(ThreatDetectionCallback callback);

    /**
     * @brief Registers a callback for state changes.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterStateChangeCallback(StateChangeCallback callback);

    /**
     * @brief Registers a callback for component status changes.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterComponentStatusCallback(ComponentStatusCallback callback);

    /**
     * @brief Registers a callback for user notifications.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterNotificationCallback(UserNotificationCallback callback);

    /**
     * @brief Unregisters a callback.
     * @param callbackId The callback ID.
     * @return True if unregistered.
     */
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /**
     * @brief Gets current runtime statistics.
     * @return Reference to statistics structure.
     */
    [[nodiscard]] const RTPStatistics& GetStatistics() const noexcept;

    /**
     * @brief Gets current performance metrics.
     * @return Reference to performance metrics.
     */
    [[nodiscard]] const PerformanceMetrics& GetPerformanceMetrics() const noexcept;

    /**
     * @brief Resets all statistics counters.
     */
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Performs comprehensive diagnostic check.
     * @return True if all systems pass.
     */
    [[nodiscard]] bool PerformDiagnostics() const;

    /**
     * @brief Exports diagnostic report.
     * @param outputPath Output file path.
     * @return True if export succeeded.
     */
    bool ExportDiagnostics(const std::wstring& outputPath) const;

    /**
     * @brief Gets diagnostic summary.
     * @return Diagnostic summary string.
     */
    [[nodiscard]] std::wstring GetDiagnosticSummary() const;

    // ========================================================================
    // COMPONENT ACCESS (Advanced)
    // ========================================================================

    /**
     * @brief Gets the FileSystemFilter component.
     * @return Reference to FileSystemFilter.
     */
    [[nodiscard]] FileSystemFilter& GetFileSystemFilter();

    /**
     * @brief Gets the ProcessCreationMonitor component.
     * @return Reference to ProcessCreationMonitor.
     */
    [[nodiscard]] ProcessCreationMonitor& GetProcessCreationMonitor();

    /**
     * @brief Gets the MemoryProtection component.
     * @return Reference to MemoryProtection.
     */
    [[nodiscard]] MemoryProtection& GetMemoryProtection();

    /**
     * @brief Gets the BehaviorBlocker component.
     * @return Reference to BehaviorBlocker.
     */
    [[nodiscard]] BehaviorBlocker& GetBehaviorBlocker();

    /**
     * @brief Gets the NetworkTrafficFilter component.
     * @return Reference to NetworkTrafficFilter.
     */
    [[nodiscard]] NetworkTrafficFilter& GetNetworkTrafficFilter();

    /**
     * @brief Gets the ExploitPrevention component.
     * @return Reference to ExploitPrevention.
     */
    [[nodiscard]] ExploitPrevention& GetExploitPrevention();

    /**
     * @brief Gets the FileIntegrityMonitor component.
     * @return Reference to FileIntegrityMonitor.
     */
    [[nodiscard]] FileIntegrityMonitor& GetFileIntegrityMonitor();

    /**
     * @brief Gets the AccessControlManager component.
     * @return Reference to AccessControlManager.
     */
    [[nodiscard]] AccessControlManager& GetAccessControlManager();

    /**
     * @brief Gets the ZeroHourProtection component.
     * @return Reference to ZeroHourProtection.
     */
    [[nodiscard]] ZeroHourProtection& GetZeroHourProtection();

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (Singleton)
    // ========================================================================
    RealTimeProtection();
    ~RealTimeProtection();

    // Non-copyable, non-movable
    RealTimeProtection(const RealTimeProtection&) = delete;
    RealTimeProtection& operator=(const RealTimeProtection&) = delete;
    RealTimeProtection(RealTimeProtection&&) = delete;
    RealTimeProtection& operator=(RealTimeProtection&&) = delete;

    // ========================================================================
    // PIMPL IMPLEMENTATION
    // ========================================================================
    std::unique_ptr<RealTimeProtectionImpl> m_impl;

    // ========================================================================
    // LEGACY MEMBERS (For backward compatibility)
    // ========================================================================
    std::atomic<bool> m_active{ false };
    RTPConfig m_config;
    mutable std::shared_mutex m_configMutex;
};

}  // namespace RealTime
}  // namespace ShadowStrike

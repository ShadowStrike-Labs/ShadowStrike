/**
 * ============================================================================
 * ShadowStrike Security - SELF-DEFENSE PROTECTION ENGINE
 * ============================================================================
 *
 * @file SelfDefense.hpp
 * @brief Enterprise-grade self-defense system for protecting ShadowStrike
 *        antivirus from termination, modification, and tampering.
 *
 * This module implements comprehensive self-defense mechanisms to ensure
 * the antivirus cannot be disabled, terminated, or tampered with by malware.
 * It coordinates with kernel-mode drivers for robust protection.
 *
 * PROTECTION LAYERS:
 * ==================
 *
 * 1. PROCESS PROTECTION
 *    - Prevents TerminateProcess on ShadowStrike processes
 *    - Blocks SuspendThread/ResumeThread attacks
 *    - Prevents handle duplication with dangerous access rights
 *    - Monitors and blocks process memory manipulation
 *    - Thread creation monitoring in protected processes
 *    - APC injection prevention
 *    - Debug privilege revocation
 *
 * 2. SERVICE PROTECTION
 *    - Prevents service stop/pause/delete operations
 *    - Protects service configuration (start type, path)
 *    - Monitors SCM database modifications
 *    - Automatic service restart on crash
 *    - Service dependency protection
 *
 * 3. DRIVER PROTECTION
 *    - Prevents minifilter driver unload
 *    - Protects driver image file
 *    - Monitors driver registry keys
 *    - Driver integrity verification
 *    - Kernel callback protection
 *
 * 4. FILE SYSTEM PROTECTION
 *    - Protects ShadowStrike installation directory
 *    - Prevents deletion/modification of executables
 *    - Signature database protection
 *    - Configuration file protection
 *    - Quarantine directory protection
 *
 * 5. REGISTRY PROTECTION
 *    - Protects service registry keys
 *    - Prevents startup entry modification
 *    - Configuration registry protection
 *    - Driver registry key protection
 *
 * 6. MEMORY PROTECTION
 *    - Code section integrity monitoring
 *    - IAT/EAT hook prevention
 *    - Memory permission enforcement
 *    - Stack/heap integrity checks
 *
 * 7. PERSISTENCE MECHANISMS
 *    - Watchdog process monitoring
 *    - Automatic component restart
 *    - Heartbeat monitoring
 *    - Crash recovery
 *    - Redundant protection paths
 *
 * 8. ACCESS CONTROL
 *    - Process access filtering (ObRegisterCallbacks)
 *    - Thread access filtering
 *    - Handle access filtering
 *    - Token privilege monitoring
 *
 * KERNEL INTEGRATION:
 * ===================
 * This module works in conjunction with the ShadowStrike minifilter driver
 * which provides kernel-level protection via:
 * - ObRegisterCallbacks (process/thread object filtering)
 * - CmRegisterCallback (registry filtering)
 * - FltRegisterFilter (file system filtering)
 * - PsSetCreateProcessNotifyRoutine (process notifications)
 *
 * @note Full protection requires the kernel driver to be loaded.
 * @note User-mode only protection is available but less robust.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST CSF
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
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <future>
#include <span>
#include <bitset>
#include <queue>
#include <any>
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
#  include <TlHelp32.h>
#  include <Psapi.h>
#  include <Aclapi.h>
#  include <Sddl.h>
#  include <winsvc.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/ThreadPool.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Security {
    class SelfDefenseImpl;
    class FileProtection;
    class RegistryProtection;
    class ProcessProtection;
    class MemoryProtection;
    class TamperProtection;
}

namespace ShadowStrike {
namespace Security {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SelfDefenseConstants {

    // ========================================================================
    // VERSION INFORMATION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // PROCESS PROTECTION
    // ========================================================================
    
    /// @brief Maximum protected processes
    inline constexpr size_t MAX_PROTECTED_PROCESSES = 32;
    
    /// @brief Maximum protected threads per process
    inline constexpr size_t MAX_PROTECTED_THREADS_PER_PROCESS = 256;
    
    /// @brief Process access rights to block
    inline constexpr uint32_t BLOCKED_PROCESS_ACCESS = 
        PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;
    
    /// @brief Thread access rights to block
    inline constexpr uint32_t BLOCKED_THREAD_ACCESS =
        THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT |
        THREAD_SET_THREAD_TOKEN;

    // ========================================================================
    // SERVICE PROTECTION
    // ========================================================================
    
    /// @brief Service name
    inline constexpr std::wstring_view SERVICE_NAME = L"ShadowStrikeService";
    
    /// @brief Driver service name
    inline constexpr std::wstring_view DRIVER_SERVICE_NAME = L"ShadowStrikeDriver";
    
    /// @brief Maximum service restart attempts
    inline constexpr uint32_t MAX_SERVICE_RESTART_ATTEMPTS = 5;
    
    /// @brief Service restart delay (milliseconds)
    inline constexpr uint32_t SERVICE_RESTART_DELAY_MS = 5000;

    // ========================================================================
    // FILE SYSTEM PROTECTION
    // ========================================================================
    
    /// @brief Maximum protected paths
    inline constexpr size_t MAX_PROTECTED_PATHS = 100;
    
    /// @brief Maximum path length
    inline constexpr size_t MAX_PATH_LENGTH = 32767;

    // ========================================================================
    // REGISTRY PROTECTION
    // ========================================================================
    
    /// @brief Maximum protected registry keys
    inline constexpr size_t MAX_PROTECTED_REGISTRY_KEYS = 50;
    
    /// @brief Maximum protected registry values
    inline constexpr size_t MAX_PROTECTED_REGISTRY_VALUES = 200;

    // ========================================================================
    // WATCHDOG
    // ========================================================================
    
    /// @brief Watchdog check interval (milliseconds)
    inline constexpr uint32_t WATCHDOG_INTERVAL_MS = 5000;
    
    /// @brief Heartbeat timeout (milliseconds)
    inline constexpr uint32_t HEARTBEAT_TIMEOUT_MS = 30000;
    
    /// @brief Maximum consecutive failures before escalation
    inline constexpr uint32_t MAX_CONSECUTIVE_FAILURES = 3;

    // ========================================================================
    // MEMORY PROTECTION
    // ========================================================================
    
    /// @brief Integrity check interval (milliseconds)
    inline constexpr uint32_t INTEGRITY_CHECK_INTERVAL_MS = 60000;
    
    /// @brief Maximum memory regions to protect
    inline constexpr size_t MAX_PROTECTED_MEMORY_REGIONS = 100;

    // ========================================================================
    // RECOVERY
    // ========================================================================
    
    /// @brief Recovery delay (milliseconds)
    inline constexpr uint32_t RECOVERY_DELAY_MS = 1000;
    
    /// @brief Maximum recovery attempts per component
    inline constexpr uint32_t MAX_RECOVERY_ATTEMPTS = 10;
    
    /// @brief Recovery cooldown period (seconds)
    inline constexpr uint32_t RECOVERY_COOLDOWN_SECONDS = 300;

    // ========================================================================
    // KNOWN THREAT PROCESSES
    // ========================================================================
    
    /// @brief Processes known to attempt AV tampering
    inline constexpr std::array<std::wstring_view, 20> THREAT_PROCESSES = {
        L"taskkill.exe",
        L"taskmgr.exe",
        L"procexp.exe",
        L"procexp64.exe",
        L"processhacker.exe",
        L"pskill.exe",
        L"pskill64.exe",
        L"sc.exe",
        L"net.exe",
        L"net1.exe",
        L"wmic.exe",
        L"cmd.exe",
        L"powershell.exe",
        L"pwsh.exe",
        L"reg.exe",
        L"regedit.exe",
        L"mmc.exe",
        L"services.msc",
        L"devmgmt.msc",
        L"diskmgmt.msc"
    };

}  // namespace SelfDefenseConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using Duration = std::chrono::steady_clock::duration;
using Milliseconds = std::chrono::milliseconds;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Self-defense protection level
 */
enum class SelfDefenseLevel : uint8_t {
    Disabled    = 0,    ///< No protection (testing only)
    Minimal     = 1,    ///< Basic user-mode protection
    Standard    = 2,    ///< Standard protection (recommended)
    Enhanced    = 3,    ///< Enhanced protection with kernel support
    Maximum     = 4,    ///< Maximum protection (may impact system)
    Paranoid    = 5     ///< Paranoid mode (aggressive blocking)
};

/**
 * @brief Protection component types
 */
enum class ProtectionComponent : uint32_t {
    None            = 0x00000000,
    Process         = 0x00000001,   ///< Process protection
    Thread          = 0x00000002,   ///< Thread protection
    Service         = 0x00000004,   ///< Service protection
    Driver          = 0x00000008,   ///< Driver protection
    FileSystem      = 0x00000010,   ///< File system protection
    Registry        = 0x00000020,   ///< Registry protection
    Memory          = 0x00000040,   ///< Memory protection
    Network         = 0x00000080,   ///< Network protection
    Watchdog        = 0x00000100,   ///< Watchdog monitoring
    Heartbeat       = 0x00000200,   ///< Heartbeat monitoring
    Recovery        = 0x00000400,   ///< Auto-recovery
    AccessControl   = 0x00000800,   ///< Access control filtering
    
    // Presets
    UserMode        = Process | Thread | FileSystem | Registry | Memory | Watchdog,
    KernelMode      = UserMode | Driver | Service | AccessControl,
    All             = 0xFFFFFFFF
};

inline constexpr ProtectionComponent operator|(ProtectionComponent a, ProtectionComponent b) noexcept {
    return static_cast<ProtectionComponent>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr ProtectionComponent operator&(ProtectionComponent a, ProtectionComponent b) noexcept {
    return static_cast<ProtectionComponent>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline constexpr bool HasComponent(ProtectionComponent value, ProtectionComponent flag) noexcept {
    return (static_cast<uint32_t>(value) & static_cast<uint32_t>(flag)) != 0;
}

/**
 * @brief Threat type classification
 */
enum class ThreatType : uint32_t {
    None                = 0x00000000,
    ProcessTermination  = 0x00000001,   ///< Attempted process kill
    ThreadTermination   = 0x00000002,   ///< Attempted thread kill
    ProcessSuspension   = 0x00000004,   ///< Attempted process/thread suspension
    MemoryModification  = 0x00000008,   ///< Attempted memory write
    CodeInjection       = 0x00000010,   ///< Code injection attempt
    HandleDuplication   = 0x00000020,   ///< Suspicious handle duplication
    ServiceControl      = 0x00000040,   ///< Service stop/modify attempt
    DriverUnload        = 0x00000080,   ///< Driver unload attempt
    FileModification    = 0x00000100,   ///< Protected file modification
    FileDeletion        = 0x00000200,   ///< Protected file deletion
    RegistryModification= 0x00000400,   ///< Protected registry modification
    RegistryDeletion    = 0x00000800,   ///< Protected registry deletion
    PrivilegeEscalation = 0x00001000,   ///< Privilege escalation attempt
    DebugAttach         = 0x00002000,   ///< Debug attach attempt
    TokenManipulation   = 0x00004000,   ///< Token manipulation
    APCInjection        = 0x00008000,   ///< APC injection attempt
    HookInstallation    = 0x00010000,   ///< Hook installation attempt
    
    All                 = 0xFFFFFFFF
};

inline constexpr ThreatType operator|(ThreatType a, ThreatType b) noexcept {
    return static_cast<ThreatType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Response to detected threat
 */
enum class ThreatResponse : uint32_t {
    None        = 0x00000000,   ///< No action (monitoring only)
    Log         = 0x00000001,   ///< Log the event
    Alert       = 0x00000002,   ///< Send alert
    Block       = 0x00000004,   ///< Block the action
    Quarantine  = 0x00000008,   ///< Quarantine attacking process
    Terminate   = 0x00000010,   ///< Terminate attacking process
    Recover     = 0x00000020,   ///< Auto-recover affected component
    Escalate    = 0x00000040,   ///< Escalate to security center
    Notify      = 0x00000080,   ///< Notify user
    
    // Presets
    Passive     = Log | Alert,
    Active      = Log | Alert | Block,
    Aggressive  = Log | Alert | Block | Terminate | Recover
};

inline constexpr ThreatResponse operator|(ThreatResponse a, ThreatResponse b) noexcept {
    return static_cast<ThreatResponse>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Protected entity type
 */
enum class ProtectedEntityType : uint8_t {
    Process     = 0,
    Thread      = 1,
    Service     = 2,
    Driver      = 3,
    File        = 4,
    Directory   = 5,
    RegistryKey = 6,
    RegistryValue = 7,
    MemoryRegion = 8
};

/**
 * @brief Component health status
 */
enum class ComponentHealth : uint8_t {
    Unknown     = 0,
    Healthy     = 1,
    Degraded    = 2,
    Failed      = 3,
    Recovering  = 4,
    Protected   = 5
};

/**
 * @brief Self-defense module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    PartiallyActive = 3,    ///< Some components failed
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

/**
 * @brief Access request type
 */
enum class AccessRequestType : uint8_t {
    ProcessOpen     = 0,
    ThreadOpen      = 1,
    HandleDuplicate = 2,
    ProcessCreate   = 3,
    ImageLoad       = 4,
    FileAccess      = 5,
    RegistryAccess  = 6,
    ServiceControl  = 7
};

/**
 * @brief Access decision
 */
enum class AccessDecision : uint8_t {
    Allow       = 0,    ///< Allow the access
    Deny        = 1,    ///< Deny the access
    StripRights = 2,    ///< Allow with reduced rights
    Defer       = 3     ///< Defer to other filters
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Self-defense configuration
 */
struct SelfDefenseConfiguration {
    /// @brief Protection level
    SelfDefenseLevel level = SelfDefenseLevel::Standard;
    
    /// @brief Enabled protection components
    ProtectionComponent enabledComponents = ProtectionComponent::All;
    
    /// @brief Default threat response
    ThreatResponse defaultResponse = ThreatResponse::Active;
    
    /// @brief Enable kernel-mode protection (requires driver)
    bool enableKernelProtection = true;
    
    /// @brief Enable watchdog process
    bool enableWatchdog = true;
    
    /// @brief Watchdog interval (milliseconds)
    uint32_t watchdogIntervalMs = SelfDefenseConstants::WATCHDOG_INTERVAL_MS;
    
    /// @brief Enable automatic recovery
    bool enableAutoRecovery = true;
    
    /// @brief Maximum auto-recovery attempts
    uint32_t maxRecoveryAttempts = SelfDefenseConstants::MAX_RECOVERY_ATTEMPTS;
    
    /// @brief Enable integrity monitoring
    bool enableIntegrityMonitoring = true;
    
    /// @brief Integrity check interval (milliseconds)
    uint32_t integrityCheckIntervalMs = SelfDefenseConstants::INTEGRITY_CHECK_INTERVAL_MS;
    
    /// @brief Enable heartbeat monitoring
    bool enableHeartbeat = true;
    
    /// @brief Heartbeat timeout (milliseconds)
    uint32_t heartbeatTimeoutMs = SelfDefenseConstants::HEARTBEAT_TIMEOUT_MS;
    
    /// @brief Log all blocked access attempts
    bool verboseLogging = false;
    
    /// @brief Send telemetry on threats
    bool sendTelemetry = true;
    
    /// @brief Custom protected process IDs
    std::vector<uint32_t> additionalProtectedProcesses;
    
    /// @brief Custom protected file paths
    std::vector<std::wstring> additionalProtectedPaths;
    
    /// @brief Custom protected registry keys
    std::vector<std::wstring> additionalProtectedKeys;
    
    /// @brief Whitelisted process names (can access protected resources)
    std::vector<std::wstring> whitelistedProcesses;
    
    /**
     * @brief Create configuration from protection level
     */
    static SelfDefenseConfiguration FromLevel(SelfDefenseLevel level);
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Information about a protected process
 */
struct ProtectedProcess {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Full image path
    std::wstring imagePath;
    
    /// @brief Image hash for verification
    std::array<uint8_t, 32> imageHash{};
    
    /// @brief Process handle (internal use)
    void* processHandle = nullptr;
    
    /// @brief Is this a ShadowStrike component
    bool isShadowStrikeComponent = false;
    
    /// @brief Is kernel-mode protection active
    bool kernelProtected = false;
    
    /// @brief Is user-mode protection active
    bool userModeProtected = false;
    
    /// @brief Protection timestamp
    TimePoint protectedSince;
    
    /// @brief Number of blocked access attempts
    std::atomic<uint64_t> blockedAttempts{0};
    
    /// @brief Last blocked attempt timestamp
    TimePoint lastBlockedAttempt;
    
    /// @brief Current health status
    ComponentHealth health = ComponentHealth::Unknown;
};

/**
 * @brief Information about a protected file/directory
 */
struct ProtectedPath {
    /// @brief Path identifier
    std::string id;
    
    /// @brief Full path
    std::wstring path;
    
    /// @brief Is directory
    bool isDirectory = false;
    
    /// @brief Include subdirectories
    bool includeSubdirectories = false;
    
    /// @brief Allowed operations (read always allowed)
    bool allowWrite = false;
    bool allowDelete = false;
    bool allowRename = false;
    
    /// @brief Protection timestamp
    TimePoint protectedSince;
    
    /// @brief Blocked operation count
    std::atomic<uint64_t> blockedOperations{0};
};

/**
 * @brief Information about a protected registry key
 */
struct ProtectedRegistryKey {
    /// @brief Key identifier
    std::string id;
    
    /// @brief Full registry path
    std::wstring keyPath;
    
    /// @brief Include subkeys
    bool includeSubkeys = false;
    
    /// @brief Protected values (empty = all values)
    std::vector<std::wstring> protectedValues;
    
    /// @brief Allowed operations
    bool allowWrite = false;
    bool allowDelete = false;
    
    /// @brief Protection timestamp
    TimePoint protectedSince;
    
    /// @brief Blocked operation count
    std::atomic<uint64_t> blockedOperations{0};
};

/**
 * @brief Threat event details
 */
struct ThreatEvent {
    /// @brief Event identifier
    uint64_t eventId = 0;
    
    /// @brief Threat type
    ThreatType type = ThreatType::None;
    
    /// @brief Event timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Attacking process ID
    uint32_t attackerProcessId = 0;
    
    /// @brief Attacking process name
    std::wstring attackerProcessName;
    
    /// @brief Attacking process path
    std::wstring attackerProcessPath;
    
    /// @brief Target entity type
    ProtectedEntityType targetType = ProtectedEntityType::Process;
    
    /// @brief Target identifier (PID, path, etc.)
    std::wstring targetIdentifier;
    
    /// @brief Requested access rights
    uint32_t requestedAccess = 0;
    
    /// @brief Blocked access rights
    uint32_t blockedAccess = 0;
    
    /// @brief Action taken
    ThreatResponse actionTaken = ThreatResponse::None;
    
    /// @brief Was the threat blocked
    bool wasBlocked = false;
    
    /// @brief Additional details
    std::unordered_map<std::string, std::string> details;
    
    /// @brief Thread ID of attacker
    uint32_t attackerThreadId = 0;
    
    /// @brief User SID of attacker
    std::wstring attackerUserSid;
    
    /**
     * @brief Get summary string
     */
    [[nodiscard]] std::string GetSummary() const;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Access request for filtering
 */
struct AccessRequest {
    /// @brief Request type
    AccessRequestType type = AccessRequestType::ProcessOpen;
    
    /// @brief Caller process ID
    uint32_t callerProcessId = 0;
    
    /// @brief Caller thread ID
    uint32_t callerThreadId = 0;
    
    /// @brief Target process ID (for process/thread access)
    uint32_t targetProcessId = 0;
    
    /// @brief Target thread ID (for thread access)
    uint32_t targetThreadId = 0;
    
    /// @brief Requested access rights
    uint32_t desiredAccess = 0;
    
    /// @brief Target path (for file/registry access)
    std::wstring targetPath;
    
    /// @brief Timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Caller image path
    std::wstring callerImagePath;
    
    /// @brief Is caller a system process
    bool isSystemCaller = false;
    
    /// @brief Is caller whitelisted
    bool isWhitelistedCaller = false;
};

/**
 * @brief Access decision result
 */
struct AccessDecisionResult {
    /// @brief Decision
    AccessDecision decision = AccessDecision::Allow;
    
    /// @brief Modified access rights (if StripRights)
    uint32_t grantedAccess = 0;
    
    /// @brief Reason for decision
    std::string reason;
    
    /// @brief Should log this decision
    bool shouldLog = false;
    
    /// @brief Associated threat event (if any)
    std::optional<ThreatEvent> threatEvent;
};

/**
 * @brief Component status information
 */
struct ComponentStatus {
    /// @brief Component type
    ProtectionComponent component = ProtectionComponent::None;
    
    /// @brief Is component active
    bool isActive = false;
    
    /// @brief Health status
    ComponentHealth health = ComponentHealth::Unknown;
    
    /// @brief Last check timestamp
    TimePoint lastCheck;
    
    /// @brief Error message (if any)
    std::string errorMessage;
    
    /// @brief Recovery attempts made
    uint32_t recoveryAttempts = 0;
    
    /// @brief Last successful operation
    TimePoint lastSuccessfulOperation;
    
    /// @brief Blocked operations count
    uint64_t blockedOperations = 0;
};

/**
 * @brief Self-defense statistics
 */
struct SelfDefenseStatistics {
    /// @brief Total threats detected
    std::atomic<uint64_t> totalThreatsDetected{0};
    
    /// @brief Total threats blocked
    std::atomic<uint64_t> totalThreatsBlocked{0};
    
    /// @brief Threats by type
    std::unordered_map<ThreatType, uint64_t> threatsByType;
    
    /// @brief Process termination attempts blocked
    std::atomic<uint64_t> processTerminationBlocked{0};
    
    /// @brief Thread termination attempts blocked
    std::atomic<uint64_t> threadTerminationBlocked{0};
    
    /// @brief Memory modification attempts blocked
    std::atomic<uint64_t> memoryModificationBlocked{0};
    
    /// @brief File modification attempts blocked
    std::atomic<uint64_t> fileModificationBlocked{0};
    
    /// @brief Registry modification attempts blocked
    std::atomic<uint64_t> registryModificationBlocked{0};
    
    /// @brief Service control attempts blocked
    std::atomic<uint64_t> serviceControlBlocked{0};
    
    /// @brief Auto-recovery events
    std::atomic<uint64_t> autoRecoveryEvents{0};
    
    /// @brief Successful auto-recoveries
    std::atomic<uint64_t> successfulRecoveries{0};
    
    /// @brief Module start time
    TimePoint startTime = Clock::now();
    
    /// @brief Last threat timestamp
    TimePoint lastThreatTime;
    
    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Heartbeat message
 */
struct HeartbeatMessage {
    /// @brief Heartbeat sequence number
    uint64_t sequenceNumber = 0;
    
    /// @brief Component sending heartbeat
    std::string componentName;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Health status
    ComponentHealth health = ComponentHealth::Healthy;
    
    /// @brief Additional status info
    std::unordered_map<std::string, std::string> statusInfo;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Callback for threat events
using ThreatCallback = std::function<void(const ThreatEvent&)>;

/// @brief Callback for access decisions (can override)
using AccessCallback = std::function<AccessDecisionResult(const AccessRequest&)>;

/// @brief Callback for component status changes
using ComponentStatusCallback = std::function<void(ProtectionComponent, ComponentHealth)>;

/// @brief Callback for recovery events
using RecoveryCallback = std::function<void(ProtectionComponent, bool success)>;

/// @brief Callback for heartbeat events
using HeartbeatCallback = std::function<void(const HeartbeatMessage&)>;

// ============================================================================
// SELF-DEFENSE ENGINE CLASS
// ============================================================================

/**
 * @class SelfDefense
 * @brief Enterprise-grade self-defense protection engine
 *
 * Provides comprehensive protection for ShadowStrike antivirus against
 * termination, tampering, and modification by malware.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& selfDefense = SelfDefense::Instance();
 *     
 *     SelfDefenseConfiguration config;
 *     config.level = SelfDefenseLevel::Enhanced;
 *     config.enableKernelProtection = true;
 *     
 *     if (!selfDefense.Initialize(config)) {
 *         LOG_ERROR("Failed to initialize self-defense");
 *     }
 *     
 *     // Register threat callback
 *     selfDefense.RegisterThreatCallback([](const ThreatEvent& event) {
 *         LOG_WARNING("Threat detected: {}", event.GetSummary());
 *     });
 *     
 *     // Protect additional process
 *     selfDefense.ProtectProcess(GetCurrentProcessId());
 * @endcode
 */
class SelfDefense final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     * @return Reference to singleton
     */
    [[nodiscard]] static SelfDefense& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    SelfDefense(const SelfDefense&) = delete;
    SelfDefense& operator=(const SelfDefense&) = delete;
    SelfDefense(SelfDefense&&) = delete;
    SelfDefense& operator=(SelfDefense&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize self-defense with configuration
     * @param config Configuration settings
     * @return true if initialization succeeded
     */
    [[nodiscard]] bool Initialize(const SelfDefenseConfiguration& config = {});
    
    /**
     * @brief Initialize with protection level preset
     * @param level Protection level
     * @return true if initialization succeeded
     */
    [[nodiscard]] bool Initialize(SelfDefenseLevel level);
    
    /**
     * @brief Shutdown self-defense (use with extreme caution)
     * @param authorizationToken Security token to authorize shutdown
     */
    void Shutdown(std::string_view authorizationToken);
    
    /**
     * @brief Check if initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Get current status
     */
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    /**
     * @brief Pause protection (requires authorization)
     * @param authorizationToken Security token
     * @param durationMs Duration in milliseconds (0 = until resumed)
     * @return true if paused
     */
    [[nodiscard]] bool Pause(std::string_view authorizationToken, uint32_t durationMs = 0);
    
    /**
     * @brief Resume protection
     */
    void Resume();
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     * @param config New configuration
     * @return true if applied
     */
    [[nodiscard]] bool SetConfiguration(const SelfDefenseConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] SelfDefenseConfiguration GetConfiguration() const;
    
    /**
     * @brief Set protection level
     * @param level Protection level
     */
    void SetProtectionLevel(SelfDefenseLevel level);
    
    /**
     * @brief Get current protection level
     */
    [[nodiscard]] SelfDefenseLevel GetProtectionLevel() const noexcept;
    
    /**
     * @brief Enable specific component
     * @param component Component to enable
     * @return true if enabled
     */
    [[nodiscard]] bool EnableComponent(ProtectionComponent component);
    
    /**
     * @brief Disable specific component (requires authorization)
     * @param component Component to disable
     * @param authorizationToken Security token
     * @return true if disabled
     */
    [[nodiscard]] bool DisableComponent(ProtectionComponent component, 
                                        std::string_view authorizationToken);
    
    /**
     * @brief Check if component is enabled
     */
    [[nodiscard]] bool IsComponentEnabled(ProtectionComponent component) const noexcept;
    
    /**
     * @brief Set threat response policy
     * @param threatType Threat type
     * @param response Response action
     */
    void SetThreatResponse(ThreatType threatType, ThreatResponse response);
    
    /**
     * @brief Get threat response policy
     */
    [[nodiscard]] ThreatResponse GetThreatResponse(ThreatType threatType) const;
    
    // ========================================================================
    // PROCESS PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect a process
     * @param processId Process ID to protect
     * @return true if protection applied
     */
    [[nodiscard]] bool ProtectProcess(uint32_t processId);
    
    /**
     * @brief Unprotect a process (requires authorization)
     * @param processId Process ID
     * @param authorizationToken Security token
     * @return true if unprotected
     */
    [[nodiscard]] bool UnprotectProcess(uint32_t processId, std::string_view authorizationToken);
    
    /**
     * @brief Check if process is protected
     */
    [[nodiscard]] bool IsProcessProtected(uint32_t processId) const;
    
    /**
     * @brief Get protected process info
     */
    [[nodiscard]] std::optional<ProtectedProcess> GetProtectedProcess(uint32_t processId) const;
    
    /**
     * @brief Get all protected processes
     */
    [[nodiscard]] std::vector<ProtectedProcess> GetAllProtectedProcesses() const;
    
    /**
     * @brief Check if access request should be allowed
     * @param callerPid Caller process ID
     * @param targetPid Target process ID
     * @param desiredAccess Requested access rights
     * @return true if allowed
     */
    [[nodiscard]] bool IsAccessAllowed(uint32_t callerPid, uint32_t targetPid, 
                                       uint32_t desiredAccess);
    
    /**
     * @brief Filter access request (detailed version)
     * @param request Access request details
     * @return Access decision result
     */
    [[nodiscard]] AccessDecisionResult FilterAccessRequest(const AccessRequest& request);
    
    /**
     * @brief Register process as ShadowStrike component
     * @param processId Process ID
     * @param componentName Component name
     * @return true if registered
     */
    [[nodiscard]] bool RegisterShadowStrikeComponent(uint32_t processId, 
                                                     std::string_view componentName);
    
    // ========================================================================
    // SERVICE PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect ShadowStrike service
     * @return true if protected
     */
    [[nodiscard]] bool ProtectService();
    
    /**
     * @brief Check if service is protected
     */
    [[nodiscard]] bool IsServiceProtected() const;
    
    /**
     * @brief Get service status
     */
    [[nodiscard]] ComponentStatus GetServiceStatus() const;
    
    /**
     * @brief Ensure service is running
     * @return true if service is running
     */
    [[nodiscard]] bool EnsureServiceRunning();
    
    // ========================================================================
    // DRIVER PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect ShadowStrike driver
     * @return true if protected
     */
    [[nodiscard]] bool ProtectDriver();
    
    /**
     * @brief Check if driver is protected
     */
    [[nodiscard]] bool IsDriverProtected() const;
    
    /**
     * @brief Get driver status
     */
    [[nodiscard]] ComponentStatus GetDriverStatus() const;
    
    /**
     * @brief Check if driver is loaded
     */
    [[nodiscard]] bool IsDriverLoaded() const;
    
    /**
     * @brief Ensure driver is loaded
     * @return true if driver is loaded
     */
    [[nodiscard]] bool EnsureDriverLoaded();
    
    // ========================================================================
    // FILE SYSTEM PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect file or directory
     * @param path Path to protect
     * @param includeSubdirectories Include subdirectories (for directories)
     * @return true if protected
     */
    [[nodiscard]] bool ProtectPath(std::wstring_view path, bool includeSubdirectories = true);
    
    /**
     * @brief Unprotect file or directory
     * @param path Path to unprotect
     * @param authorizationToken Security token
     * @return true if unprotected
     */
    [[nodiscard]] bool UnprotectPath(std::wstring_view path, std::string_view authorizationToken);
    
    /**
     * @brief Check if path is protected
     */
    [[nodiscard]] bool IsPathProtected(std::wstring_view path) const;
    
    /**
     * @brief Get protected path info
     */
    [[nodiscard]] std::optional<ProtectedPath> GetProtectedPath(std::wstring_view path) const;
    
    /**
     * @brief Get all protected paths
     */
    [[nodiscard]] std::vector<ProtectedPath> GetAllProtectedPaths() const;
    
    /**
     * @brief Protect ShadowStrike installation directory
     * @return true if protected
     */
    [[nodiscard]] bool ProtectInstallationDirectory();
    
    // ========================================================================
    // REGISTRY PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect registry key
     * @param keyPath Full registry path
     * @param includeSubkeys Include subkeys
     * @return true if protected
     */
    [[nodiscard]] bool ProtectRegistryKey(std::wstring_view keyPath, bool includeSubkeys = true);
    
    /**
     * @brief Unprotect registry key
     * @param keyPath Registry path
     * @param authorizationToken Security token
     * @return true if unprotected
     */
    [[nodiscard]] bool UnprotectRegistryKey(std::wstring_view keyPath, 
                                            std::string_view authorizationToken);
    
    /**
     * @brief Check if registry key is protected
     */
    [[nodiscard]] bool IsRegistryKeyProtected(std::wstring_view keyPath) const;
    
    /**
     * @brief Get protected registry key info
     */
    [[nodiscard]] std::optional<ProtectedRegistryKey> GetProtectedRegistryKey(
        std::wstring_view keyPath) const;
    
    /**
     * @brief Get all protected registry keys
     */
    [[nodiscard]] std::vector<ProtectedRegistryKey> GetAllProtectedRegistryKeys() const;
    
    /**
     * @brief Protect ShadowStrike registry keys
     * @return true if protected
     */
    [[nodiscard]] bool ProtectServiceRegistryKeys();
    
    // ========================================================================
    // MEMORY PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect memory region
     * @param address Start address
     * @param size Region size
     * @return true if protected
     */
    [[nodiscard]] bool ProtectMemoryRegion(uintptr_t address, size_t size);
    
    /**
     * @brief Unprotect memory region
     * @param address Start address
     * @param authorizationToken Security token
     * @return true if unprotected
     */
    [[nodiscard]] bool UnprotectMemoryRegion(uintptr_t address, std::string_view authorizationToken);
    
    /**
     * @brief Protect current module's code section
     * @return true if protected
     */
    [[nodiscard]] bool ProtectCodeSection();
    
    /**
     * @brief Verify memory integrity
     * @return true if integrity intact
     */
    [[nodiscard]] bool VerifyMemoryIntegrity();
    
    // ========================================================================
    // WATCHDOG AND RECOVERY
    // ========================================================================
    
    /**
     * @brief Start watchdog monitoring
     * @return true if started
     */
    [[nodiscard]] bool StartWatchdog();
    
    /**
     * @brief Stop watchdog monitoring
     * @param authorizationToken Security token
     */
    void StopWatchdog(std::string_view authorizationToken);
    
    /**
     * @brief Check if watchdog is running
     */
    [[nodiscard]] bool IsWatchdogRunning() const;
    
    /**
     * @brief Send heartbeat
     * @param componentName Component sending heartbeat
     */
    void SendHeartbeat(std::string_view componentName);
    
    /**
     * @brief Trigger component recovery
     * @param component Component to recover
     * @return true if recovery initiated
     */
    [[nodiscard]] bool TriggerRecovery(ProtectionComponent component);
    
    /**
     * @brief Get component health
     * @param component Component to check
     * @return Component health status
     */
    [[nodiscard]] ComponentHealth GetComponentHealth(ProtectionComponent component) const;
    
    /**
     * @brief Get all component statuses
     */
    [[nodiscard]] std::vector<ComponentStatus> GetAllComponentStatuses() const;
    
    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add process to whitelist
     * @param processName Process name
     * @param authorizationToken Security token
     * @return true if added
     */
    [[nodiscard]] bool AddToWhitelist(std::wstring_view processName, 
                                      std::string_view authorizationToken);
    
    /**
     * @brief Remove process from whitelist
     * @param processName Process name
     * @param authorizationToken Security token
     * @return true if removed
     */
    [[nodiscard]] bool RemoveFromWhitelist(std::wstring_view processName,
                                           std::string_view authorizationToken);
    
    /**
     * @brief Check if process is whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(std::wstring_view processName) const;
    
    /**
     * @brief Check if process ID is whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(uint32_t processId) const;
    
    /**
     * @brief Get all whitelisted processes
     */
    [[nodiscard]] std::vector<std::wstring> GetWhitelistedProcesses() const;
    
    // ========================================================================
    // CALLBACKS AND EVENTS
    // ========================================================================
    
    /**
     * @brief Register threat callback
     * @param callback Callback function
     * @return Callback ID
     */
    [[nodiscard]] uint64_t RegisterThreatCallback(ThreatCallback callback);
    
    /**
     * @brief Unregister threat callback
     * @param callbackId Callback ID
     */
    void UnregisterThreatCallback(uint64_t callbackId);
    
    /**
     * @brief Register access decision callback
     * @param callback Callback function
     * @return Callback ID
     */
    [[nodiscard]] uint64_t RegisterAccessCallback(AccessCallback callback);
    
    /**
     * @brief Unregister access callback
     * @param callbackId Callback ID
     */
    void UnregisterAccessCallback(uint64_t callbackId);
    
    /**
     * @brief Register component status callback
     * @param callback Callback function
     * @return Callback ID
     */
    [[nodiscard]] uint64_t RegisterStatusCallback(ComponentStatusCallback callback);
    
    /**
     * @brief Unregister status callback
     * @param callbackId Callback ID
     */
    void UnregisterStatusCallback(uint64_t callbackId);
    
    /**
     * @brief Register recovery callback
     * @param callback Callback function
     * @return Callback ID
     */
    [[nodiscard]] uint64_t RegisterRecoveryCallback(RecoveryCallback callback);
    
    /**
     * @brief Unregister recovery callback
     * @param callbackId Callback ID
     */
    void UnregisterRecoveryCallback(uint64_t callbackId);
    
    /**
     * @brief Register heartbeat callback
     * @param callback Callback function
     * @return Callback ID
     */
    [[nodiscard]] uint64_t RegisterHeartbeatCallback(HeartbeatCallback callback);
    
    /**
     * @brief Unregister heartbeat callback
     * @param callbackId Callback ID
     */
    void UnregisterHeartbeatCallback(uint64_t callbackId);
    
    // ========================================================================
    // STATISTICS AND REPORTING
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] SelfDefenseStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     * @param authorizationToken Security token
     */
    void ResetStatistics(std::string_view authorizationToken);
    
    /**
     * @brief Get threat event history
     * @param maxEntries Maximum entries
     * @return Vector of threat events
     */
    [[nodiscard]] std::vector<ThreatEvent> GetThreatHistory(size_t maxEntries = 100) const;
    
    /**
     * @brief Clear threat history
     * @param authorizationToken Security token
     */
    void ClearThreatHistory(std::string_view authorizationToken);
    
    /**
     * @brief Export security report
     * @return JSON formatted report
     */
    [[nodiscard]] std::string ExportReport() const;
    
    // ========================================================================
    // UTILITY METHODS
    // ========================================================================
    
    /**
     * @brief Self-test all protection mechanisms
     * @return true if all tests pass
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Verify authorization token
     * @param token Token to verify
     * @return true if valid
     */
    [[nodiscard]] bool VerifyAuthorizationToken(std::string_view token) const;
    
    /**
     * @brief Generate authorization token (internal use)
     * @param purpose Token purpose
     * @param validitySeconds Token validity period
     * @return Authorization token
     */
    [[nodiscard]] std::string GenerateAuthorizationToken(std::string_view purpose,
                                                         uint32_t validitySeconds = 300);
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    SelfDefense();
    ~SelfDefense();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<SelfDefenseImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get protection component name
 */
[[nodiscard]] std::string_view GetComponentName(ProtectionComponent component) noexcept;

/**
 * @brief Get threat type name
 */
[[nodiscard]] std::string_view GetThreatTypeName(ThreatType type) noexcept;

/**
 * @brief Get component health name
 */
[[nodiscard]] std::string_view GetHealthName(ComponentHealth health) noexcept;

/**
 * @brief Get protection level name
 */
[[nodiscard]] std::string_view GetProtectionLevelName(SelfDefenseLevel level) noexcept;

// ============================================================================
// RAII HELPERS
// ============================================================================

/**
 * @class ScopedSelfDefensePause
 * @brief RAII wrapper to temporarily pause self-defense
 */
class ScopedSelfDefensePause final {
public:
    explicit ScopedSelfDefensePause(std::string_view authToken, uint32_t durationMs = 0);
    ~ScopedSelfDefensePause();
    
    ScopedSelfDefensePause(const ScopedSelfDefensePause&) = delete;
    ScopedSelfDefensePause& operator=(const ScopedSelfDefensePause&) = delete;
    
    [[nodiscard]] bool IsPaused() const noexcept { return m_paused; }

private:
    bool m_paused = false;
};

/**
 * @class ProtectedScope
 * @brief RAII wrapper to protect a process for the current scope
 */
class ProtectedScope final {
public:
    explicit ProtectedScope(uint32_t processId = 0);
    ~ProtectedScope();
    
    ProtectedScope(const ProtectedScope&) = delete;
    ProtectedScope& operator=(const ProtectedScope&) = delete;
    
    [[nodiscard]] bool IsProtected() const noexcept { return m_protected; }

private:
    uint32_t m_processId = 0;
    bool m_protected = false;
    std::string m_authToken;
};

}  // namespace Security
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Protect current process
 */
#define SS_PROTECT_SELF() \
    ::ShadowStrike::Security::SelfDefense::Instance().ProtectProcess(::GetCurrentProcessId())

/**
 * @brief Check if self-defense is active
 */
#define SS_IS_SELF_DEFENSE_ACTIVE() \
    ::ShadowStrike::Security::SelfDefense::Instance().IsInitialized()

/**
 * @brief Send heartbeat from current component
 */
#define SS_HEARTBEAT(name) \
    ::ShadowStrike::Security::SelfDefense::Instance().SendHeartbeat(name)

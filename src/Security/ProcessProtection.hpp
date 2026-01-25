/**
 * ============================================================================
 * ShadowStrike Security - PROCESS PROTECTION ENGINE
 * ============================================================================
 *
 * @file ProcessProtection.hpp
 * @brief Enterprise-grade process protection system implementing Windows
 *        Protected Process Light (PPL), handle filtering, and comprehensive
 *        process security mechanisms.
 *
 * This module provides multiple layers of process protection for ShadowStrike
 * antivirus, preventing malware from terminating, suspending, or tampering
 * with protected processes.
 *
 * PROTECTION MECHANISMS:
 * ======================
 *
 * 1. PROTECTED PROCESS LIGHT (PPL)
 *    - PsProtectedSignerAntimalware elevation
 *    - Kernel-enforced protection
 *    - Signed code requirements
 *    - Protected handle creation
 *
 * 2. HANDLE FILTERING
 *    - ObRegisterCallbacks integration
 *    - Access rights stripping
 *    - Handle duplication control
 *    - Cross-process handle monitoring
 *
 * 3. OBJECT PROTECTION
 *    - Process object security
 *    - Thread object security
 *    - Token object security
 *    - Job object restrictions
 *
 * 4. ACCESS CONTROL
 *    - DACL/SACL enforcement
 *    - Integrity level enforcement
 *    - Mandatory access control
 *    - Security descriptor management
 *
 * 5. ANTI-TERMINATION
 *    - Critical process flag
 *    - Termination notification
 *    - Watchdog integration
 *    - Auto-restart capability
 *
 * 6. ANTI-SUSPENSION
 *    - Thread suspension monitoring
 *    - Alertable thread protection
 *    - APC injection prevention
 *    - Context modification detection
 *
 * 7. ANTI-INJECTION
 *    - Thread creation monitoring
 *    - Remote thread prevention
 *    - APC injection blocking
 *    - Memory allocation monitoring
 *
 * 8. INTEGRITY VERIFICATION
 *    - Process image verification
 *    - Module load verification
 *    - Code signing enforcement
 *    - Hash-based verification
 *
 * PPL PROTECTION LEVELS:
 * ======================
 * - PsProtectedTypeNone (0) - No protection
 * - PsProtectedTypeProtectedLight (1) - Light protection
 * - PsProtectedTypeProtected (2) - Full protection
 *
 * PPL SIGNER TYPES:
 * =================
 * - PsProtectedSignerNone (0)
 * - PsProtectedSignerAuthenticode (1)
 * - PsProtectedSignerCodeGen (2)
 * - PsProtectedSignerAntimalware (3) - Used by AV
 * - PsProtectedSignerLsa (4)
 * - PsProtectedSignerWindows (5)
 * - PsProtectedSignerWinTcb (6)
 *
 * @note Full PPL support requires ELAM driver and Microsoft signing.
 * @note Some features require kernel-mode driver support.
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
#  include <winternl.h>
#  include <TlHelp32.h>
#  include <Psapi.h>
#  include <Aclapi.h>
#  include <Sddl.h>
#  include <securitybaseapi.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/ThreadPool.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Security {
    class ProcessProtectionImpl;
    class SelfDefense;
    class TamperProtection;
}

namespace ShadowStrike {
namespace Security {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ProcessProtectionConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // PPL CONSTANTS
    // ========================================================================
    
    /// @brief Protection type: None
    inline constexpr uint8_t PS_PROTECTED_TYPE_NONE = 0;
    
    /// @brief Protection type: Protected Light
    inline constexpr uint8_t PS_PROTECTED_TYPE_PROTECTED_LIGHT = 1;
    
    /// @brief Protection type: Protected (full)
    inline constexpr uint8_t PS_PROTECTED_TYPE_PROTECTED = 2;
    
    /// @brief Signer: None
    inline constexpr uint8_t PS_PROTECTED_SIGNER_NONE = 0;
    
    /// @brief Signer: Authenticode
    inline constexpr uint8_t PS_PROTECTED_SIGNER_AUTHENTICODE = 1;
    
    /// @brief Signer: CodeGen
    inline constexpr uint8_t PS_PROTECTED_SIGNER_CODEGEN = 2;
    
    /// @brief Signer: Antimalware (used by AV)
    inline constexpr uint8_t PS_PROTECTED_SIGNER_ANTIMALWARE = 3;
    
    /// @brief Signer: LSA
    inline constexpr uint8_t PS_PROTECTED_SIGNER_LSA = 4;
    
    /// @brief Signer: Windows
    inline constexpr uint8_t PS_PROTECTED_SIGNER_WINDOWS = 5;
    
    /// @brief Signer: WinTcb (highest)
    inline constexpr uint8_t PS_PROTECTED_SIGNER_WINTCB = 6;

    // ========================================================================
    // ACCESS RIGHTS
    // ========================================================================
    
    /// @brief Dangerous process access rights to block
    inline constexpr uint32_t DANGEROUS_PROCESS_ACCESS =
        PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_SET_INFORMATION;
    
    /// @brief Dangerous thread access rights to block
    inline constexpr uint32_t DANGEROUS_THREAD_ACCESS =
        THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT |
        THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN;
    
    /// @brief Safe process access rights to allow
    inline constexpr uint32_t SAFE_PROCESS_ACCESS =
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
        PROCESS_VM_READ | SYNCHRONIZE;
    
    /// @brief Safe thread access rights to allow
    inline constexpr uint32_t SAFE_THREAD_ACCESS =
        THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION |
        THREAD_GET_CONTEXT | SYNCHRONIZE;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum protected processes
    inline constexpr size_t MAX_PROTECTED_PROCESSES = 50;
    
    /// @brief Maximum protected threads
    inline constexpr size_t MAX_PROTECTED_THREADS = 500;
    
    /// @brief Maximum access rules
    inline constexpr size_t MAX_ACCESS_RULES = 100;
    
    /// @brief Maximum blocked access attempts to log
    inline constexpr size_t MAX_BLOCKED_ATTEMPTS_LOG = 1000;

    // ========================================================================
    // MONITORING
    // ========================================================================
    
    /// @brief Process monitoring interval (milliseconds)
    inline constexpr uint32_t MONITOR_INTERVAL_MS = 5000;
    
    /// @brief Health check interval (milliseconds)
    inline constexpr uint32_t HEALTH_CHECK_INTERVAL_MS = 10000;
    
    /// @brief Thread enumeration timeout (milliseconds)
    inline constexpr uint32_t THREAD_ENUM_TIMEOUT_MS = 5000;

    // ========================================================================
    // INTEGRITY LEVELS
    // ========================================================================
    
    /// @brief Untrusted integrity level
    inline constexpr uint32_t SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000;
    
    /// @brief Low integrity level
    inline constexpr uint32_t SECURITY_MANDATORY_LOW_RID = 0x00001000;
    
    /// @brief Medium integrity level
    inline constexpr uint32_t SECURITY_MANDATORY_MEDIUM_RID = 0x00002000;
    
    /// @brief High integrity level
    inline constexpr uint32_t SECURITY_MANDATORY_HIGH_RID = 0x00003000;
    
    /// @brief System integrity level
    inline constexpr uint32_t SECURITY_MANDATORY_SYSTEM_RID = 0x00004000;
    
    /// @brief Protected process integrity level
    inline constexpr uint32_t SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000;

}  // namespace ProcessProtectionConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using Milliseconds = std::chrono::milliseconds;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Protection type (PPL level)
 */
enum class ProtectionType : uint8_t {
    None            = 0,    ///< No protection
    ProtectedLight  = 1,    ///< Protected Process Light
    Protected       = 2     ///< Full Protected Process
};

/**
 * @brief Protection signer type
 */
enum class ProtectionSigner : uint8_t {
    None            = 0,
    Authenticode    = 1,
    CodeGen         = 2,
    Antimalware     = 3,    ///< Used by AV products
    Lsa             = 4,
    Windows         = 5,
    WinTcb          = 6     ///< Highest level
};

/**
 * @brief Access request type
 */
enum class AccessRequestType : uint8_t {
    ProcessOpen     = 0,
    ProcessDuplicate= 1,
    ThreadOpen      = 2,
    ThreadDuplicate = 3,
    HandleDuplicate = 4,
    MemoryRead      = 5,
    MemoryWrite     = 6,
    ThreadCreate    = 7,
    APCQueue        = 8
};

/**
 * @brief Access decision
 */
enum class AccessDecision : uint8_t {
    Allow           = 0,    ///< Allow full access
    AllowReduced    = 1,    ///< Allow with reduced rights
    Deny            = 2,    ///< Deny access
    DenyAndAlert    = 3     ///< Deny and generate alert
};

/**
 * @brief Protection status
 */
enum class ProtectionStatus : uint8_t {
    Unprotected     = 0,
    UserModeOnly    = 1,    ///< User-mode protection only
    KernelProtected = 2,    ///< Kernel-mode protection active
    PPLProtected    = 3,    ///< Full PPL protection
    Critical        = 4     ///< Critical process status
};

/**
 * @brief Threat action type
 */
enum class ThreatAction : uint32_t {
    None                = 0x00000000,
    ProcessTerminate    = 0x00000001,
    ProcessSuspend      = 0x00000002,
    ThreadTerminate     = 0x00000004,
    ThreadSuspend       = 0x00000008,
    MemoryWrite         = 0x00000010,
    MemoryAlloc         = 0x00000020,
    ThreadCreate        = 0x00000040,
    APCQueue            = 0x00000080,
    HandleDuplicate     = 0x00000100,
    TokenSteal          = 0x00000200,
    ContextModify       = 0x00000400,
    DebugAttach         = 0x00000800,
    
    AllProcess          = ProcessTerminate | ProcessSuspend,
    AllThread           = ThreadTerminate | ThreadSuspend | ThreadCreate,
    AllMemory           = MemoryWrite | MemoryAlloc,
    All                 = 0xFFFFFFFF
};

inline constexpr ThreatAction operator|(ThreatAction a, ThreatAction b) noexcept {
    return static_cast<ThreatAction>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Response to threat
 */
enum class ThreatResponse : uint32_t {
    None            = 0x00000000,
    Log             = 0x00000001,
    Alert           = 0x00000002,
    Block           = 0x00000004,
    TerminateSource = 0x00000008,
    QuarantineSource= 0x00000010,
    Escalate        = 0x00000020,
    
    Passive         = Log | Alert,
    Active          = Log | Alert | Block,
    Aggressive      = Log | Alert | Block | TerminateSource
};

inline constexpr ThreatResponse operator|(ThreatResponse a, ThreatResponse b) noexcept {
    return static_cast<ThreatResponse>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

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
 * @brief Process protection level information
 */
struct ProtectionLevel {
    /// @brief Protection type (None, Light, Full)
    ProtectionType type = ProtectionType::None;
    
    /// @brief Protection signer
    ProtectionSigner signer = ProtectionSigner::None;
    
    /// @brief Raw protection level value
    uint8_t rawLevel = 0;
    
    /// @brief Is PPL active
    [[nodiscard]] bool IsPPL() const noexcept {
        return type != ProtectionType::None;
    }
    
    /// @brief Is antimalware protection
    [[nodiscard]] bool IsAntimalware() const noexcept {
        return signer == ProtectionSigner::Antimalware;
    }
    
    /// @brief Get combined level
    [[nodiscard]] uint32_t GetCombinedLevel() const noexcept {
        return (static_cast<uint32_t>(type) << 4) | static_cast<uint32_t>(signer);
    }
    
    /// @brief Compare protection levels
    [[nodiscard]] bool operator>=(const ProtectionLevel& other) const noexcept {
        return GetCombinedLevel() >= other.GetCombinedLevel();
    }
};

/**
 * @brief Process protection configuration
 */
struct ProcessProtectionConfiguration {
    /// @brief Enable PPL protection (requires driver/ELAM)
    bool enablePPL = true;
    
    /// @brief Enable handle filtering
    bool enableHandleFiltering = true;
    
    /// @brief Enable thread protection
    bool enableThreadProtection = true;
    
    /// @brief Enable anti-termination
    bool enableAntiTermination = true;
    
    /// @brief Enable anti-suspension
    bool enableAntiSuspension = true;
    
    /// @brief Enable anti-injection
    bool enableAntiInjection = true;
    
    /// @brief Enable integrity verification
    bool enableIntegrityVerification = true;
    
    /// @brief Set critical process flag
    bool setCriticalProcess = false;
    
    /// @brief Default threat response
    ThreatResponse defaultResponse = ThreatResponse::Active;
    
    /// @brief Block dangerous access rights
    uint32_t blockedProcessAccess = ProcessProtectionConstants::DANGEROUS_PROCESS_ACCESS;
    
    /// @brief Block dangerous thread access
    uint32_t blockedThreadAccess = ProcessProtectionConstants::DANGEROUS_THREAD_ACCESS;
    
    /// @brief Monitoring interval (milliseconds)
    uint32_t monitorIntervalMs = ProcessProtectionConstants::MONITOR_INTERVAL_MS;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /// @brief Send telemetry
    bool sendTelemetry = true;
    
    /// @brief Whitelisted caller processes
    std::vector<std::wstring> whitelistedCallers;
    
    /// @brief Additional processes to protect
    std::vector<uint32_t> additionalProtectedPids;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Protected process information
 */
struct ProtectedProcessInfo {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Image path
    std::wstring imagePath;
    
    /// @brief Image hash (SHA-256)
    std::array<uint8_t, 32> imageHash{};
    
    /// @brief Process handle
    void* processHandle = nullptr;
    
    /// @brief Protection level
    ProtectionLevel protectionLevel;
    
    /// @brief Protection status
    ProtectionStatus status = ProtectionStatus::Unprotected;
    
    /// @brief Is ShadowStrike component
    bool isShadowStrikeComponent = false;
    
    /// @brief Is critical process
    bool isCritical = false;
    
    /// @brief Protection timestamp
    TimePoint protectedSince;
    
    /// @brief Thread count
    uint32_t threadCount = 0;
    
    /// @brief Handle count
    uint32_t handleCount = 0;
    
    /// @brief Integrity level
    uint32_t integrityLevel = 0;
    
    /// @brief Session ID
    uint32_t sessionId = 0;
    
    /// @brief Blocked access attempts
    std::atomic<uint64_t> blockedAttempts{0};
    
    /// @brief Last blocked attempt time
    TimePoint lastBlockedAttempt;
    
    /// @brief Last verified time
    TimePoint lastVerified;
};

/**
 * @brief Protected thread information
 */
struct ProtectedThreadInfo {
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Owning process ID
    uint32_t processId = 0;
    
    /// @brief Thread handle
    void* threadHandle = nullptr;
    
    /// @brief Is primary thread
    bool isPrimaryThread = false;
    
    /// @brief Is hidden from debugger
    bool isHiddenFromDebugger = false;
    
    /// @brief Protection timestamp
    TimePoint protectedSince;
    
    /// @brief Start address
    uintptr_t startAddress = 0;
    
    /// @brief Thread state
    uint32_t threadState = 0;
    
    /// @brief Blocked access attempts
    std::atomic<uint64_t> blockedAttempts{0};
};

/**
 * @brief Access request details
 */
struct AccessRequest {
    /// @brief Request type
    AccessRequestType type = AccessRequestType::ProcessOpen;
    
    /// @brief Caller process ID
    uint32_t callerProcessId = 0;
    
    /// @brief Caller thread ID
    uint32_t callerThreadId = 0;
    
    /// @brief Target process ID
    uint32_t targetProcessId = 0;
    
    /// @brief Target thread ID (for thread access)
    uint32_t targetThreadId = 0;
    
    /// @brief Requested access rights
    uint32_t desiredAccess = 0;
    
    /// @brief Timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Caller image path
    std::wstring callerImagePath;
    
    /// @brief Caller integrity level
    uint32_t callerIntegrityLevel = 0;
    
    /// @brief Is caller elevated
    bool callerIsElevated = false;
    
    /// @brief Is caller system process
    bool callerIsSystem = false;
    
    /// @brief Is caller whitelisted
    bool callerIsWhitelisted = false;
    
    /// @brief Caller protection level
    ProtectionLevel callerProtectionLevel;
};

/**
 * @brief Access decision result
 */
struct AccessDecisionResult {
    /// @brief Decision
    AccessDecision decision = AccessDecision::Allow;
    
    /// @brief Granted access rights (if reduced)
    uint32_t grantedAccess = 0;
    
    /// @brief Stripped access rights
    uint32_t strippedAccess = 0;
    
    /// @brief Reason for decision
    std::string reason;
    
    /// @brief Should log this decision
    bool shouldLog = false;
    
    /// @brief Should alert on this decision
    bool shouldAlert = false;
};

/**
 * @brief Blocked access event
 */
struct BlockedAccessEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Access request
    AccessRequest request;
    
    /// @brief Decision made
    AccessDecisionResult decision;
    
    /// @brief Threat action attempted
    ThreatAction threatAction = ThreatAction::None;
    
    /// @brief Response taken
    ThreatResponse responseTaken = ThreatResponse::None;
    
    /// @brief Event timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Additional context
    std::unordered_map<std::string, std::string> context;
    
    /**
     * @brief Get event summary
     */
    [[nodiscard]] std::string GetSummary() const;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Process protection statistics
 */
struct ProcessProtectionStatistics {
    /// @brief Total protected processes
    std::atomic<uint64_t> totalProtectedProcesses{0};
    
    /// @brief Total protected threads
    std::atomic<uint64_t> totalProtectedThreads{0};
    
    /// @brief Total access requests processed
    std::atomic<uint64_t> totalAccessRequests{0};
    
    /// @brief Total access blocked
    std::atomic<uint64_t> totalAccessBlocked{0};
    
    /// @brief Total access reduced
    std::atomic<uint64_t> totalAccessReduced{0};
    
    /// @brief Process termination blocked
    std::atomic<uint64_t> processTerminationBlocked{0};
    
    /// @brief Thread termination blocked
    std::atomic<uint64_t> threadTerminationBlocked{0};
    
    /// @brief Memory write blocked
    std::atomic<uint64_t> memoryWriteBlocked{0};
    
    /// @brief Thread creation blocked
    std::atomic<uint64_t> threadCreationBlocked{0};
    
    /// @brief APC injection blocked
    std::atomic<uint64_t> apcInjectionBlocked{0};
    
    /// @brief Handle duplication blocked
    std::atomic<uint64_t> handleDuplicationBlocked{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /// @brief Last event time
    TimePoint lastEventTime;
    
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

/// @brief Callback for access decisions (can override)
using AccessDecisionCallback = std::function<std::optional<AccessDecisionResult>(const AccessRequest&)>;

/// @brief Callback for blocked access events
using BlockedAccessCallback = std::function<void(const BlockedAccessEvent&)>;

/// @brief Callback for protection status changes
using ProtectionStatusCallback = std::function<void(uint32_t processId, ProtectionStatus newStatus)>;

/// @brief Callback for threat detection
using ThreatCallback = std::function<void(ThreatAction action, const AccessRequest& request)>;

// ============================================================================
// PROCESS PROTECTION ENGINE CLASS
// ============================================================================

/**
 * @class ProcessProtection
 * @brief Enterprise-grade process protection engine
 *
 * Provides comprehensive process protection including PPL, handle filtering,
 * anti-termination, anti-injection, and access control.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& protection = ProcessProtection::Instance();
 *     
 *     ProcessProtectionConfiguration config;
 *     config.enablePPL = true;
 *     config.enableHandleFiltering = true;
 *     
 *     if (!protection.Initialize(config)) {
 *         LOG_ERROR("Failed to initialize process protection");
 *     }
 *     
 *     // Protect current process
 *     protection.ProtectProcess(GetCurrentProcessId());
 *     
 *     // Attempt to elevate to PPL
 *     if (protection.ElevateToPPL()) {
 *         LOG_INFO("Process elevated to PPL");
 *     }
 *     
 *     // Register callback for blocked access
 *     protection.RegisterBlockedAccessCallback([](const BlockedAccessEvent& event) {
 *         LOG_WARNING("Access blocked: {}", event.GetSummary());
 *     });
 * @endcode
 */
class ProcessProtection final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static ProcessProtection& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    ProcessProtection(const ProcessProtection&) = delete;
    ProcessProtection& operator=(const ProcessProtection&) = delete;
    ProcessProtection(ProcessProtection&&) = delete;
    ProcessProtection& operator=(ProcessProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize process protection
     */
    [[nodiscard]] bool Initialize(const ProcessProtectionConfiguration& config = {});
    
    /**
     * @brief Shutdown process protection
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
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     */
    [[nodiscard]] bool SetConfiguration(const ProcessProtectionConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] ProcessProtectionConfiguration GetConfiguration() const;
    
    /**
     * @brief Set default threat response
     */
    void SetDefaultResponse(ThreatResponse response);
    
    /**
     * @brief Set response for specific threat action
     */
    void SetThreatResponse(ThreatAction action, ThreatResponse response);
    
    // ========================================================================
    // PPL PROTECTION
    // ========================================================================
    
    /**
     * @brief Attempt to elevate current process to PPL
     * @return true if elevated (requires ELAM driver)
     */
    [[nodiscard]] bool ElevateToPPL();
    
    /**
     * @brief Check if current process is PPL protected
     */
    [[nodiscard]] bool IsPPLProtected() const;
    
    /**
     * @brief Get protection level of a process
     */
    [[nodiscard]] ProtectionLevel GetProtectionLevel(uint32_t processId);
    
    /**
     * @brief Get protection level (raw value)
     */
    [[nodiscard]] uint32_t GetProtectionLevelRaw(uint32_t processId);
    
    /**
     * @brief Check if process has required protection level
     */
    [[nodiscard]] bool HasRequiredProtectionLevel(uint32_t processId, ProtectionLevel required);
    
    // ========================================================================
    // PROCESS PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect a process
     */
    [[nodiscard]] bool ProtectProcess(uint32_t processId);
    
    /**
     * @brief Unprotect a process
     */
    [[nodiscard]] bool UnprotectProcess(uint32_t processId, std::string_view authorizationToken);
    
    /**
     * @brief Check if process is protected
     */
    [[nodiscard]] bool IsProcessProtected(uint32_t processId) const;
    
    /**
     * @brief Get protected process info
     */
    [[nodiscard]] std::optional<ProtectedProcessInfo> GetProtectedProcessInfo(uint32_t processId) const;
    
    /**
     * @brief Get all protected processes
     */
    [[nodiscard]] std::vector<ProtectedProcessInfo> GetAllProtectedProcesses() const;
    
    /**
     * @brief Set process as critical
     */
    [[nodiscard]] bool SetCriticalProcess(uint32_t processId, bool critical);
    
    /**
     * @brief Check if process is critical
     */
    [[nodiscard]] bool IsCriticalProcess(uint32_t processId) const;
    
    // ========================================================================
    // THREAD PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect a thread
     */
    [[nodiscard]] bool ProtectThread(uint32_t threadId);
    
    /**
     * @brief Protect all threads in a process
     */
    [[nodiscard]] size_t ProtectAllThreads(uint32_t processId);
    
    /**
     * @brief Unprotect a thread
     */
    [[nodiscard]] bool UnprotectThread(uint32_t threadId, std::string_view authorizationToken);
    
    /**
     * @brief Check if thread is protected
     */
    [[nodiscard]] bool IsThreadProtected(uint32_t threadId) const;
    
    /**
     * @brief Get protected thread info
     */
    [[nodiscard]] std::optional<ProtectedThreadInfo> GetProtectedThreadInfo(uint32_t threadId) const;
    
    /**
     * @brief Get all protected threads for a process
     */
    [[nodiscard]] std::vector<ProtectedThreadInfo> GetProtectedThreads(uint32_t processId) const;
    
    /**
     * @brief Hide thread from debugger
     */
    [[nodiscard]] bool HideThreadFromDebugger(uint32_t threadId);
    
    // ========================================================================
    // ACCESS CONTROL
    // ========================================================================
    
    /**
     * @brief Check if access is allowed
     */
    [[nodiscard]] bool IsAccessAllowed(uint32_t callerPid, uint32_t targetPid, 
                                       uint32_t desiredAccess);
    
    /**
     * @brief Filter access request (detailed)
     */
    [[nodiscard]] AccessDecisionResult FilterAccessRequest(const AccessRequest& request);
    
    /**
     * @brief Strip dangerous access rights
     */
    [[nodiscard]] uint32_t StripDangerousAccess(uint32_t desiredAccess, bool isThread = false);
    
    /**
     * @brief Set blocked access rights for processes
     */
    void SetBlockedProcessAccess(uint32_t accessMask);
    
    /**
     * @brief Set blocked access rights for threads
     */
    void SetBlockedThreadAccess(uint32_t accessMask);
    
    // ========================================================================
    // SECURITY DESCRIPTOR MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Apply restrictive security descriptor to process
     */
    [[nodiscard]] bool ApplyRestrictiveSecurityDescriptor(uint32_t processId);
    
    /**
     * @brief Get process security descriptor
     */
    [[nodiscard]] std::vector<uint8_t> GetProcessSecurityDescriptor(uint32_t processId);
    
    /**
     * @brief Set process integrity level
     */
    [[nodiscard]] bool SetProcessIntegrityLevel(uint32_t processId, uint32_t integrityLevel);
    
    /**
     * @brief Get process integrity level
     */
    [[nodiscard]] uint32_t GetProcessIntegrityLevel(uint32_t processId);
    
    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add caller to whitelist
     */
    [[nodiscard]] bool AddToWhitelist(std::wstring_view processName, 
                                      std::string_view authorizationToken);
    
    /**
     * @brief Remove caller from whitelist
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
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Register access decision callback
     */
    [[nodiscard]] uint64_t RegisterAccessCallback(AccessDecisionCallback callback);
    
    /**
     * @brief Unregister access callback
     */
    void UnregisterAccessCallback(uint64_t callbackId);
    
    /**
     * @brief Register blocked access callback
     */
    [[nodiscard]] uint64_t RegisterBlockedAccessCallback(BlockedAccessCallback callback);
    
    /**
     * @brief Unregister blocked access callback
     */
    void UnregisterBlockedAccessCallback(uint64_t callbackId);
    
    /**
     * @brief Register protection status callback
     */
    [[nodiscard]] uint64_t RegisterProtectionStatusCallback(ProtectionStatusCallback callback);
    
    /**
     * @brief Unregister protection status callback
     */
    void UnregisterProtectionStatusCallback(uint64_t callbackId);
    
    /**
     * @brief Register threat callback
     */
    [[nodiscard]] uint64_t RegisterThreatCallback(ThreatCallback callback);
    
    /**
     * @brief Unregister threat callback
     */
    void UnregisterThreatCallback(uint64_t callbackId);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] ProcessProtectionStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics(std::string_view authorizationToken);
    
    /**
     * @brief Get blocked access history
     */
    [[nodiscard]] std::vector<BlockedAccessEvent> GetBlockedAccessHistory(size_t maxEntries = 100) const;
    
    /**
     * @brief Clear blocked access history
     */
    void ClearBlockedAccessHistory(std::string_view authorizationToken);
    
    /**
     * @brief Export report
     */
    [[nodiscard]] std::string ExportReport() const;
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Self-test protection mechanisms
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Verify process integrity
     */
    [[nodiscard]] bool VerifyProcessIntegrity(uint32_t processId);
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    ProcessProtection();
    ~ProcessProtection();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<ProcessProtectionImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get protection type name
 */
[[nodiscard]] std::string_view GetProtectionTypeName(ProtectionType type) noexcept;

/**
 * @brief Get protection signer name
 */
[[nodiscard]] std::string_view GetProtectionSignerName(ProtectionSigner signer) noexcept;

/**
 * @brief Get protection status name
 */
[[nodiscard]] std::string_view GetProtectionStatusName(ProtectionStatus status) noexcept;

/**
 * @brief Get access request type name
 */
[[nodiscard]] std::string_view GetAccessRequestTypeName(AccessRequestType type) noexcept;

/**
 * @brief Get threat action name
 */
[[nodiscard]] std::string_view GetThreatActionName(ThreatAction action) noexcept;

/**
 * @brief Format access rights for display
 */
[[nodiscard]] std::string FormatAccessRights(uint32_t accessRights, bool isThread = false);

// ============================================================================
// RAII HELPERS
// ============================================================================

/**
 * @class ProcessProtectionGuard
 * @brief RAII wrapper for temporary process protection
 */
class ProcessProtectionGuard final {
public:
    explicit ProcessProtectionGuard(uint32_t processId = 0);
    ~ProcessProtectionGuard();
    
    ProcessProtectionGuard(const ProcessProtectionGuard&) = delete;
    ProcessProtectionGuard& operator=(const ProcessProtectionGuard&) = delete;
    
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
#define SS_PROTECT_PROCESS() \
    ::ShadowStrike::Security::ProcessProtection::Instance().ProtectProcess(::GetCurrentProcessId())

/**
 * @brief Check if current process is PPL protected
 */
#define SS_IS_PPL_PROTECTED() \
    ::ShadowStrike::Security::ProcessProtection::Instance().IsPPLProtected()

/**
 * @brief Get current process protection level
 */
#define SS_GET_PROTECTION_LEVEL() \
    ::ShadowStrike::Security::ProcessProtection::Instance().GetProtectionLevel(::GetCurrentProcessId())

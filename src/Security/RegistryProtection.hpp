/**
 * ============================================================================
 * ShadowStrike Security - REGISTRY PROTECTION ENGINE
 * ============================================================================
 *
 * @file RegistryProtection.hpp
 * @brief Enterprise-grade registry protection system for securing ShadowStrike
 *        configuration keys, service entries, and startup persistence.
 *
 * This module implements comprehensive registry protection mechanisms to prevent
 * malware from modifying, deleting, or tampering with critical antivirus registry
 * entries and configuration.
 *
 * PROTECTION MECHANISMS:
 * ======================
 *
 * 1. KEY LOCKDOWN
 *    - Service configuration protection
 *    - Startup entry protection
 *    - Driver registry protection
 *    - Configuration key protection
 *    - License key protection
 *
 * 2. OPERATION FILTERING
 *    - Key creation blocking
 *    - Key deletion blocking
 *    - Value modification blocking
 *    - Permission change blocking
 *    - Ownership change blocking
 *
 * 3. MINIFILTER/CALLBACK INTEGRATION
 *    - CmRegisterCallbackEx integration
 *    - Pre-operation callbacks
 *    - Post-operation callbacks
 *    - Transaction support
 *    - Callback context management
 *
 * 4. INTEGRITY MONITORING
 *    - Value hash verification
 *    - Change detection
 *    - Baseline management
 *    - Real-time monitoring
 *    - Silent rollback capability
 *
 * 5. ACCESS CONTROL
 *    - DACL enforcement
 *    - ACE manipulation protection
 *    - Ownership protection
 *    - Inheritance control
 *    - Mandatory integrity labels
 *
 * 6. ROLLBACK CAPABILITY
 *    - Automatic value restoration
 *    - Key structure restoration
 *    - Transaction-based rollback
 *    - Snapshot management
 *    - Version history
 *
 * 7. PERSISTENCE PROTECTION
 *    - Run key protection
 *    - RunOnce key protection
 *    - Service start type protection
 *    - Driver load order protection
 *    - Shell extension protection
 *
 * PROTECTED REGISTRY AREAS:
 * =========================
 * - HKLM\SOFTWARE\ShadowStrike\*
 * - HKLM\SYSTEM\CurrentControlSet\Services\ShadowStrike*
 * - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
 * - HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\*
 * - HKCU\SOFTWARE\ShadowStrike\*
 *
 * @note Full protection requires kernel-mode registry callback.
 * @note User-mode protection available with polling-based monitoring.
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
#include <any>

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
#  include <winreg.h>
#  include <Aclapi.h>
#  include <Sddl.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Security {
    class RegistryProtectionImpl;
    class TamperProtection;
    class SelfDefense;
}

namespace ShadowStrike {
namespace Security {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace RegistryProtectionConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum protected keys
    inline constexpr size_t MAX_PROTECTED_KEYS = 200;
    
    /// @brief Maximum protected values
    inline constexpr size_t MAX_PROTECTED_VALUES = 1000;
    
    /// @brief Maximum key path length
    inline constexpr size_t MAX_KEY_PATH_LENGTH = 512;
    
    /// @brief Maximum value name length
    inline constexpr size_t MAX_VALUE_NAME_LENGTH = 256;
    
    /// @brief Maximum value data size for hashing
    inline constexpr size_t MAX_VALUE_DATA_SIZE = 1 * 1024 * 1024;
    
    /// @brief Maximum snapshots per key
    inline constexpr size_t MAX_SNAPSHOTS_PER_KEY = 10;
    
    /// @brief Maximum blocked operations log
    inline constexpr size_t MAX_BLOCKED_OPERATIONS_LOG = 1000;

    // ========================================================================
    // INTERVALS
    // ========================================================================
    
    /// @brief Integrity check interval (milliseconds)
    inline constexpr uint32_t INTEGRITY_CHECK_INTERVAL_MS = 30000;
    
    /// @brief Polling interval for user-mode monitoring (milliseconds)
    inline constexpr uint32_t POLLING_INTERVAL_MS = 5000;
    
    /// @brief Rollback delay (milliseconds)
    inline constexpr uint32_t ROLLBACK_DELAY_MS = 100;

    // ========================================================================
    // HASH SIZE
    // ========================================================================
    
    inline constexpr size_t SHA256_SIZE = 32;

    // ========================================================================
    // DEFAULT PROTECTED KEYS
    // ========================================================================
    
    inline constexpr std::array<std::wstring_view, 10> DEFAULT_PROTECTED_KEYS = {
        L"HKLM\\SOFTWARE\\ShadowStrike",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikeService",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikeDriver",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"HKCU\\SOFTWARE\\ShadowStrike",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\ShadowStrikeService",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\ShadowStrikeService",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    };

}  // namespace RegistryProtectionConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using Milliseconds = std::chrono::milliseconds;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Registry protection mode
 */
enum class RegistryProtectionMode : uint8_t {
    Disabled    = 0,    ///< No protection
    Monitor     = 1,    ///< Monitor and log only
    Protect     = 2,    ///< Monitor and block
    Rollback    = 3,    ///< Monitor, block, and rollback
    Strict      = 4     ///< Strict enforcement
};

/**
 * @brief Registry operation type
 */
enum class RegistryOperation : uint32_t {
    None                = 0x00000000,
    QueryKey            = 0x00000001,
    SetValue            = 0x00000002,
    DeleteValue         = 0x00000004,
    CreateKey           = 0x00000008,
    DeleteKey           = 0x00000010,
    RenameKey           = 0x00000020,
    EnumerateKey        = 0x00000040,
    EnumerateValue      = 0x00000080,
    QueryValue          = 0x00000100,
    SetKeySecurity      = 0x00000200,
    QueryKeySecurity    = 0x00000400,
    FlushKey            = 0x00000800,
    LoadKey             = 0x00001000,
    UnloadKey           = 0x00002000,
    SaveKey             = 0x00004000,
    RestoreKey          = 0x00008000,
    
    AllWrite            = SetValue | DeleteValue | CreateKey | DeleteKey | RenameKey | SetKeySecurity,
    AllRead             = QueryKey | EnumerateKey | EnumerateValue | QueryValue | QueryKeySecurity,
    All                 = 0xFFFFFFFF
};

inline constexpr RegistryOperation operator|(RegistryOperation a, RegistryOperation b) noexcept {
    return static_cast<RegistryOperation>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr RegistryOperation operator&(RegistryOperation a, RegistryOperation b) noexcept {
    return static_cast<RegistryOperation>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * @brief Registry value type
 */
enum class RegistryValueType : uint32_t {
    None            = REG_NONE,
    String          = REG_SZ,
    ExpandString    = REG_EXPAND_SZ,
    Binary          = REG_BINARY,
    DWord           = REG_DWORD,
    DWordBigEndian  = REG_DWORD_BIG_ENDIAN,
    Link            = REG_LINK,
    MultiString     = REG_MULTI_SZ,
    ResourceList    = REG_RESOURCE_LIST,
    FullResourceDesc= REG_FULL_RESOURCE_DESCRIPTOR,
    ResourceReqList = REG_RESOURCE_REQUIREMENTS_LIST,
    QWord           = REG_QWORD
};

/**
 * @brief Protection type
 */
enum class KeyProtectionType : uint8_t {
    None            = 0,
    ReadOnly        = 1,    ///< Allow reads, block writes
    NoDelete        = 2,    ///< Allow writes, block delete
    NoModify        = 3,    ///< Block all modifications
    Full            = 4,    ///< Full protection
    ValuesOnly      = 5,    ///< Protect values, allow key operations
    Custom          = 6     ///< Custom operation mask
};

/**
 * @brief Integrity status
 */
enum class IntegrityStatus : uint8_t {
    Unknown     = 0,
    Valid       = 1,
    Modified    = 2,
    Missing     = 3,
    Corrupted   = 4,
    New         = 5,
    Restored    = 6
};

/**
 * @brief Operation decision
 */
enum class OperationDecision : uint8_t {
    Allow       = 0,
    Block       = 1,
    AllowLogged = 2,
    Rollback    = 3,
    Defer       = 4
};

/**
 * @brief Protection event type
 */
enum class ProtectionEventType : uint32_t {
    None                    = 0x00000000,
    OperationBlocked        = 0x00000001,
    OperationAllowed        = 0x00000002,
    IntegrityViolation      = 0x00000004,
    UnauthorizedAccess      = 0x00000008,
    KeyCreated              = 0x00000010,
    KeyDeleted              = 0x00000020,
    ValueModified           = 0x00000040,
    ValueDeleted            = 0x00000080,
    RollbackPerformed       = 0x00000100,
    SnapshotCreated         = 0x00000200,
    SnapshotRestored        = 0x00000400,
    
    All                     = 0xFFFFFFFF
};

inline constexpr ProtectionEventType operator|(ProtectionEventType a, ProtectionEventType b) noexcept {
    return static_cast<ProtectionEventType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Protection response
 */
enum class ProtectionResponse : uint32_t {
    None            = 0x00000000,
    Log             = 0x00000001,
    Alert           = 0x00000002,
    Block           = 0x00000004,
    Rollback        = 0x00000008,
    Snapshot        = 0x00000010,
    TerminateSource = 0x00000020,
    Escalate        = 0x00000040,
    
    Passive         = Log | Alert,
    Active          = Log | Alert | Block,
    Aggressive      = Log | Alert | Block | Rollback | TerminateSource
};

inline constexpr ProtectionResponse operator|(ProtectionResponse a, ProtectionResponse b) noexcept {
    return static_cast<ProtectionResponse>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
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
 * @brief Registry protection configuration
 */
struct RegistryProtectionConfiguration {
    /// @brief Protection mode
    RegistryProtectionMode mode = RegistryProtectionMode::Protect;
    
    /// @brief Enable kernel-mode callbacks (requires driver)
    bool enableKernelCallbacks = true;
    
    /// @brief Enable user-mode polling (fallback)
    bool enableUserModePolling = true;
    
    /// @brief Polling interval (milliseconds)
    uint32_t pollingIntervalMs = RegistryProtectionConstants::POLLING_INTERVAL_MS;
    
    /// @brief Enable integrity monitoring
    bool enableIntegrityMonitoring = true;
    
    /// @brief Integrity check interval (milliseconds)
    uint32_t integrityCheckIntervalMs = RegistryProtectionConstants::INTEGRITY_CHECK_INTERVAL_MS;
    
    /// @brief Enable automatic rollback
    bool enableAutoRollback = true;
    
    /// @brief Create snapshots before modifications
    bool enableSnapshots = true;
    
    /// @brief Maximum snapshots per key
    uint32_t maxSnapshotsPerKey = RegistryProtectionConstants::MAX_SNAPSHOTS_PER_KEY;
    
    /// @brief Default protection response
    ProtectionResponse defaultResponse = ProtectionResponse::Active;
    
    /// @brief Protected key paths
    std::vector<std::wstring> protectedKeys;
    
    /// @brief Whitelisted processes
    std::vector<std::wstring> whitelistedProcesses;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /// @brief Send telemetry
    bool sendTelemetry = true;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
    
    /**
     * @brief Create from protection mode
     */
    static RegistryProtectionConfiguration FromMode(RegistryProtectionMode mode);
};

/**
 * @brief Protected registry key information
 */
struct ProtectedKey {
    /// @brief Key identifier
    std::string id;
    
    /// @brief Full key path
    std::wstring keyPath;
    
    /// @brief Normalized path
    std::wstring normalizedPath;
    
    /// @brief Root key handle
    HKEY rootKey = nullptr;
    
    /// @brief Protection type
    KeyProtectionType type = KeyProtectionType::Full;
    
    /// @brief Blocked operations mask
    RegistryOperation blockedOperations = RegistryOperation::AllWrite;
    
    /// @brief Include subkeys
    bool includeSubkeys = true;
    
    /// @brief Protected values (empty = all values)
    std::vector<std::wstring> protectedValues;
    
    /// @brief Excluded values
    std::vector<std::wstring> excludedValues;
    
    /// @brief Integrity status
    IntegrityStatus integrity = IntegrityStatus::Unknown;
    
    /// @brief Protection timestamp
    TimePoint protectedSince;
    
    /// @brief Last verified timestamp
    TimePoint lastVerified;
    
    /// @brief Blocked operation count
    std::atomic<uint64_t> blockedOperations_{0};
    
    /// @brief Has snapshot
    bool hasSnapshot = false;
    
    /// @brief Last snapshot time
    TimePoint lastSnapshotTime;
};

/**
 * @brief Protected registry value information
 */
struct ProtectedValue {
    /// @brief Value identifier
    std::string id;
    
    /// @brief Key path
    std::wstring keyPath;
    
    /// @brief Value name
    std::wstring valueName;
    
    /// @brief Value type
    RegistryValueType valueType = RegistryValueType::None;
    
    /// @brief Expected data hash
    Hash256 expectedHash{};
    
    /// @brief Current data hash
    Hash256 currentHash{};
    
    /// @brief Expected data (for small values)
    std::vector<uint8_t> expectedData;
    
    /// @brief Data size
    size_t dataSize = 0;
    
    /// @brief Integrity status
    IntegrityStatus integrity = IntegrityStatus::Unknown;
    
    /// @brief Protection timestamp
    TimePoint protectedSince;
    
    /// @brief Last verified timestamp
    TimePoint lastVerified;
    
    /// @brief Modification count
    uint32_t modificationCount = 0;
};

/**
 * @brief Registry key snapshot
 */
struct KeySnapshot {
    /// @brief Snapshot ID
    std::string id;
    
    /// @brief Key path
    std::wstring keyPath;
    
    /// @brief Snapshot timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Values snapshot
    std::vector<std::pair<std::wstring, std::vector<uint8_t>>> values;
    
    /// @brief Value types
    std::vector<std::pair<std::wstring, RegistryValueType>> valueTypes;
    
    /// @brief Subkey names
    std::vector<std::wstring> subkeys;
    
    /// @brief Security descriptor (SDDL)
    std::wstring securityDescriptor;
    
    /// @brief Snapshot version
    uint32_t version = 0;
    
    /// @brief Snapshot reason
    std::string reason;
};

/**
 * @brief Registry operation request
 */
struct RegistryOperationRequest {
    /// @brief Operation type
    RegistryOperation operation = RegistryOperation::None;
    
    /// @brief Key path
    std::wstring keyPath;
    
    /// @brief Value name (for value operations)
    std::wstring valueName;
    
    /// @brief New value data (for set operations)
    std::vector<uint8_t> newData;
    
    /// @brief Value type (for set operations)
    RegistryValueType valueType = RegistryValueType::None;
    
    /// @brief Requesting process ID
    uint32_t processId = 0;
    
    /// @brief Requesting thread ID
    uint32_t threadId = 0;
    
    /// @brief Requesting process name
    std::wstring processName;
    
    /// @brief Requesting process path
    std::wstring processPath;
    
    /// @brief Requested access rights
    uint32_t desiredAccess = 0;
    
    /// @brief Request timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Is requesting process elevated
    bool isElevated = false;
    
    /// @brief Is requesting process system
    bool isSystem = false;
    
    /// @brief Is requesting process whitelisted
    bool isWhitelisted = false;
};

/**
 * @brief Operation decision result
 */
struct OperationDecisionResult {
    /// @brief Decision
    OperationDecision decision = OperationDecision::Allow;
    
    /// @brief Reason for decision
    std::string reason;
    
    /// @brief Should log this decision
    bool shouldLog = false;
    
    /// @brief Should alert on this decision
    bool shouldAlert = false;
    
    /// @brief Should create snapshot before operation
    bool shouldSnapshot = false;
    
    /// @brief Should rollback after operation
    bool shouldRollback = false;
};

/**
 * @brief Registry protection event
 */
struct RegistryProtectionEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Event type
    ProtectionEventType type = ProtectionEventType::None;
    
    /// @brief Event timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Affected key path
    std::wstring keyPath;
    
    /// @brief Affected value name
    std::wstring valueName;
    
    /// @brief Registry operation
    RegistryOperation operation = RegistryOperation::None;
    
    /// @brief Operation decision
    OperationDecision decision = OperationDecision::Allow;
    
    /// @brief Source process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Source process name
    std::wstring sourceProcessName;
    
    /// @brief Source process path
    std::wstring sourceProcessPath;
    
    /// @brief Response taken
    ProtectionResponse responseTaken = ProtectionResponse::None;
    
    /// @brief Was blocked
    bool wasBlocked = false;
    
    /// @brief Was rolled back
    bool wasRolledBack = false;
    
    /// @brief Event description
    std::string description;
    
    /// @brief Previous value hash
    Hash256 previousHash{};
    
    /// @brief New value hash
    Hash256 newHash{};
    
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
 * @brief Registry protection statistics
 */
struct RegistryProtectionStatistics {
    /// @brief Total protected keys
    std::atomic<uint64_t> totalProtectedKeys{0};
    
    /// @brief Total protected values
    std::atomic<uint64_t> totalProtectedValues{0};
    
    /// @brief Total operations processed
    std::atomic<uint64_t> totalOperations{0};
    
    /// @brief Total operations blocked
    std::atomic<uint64_t> totalBlocked{0};
    
    /// @brief Total rollbacks performed
    std::atomic<uint64_t> totalRollbacks{0};
    
    /// @brief Total integrity checks
    std::atomic<uint64_t> totalIntegrityChecks{0};
    
    /// @brief Integrity violations
    std::atomic<uint64_t> integrityViolations{0};
    
    /// @brief Snapshots created
    std::atomic<uint64_t> snapshotsCreated{0};
    
    /// @brief Snapshots restored
    std::atomic<uint64_t> snapshotsRestored{0};
    
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

/// @brief Callback for protection events
using RegistryEventCallback = std::function<void(const RegistryProtectionEvent&)>;

/// @brief Callback for operation decisions (can override)
using OperationDecisionCallback = std::function<std::optional<OperationDecisionResult>(
    const RegistryOperationRequest&)>;

/// @brief Callback for integrity violations
using IntegrityCallback = std::function<void(const ProtectedKey&)>;

/// @brief Callback for value changes
using ValueChangeCallback = std::function<void(const ProtectedValue&, 
                                               const std::vector<uint8_t>& oldData,
                                               const std::vector<uint8_t>& newData)>;

// ============================================================================
// REGISTRY PROTECTION ENGINE CLASS
// ============================================================================

/**
 * @class RegistryProtection
 * @brief Enterprise-grade registry protection engine
 *
 * Provides comprehensive registry protection including key lockdown,
 * integrity monitoring, automatic rollback, and tamper detection.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& regProtection = RegistryProtection::Instance();
 *     
 *     RegistryProtectionConfiguration config;
 *     config.mode = RegistryProtectionMode::Rollback;
 *     config.enableAutoRollback = true;
 *     
 *     if (!regProtection.Initialize(config)) {
 *         LOG_ERROR("Failed to initialize registry protection");
 *     }
 *     
 *     // Protect ShadowStrike registry keys
 *     regProtection.ProtectKey(L"HKLM\\SOFTWARE\\ShadowStrike");
 *     
 *     // Check if operation is allowed
 *     bool allowed = regProtection.IsOperationAllowed(keyPath, opType);
 * @endcode
 */
class RegistryProtection final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static RegistryProtection& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    RegistryProtection(const RegistryProtection&) = delete;
    RegistryProtection& operator=(const RegistryProtection&) = delete;
    RegistryProtection(RegistryProtection&&) = delete;
    RegistryProtection& operator=(RegistryProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize registry protection
     */
    [[nodiscard]] bool Initialize(const RegistryProtectionConfiguration& config = {});
    
    /**
     * @brief Initialize with protection mode
     */
    [[nodiscard]] bool Initialize(RegistryProtectionMode mode);
    
    /**
     * @brief Shutdown registry protection
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
    [[nodiscard]] bool SetConfiguration(const RegistryProtectionConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] RegistryProtectionConfiguration GetConfiguration() const;
    
    /**
     * @brief Set protection mode
     */
    void SetProtectionMode(RegistryProtectionMode mode);
    
    /**
     * @brief Get protection mode
     */
    [[nodiscard]] RegistryProtectionMode GetProtectionMode() const noexcept;
    
    // ========================================================================
    // KEY PROTECTION
    // ========================================================================
    
    /**
     * @brief Register critical key for protection
     */
    void ProtectKey(const std::wstring& keyPath);
    
    /**
     * @brief Protect key with options
     */
    [[nodiscard]] bool ProtectKey(std::wstring_view keyPath, KeyProtectionType type,
                                  bool includeSubkeys = true);
    
    /**
     * @brief Unprotect key
     */
    [[nodiscard]] bool UnprotectKey(std::wstring_view keyPath, 
                                    std::string_view authorizationToken);
    
    /**
     * @brief Check if key is protected
     */
    [[nodiscard]] bool IsKeyProtected(std::wstring_view keyPath) const;
    
    /**
     * @brief Get protected key info
     */
    [[nodiscard]] std::optional<ProtectedKey> GetProtectedKey(std::wstring_view keyPath) const;
    
    /**
     * @brief Get all protected keys
     */
    [[nodiscard]] std::vector<ProtectedKey> GetAllProtectedKeys() const;
    
    /**
     * @brief Protect ShadowStrike service keys
     */
    [[nodiscard]] bool ProtectServiceKeys();
    
    /**
     * @brief Protect startup entries
     */
    [[nodiscard]] bool ProtectStartupEntries();
    
    // ========================================================================
    // VALUE PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect specific value
     */
    [[nodiscard]] bool ProtectValue(std::wstring_view keyPath, std::wstring_view valueName);
    
    /**
     * @brief Unprotect specific value
     */
    [[nodiscard]] bool UnprotectValue(std::wstring_view keyPath, std::wstring_view valueName,
                                      std::string_view authorizationToken);
    
    /**
     * @brief Check if value is protected
     */
    [[nodiscard]] bool IsValueProtected(std::wstring_view keyPath, 
                                        std::wstring_view valueName) const;
    
    /**
     * @brief Get protected value info
     */
    [[nodiscard]] std::optional<ProtectedValue> GetProtectedValue(
        std::wstring_view keyPath, std::wstring_view valueName) const;
    
    /**
     * @brief Get all protected values for a key
     */
    [[nodiscard]] std::vector<ProtectedValue> GetProtectedValues(std::wstring_view keyPath) const;
    
    // ========================================================================
    // OPERATION FILTERING
    // ========================================================================
    
    /**
     * @brief Check if registry operation is allowed
     */
    [[nodiscard]] bool IsOperationAllowed(const std::wstring& keyPath, uint32_t opType);
    
    /**
     * @brief Filter registry operation request
     */
    [[nodiscard]] OperationDecisionResult FilterOperation(const RegistryOperationRequest& request);
    
    /**
     * @brief Set custom decision callback
     */
    void SetDecisionCallback(OperationDecisionCallback callback);
    
    /**
     * @brief Clear custom decision callback
     */
    void ClearDecisionCallback();
    
    // ========================================================================
    // INTEGRITY MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Verify key integrity
     */
    [[nodiscard]] IntegrityStatus VerifyKeyIntegrity(std::wstring_view keyPath);
    
    /**
     * @brief Verify value integrity
     */
    [[nodiscard]] IntegrityStatus VerifyValueIntegrity(std::wstring_view keyPath,
                                                       std::wstring_view valueName);
    
    /**
     * @brief Verify all protected keys
     */
    [[nodiscard]] std::vector<std::pair<std::wstring, IntegrityStatus>> VerifyAllIntegrity();
    
    /**
     * @brief Update key baseline
     */
    [[nodiscard]] bool UpdateKeyBaseline(std::wstring_view keyPath, 
                                         std::string_view authorizationToken);
    
    /**
     * @brief Update value baseline
     */
    [[nodiscard]] bool UpdateValueBaseline(std::wstring_view keyPath, std::wstring_view valueName,
                                           std::string_view authorizationToken);
    
    /**
     * @brief Force integrity check
     */
    void ForceIntegrityCheck();
    
    // ========================================================================
    // SNAPSHOT AND ROLLBACK
    // ========================================================================
    
    /**
     * @brief Create key snapshot
     */
    [[nodiscard]] bool CreateSnapshot(std::wstring_view keyPath);
    
    /**
     * @brief Restore from snapshot
     */
    [[nodiscard]] bool RestoreFromSnapshot(std::wstring_view keyPath, uint32_t version = 0);
    
    /**
     * @brief Get available snapshots for key
     */
    [[nodiscard]] std::vector<KeySnapshot> GetAvailableSnapshots(std::wstring_view keyPath) const;
    
    /**
     * @brief Rollback key to baseline
     */
    [[nodiscard]] bool RollbackKey(std::wstring_view keyPath);
    
    /**
     * @brief Rollback value to baseline
     */
    [[nodiscard]] bool RollbackValue(std::wstring_view keyPath, std::wstring_view valueName);
    
    /**
     * @brief Delete old snapshots
     */
    void CleanupOldSnapshots();
    
    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add process to whitelist
     */
    [[nodiscard]] bool AddToWhitelist(std::wstring_view processName,
                                      std::string_view authorizationToken);
    
    /**
     * @brief Remove process from whitelist
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
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Register event callback
     */
    [[nodiscard]] uint64_t RegisterEventCallback(RegistryEventCallback callback);
    
    /**
     * @brief Unregister event callback
     */
    void UnregisterEventCallback(uint64_t callbackId);
    
    /**
     * @brief Register integrity callback
     */
    [[nodiscard]] uint64_t RegisterIntegrityCallback(IntegrityCallback callback);
    
    /**
     * @brief Unregister integrity callback
     */
    void UnregisterIntegrityCallback(uint64_t callbackId);
    
    /**
     * @brief Register value change callback
     */
    [[nodiscard]] uint64_t RegisterValueChangeCallback(ValueChangeCallback callback);
    
    /**
     * @brief Unregister value change callback
     */
    void UnregisterValueChangeCallback(uint64_t callbackId);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] RegistryProtectionStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics(std::string_view authorizationToken);
    
    /**
     * @brief Get event history
     */
    [[nodiscard]] std::vector<RegistryProtectionEvent> GetEventHistory(size_t maxEntries = 100) const;
    
    /**
     * @brief Clear event history
     */
    void ClearEventHistory(std::string_view authorizationToken);
    
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
     * @brief Normalize key path
     */
    [[nodiscard]] static std::wstring NormalizeKeyPath(std::wstring_view keyPath);
    
    /**
     * @brief Parse root key from path
     */
    [[nodiscard]] static HKEY ParseRootKey(std::wstring_view keyPath);
    
    /**
     * @brief Get subkey path (without root)
     */
    [[nodiscard]] static std::wstring GetSubkeyPath(std::wstring_view fullPath);
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    RegistryProtection();
    ~RegistryProtection();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<RegistryProtectionImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get protection mode name
 */
[[nodiscard]] std::string_view GetProtectionModeName(RegistryProtectionMode mode) noexcept;

/**
 * @brief Get registry operation name
 */
[[nodiscard]] std::string_view GetRegistryOperationName(RegistryOperation operation) noexcept;

/**
 * @brief Get key protection type name
 */
[[nodiscard]] std::string_view GetProtectionTypeName(KeyProtectionType type) noexcept;

/**
 * @brief Get integrity status name
 */
[[nodiscard]] std::string_view GetIntegrityStatusName(IntegrityStatus status) noexcept;

/**
 * @brief Get value type name
 */
[[nodiscard]] std::string_view GetValueTypeName(RegistryValueType type) noexcept;

/**
 * @brief Format registry operation for display
 */
[[nodiscard]] std::string FormatRegistryOperation(RegistryOperation operation);

// ============================================================================
// RAII HELPERS
// ============================================================================

/**
 * @class RegistryProtectionGuard
 * @brief RAII wrapper for temporary key protection
 */
class RegistryProtectionGuard final {
public:
    explicit RegistryProtectionGuard(std::wstring_view keyPath, 
                                     KeyProtectionType type = KeyProtectionType::Full);
    ~RegistryProtectionGuard();
    
    RegistryProtectionGuard(const RegistryProtectionGuard&) = delete;
    RegistryProtectionGuard& operator=(const RegistryProtectionGuard&) = delete;
    
    [[nodiscard]] bool IsProtected() const noexcept { return m_protected; }

private:
    std::wstring m_keyPath;
    bool m_protected = false;
    std::string m_authToken;
};

}  // namespace Security
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Protect ShadowStrike service keys
 */
#define SS_PROTECT_SERVICE_REGISTRY() \
    ::ShadowStrike::Security::RegistryProtection::Instance().ProtectServiceKeys()

/**
 * @brief Check if registry operation is allowed
 */
#define SS_IS_REG_OP_ALLOWED(path, op) \
    ::ShadowStrike::Security::RegistryProtection::Instance().IsOperationAllowed((path), (op))

/**
 * ============================================================================
 * ShadowStrike NGAV - USB DEVICE CONTROL MANAGER MODULE
 * ============================================================================
 *
 * @file DeviceControlManager.hpp
 * @brief Enterprise-grade USB device control policy engine for managing
 *        device access permissions based on organizational security policies.
 *
 * Provides comprehensive device control with granular access policies,
 * whitelisting, blacklisting, and audit logging for compliance.
 *
 * POLICY CAPABILITIES:
 * ====================
 *
 * 1. ACCESS CONTROL
 *    - Full access (read/write/execute)
 *    - Read-only access
 *    - Block all access
 *    - Quarantine mode (scan only)
 *    - Audit-only mode (log without enforcement)
 *
 * 2. DEVICE IDENTIFICATION
 *    - Vendor ID (VID)
 *    - Product ID (PID)
 *    - Serial number
 *    - Device class
 *    - Interface type
 *    - Wildcard matching
 *
 * 3. POLICY RULES
 *    - Rule priority ordering
 *    - Time-based rules
 *    - User/group-based rules
 *    - Location-based rules
 *    - Conditional rules
 *
 * 4. ENTERPRISE FEATURES
 *    - Group Policy integration
 *    - SIEM integration
 *    - Compliance reporting
 *    - Audit trail
 *    - Emergency override
 *
 * 5. DEVICE TYPES
 *    - Mass storage
 *    - HID devices
 *    - Network adapters
 *    - Imaging devices
 *    - Wireless devices
 *    - Smart card readers
 *
 * INTEGRATION:
 * ============
 * - Whitelist for trusted devices
 * - ThreatIntel for known bad devices
 * - ConfigManager for policy deployment
 * - USBDeviceMonitor for events
 *
 * @note Integrates with Windows Device Installation Policies.
 * @note Supports Active Directory GPO deployment.
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
#include <variant>
#include <span>

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
#include "../Utils/ProcessUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::USB {
    class DeviceControlManagerImpl;
    struct USBDeviceInfo;
}

namespace ShadowStrike {
namespace USB {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace DeviceControlConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum rules
    inline constexpr size_t MAX_RULES = 10000;
    
    /// @brief Maximum audit log entries
    inline constexpr size_t MAX_AUDIT_ENTRIES = 100000;
    
    /// @brief Rule ID prefix
    inline constexpr const char* RULE_ID_PREFIX = "DCR";
    
    /// @brief Wildcard character
    inline constexpr char WILDCARD_CHAR = '*';
    
    /// @brief USB device class codes
    namespace DeviceClass {
        inline constexpr uint8_t INTERFACE_SPECIFIC = 0x00;
        inline constexpr uint8_t AUDIO = 0x01;
        inline constexpr uint8_t COMMUNICATIONS = 0x02;
        inline constexpr uint8_t HID = 0x03;
        inline constexpr uint8_t PHYSICAL = 0x05;
        inline constexpr uint8_t IMAGE = 0x06;
        inline constexpr uint8_t PRINTER = 0x07;
        inline constexpr uint8_t MASS_STORAGE = 0x08;
        inline constexpr uint8_t HUB = 0x09;
        inline constexpr uint8_t CDC_DATA = 0x0A;
        inline constexpr uint8_t SMART_CARD = 0x0B;
        inline constexpr uint8_t CONTENT_SECURITY = 0x0D;
        inline constexpr uint8_t VIDEO = 0x0E;
        inline constexpr uint8_t WIRELESS = 0xE0;
    }

}  // namespace DeviceControlConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Access level
 */
enum class AccessLevel : uint8_t {
    FullAccess      = 0,    ///< Read, write, execute
    ReadOnly        = 1,    ///< Read only access
    WriteOnly       = 2,    ///< Write only (rare)
    NoExecute       = 3,    ///< Read/write but no execute
    Blocked         = 4,    ///< No access allowed
    QuarantineOnly  = 5,    ///< Scan/quarantine only
    AuditOnly       = 6,    ///< Log but don't enforce
    Custom          = 255   ///< Custom permissions
};

/**
 * @brief Device type category
 */
enum class DeviceCategory : uint8_t {
    Unknown         = 0,
    MassStorage     = 1,
    HIDKeyboard     = 2,
    HIDMouse        = 3,
    HIDOther        = 4,
    NetworkAdapter  = 5,
    ImagingDevice   = 6,
    Printer         = 7,
    AudioDevice     = 8,
    VideoDevice     = 9,
    SmartCard       = 10,
    WirelessDevice  = 11,
    Hub             = 12,
    Composite       = 13
};

/**
 * @brief Rule match type
 */
enum class RuleMatchType : uint8_t {
    Exact           = 0,    ///< Exact match
    Prefix          = 1,    ///< Prefix match
    Suffix          = 2,    ///< Suffix match
    Contains        = 3,    ///< Contains substring
    Regex           = 4,    ///< Regular expression
    Wildcard        = 5     ///< Wildcard pattern
};

/**
 * @brief Rule action
 */
enum class RuleAction : uint8_t {
    Allow           = 0,
    Deny            = 1,
    AllowReadOnly   = 2,
    AuditOnly       = 3,
    RequireApproval = 4,
    Quarantine      = 5
};

/**
 * @brief Rule priority
 */
enum class RulePriority : uint8_t {
    Critical        = 0,    ///< Highest priority
    High            = 25,
    Normal          = 50,
    Low             = 75,
    Default         = 100   ///< Lowest priority
};

/**
 * @brief Evaluation result
 */
enum class EvaluationResult : uint8_t {
    Allowed         = 0,
    AllowedReadOnly = 1,
    Blocked         = 2,
    Quarantined     = 3,
    PendingApproval = 4,
    NoMatchingRule  = 5,
    Error           = 255
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Device criteria for rule matching
 */
struct DeviceCriteria {
    /// @brief Vendor ID (optional, 0 = any)
    uint16_t vendorId = 0;
    
    /// @brief Product ID (optional, 0 = any)
    uint16_t productId = 0;
    
    /// @brief Serial number pattern
    std::string serialNumberPattern;
    
    /// @brief Device class (optional)
    std::optional<uint8_t> deviceClass;
    
    /// @brief Device category
    DeviceCategory category = DeviceCategory::Unknown;
    
    /// @brief Manufacturer pattern
    std::string manufacturerPattern;
    
    /// @brief Product name pattern
    std::string productNamePattern;
    
    /// @brief Match type for patterns
    RuleMatchType matchType = RuleMatchType::Wildcard;
    
    /// @brief Is any criteria (match all devices)
    bool isAnyCriteria = false;
    
    [[nodiscard]] bool Matches(const USBDeviceInfo& device) const;
    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] std::string ToCriteriaString() const;

    /// @brief Wildcard pattern matching helper
    [[nodiscard]] static bool MatchWildcard(const std::string& str, const std::string& pattern);
};

/**
 * @brief Time-based condition
 */
struct TimeCondition {
    /// @brief Enabled
    bool enabled = false;
    
    /// @brief Start time (hour:minute)
    std::chrono::minutes startTime{0};
    
    /// @brief End time (hour:minute)
    std::chrono::minutes endTime{1440};  // 24 hours
    
    /// @brief Days of week (bitmask: Sun=1, Mon=2, ..., Sat=64)
    uint8_t daysOfWeek = 0x7F;  // All days
    
    /// @brief Start date (optional)
    std::optional<SystemTimePoint> startDate;
    
    /// @brief End date (optional)
    std::optional<SystemTimePoint> endDate;
    
    [[nodiscard]] bool IsActive() const;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief User/group condition
 */
struct UserCondition {
    /// @brief Enabled
    bool enabled = false;
    
    /// @brief Allowed users
    std::vector<std::string> allowedUsers;
    
    /// @brief Allowed groups
    std::vector<std::string> allowedGroups;
    
    /// @brief Denied users
    std::vector<std::string> deniedUsers;
    
    /// @brief Denied groups
    std::vector<std::string> deniedGroups;
    
    [[nodiscard]] bool AllowsCurrentUser() const;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Device control rule
 */
struct DeviceRule {
    /// @brief Rule ID
    std::string ruleId;
    
    /// @brief Rule name
    std::string name;
    
    /// @brief Rule description
    std::string description;
    
    /// @brief Device criteria
    DeviceCriteria criteria;
    
    /// @brief Rule action
    RuleAction action = RuleAction::Deny;
    
    /// @brief Access level (if allowed)
    AccessLevel accessLevel = AccessLevel::Blocked;
    
    /// @brief Rule priority
    RulePriority priority = RulePriority::Normal;
    
    /// @brief Is rule enabled
    bool enabled = true;
    
    /// @brief Log audit events
    bool logAudit = true;
    
    /// @brief Notify user on match
    bool notifyUser = true;
    
    /// @brief Time condition
    TimeCondition timeCondition;
    
    /// @brief User condition
    UserCondition userCondition;
    
    /// @brief Custom message
    std::string customMessage;
    
    /// @brief Created time
    SystemTimePoint createdTime;
    
    /// @brief Modified time
    SystemTimePoint modifiedTime;
    
    /// @brief Created by (user/policy)
    std::string createdBy;
    
    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] static std::optional<DeviceRule> FromJson(const std::string& json);
};

/**
 * @brief Policy evaluation result
 */
struct PolicyEvaluationResult {
    /// @brief Result
    EvaluationResult result = EvaluationResult::NoMatchingRule;
    
    /// @brief Access level granted
    AccessLevel accessLevel = AccessLevel::Blocked;
    
    /// @brief Matching rule ID
    std::string matchingRuleId;
    
    /// @brief Matching rule name
    std::string matchingRuleName;
    
    /// @brief User message
    std::string userMessage;
    
    /// @brief Should notify user
    bool notifyUser = false;
    
    /// @brief Should audit log
    bool auditLog = true;
    
    /// @brief Evaluation time
    SystemTimePoint evaluationTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Audit log entry
 */
struct AuditLogEntry {
    /// @brief Entry ID
    uint64_t entryId = 0;
    
    /// @brief Device info
    std::string deviceId;
    std::string vendorId;
    std::string productId;
    std::string serialNumber;
    std::string deviceName;
    
    /// @brief Evaluation result
    EvaluationResult result = EvaluationResult::NoMatchingRule;
    
    /// @brief Access level granted
    AccessLevel accessLevel = AccessLevel::Blocked;
    
    /// @brief Rule applied
    std::string ruleId;
    std::string ruleName;
    
    /// @brief User info
    std::string userName;
    std::string machineName;
    
    /// @brief Event timestamp
    SystemTimePoint timestamp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct DeviceControlStatistics {
    std::atomic<uint64_t> totalEvaluations{0};
    std::atomic<uint64_t> devicesAllowed{0};
    std::atomic<uint64_t> devicesBlocked{0};
    std::atomic<uint64_t> devicesReadOnly{0};
    std::atomic<uint64_t> devicesQuarantined{0};
    std::atomic<uint64_t> ruleMatches{0};
    std::atomic<uint64_t> noRuleMatches{0};
    std::atomic<uint64_t> policyErrors{0};
    std::atomic<uint32_t> activeRules{0};
    std::atomic<uint32_t> disabledRules{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct DeviceControlConfiguration {
    /// @brief Enable device control
    bool enabled = true;
    
    /// @brief Default action (when no rule matches)
    RuleAction defaultAction = RuleAction::Deny;
    
    /// @brief Default access level
    AccessLevel defaultAccessLevel = AccessLevel::Blocked;
    
    /// @brief Enable audit logging
    bool enableAuditLog = true;
    
    /// @brief Maximum audit entries
    size_t maxAuditEntries = DeviceControlConstants::MAX_AUDIT_ENTRIES;
    
    /// @brief Enable user notifications
    bool enableUserNotifications = true;
    
    /// @brief Notify on block only
    bool notifyOnBlockOnly = true;
    
    /// @brief Block new devices by default
    bool blockNewDevicesByDefault = true;
    
    /// @brief Allow emergency override
    bool allowEmergencyOverride = false;
    
    /// @brief Override password hash (SHA-256)
    std::string emergencyOverridePasswordHash;
    
    /// @brief Policy refresh interval
    std::chrono::seconds policyRefreshInterval{300};  // 5 minutes
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using EvaluationCallback = std::function<void(const USBDeviceInfo&, const PolicyEvaluationResult&)>;
using AuditCallback = std::function<void(const AuditLogEntry&)>;
using RuleChangeCallback = std::function<void(const DeviceRule&, bool added)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// DEVICE CONTROL MANAGER CLASS
// ============================================================================

/**
 * @class DeviceControlManager
 * @brief Enterprise USB device control policy engine
 */
class DeviceControlManager final {
public:
    [[nodiscard]] static DeviceControlManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    DeviceControlManager(const DeviceControlManager&) = delete;
    DeviceControlManager& operator=(const DeviceControlManager&) = delete;
    DeviceControlManager(DeviceControlManager&&) = delete;
    DeviceControlManager& operator=(DeviceControlManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const DeviceControlConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const DeviceControlConfiguration& config);
    [[nodiscard]] DeviceControlConfiguration GetConfiguration() const;

    // ========================================================================
    // POLICY EVALUATION
    // ========================================================================
    
    /// @brief Evaluate device against policy
    [[nodiscard]] PolicyEvaluationResult EvaluateDevice(const USBDeviceInfo& device);
    
    /// @brief Evaluate device by identifiers
    [[nodiscard]] PolicyEvaluationResult EvaluateDevice(
        uint16_t vendorId,
        uint16_t productId,
        const std::string& serialNumber = "");
    
    /// @brief Check if device is allowed
    [[nodiscard]] bool IsDeviceAllowed(const USBDeviceInfo& device);
    
    /// @brief Get access level for device
    [[nodiscard]] AccessLevel GetAccessLevel(const USBDeviceInfo& device);

    // ========================================================================
    // RULE MANAGEMENT
    // ========================================================================
    
    /// @brief Add rule
    [[nodiscard]] bool AddRule(const DeviceRule& rule);
    
    /// @brief Update rule
    [[nodiscard]] bool UpdateRule(const DeviceRule& rule);
    
    /// @brief Remove rule
    [[nodiscard]] bool RemoveRule(const std::string& ruleId);
    
    /// @brief Enable/disable rule
    [[nodiscard]] bool SetRuleEnabled(const std::string& ruleId, bool enabled);
    
    /// @brief Get rule by ID
    [[nodiscard]] std::optional<DeviceRule> GetRule(const std::string& ruleId) const;
    
    /// @brief Get all rules
    [[nodiscard]] std::vector<DeviceRule> GetAllRules() const;
    
    /// @brief Get rules by priority
    [[nodiscard]] std::vector<DeviceRule> GetRulesByPriority() const;
    
    /// @brief Clear all rules
    void ClearAllRules();
    
    /// @brief Load rules from file
    [[nodiscard]] bool LoadRulesFromFile(const std::string& path);
    
    /// @brief Save rules to file
    [[nodiscard]] bool SaveRulesToFile(const std::string& path) const;

    // ========================================================================
    // AUDIT LOG
    // ========================================================================
    
    /// @brief Get audit log
    [[nodiscard]] std::vector<AuditLogEntry> GetAuditLog(
        size_t maxEntries = 1000,
        std::optional<SystemTimePoint> fromTime = std::nullopt,
        std::optional<SystemTimePoint> toTime = std::nullopt) const;
    
    /// @brief Export audit log
    [[nodiscard]] bool ExportAuditLog(const std::string& path) const;
    
    /// @brief Clear audit log
    void ClearAuditLog();

    // ========================================================================
    // EMERGENCY OVERRIDE
    // ========================================================================
    
    /// @brief Enable emergency override
    [[nodiscard]] bool EnableEmergencyOverride(const std::string& password);
    
    /// @brief Disable emergency override
    void DisableEmergencyOverride();
    
    /// @brief Check if override active
    [[nodiscard]] bool IsEmergencyOverrideActive() const noexcept;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterEvaluationCallback(EvaluationCallback callback);
    void RegisterAuditCallback(AuditCallback callback);
    void RegisterRuleChangeCallback(RuleChangeCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] DeviceControlStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    DeviceControlManager();
    ~DeviceControlManager();
    
    std::unique_ptr<DeviceControlManagerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetAccessLevelName(AccessLevel level) noexcept;
[[nodiscard]] std::string_view GetDeviceCategoryName(DeviceCategory cat) noexcept;
[[nodiscard]] std::string_view GetRuleActionName(RuleAction action) noexcept;
[[nodiscard]] std::string_view GetEvaluationResultName(EvaluationResult result) noexcept;
[[nodiscard]] DeviceCategory ClassifyDeviceClass(uint8_t classCode) noexcept;
[[nodiscard]] std::string GenerateRuleId();

}  // namespace USB
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_DEVICE_EVALUATE(device) \
    ::ShadowStrike::USB::DeviceControlManager::Instance().EvaluateDevice(device)

#define SS_DEVICE_ALLOWED(device) \
    ::ShadowStrike::USB::DeviceControlManager::Instance().IsDeviceAllowed(device)
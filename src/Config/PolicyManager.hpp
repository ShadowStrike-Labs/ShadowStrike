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
 * ShadowStrike NGAV - POLICY MANAGER MODULE
 * ============================================================================
 *
 * @file PolicyManager.hpp
 * @brief Enterprise-grade security policy management system with centralized
 *        policy distribution, enforcement, compliance monitoring, and auditing.
 *
 * Manages immutable enterprise security policies pushed from the central
 * management console, ensuring consistent security posture across all endpoints.
 *
 * POLICY MANAGEMENT CAPABILITIES:
 * ================================
 *
 * 1. POLICY DISTRIBUTION
 *    - Push from management console
 *    - Scheduled sync
 *    - Delta updates
 *    - Conflict resolution
 *    - Rollback support
 *
 * 2. ENFORCEMENT LEVELS
 *    - Mandatory (cannot be overridden)
 *    - Default (can be overridden)
 *    - Advisory (suggestions only)
 *    - Audit (log-only mode)
 *
 * 3. POLICY TYPES
 *    - Scan policies
 *    - Protection policies
 *    - Exclusion policies
 *    - Network policies
 *    - Device control policies
 *
 * 4. COMPLIANCE MONITORING
 *    - Policy adherence tracking
 *    - Violation detection
 *    - Remediation actions
 *    - Compliance reporting
 *
 * 5. AUDIT & REPORTING
 *    - Policy change logging
 *    - Enforcement audit trail
 *    - Compliance dashboards
 *    - Export capabilities
 *
 * @note Thread-safe singleton design.
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
#include <set>
#include <unordered_map>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>
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
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/XMLUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Config {
    class PolicyManagerImpl;
}

namespace ShadowStrike {
namespace Config {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace PolicyConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum policy name length
    inline constexpr size_t MAX_POLICY_NAME_LENGTH = 256;
    
    /// @brief Maximum policies per group
    inline constexpr size_t MAX_POLICIES_PER_GROUP = 1024;
    
    /// @brief Policy sync interval (seconds)
    inline constexpr uint32_t POLICY_SYNC_INTERVAL_SECONDS = 300;
    
    /// @brief Maximum policy history entries
    inline constexpr uint32_t MAX_POLICY_HISTORY = 1000;

}  // namespace PolicyConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

/// @brief Policy setting value
using PolicyValue = std::variant<
    std::monostate,
    bool,
    int64_t,
    double,
    std::string,
    std::vector<std::string>,
    std::map<std::string, std::string>
>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Policy enforcement level
 */
enum class EnforcementLevel : uint8_t {
    Mandatory       = 0,    ///< Cannot be overridden by user
    Default         = 1,    ///< Can be overridden (default)
    Advisory        = 2,    ///< Suggestion only (shown in UI)
    AuditOnly       = 3,    ///< Log violations but don't enforce
    Disabled        = 4     ///< Policy is disabled
};

/**
 * @brief Policy type
 */
enum class PolicyType : uint8_t {
    Scan            = 0,    ///< Scanning behavior
    Protection      = 1,    ///< Real-time protection settings
    Exclusion       = 2,    ///< File/path exclusions
    Network         = 3,    ///< Network security settings
    DeviceControl   = 4,    ///< USB/device control
    Application     = 5,    ///< Application control
    DataProtection  = 6,    ///< DLP settings
    Firewall        = 7,    ///< Firewall rules
    WebControl      = 8,    ///< Web filtering
    EmailControl    = 9,    ///< Email security
    Encryption      = 10,   ///< Encryption policies
    Update          = 11,   ///< Update settings
    Logging         = 12,   ///< Logging configuration
    Custom          = 13    ///< Custom/extension policies
};

/**
 * @brief Policy state
 */
enum class PolicyState : uint8_t {
    Active          = 0,    ///< Currently active
    Pending         = 1,    ///< Pending activation
    Superseded      = 2,    ///< Replaced by newer policy
    Expired         = 3,    ///< Past expiry date
    Revoked         = 4,    ///< Explicitly revoked
    Failed          = 5     ///< Failed to apply
};

/**
 * @brief Compliance status
 */
enum class ComplianceStatus : uint8_t {
    Compliant           = 0,
    NonCompliant        = 1,
    PartiallyCompliant  = 2,
    Pending             = 3,
    NotApplicable       = 4,
    Unknown             = 5
};

/**
 * @brief Policy action on violation
 */
enum class ViolationAction : uint8_t {
    Allow           = 0,    ///< Allow with warning
    Block           = 1,    ///< Block action
    Quarantine      = 2,    ///< Quarantine file
    Notify          = 3,    ///< Notify admin
    Remediate       = 4,    ///< Auto-remediate
    Audit           = 5     ///< Log only
};

/**
 * @brief Manager status
 */
enum class PolicyStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Syncing         = 3,
    Applying        = 4,
    Error           = 5,
    Stopping        = 6,
    Stopped         = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Policy setting
 */
struct PolicySetting {
    /// @brief Setting key
    std::string key;
    
    /// @brief Display name
    std::string displayName;
    
    /// @brief Value
    PolicyValue value;
    
    /// @brief Enforcement level
    EnforcementLevel enforcement = EnforcementLevel::Default;
    
    /// @brief Description
    std::string description;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Policy definition
 */
struct Policy {
    /// @brief Unique policy ID (GUID)
    std::string id;
    
    /// @brief Policy name
    std::string name;
    
    /// @brief Description
    std::string description;
    
    /// @brief Policy type
    PolicyType type = PolicyType::Custom;
    
    /// @brief State
    PolicyState state = PolicyState::Pending;
    
    /// @brief Enforcement level
    EnforcementLevel enforcement = EnforcementLevel::Default;
    
    /// @brief Is mandatory (cannot be locally disabled)
    bool isMandatory = false;
    
    /// @brief Priority (higher = takes precedence)
    uint32_t priority = 100;
    
    /// @brief Version
    uint32_t version = 1;
    
    /// @brief Settings
    std::map<std::string, PolicySetting> settings;
    
    /// @brief Target groups (empty = all)
    std::set<std::string> targetGroups;
    
    /// @brief Target machines (empty = all)
    std::set<std::string> targetMachines;
    
    /// @brief Effective from
    SystemTimePoint effectiveFrom;
    
    /// @brief Expires at (optional)
    std::optional<SystemTimePoint> expiresAt;
    
    /// @brief Created timestamp
    SystemTimePoint createdAt;
    
    /// @brief Last modified
    SystemTimePoint modifiedAt;
    
    /// @brief Created by
    std::string createdBy;
    
    /// @brief Signature (for integrity)
    std::vector<uint8_t> signature;
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] bool IsExpired() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Policy violation
 */
struct PolicyViolation {
    /// @brief Violation ID
    uint64_t violationId = 0;
    
    /// @brief Policy ID
    std::string policyId;
    
    /// @brief Setting key
    std::string settingKey;
    
    /// @brief Expected value
    PolicyValue expectedValue;
    
    /// @brief Actual value
    PolicyValue actualValue;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Machine name
    std::string machineName;
    
    /// @brief User name
    std::string userName;
    
    /// @brief Process that caused violation
    std::string processName;
    
    /// @brief Action taken
    ViolationAction action = ViolationAction::Audit;
    
    /// @brief Was remediated
    bool remediated = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Compliance report
 */
struct ComplianceReport {
    /// @brief Report ID
    uint64_t reportId = 0;
    
    /// @brief Machine name
    std::string machineName;
    
    /// @brief Overall status
    ComplianceStatus overallStatus = ComplianceStatus::Unknown;
    
    /// @brief Per-policy compliance
    std::map<std::string, ComplianceStatus> policyCompliance;
    
    /// @brief Total policies
    uint32_t totalPolicies = 0;
    
    /// @brief Compliant count
    uint32_t compliantCount = 0;
    
    /// @brief Non-compliant count
    uint32_t nonCompliantCount = 0;
    
    /// @brief Pending violations
    std::vector<PolicyViolation> pendingViolations;
    
    /// @brief Generated timestamp
    SystemTimePoint generatedAt;
    
    [[nodiscard]] double GetCompliancePercentage() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Policy sync result
 */
struct PolicySyncResult {
    /// @brief Success
    bool success = false;
    
    /// @brief New policies
    uint32_t newPolicies = 0;
    
    /// @brief Updated policies
    uint32_t updatedPolicies = 0;
    
    /// @brief Removed policies
    uint32_t removedPolicies = 0;
    
    /// @brief Failed to apply
    uint32_t failedPolicies = 0;
    
    /// @brief Sync timestamp
    SystemTimePoint syncTime;
    
    /// @brief Errors
    std::vector<std::string> errors;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct PolicyStatistics {
    std::atomic<uint64_t> policiesApplied{0};
    std::atomic<uint64_t> policiesActive{0};
    std::atomic<uint64_t> enforcementChecks{0};
    std::atomic<uint64_t> violationsDetected{0};
    std::atomic<uint64_t> violationsRemediated{0};
    std::atomic<uint64_t> syncOperations{0};
    std::atomic<uint64_t> syncFailures{0};
    std::array<std::atomic<uint64_t>, 16> byPolicyType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct PolicyManagerConfiguration {
    /// @brief Enable policy enforcement
    bool enabled = true;
    
    /// @brief Management server URL
    std::string managementServerUrl;
    
    /// @brief Sync interval (seconds)
    uint32_t syncIntervalSeconds = PolicyConstants::POLICY_SYNC_INTERVAL_SECONDS;
    
    /// @brief Enable auto-sync
    bool enableAutoSync = true;
    
    /// @brief Enable offline caching
    bool enableOfflineCache = true;
    
    /// @brief Offline cache path
    fs::path offlineCachePath;
    
    /// @brief Enable violation logging
    bool enableViolationLogging = true;
    
    /// @brief Enable auto-remediation
    bool enableAutoRemediation = false;
    
    /// @brief Maximum violation history
    uint32_t maxViolationHistory = 10000;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using PolicyChangeCallback = std::function<void(const Policy& policy, bool added)>;
using ViolationCallback = std::function<void(const PolicyViolation& violation)>;
using SyncCallback = std::function<void(const PolicySyncResult& result)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// POLICY MANAGER CLASS
// ============================================================================

/**
 * @class PolicyManager
 * @brief Enterprise policy management
 */
class PolicyManager final {
public:
    [[nodiscard]] static PolicyManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    PolicyManager(const PolicyManager&) = delete;
    PolicyManager& operator=(const PolicyManager&) = delete;
    PolicyManager(PolicyManager&&) = delete;
    PolicyManager& operator=(PolicyManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const PolicyManagerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] PolicyStatus GetStatus() const noexcept;

    // ========================================================================
    // POLICY APPLICATION
    // ========================================================================
    
    /// @brief Apply policy from server
    [[nodiscard]] bool ApplyPolicy(const Policy& policy);
    
    /// @brief Apply multiple policies
    [[nodiscard]] PolicySyncResult ApplyPolicies(const std::vector<Policy>& policies);
    
    /// @brief Remove policy
    [[nodiscard]] bool RemovePolicy(const std::string& policyId);
    
    /// @brief Activate policy
    [[nodiscard]] bool ActivatePolicy(const std::string& policyId);
    
    /// @brief Deactivate policy
    [[nodiscard]] bool DeactivatePolicy(const std::string& policyId);

    // ========================================================================
    // POLICY QUERY
    // ========================================================================
    
    /// @brief Get policy by ID
    [[nodiscard]] std::optional<Policy> GetPolicy(const std::string& policyId) const;
    
    /// @brief Get all policies
    [[nodiscard]] std::vector<Policy> GetAllPolicies() const;
    
    /// @brief Get policies by type
    [[nodiscard]] std::vector<Policy> GetPoliciesByType(PolicyType type) const;
    
    /// @brief Get active policies
    [[nodiscard]] std::vector<Policy> GetActivePolicies() const;
    
    /// @brief Get mandatory policies
    [[nodiscard]] std::vector<Policy> GetMandatoryPolicies() const;

    // ========================================================================
    // ENFORCEMENT
    // ========================================================================
    
    /// @brief Check if setting is enforced
    [[nodiscard]] bool IsEnforced(const std::string& settingName) const;
    
    /// @brief Get enforced value
    [[nodiscard]] std::optional<PolicyValue> GetEnforcedValue(const std::string& settingName) const;
    
    /// @brief Get policy value with original (deprecated)
    [[nodiscard]] std::string GetPolicyValue(const std::string& settingName) const;
    
    /// @brief Get enforcement level for setting
    [[nodiscard]] EnforcementLevel GetEnforcementLevel(const std::string& settingName) const;
    
    /// @brief Validate setting against policy
    [[nodiscard]] bool ValidateSetting(const std::string& key, const PolicyValue& value) const;

    // ========================================================================
    // COMPLIANCE
    // ========================================================================
    
    /// @brief Check compliance
    [[nodiscard]] ComplianceStatus CheckCompliance() const;
    
    /// @brief Generate compliance report
    [[nodiscard]] ComplianceReport GenerateComplianceReport() const;
    
    /// @brief Get compliance percentage
    [[nodiscard]] double GetCompliancePercentage() const;
    
    /// @brief Get pending violations
    [[nodiscard]] std::vector<PolicyViolation> GetPendingViolations() const;
    
    /// @brief Remediate violation
    [[nodiscard]] bool RemediateViolation(uint64_t violationId);

    // ========================================================================
    // SYNCHRONIZATION
    // ========================================================================
    
    /// @brief Sync with management server
    [[nodiscard]] PolicySyncResult SyncWithServer();
    
    /// @brief Force immediate sync
    [[nodiscard]] PolicySyncResult ForceSyncNow();
    
    /// @brief Get last sync time
    [[nodiscard]] std::optional<SystemTimePoint> GetLastSyncTime() const;
    
    /// @brief Is sync in progress
    [[nodiscard]] bool IsSyncInProgress() const noexcept;

    // ========================================================================
    // OFFLINE SUPPORT
    // ========================================================================
    
    /// @brief Save policies to offline cache
    [[nodiscard]] bool SaveToOfflineCache() const;
    
    /// @brief Load policies from offline cache
    [[nodiscard]] bool LoadFromOfflineCache();
    
    /// @brief Clear offline cache
    void ClearOfflineCache();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    uint64_t RegisterPolicyChangeCallback(PolicyChangeCallback callback);
    uint64_t RegisterViolationCallback(ViolationCallback callback);
    uint64_t RegisterSyncCallback(SyncCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] PolicyStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    PolicyManager();
    ~PolicyManager();
    
    std::unique_ptr<PolicyManagerImpl> m_impl;
    std::map<std::string, Policy> m_activePolicies;
    mutable std::shared_mutex m_mutex;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetEnforcementLevelName(EnforcementLevel level) noexcept;
[[nodiscard]] std::string_view GetPolicyTypeName(PolicyType type) noexcept;
[[nodiscard]] std::string_view GetPolicyStateName(PolicyState state) noexcept;
[[nodiscard]] std::string_view GetComplianceStatusName(ComplianceStatus status) noexcept;
[[nodiscard]] std::string_view GetViolationActionName(ViolationAction action) noexcept;

/// @brief Convert PolicyValue to string
[[nodiscard]] std::string PolicyValueToString(const PolicyValue& value);

/// @brief Parse policy from JSON
[[nodiscard]] std::optional<Policy> ParsePolicyFromJson(const std::string& json);

/// @brief Parse policy from XML
[[nodiscard]] std::optional<Policy> ParsePolicyFromXml(const std::string& xml);

}  // namespace Config
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_IS_ENFORCED(setting) \
    ::ShadowStrike::Config::PolicyManager::Instance().IsEnforced(setting)

#define SS_GET_POLICY_VALUE(setting) \
    ::ShadowStrike::Config::PolicyManager::Instance().GetEnforcedValue(setting)

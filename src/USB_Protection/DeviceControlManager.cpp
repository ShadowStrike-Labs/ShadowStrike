/**
 * ============================================================================
 * ShadowStrike NGAV - USB DEVICE CONTROL MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file DeviceControlManager.cpp
 * @brief Enterprise-grade USB device control policy engine implementation
 *
 * Implements comprehensive device control with:
 * - Granular access policies (Full/ReadOnly/Block/Quarantine)
 * - Rule-based policy evaluation with priority ordering
 * - Time-based and user-based conditional rules
 * - Audit logging for compliance
 * - Emergency override capabilities
 * - Thread-safe concurrent access
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "DeviceControlManager.hpp"
#include "USBDeviceMonitor.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/CryptoUtils.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <random>

namespace ShadowStrike {
namespace USB {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

static constexpr const wchar_t* LOG_CATEGORY = L"DeviceControlManager";

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> DeviceControlManager::s_instanceCreated{false};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class DeviceControlManagerImpl {
public:
    DeviceControlManagerImpl() = default;
    ~DeviceControlManagerImpl() = default;

    // Non-copyable, non-movable
    DeviceControlManagerImpl(const DeviceControlManagerImpl&) = delete;
    DeviceControlManagerImpl& operator=(const DeviceControlManagerImpl&) = delete;
    DeviceControlManagerImpl(DeviceControlManagerImpl&&) = delete;
    DeviceControlManagerImpl& operator=(DeviceControlManagerImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const DeviceControlConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (m_status != ModuleStatus::Uninitialized &&
            m_status != ModuleStatus::Stopped) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized or running");
            return false;
        }

        m_status = ModuleStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration provided");
            m_status = ModuleStatus::Error;
            return false;
        }

        m_config = config;
        m_stats.Reset();
        m_stats.startTime = Clock::now();

        // Generate next audit entry ID
        m_nextAuditEntryId = 1;
        m_nextRuleId = 1;

        m_status = ModuleStatus::Running;

        SS_LOG_INFO(LOG_CATEGORY, L"DeviceControlManager initialized successfully");
        SS_LOG_INFO(LOG_CATEGORY, L"  Default action: %hs",
            std::string(GetRuleActionName(m_config.defaultAction)).c_str());
        SS_LOG_INFO(LOG_CATEGORY, L"  Audit logging: %ls",
            m_config.enableAuditLog ? L"enabled" : L"disabled");

        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);

        if (m_status == ModuleStatus::Uninitialized ||
            m_status == ModuleStatus::Stopped) {
            return;
        }

        m_status = ModuleStatus::Stopping;

        // Clear callbacks
        m_evaluationCallbacks.clear();
        m_auditCallbacks.clear();
        m_ruleChangeCallbacks.clear();
        m_errorCallbacks.clear();

        // Clear rules (keep audit log for forensics)
        m_rules.clear();

        m_status = ModuleStatus::Stopped;

        SS_LOG_INFO(LOG_CATEGORY, L"DeviceControlManager shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_status == ModuleStatus::Running;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_status;
    }

    [[nodiscard]] bool UpdateConfiguration(const DeviceControlConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            return false;
        }

        m_config = config;
        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
        return true;
    }

    [[nodiscard]] DeviceControlConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // POLICY EVALUATION
    // ========================================================================

    [[nodiscard]] PolicyEvaluationResult EvaluateDevice(const USBDeviceInfo& device) {
        std::shared_lock lock(m_mutex);

        PolicyEvaluationResult result;
        result.evaluationTime = std::chrono::system_clock::now();

        m_stats.totalEvaluations++;

        // Check emergency override
        if (m_emergencyOverrideActive) {
            result.result = EvaluationResult::Allowed;
            result.accessLevel = AccessLevel::FullAccess;
            result.userMessage = "Emergency override active";
            result.matchingRuleName = "EMERGENCY_OVERRIDE";
            m_stats.devicesAllowed++;

            LogAuditEntry(device, result);
            NotifyEvaluationCallbacks(device, result);
            return result;
        }

        // Check if device control is enabled
        if (!m_config.enabled) {
            result.result = EvaluationResult::Allowed;
            result.accessLevel = AccessLevel::FullAccess;
            result.userMessage = "Device control disabled";
            m_stats.devicesAllowed++;
            return result;
        }

        // Get rules sorted by priority
        auto sortedRules = GetRulesSortedByPriority();

        // Evaluate each rule in priority order
        for (const auto& rule : sortedRules) {
            if (!rule.enabled) {
                continue;
            }

            // Check time condition
            if (rule.timeCondition.enabled && !rule.timeCondition.IsActive()) {
                continue;
            }

            // Check user condition
            if (rule.userCondition.enabled && !rule.userCondition.AllowsCurrentUser()) {
                continue;
            }

            // Check if device matches criteria
            if (rule.criteria.Matches(device)) {
                m_stats.ruleMatches++;

                result.matchingRuleId = rule.ruleId;
                result.matchingRuleName = rule.name;
                result.notifyUser = rule.notifyUser;
                result.auditLog = rule.logAudit;
                result.userMessage = rule.customMessage.empty() ?
                    GetDefaultMessage(rule.action) : rule.customMessage;

                switch (rule.action) {
                    case RuleAction::Allow:
                        result.result = EvaluationResult::Allowed;
                        result.accessLevel = rule.accessLevel;
                        m_stats.devicesAllowed++;
                        break;

                    case RuleAction::AllowReadOnly:
                        result.result = EvaluationResult::AllowedReadOnly;
                        result.accessLevel = AccessLevel::ReadOnly;
                        m_stats.devicesReadOnly++;
                        break;

                    case RuleAction::Deny:
                        result.result = EvaluationResult::Blocked;
                        result.accessLevel = AccessLevel::Blocked;
                        m_stats.devicesBlocked++;
                        break;

                    case RuleAction::Quarantine:
                        result.result = EvaluationResult::Quarantined;
                        result.accessLevel = AccessLevel::QuarantineOnly;
                        m_stats.devicesQuarantined++;
                        break;

                    case RuleAction::RequireApproval:
                        result.result = EvaluationResult::PendingApproval;
                        result.accessLevel = AccessLevel::Blocked;
                        break;

                    case RuleAction::AuditOnly:
                        result.result = EvaluationResult::Allowed;
                        result.accessLevel = AccessLevel::FullAccess;
                        result.auditLog = true;
                        m_stats.devicesAllowed++;
                        break;
                }

                // Log and notify
                if (result.auditLog) {
                    LogAuditEntry(device, result);
                }
                NotifyEvaluationCallbacks(device, result);

                SS_LOG_INFO(LOG_CATEGORY,
                    L"Device evaluated: VID=%04X PID=%04X -> %hs (Rule: %hs)",
                    device.vid, device.pid,
                    std::string(GetEvaluationResultName(result.result)).c_str(),
                    rule.name.c_str());

                return result;
            }
        }

        // No matching rule - apply default action
        m_stats.noRuleMatches++;
        result.result = EvaluationResult::NoMatchingRule;
        result.userMessage = "No matching policy rule";

        switch (m_config.defaultAction) {
            case RuleAction::Allow:
                result.result = EvaluationResult::Allowed;
                result.accessLevel = m_config.defaultAccessLevel;
                m_stats.devicesAllowed++;
                break;

            case RuleAction::Deny:
            default:
                result.result = EvaluationResult::Blocked;
                result.accessLevel = AccessLevel::Blocked;
                m_stats.devicesBlocked++;
                break;
        }

        if (m_config.enableAuditLog) {
            LogAuditEntry(device, result);
        }
        NotifyEvaluationCallbacks(device, result);

        SS_LOG_INFO(LOG_CATEGORY,
            L"Device evaluated (default): VID=%04X PID=%04X -> %hs",
            device.vid, device.pid,
            std::string(GetEvaluationResultName(result.result)).c_str());

        return result;
    }

    [[nodiscard]] PolicyEvaluationResult EvaluateDevice(
        uint16_t vendorId, uint16_t productId, const std::string& serialNumber) {

        USBDeviceInfo device;
        device.vid = vendorId;
        device.pid = productId;
        device.serialNumber = serialNumber;
        device.vendorId = FormatHex(vendorId);
        device.productId = FormatHex(productId);

        return EvaluateDevice(device);
    }

    [[nodiscard]] bool IsDeviceAllowed(const USBDeviceInfo& device) {
        auto result = EvaluateDevice(device);
        return result.result == EvaluationResult::Allowed ||
               result.result == EvaluationResult::AllowedReadOnly;
    }

    [[nodiscard]] AccessLevel GetAccessLevel(const USBDeviceInfo& device) {
        auto result = EvaluateDevice(device);
        return result.accessLevel;
    }

    // ========================================================================
    // RULE MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool AddRule(const DeviceRule& rule) {
        std::unique_lock lock(m_mutex);

        // Validate rule
        if (rule.ruleId.empty()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Cannot add rule with empty ID");
            return false;
        }

        if (m_rules.size() >= DeviceControlConstants::MAX_RULES) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Maximum rule count reached: %zu",
                DeviceControlConstants::MAX_RULES);
            return false;
        }

        // Check for duplicate ID
        auto it = std::find_if(m_rules.begin(), m_rules.end(),
            [&rule](const DeviceRule& r) { return r.ruleId == rule.ruleId; });

        if (it != m_rules.end()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Rule ID already exists: %hs", rule.ruleId.c_str());
            return false;
        }

        DeviceRule newRule = rule;
        newRule.createdTime = std::chrono::system_clock::now();
        newRule.modifiedTime = newRule.createdTime;

        m_rules.push_back(newRule);
        UpdateRuleStats();

        // Notify callbacks
        for (const auto& callback : m_ruleChangeCallbacks) {
            try {
                callback(newRule, true);
            } catch (...) {
                SS_LOG_WARN(LOG_CATEGORY, L"Rule change callback threw exception");
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Rule added: %hs (%hs)",
            newRule.name.c_str(), newRule.ruleId.c_str());

        return true;
    }

    [[nodiscard]] bool UpdateRule(const DeviceRule& rule) {
        std::unique_lock lock(m_mutex);

        auto it = std::find_if(m_rules.begin(), m_rules.end(),
            [&rule](const DeviceRule& r) { return r.ruleId == rule.ruleId; });

        if (it == m_rules.end()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Rule not found: %hs", rule.ruleId.c_str());
            return false;
        }

        DeviceRule updatedRule = rule;
        updatedRule.createdTime = it->createdTime;
        updatedRule.modifiedTime = std::chrono::system_clock::now();

        *it = updatedRule;
        UpdateRuleStats();

        SS_LOG_INFO(LOG_CATEGORY, L"Rule updated: %hs", rule.ruleId.c_str());
        return true;
    }

    [[nodiscard]] bool RemoveRule(const std::string& ruleId) {
        std::unique_lock lock(m_mutex);

        auto it = std::find_if(m_rules.begin(), m_rules.end(),
            [&ruleId](const DeviceRule& r) { return r.ruleId == ruleId; });

        if (it == m_rules.end()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Rule not found for removal: %hs", ruleId.c_str());
            return false;
        }

        DeviceRule removedRule = *it;
        m_rules.erase(it);
        UpdateRuleStats();

        // Notify callbacks
        for (const auto& callback : m_ruleChangeCallbacks) {
            try {
                callback(removedRule, false);
            } catch (...) {
                SS_LOG_WARN(LOG_CATEGORY, L"Rule change callback threw exception");
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Rule removed: %hs", ruleId.c_str());
        return true;
    }

    [[nodiscard]] bool SetRuleEnabled(const std::string& ruleId, bool enabled) {
        std::unique_lock lock(m_mutex);

        auto it = std::find_if(m_rules.begin(), m_rules.end(),
            [&ruleId](const DeviceRule& r) { return r.ruleId == ruleId; });

        if (it == m_rules.end()) {
            return false;
        }

        it->enabled = enabled;
        it->modifiedTime = std::chrono::system_clock::now();
        UpdateRuleStats();

        SS_LOG_INFO(LOG_CATEGORY, L"Rule %hs: %hs",
            enabled ? "enabled" : "disabled", ruleId.c_str());
        return true;
    }

    [[nodiscard]] std::optional<DeviceRule> GetRule(const std::string& ruleId) const {
        std::shared_lock lock(m_mutex);

        auto it = std::find_if(m_rules.begin(), m_rules.end(),
            [&ruleId](const DeviceRule& r) { return r.ruleId == ruleId; });

        if (it != m_rules.end()) {
            return *it;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<DeviceRule> GetAllRules() const {
        std::shared_lock lock(m_mutex);
        return m_rules;
    }

    [[nodiscard]] std::vector<DeviceRule> GetRulesByPriority() const {
        std::shared_lock lock(m_mutex);
        return GetRulesSortedByPriority();
    }

    void ClearAllRules() {
        std::unique_lock lock(m_mutex);
        m_rules.clear();
        UpdateRuleStats();
        SS_LOG_INFO(LOG_CATEGORY, L"All rules cleared");
    }

    [[nodiscard]] bool LoadRulesFromFile(const std::string& path) {
        std::unique_lock lock(m_mutex);

        try {
            std::wstring widePath = Utils::StringUtils::ToWide(path);
            Utils::JSON::Json json;
            Utils::JSON::Error err;

            if (!Utils::JSON::LoadFromFile(widePath, json, &err)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to load rules file: %hs",
                    err.message.c_str());
                return false;
            }

            if (!json.contains("rules") || !json["rules"].is_array()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Invalid rules file format");
                return false;
            }

            std::vector<DeviceRule> loadedRules;
            for (const auto& ruleJson : json["rules"]) {
                auto rule = DeviceRule::FromJson(ruleJson.dump());
                if (rule) {
                    loadedRules.push_back(*rule);
                }
            }

            m_rules = std::move(loadedRules);
            UpdateRuleStats();

            SS_LOG_INFO(LOG_CATEGORY, L"Loaded %zu rules from file", m_rules.size());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception loading rules: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool SaveRulesToFile(const std::string& path) const {
        std::shared_lock lock(m_mutex);

        try {
            Utils::JSON::Json json;
            json["version"] = "3.0.0";
            json["rules"] = Utils::JSON::Json::array();

            for (const auto& rule : m_rules) {
                Utils::JSON::Json ruleJson;
                Utils::JSON::Parse(rule.ToJson(), ruleJson);
                json["rules"].push_back(ruleJson);
            }

            std::wstring widePath = Utils::StringUtils::ToWide(path);
            Utils::JSON::SaveOptions opts;
            opts.pretty = true;
            opts.indentSpaces = 2;
            opts.atomicReplace = true;

            Utils::JSON::Error err;
            if (!Utils::JSON::SaveToFile(widePath, json, &err, opts)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to save rules file: %hs",
                    err.message.c_str());
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Saved %zu rules to file", m_rules.size());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception saving rules: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // AUDIT LOG
    // ========================================================================

    [[nodiscard]] std::vector<AuditLogEntry> GetAuditLog(
        size_t maxEntries,
        std::optional<SystemTimePoint> fromTime,
        std::optional<SystemTimePoint> toTime) const {

        std::shared_lock lock(m_mutex);

        std::vector<AuditLogEntry> result;
        result.reserve(std::min(maxEntries, m_auditLog.size()));

        for (const auto& entry : m_auditLog) {
            if (result.size() >= maxEntries) break;

            if (fromTime && entry.timestamp < *fromTime) continue;
            if (toTime && entry.timestamp > *toTime) continue;

            result.push_back(entry);
        }

        return result;
    }

    [[nodiscard]] bool ExportAuditLog(const std::string& path) const {
        std::shared_lock lock(m_mutex);

        try {
            Utils::JSON::Json json;
            json["exportTime"] = std::chrono::system_clock::now().time_since_epoch().count();
            json["entries"] = Utils::JSON::Json::array();

            for (const auto& entry : m_auditLog) {
                Utils::JSON::Json entryJson;
                Utils::JSON::Parse(entry.ToJson(), entryJson);
                json["entries"].push_back(entryJson);
            }

            std::wstring widePath = Utils::StringUtils::ToWide(path);
            Utils::JSON::SaveOptions opts;
            opts.pretty = true;
            opts.atomicReplace = true;

            Utils::JSON::Error err;
            if (!Utils::JSON::SaveToFile(widePath, json, &err, opts)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to export audit log");
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Exported %zu audit entries", m_auditLog.size());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception exporting audit log: %hs", e.what());
            return false;
        }
    }

    void ClearAuditLog() {
        std::unique_lock lock(m_mutex);
        m_auditLog.clear();
        m_nextAuditEntryId = 1;
        SS_LOG_INFO(LOG_CATEGORY, L"Audit log cleared");
    }

    // ========================================================================
    // EMERGENCY OVERRIDE
    // ========================================================================

    [[nodiscard]] bool EnableEmergencyOverride(const std::string& password) {
        std::unique_lock lock(m_mutex);

        if (!m_config.allowEmergencyOverride) {
            SS_LOG_WARN(LOG_CATEGORY, L"Emergency override not allowed by configuration");
            return false;
        }

        if (m_config.emergencyOverridePasswordHash.empty()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Emergency override password not configured");
            return false;
        }

        // Hash the provided password and compare
        std::array<uint8_t, 32> hashBytes{};
        if (!Utils::HashUtils::SHA256(
            reinterpret_cast<const uint8_t*>(password.data()),
            password.size(),
            hashBytes.data())) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to hash password");
            return false;
        }

        std::string hashHex = Utils::HashUtils::ToHexString(hashBytes);

        if (hashHex != m_config.emergencyOverridePasswordHash) {
            SS_LOG_WARN(LOG_CATEGORY, L"Emergency override: invalid password");
            return false;
        }

        m_emergencyOverrideActive = true;
        m_emergencyOverrideTime = std::chrono::system_clock::now();

        SS_LOG_WARN(LOG_CATEGORY, L"EMERGENCY OVERRIDE ENABLED");
        return true;
    }

    void DisableEmergencyOverride() {
        std::unique_lock lock(m_mutex);
        m_emergencyOverrideActive = false;
        SS_LOG_INFO(LOG_CATEGORY, L"Emergency override disabled");
    }

    [[nodiscard]] bool IsEmergencyOverrideActive() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_emergencyOverrideActive;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterEvaluationCallback(EvaluationCallback callback) {
        std::unique_lock lock(m_mutex);
        m_evaluationCallbacks.push_back(std::move(callback));
    }

    void RegisterAuditCallback(AuditCallback callback) {
        std::unique_lock lock(m_mutex);
        m_auditCallbacks.push_back(std::move(callback));
    }

    void RegisterRuleChangeCallback(RuleChangeCallback callback) {
        std::unique_lock lock(m_mutex);
        m_ruleChangeCallbacks.push_back(std::move(callback));
    }

    void RegisterErrorCallback(ErrorCallback callback) {
        std::unique_lock lock(m_mutex);
        m_errorCallbacks.push_back(std::move(callback));
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_mutex);
        m_evaluationCallbacks.clear();
        m_auditCallbacks.clear();
        m_ruleChangeCallbacks.clear();
        m_errorCallbacks.clear();
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] DeviceControlStatistics GetStatistics() const {
        std::shared_lock lock(m_mutex);
        return m_stats;
    }

    void ResetStatistics() {
        std::unique_lock lock(m_mutex);
        m_stats.Reset();
        UpdateRuleStats();
    }

    [[nodiscard]] bool SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"Starting self-test...");

        try {
            // Test 1: Rule creation and retrieval
            DeviceRule testRule;
            testRule.ruleId = "TEST_RULE_001";
            testRule.name = "Self-Test Rule";
            testRule.action = RuleAction::Deny;
            testRule.criteria.vendorId = 0x1234;
            testRule.criteria.productId = 0x5678;

            if (!AddRule(testRule)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Cannot add rule");
                return false;
            }

            auto retrieved = GetRule("TEST_RULE_001");
            if (!retrieved || retrieved->name != "Self-Test Rule") {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Rule retrieval mismatch");
                RemoveRule("TEST_RULE_001");
                return false;
            }

            // Test 2: Policy evaluation
            USBDeviceInfo testDevice;
            testDevice.vid = 0x1234;
            testDevice.pid = 0x5678;
            testDevice.serialNumber = "TEST123";

            auto evalResult = EvaluateDevice(testDevice);
            if (evalResult.result != EvaluationResult::Blocked) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Evaluation mismatch");
                RemoveRule("TEST_RULE_001");
                return false;
            }

            // Test 3: Rule removal
            if (!RemoveRule("TEST_RULE_001")) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Cannot remove rule");
                return false;
            }

            // Test 4: Statistics
            auto stats = GetStatistics();
            if (stats.totalEvaluations == 0) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Statistics not tracking");
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Self-test completed successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test exception: %hs", e.what());
            return false;
        }
    }

private:
    // ========================================================================
    // PRIVATE HELPERS
    // ========================================================================

    [[nodiscard]] std::vector<DeviceRule> GetRulesSortedByPriority() const {
        std::vector<DeviceRule> sorted = m_rules;
        std::sort(sorted.begin(), sorted.end(),
            [](const DeviceRule& a, const DeviceRule& b) {
                return static_cast<uint8_t>(a.priority) < static_cast<uint8_t>(b.priority);
            });
        return sorted;
    }

    void UpdateRuleStats() {
        uint32_t active = 0;
        uint32_t disabled = 0;

        for (const auto& rule : m_rules) {
            if (rule.enabled) {
                active++;
            } else {
                disabled++;
            }
        }

        m_stats.activeRules.store(active);
        m_stats.disabledRules.store(disabled);
    }

    void LogAuditEntry(const USBDeviceInfo& device, const PolicyEvaluationResult& result) {
        if (!m_config.enableAuditLog) return;

        AuditLogEntry entry;
        entry.entryId = m_nextAuditEntryId++;
        entry.deviceId = device.deviceId;
        entry.vendorId = device.vendorId;
        entry.productId = device.productId;
        entry.serialNumber = device.serialNumber;
        entry.deviceName = device.friendlyName;
        entry.result = result.result;
        entry.accessLevel = result.accessLevel;
        entry.ruleId = result.matchingRuleId;
        entry.ruleName = result.matchingRuleName;
        entry.timestamp = result.evaluationTime;

        // Get current user info
        wchar_t userName[256] = {0};
        DWORD userNameSize = sizeof(userName) / sizeof(wchar_t);
        if (GetUserNameW(userName, &userNameSize)) {
            entry.userName = Utils::StringUtils::ToNarrow(userName);
        }

        wchar_t machineName[256] = {0};
        DWORD machineNameSize = sizeof(machineName) / sizeof(wchar_t);
        if (GetComputerNameW(machineName, &machineNameSize)) {
            entry.machineName = Utils::StringUtils::ToNarrow(machineName);
        }

        // Trim audit log if needed
        while (m_auditLog.size() >= m_config.maxAuditEntries) {
            m_auditLog.pop_front();
        }

        m_auditLog.push_back(entry);

        // Notify callbacks
        for (const auto& callback : m_auditCallbacks) {
            try {
                callback(entry);
            } catch (...) {
                SS_LOG_WARN(LOG_CATEGORY, L"Audit callback threw exception");
            }
        }
    }

    void NotifyEvaluationCallbacks(const USBDeviceInfo& device,
                                    const PolicyEvaluationResult& result) {
        for (const auto& callback : m_evaluationCallbacks) {
            try {
                callback(device, result);
            } catch (...) {
                SS_LOG_WARN(LOG_CATEGORY, L"Evaluation callback threw exception");
            }
        }
    }

    void NotifyError(const std::string& message, int code) {
        for (const auto& callback : m_errorCallbacks) {
            try {
                callback(message, code);
            } catch (...) {
                // Ignore callback errors
            }
        }
    }

    [[nodiscard]] static std::string GetDefaultMessage(RuleAction action) {
        switch (action) {
            case RuleAction::Allow:
                return "Device access allowed by policy";
            case RuleAction::AllowReadOnly:
                return "Device access restricted to read-only";
            case RuleAction::Deny:
                return "Device access blocked by security policy";
            case RuleAction::Quarantine:
                return "Device quarantined for scanning";
            case RuleAction::RequireApproval:
                return "Device requires administrator approval";
            case RuleAction::AuditOnly:
                return "Device access logged for audit";
            default:
                return "Unknown policy action";
        }
    }

    [[nodiscard]] static std::string FormatHex(uint16_t value) {
        std::ostringstream oss;
        oss << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << value;
        return oss.str();
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    ModuleStatus m_status{ModuleStatus::Uninitialized};
    DeviceControlConfiguration m_config;

    std::vector<DeviceRule> m_rules;
    std::deque<AuditLogEntry> m_auditLog;

    uint64_t m_nextAuditEntryId{1};
    uint64_t m_nextRuleId{1};

    bool m_emergencyOverrideActive{false};
    SystemTimePoint m_emergencyOverrideTime;

    DeviceControlStatistics m_stats;

    std::vector<EvaluationCallback> m_evaluationCallbacks;
    std::vector<AuditCallback> m_auditCallbacks;
    std::vector<RuleChangeCallback> m_ruleChangeCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;
};

// ============================================================================
// DEVICE CONTROL MANAGER - SINGLETON IMPLEMENTATION
// ============================================================================

DeviceControlManager& DeviceControlManager::Instance() noexcept {
    static DeviceControlManager instance;
    return instance;
}

bool DeviceControlManager::HasInstance() noexcept {
    return s_instanceCreated.load();
}

DeviceControlManager::DeviceControlManager()
    : m_impl(std::make_unique<DeviceControlManagerImpl>()) {
    s_instanceCreated.store(true);
}

DeviceControlManager::~DeviceControlManager() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    s_instanceCreated.store(false);
}

// ============================================================================
// LIFECYCLE DELEGATIONS
// ============================================================================

bool DeviceControlManager::Initialize(const DeviceControlConfiguration& config) {
    return m_impl->Initialize(config);
}

void DeviceControlManager::Shutdown() {
    m_impl->Shutdown();
}

bool DeviceControlManager::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus DeviceControlManager::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool DeviceControlManager::UpdateConfiguration(const DeviceControlConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

DeviceControlConfiguration DeviceControlManager::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

// ============================================================================
// POLICY EVALUATION DELEGATIONS
// ============================================================================

PolicyEvaluationResult DeviceControlManager::EvaluateDevice(const USBDeviceInfo& device) {
    return m_impl->EvaluateDevice(device);
}

PolicyEvaluationResult DeviceControlManager::EvaluateDevice(
    uint16_t vendorId, uint16_t productId, const std::string& serialNumber) {
    return m_impl->EvaluateDevice(vendorId, productId, serialNumber);
}

bool DeviceControlManager::IsDeviceAllowed(const USBDeviceInfo& device) {
    return m_impl->IsDeviceAllowed(device);
}

AccessLevel DeviceControlManager::GetAccessLevel(const USBDeviceInfo& device) {
    return m_impl->GetAccessLevel(device);
}

// ============================================================================
// RULE MANAGEMENT DELEGATIONS
// ============================================================================

bool DeviceControlManager::AddRule(const DeviceRule& rule) {
    return m_impl->AddRule(rule);
}

bool DeviceControlManager::UpdateRule(const DeviceRule& rule) {
    return m_impl->UpdateRule(rule);
}

bool DeviceControlManager::RemoveRule(const std::string& ruleId) {
    return m_impl->RemoveRule(ruleId);
}

bool DeviceControlManager::SetRuleEnabled(const std::string& ruleId, bool enabled) {
    return m_impl->SetRuleEnabled(ruleId, enabled);
}

std::optional<DeviceRule> DeviceControlManager::GetRule(const std::string& ruleId) const {
    return m_impl->GetRule(ruleId);
}

std::vector<DeviceRule> DeviceControlManager::GetAllRules() const {
    return m_impl->GetAllRules();
}

std::vector<DeviceRule> DeviceControlManager::GetRulesByPriority() const {
    return m_impl->GetRulesByPriority();
}

void DeviceControlManager::ClearAllRules() {
    m_impl->ClearAllRules();
}

bool DeviceControlManager::LoadRulesFromFile(const std::string& path) {
    return m_impl->LoadRulesFromFile(path);
}

bool DeviceControlManager::SaveRulesToFile(const std::string& path) const {
    return m_impl->SaveRulesToFile(path);
}

// ============================================================================
// AUDIT LOG DELEGATIONS
// ============================================================================

std::vector<AuditLogEntry> DeviceControlManager::GetAuditLog(
    size_t maxEntries,
    std::optional<SystemTimePoint> fromTime,
    std::optional<SystemTimePoint> toTime) const {
    return m_impl->GetAuditLog(maxEntries, fromTime, toTime);
}

bool DeviceControlManager::ExportAuditLog(const std::string& path) const {
    return m_impl->ExportAuditLog(path);
}

void DeviceControlManager::ClearAuditLog() {
    m_impl->ClearAuditLog();
}

// ============================================================================
// EMERGENCY OVERRIDE DELEGATIONS
// ============================================================================

bool DeviceControlManager::EnableEmergencyOverride(const std::string& password) {
    return m_impl->EnableEmergencyOverride(password);
}

void DeviceControlManager::DisableEmergencyOverride() {
    m_impl->DisableEmergencyOverride();
}

bool DeviceControlManager::IsEmergencyOverrideActive() const noexcept {
    return m_impl->IsEmergencyOverrideActive();
}

// ============================================================================
// CALLBACK DELEGATIONS
// ============================================================================

void DeviceControlManager::RegisterEvaluationCallback(EvaluationCallback callback) {
    m_impl->RegisterEvaluationCallback(std::move(callback));
}

void DeviceControlManager::RegisterAuditCallback(AuditCallback callback) {
    m_impl->RegisterAuditCallback(std::move(callback));
}

void DeviceControlManager::RegisterRuleChangeCallback(RuleChangeCallback callback) {
    m_impl->RegisterRuleChangeCallback(std::move(callback));
}

void DeviceControlManager::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void DeviceControlManager::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

// ============================================================================
// STATISTICS DELEGATIONS
// ============================================================================

DeviceControlStatistics DeviceControlManager::GetStatistics() const {
    return m_impl->GetStatistics();
}

void DeviceControlManager::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool DeviceControlManager::SelfTest() {
    return m_impl->SelfTest();
}

std::string DeviceControlManager::GetVersionString() noexcept {
    return std::to_string(DeviceControlConstants::VERSION_MAJOR) + "." +
           std::to_string(DeviceControlConstants::VERSION_MINOR) + "." +
           std::to_string(DeviceControlConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

bool DeviceCriteria::Matches(const USBDeviceInfo& device) const {
    // Match any device if isAnyCriteria is set
    if (isAnyCriteria) {
        return true;
    }

    // Check VID/PID (0 means any)
    if (vendorId != 0 && device.vid != vendorId) {
        return false;
    }

    if (productId != 0 && device.pid != productId) {
        return false;
    }

    // Check device class
    if (deviceClass && device.classCode != *deviceClass) {
        return false;
    }

    // Check category
    if (category != DeviceCategory::Unknown &&
        static_cast<uint8_t>(device.type) != static_cast<uint8_t>(category)) {
        return false;
    }

    // Check serial number pattern
    if (!serialNumberPattern.empty()) {
        bool matches = false;
        switch (matchType) {
            case RuleMatchType::Exact:
                matches = (device.serialNumber == serialNumberPattern);
                break;
            case RuleMatchType::Prefix:
                matches = device.serialNumber.starts_with(serialNumberPattern);
                break;
            case RuleMatchType::Suffix:
                matches = device.serialNumber.ends_with(serialNumberPattern);
                break;
            case RuleMatchType::Contains:
                matches = device.serialNumber.find(serialNumberPattern) != std::string::npos;
                break;
            case RuleMatchType::Wildcard:
                matches = MatchWildcard(device.serialNumber, serialNumberPattern);
                break;
            case RuleMatchType::Regex:
                try {
                    std::regex re(serialNumberPattern);
                    matches = std::regex_match(device.serialNumber, re);
                } catch (...) {
                    matches = false;
                }
                break;
        }
        if (!matches) return false;
    }

    // Check manufacturer pattern
    if (!manufacturerPattern.empty()) {
        if (device.manufacturer.find(manufacturerPattern) == std::string::npos) {
            return false;
        }
    }

    // Check product name pattern
    if (!productNamePattern.empty()) {
        if (device.product.find(productNamePattern) == std::string::npos) {
            return false;
        }
    }

    return true;
}

bool DeviceCriteria::MatchWildcard(const std::string& str, const std::string& pattern) {
    size_t s = 0, p = 0;
    size_t starIdx = std::string::npos;
    size_t matchIdx = 0;

    while (s < str.size()) {
        if (p < pattern.size() &&
            (pattern[p] == DeviceControlConstants::WILDCARD_CHAR || pattern[p] == str[s])) {
            if (pattern[p] == DeviceControlConstants::WILDCARD_CHAR) {
                starIdx = p;
                matchIdx = s;
                p++;
            } else {
                s++;
                p++;
            }
        } else if (starIdx != std::string::npos) {
            p = starIdx + 1;
            matchIdx++;
            s = matchIdx;
        } else {
            return false;
        }
    }

    while (p < pattern.size() && pattern[p] == DeviceControlConstants::WILDCARD_CHAR) {
        p++;
    }

    return p == pattern.size();
}

std::string DeviceCriteria::ToJson() const {
    Utils::JSON::Json json;
    json["vendorId"] = vendorId;
    json["productId"] = productId;
    json["serialNumberPattern"] = serialNumberPattern;
    if (deviceClass) {
        json["deviceClass"] = *deviceClass;
    }
    json["category"] = static_cast<uint8_t>(category);
    json["manufacturerPattern"] = manufacturerPattern;
    json["productNamePattern"] = productNamePattern;
    json["matchType"] = static_cast<uint8_t>(matchType);
    json["isAnyCriteria"] = isAnyCriteria;
    return json.dump();
}

std::string DeviceCriteria::ToCriteriaString() const {
    std::ostringstream oss;
    if (isAnyCriteria) {
        oss << "*";
    } else {
        if (vendorId != 0) {
            oss << "VID:" << std::hex << std::uppercase << vendorId;
        }
        if (productId != 0) {
            if (!oss.str().empty()) oss << " ";
            oss << "PID:" << std::hex << std::uppercase << productId;
        }
        if (!serialNumberPattern.empty()) {
            if (!oss.str().empty()) oss << " ";
            oss << "SN:" << serialNumberPattern;
        }
    }
    return oss.str();
}

// ============================================================================
// TIME CONDITION IMPLEMENTATION
// ============================================================================

bool TimeCondition::IsActive() const {
    if (!enabled) return true;

    auto now = std::chrono::system_clock::now();

    // Check date range
    if (startDate && now < *startDate) return false;
    if (endDate && now > *endDate) return false;

    // Get current time components
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &tt);

    // Check day of week (Sun=0, Mon=1, ..., Sat=6)
    uint8_t dayBit = 1 << tm.tm_wday;
    if ((daysOfWeek & dayBit) == 0) return false;

    // Check time of day
    auto currentMinutes = std::chrono::minutes(tm.tm_hour * 60 + tm.tm_min);
    if (currentMinutes < startTime || currentMinutes > endTime) return false;

    return true;
}

std::string TimeCondition::ToJson() const {
    Utils::JSON::Json json;
    json["enabled"] = enabled;
    json["startTime"] = startTime.count();
    json["endTime"] = endTime.count();
    json["daysOfWeek"] = daysOfWeek;
    if (startDate) {
        json["startDate"] = startDate->time_since_epoch().count();
    }
    if (endDate) {
        json["endDate"] = endDate->time_since_epoch().count();
    }
    return json.dump();
}

// ============================================================================
// USER CONDITION IMPLEMENTATION
// ============================================================================

bool UserCondition::AllowsCurrentUser() const {
    if (!enabled) return true;

    // Get current user name
    wchar_t userName[256] = {0};
    DWORD userNameSize = sizeof(userName) / sizeof(wchar_t);
    if (!GetUserNameW(userName, &userNameSize)) {
        return false;
    }

    std::string currentUser = Utils::StringUtils::ToNarrow(userName);

    // Check denied users first
    for (const auto& denied : deniedUsers) {
        if (_stricmp(currentUser.c_str(), denied.c_str()) == 0) {
            return false;
        }
    }

    // If allowed users list is not empty, user must be in it
    if (!allowedUsers.empty()) {
        bool found = false;
        for (const auto& allowed : allowedUsers) {
            if (_stricmp(currentUser.c_str(), allowed.c_str()) == 0) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }

    // TODO: Implement group membership checking via Windows API
    // For now, group conditions are not evaluated

    return true;
}

std::string UserCondition::ToJson() const {
    Utils::JSON::Json json;
    json["enabled"] = enabled;
    json["allowedUsers"] = allowedUsers;
    json["allowedGroups"] = allowedGroups;
    json["deniedUsers"] = deniedUsers;
    json["deniedGroups"] = deniedGroups;
    return json.dump();
}

// ============================================================================
// DEVICE RULE IMPLEMENTATION
// ============================================================================

std::string DeviceRule::ToJson() const {
    Utils::JSON::Json json;
    json["ruleId"] = ruleId;
    json["name"] = name;
    json["description"] = description;

    Utils::JSON::Json criteriaJson;
    Utils::JSON::Parse(criteria.ToJson(), criteriaJson);
    json["criteria"] = criteriaJson;

    json["action"] = static_cast<uint8_t>(action);
    json["accessLevel"] = static_cast<uint8_t>(accessLevel);
    json["priority"] = static_cast<uint8_t>(priority);
    json["enabled"] = enabled;
    json["logAudit"] = logAudit;
    json["notifyUser"] = notifyUser;

    Utils::JSON::Json timeJson;
    Utils::JSON::Parse(timeCondition.ToJson(), timeJson);
    json["timeCondition"] = timeJson;

    Utils::JSON::Json userJson;
    Utils::JSON::Parse(userCondition.ToJson(), userJson);
    json["userCondition"] = userJson;

    json["customMessage"] = customMessage;
    json["createdTime"] = createdTime.time_since_epoch().count();
    json["modifiedTime"] = modifiedTime.time_since_epoch().count();
    json["createdBy"] = createdBy;

    return json.dump();
}

std::optional<DeviceRule> DeviceRule::FromJson(const std::string& json) {
    try {
        Utils::JSON::Json j;
        Utils::JSON::Error err;
        if (!Utils::JSON::Parse(json, j, &err)) {
            return std::nullopt;
        }

        DeviceRule rule;
        rule.ruleId = j.value("ruleId", "");
        rule.name = j.value("name", "");
        rule.description = j.value("description", "");
        rule.action = static_cast<RuleAction>(j.value("action", 1));
        rule.accessLevel = static_cast<AccessLevel>(j.value("accessLevel", 4));
        rule.priority = static_cast<RulePriority>(j.value("priority", 50));
        rule.enabled = j.value("enabled", true);
        rule.logAudit = j.value("logAudit", true);
        rule.notifyUser = j.value("notifyUser", true);
        rule.customMessage = j.value("customMessage", "");
        rule.createdBy = j.value("createdBy", "");

        if (j.contains("criteria")) {
            const auto& c = j["criteria"];
            rule.criteria.vendorId = c.value("vendorId", 0);
            rule.criteria.productId = c.value("productId", 0);
            rule.criteria.serialNumberPattern = c.value("serialNumberPattern", "");
            rule.criteria.manufacturerPattern = c.value("manufacturerPattern", "");
            rule.criteria.productNamePattern = c.value("productNamePattern", "");
            rule.criteria.matchType = static_cast<RuleMatchType>(c.value("matchType", 5));
            rule.criteria.isAnyCriteria = c.value("isAnyCriteria", false);
            if (c.contains("deviceClass")) {
                rule.criteria.deviceClass = c["deviceClass"].get<uint8_t>();
            }
            rule.criteria.category = static_cast<DeviceCategory>(c.value("category", 0));
        }

        return rule;

    } catch (...) {
        return std::nullopt;
    }
}

// ============================================================================
// POLICY EVALUATION RESULT IMPLEMENTATION
// ============================================================================

std::string PolicyEvaluationResult::ToJson() const {
    Utils::JSON::Json json;
    json["result"] = static_cast<uint8_t>(result);
    json["resultName"] = std::string(GetEvaluationResultName(result));
    json["accessLevel"] = static_cast<uint8_t>(accessLevel);
    json["accessLevelName"] = std::string(GetAccessLevelName(accessLevel));
    json["matchingRuleId"] = matchingRuleId;
    json["matchingRuleName"] = matchingRuleName;
    json["userMessage"] = userMessage;
    json["notifyUser"] = notifyUser;
    json["auditLog"] = auditLog;
    json["evaluationTime"] = evaluationTime.time_since_epoch().count();
    return json.dump();
}

// ============================================================================
// AUDIT LOG ENTRY IMPLEMENTATION
// ============================================================================

std::string AuditLogEntry::ToJson() const {
    Utils::JSON::Json json;
    json["entryId"] = entryId;
    json["deviceId"] = deviceId;
    json["vendorId"] = vendorId;
    json["productId"] = productId;
    json["serialNumber"] = serialNumber;
    json["deviceName"] = deviceName;
    json["result"] = static_cast<uint8_t>(result);
    json["resultName"] = std::string(GetEvaluationResultName(result));
    json["accessLevel"] = static_cast<uint8_t>(accessLevel);
    json["accessLevelName"] = std::string(GetAccessLevelName(accessLevel));
    json["ruleId"] = ruleId;
    json["ruleName"] = ruleName;
    json["userName"] = userName;
    json["machineName"] = machineName;
    json["timestamp"] = timestamp.time_since_epoch().count();
    return json.dump();
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void DeviceControlStatistics::Reset() noexcept {
    totalEvaluations.store(0);
    devicesAllowed.store(0);
    devicesBlocked.store(0);
    devicesReadOnly.store(0);
    devicesQuarantined.store(0);
    ruleMatches.store(0);
    noRuleMatches.store(0);
    policyErrors.store(0);
    activeRules.store(0);
    disabledRules.store(0);
    startTime = Clock::now();
}

std::string DeviceControlStatistics::ToJson() const {
    Utils::JSON::Json json;
    json["totalEvaluations"] = totalEvaluations.load();
    json["devicesAllowed"] = devicesAllowed.load();
    json["devicesBlocked"] = devicesBlocked.load();
    json["devicesReadOnly"] = devicesReadOnly.load();
    json["devicesQuarantined"] = devicesQuarantined.load();
    json["ruleMatches"] = ruleMatches.load();
    json["noRuleMatches"] = noRuleMatches.load();
    json["policyErrors"] = policyErrors.load();
    json["activeRules"] = activeRules.load();
    json["disabledRules"] = disabledRules.load();

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    json["uptimeSeconds"] = uptime;

    return json.dump();
}

// ============================================================================
// CONFIGURATION VALIDATION
// ============================================================================

bool DeviceControlConfiguration::IsValid() const noexcept {
    if (maxAuditEntries == 0 || maxAuditEntries > 10000000) {
        return false;
    }
    if (policyRefreshInterval.count() < 0) {
        return false;
    }
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetAccessLevelName(AccessLevel level) noexcept {
    switch (level) {
        case AccessLevel::FullAccess:     return "FullAccess";
        case AccessLevel::ReadOnly:       return "ReadOnly";
        case AccessLevel::WriteOnly:      return "WriteOnly";
        case AccessLevel::NoExecute:      return "NoExecute";
        case AccessLevel::Blocked:        return "Blocked";
        case AccessLevel::QuarantineOnly: return "QuarantineOnly";
        case AccessLevel::AuditOnly:      return "AuditOnly";
        case AccessLevel::Custom:         return "Custom";
        default:                          return "Unknown";
    }
}

std::string_view GetDeviceCategoryName(DeviceCategory cat) noexcept {
    switch (cat) {
        case DeviceCategory::Unknown:        return "Unknown";
        case DeviceCategory::MassStorage:    return "MassStorage";
        case DeviceCategory::HIDKeyboard:    return "HIDKeyboard";
        case DeviceCategory::HIDMouse:       return "HIDMouse";
        case DeviceCategory::HIDOther:       return "HIDOther";
        case DeviceCategory::NetworkAdapter: return "NetworkAdapter";
        case DeviceCategory::ImagingDevice:  return "ImagingDevice";
        case DeviceCategory::Printer:        return "Printer";
        case DeviceCategory::AudioDevice:    return "AudioDevice";
        case DeviceCategory::VideoDevice:    return "VideoDevice";
        case DeviceCategory::SmartCard:      return "SmartCard";
        case DeviceCategory::WirelessDevice: return "WirelessDevice";
        case DeviceCategory::Hub:            return "Hub";
        case DeviceCategory::Composite:      return "Composite";
        default:                             return "Unknown";
    }
}

std::string_view GetRuleActionName(RuleAction action) noexcept {
    switch (action) {
        case RuleAction::Allow:           return "Allow";
        case RuleAction::Deny:            return "Deny";
        case RuleAction::AllowReadOnly:   return "AllowReadOnly";
        case RuleAction::AuditOnly:       return "AuditOnly";
        case RuleAction::RequireApproval: return "RequireApproval";
        case RuleAction::Quarantine:      return "Quarantine";
        default:                          return "Unknown";
    }
}

std::string_view GetEvaluationResultName(EvaluationResult result) noexcept {
    switch (result) {
        case EvaluationResult::Allowed:         return "Allowed";
        case EvaluationResult::AllowedReadOnly: return "AllowedReadOnly";
        case EvaluationResult::Blocked:         return "Blocked";
        case EvaluationResult::Quarantined:     return "Quarantined";
        case EvaluationResult::PendingApproval: return "PendingApproval";
        case EvaluationResult::NoMatchingRule:  return "NoMatchingRule";
        case EvaluationResult::Error:           return "Error";
        default:                                return "Unknown";
    }
}

DeviceCategory ClassifyDeviceClass(uint8_t classCode) noexcept {
    using namespace DeviceControlConstants::DeviceClass;

    switch (classCode) {
        case MASS_STORAGE:    return DeviceCategory::MassStorage;
        case HID:             return DeviceCategory::HIDOther;
        case AUDIO:           return DeviceCategory::AudioDevice;
        case VIDEO:           return DeviceCategory::VideoDevice;
        case IMAGE:           return DeviceCategory::ImagingDevice;
        case PRINTER:         return DeviceCategory::Printer;
        case SMART_CARD:      return DeviceCategory::SmartCard;
        case WIRELESS:        return DeviceCategory::WirelessDevice;
        case HUB:             return DeviceCategory::Hub;
        case COMMUNICATIONS:  return DeviceCategory::NetworkAdapter;
        default:              return DeviceCategory::Unknown;
    }
}

std::string GenerateRuleId() {
    static std::atomic<uint64_t> counter{0};

    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();

    uint64_t seq = counter.fetch_add(1);

    std::ostringstream oss;
    oss << DeviceControlConstants::RULE_ID_PREFIX << "-"
        << std::hex << std::uppercase << seconds << "-"
        << std::setfill('0') << std::setw(4) << (seq & 0xFFFF);

    return oss.str();
}

}  // namespace USB
}  // namespace ShadowStrike

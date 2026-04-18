/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::PolicyEngine {

using Clock = std::chrono::system_clock;

// ============================================================================
// ENUMERATIONS
// ============================================================================

enum class PolicyStatus : uint8_t {
    Active   = 0,
    Disabled = 1,
    Draft    = 2,
    Archived = 3
};

enum class PolicyScope : uint8_t {
    Global   = 0,   // applied to entire endpoint
    Process  = 1,   // scoped to specific process names
    Path     = 2,   // scoped to filesystem paths
    Network  = 3,   // scoped to network rules
    User     = 4    // scoped to user accounts
};

enum class EnforcementMode : uint8_t {
    Audit    = 0,   // log violations but don't block
    Enforce  = 1,   // block violations
    Disabled = 2    // skip enforcement entirely
};

enum class DriftSeverity : uint8_t {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4
};

enum class AuditAction : uint8_t {
    PolicyCreated    = 0,
    PolicyUpdated    = 1,
    PolicyDeleted    = 2,
    PolicyEnabled    = 3,
    PolicyDisabled   = 4,
    RuleAdded        = 5,
    RuleRemoved      = 6,
    DriftDetected    = 7,
    DriftRemediated  = 8,
    EnforcementBlock = 9,
    ManualOverride   = 10
};

// ============================================================================
// TOSTRING HELPERS
// ============================================================================

[[nodiscard]] constexpr std::string_view ToString(PolicyStatus s) noexcept {
    switch (s) {
        case PolicyStatus::Active:   return "Active";
        case PolicyStatus::Disabled: return "Disabled";
        case PolicyStatus::Draft:    return "Draft";
        case PolicyStatus::Archived: return "Archived";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(PolicyScope s) noexcept {
    switch (s) {
        case PolicyScope::Global:  return "Global";
        case PolicyScope::Process: return "Process";
        case PolicyScope::Path:    return "Path";
        case PolicyScope::Network: return "Network";
        case PolicyScope::User:    return "User";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(EnforcementMode m) noexcept {
    switch (m) {
        case EnforcementMode::Audit:    return "Audit";
        case EnforcementMode::Enforce:  return "Enforce";
        case EnforcementMode::Disabled: return "Disabled";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(DriftSeverity s) noexcept {
    switch (s) {
        case DriftSeverity::Info:     return "Info";
        case DriftSeverity::Low:      return "Low";
        case DriftSeverity::Medium:   return "Medium";
        case DriftSeverity::High:     return "High";
        case DriftSeverity::Critical: return "Critical";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(AuditAction a) noexcept {
    switch (a) {
        case AuditAction::PolicyCreated:    return "PolicyCreated";
        case AuditAction::PolicyUpdated:    return "PolicyUpdated";
        case AuditAction::PolicyDeleted:    return "PolicyDeleted";
        case AuditAction::PolicyEnabled:    return "PolicyEnabled";
        case AuditAction::PolicyDisabled:   return "PolicyDisabled";
        case AuditAction::RuleAdded:        return "RuleAdded";
        case AuditAction::RuleRemoved:      return "RuleRemoved";
        case AuditAction::DriftDetected:    return "DriftDetected";
        case AuditAction::DriftRemediated:  return "DriftRemediated";
        case AuditAction::EnforcementBlock: return "EnforcementBlock";
        case AuditAction::ManualOverride:   return "ManualOverride";
    }
    return "Unknown";
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

struct PolicyRule {
    std::string ruleId;
    std::string description;
    std::string key;        // config key or registry path
    std::string expected;   // expected value (stringified)
    std::string comparator; // "eq", "ne", "contains", "regex", "gt", "lt"
};

struct PolicyDefinition {
    std::string             policyId;
    std::string             name;
    std::string             description;
    PolicyStatus            status = PolicyStatus::Draft;
    PolicyScope             scope = PolicyScope::Global;
    EnforcementMode         enforcement = EnforcementMode::Audit;
    uint32_t                version = 1;
    Clock::time_point       createdAt;
    Clock::time_point       updatedAt;
    std::string             createdBy;
    std::vector<PolicyRule> rules;
};

struct DriftRecord {
    std::string       driftId;
    std::string       policyId;
    std::string       ruleId;
    DriftSeverity     severity = DriftSeverity::Medium;
    std::string       expectedValue;
    std::string       actualValue;
    Clock::time_point detectedAt;
    bool              remediated = false;
    Clock::time_point remediatedAt;
};

struct AuditEntry {
    std::string       entryId;
    AuditAction       action = AuditAction::PolicyCreated;
    std::string       policyId;
    std::string       actor;        // "system" or username
    std::string       details;      // free-form JSON or description
    Clock::time_point timestamp;
};

struct PolicyQueryParams {
    std::optional<PolicyStatus>                        status;
    std::optional<PolicyScope>                         scope;
    std::optional<Clock::time_point>                   updatedAfter;
    uint32_t maxResults = 100;
};

struct DriftQueryParams {
    std::optional<std::string>                         policyId;
    std::optional<DriftSeverity>                       minSeverity;
    std::optional<bool>                                remediated;
    std::optional<Clock::time_point>                   detectedAfter;
    uint32_t maxResults = 100;
};

struct AuditQueryParams {
    std::optional<AuditAction>                         action;
    std::optional<std::string>                         policyId;
    std::optional<std::string>                         actor;
    std::optional<Clock::time_point>                   after;
    uint32_t maxResults = 200;
};

} // namespace ShadowStrike::Products::PhantomEDR::PolicyEngine

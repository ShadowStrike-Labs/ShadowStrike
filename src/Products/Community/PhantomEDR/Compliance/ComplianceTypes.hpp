/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::Compliance {

// ============================================================================
// ENUMERATIONS
// ============================================================================

enum class ComplianceFramework : uint8_t {
    CIS_Windows11        = 0,
    CIS_Windows10        = 1,
    NIST_800_53          = 2,
    PCI_DSS_4_0          = 3,
    HIPAA                = 4,
    ISO_27001            = 5,
    Custom               = 255
};

enum class CheckCategory : uint8_t {
    PasswordPolicy       = 0,
    AccountLockout       = 1,
    AuditPolicy          = 2,
    SecurityOptions      = 3,
    UserRightsAssignment = 4,
    FirewallProfile      = 5,
    ServiceConfiguration = 6,
    RegistryPermissions  = 7,
    FileSystemPermissions= 8,
    NetworkConfiguration = 9,
    WindowsUpdate        = 10,
    BitLocker            = 11,
    RemoteAccess         = 12,
    Logging              = 13,
    AntiVirus            = 14,
    Custom               = 255
};

enum class CheckStatus : uint8_t {
    Pass          = 0,
    Fail          = 1,
    Unknown       = 2,
    NotApplicable = 3,
    Error         = 4
};

enum class CheckType : uint8_t {
    RegistryValue        = 0,
    ServiceStatus        = 1,
    AuditPolicySetting   = 2,
    FirewallRule          = 3,
    SecurityPolicy       = 4,
    FilePermission       = 5,
    AccountPolicy        = 6,
    Custom               = 255
};

enum class Severity : uint8_t {
    Critical = 0,
    High     = 1,
    Medium   = 2,
    Low      = 3,
    Info     = 4
};

enum class FixEffort : uint8_t {
    Trivial  = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3
};

// ============================================================================
// TOSTRING HELPERS
// ============================================================================

[[nodiscard]] constexpr std::string_view ToString(ComplianceFramework f) noexcept {
    switch (f) {
        case ComplianceFramework::CIS_Windows11:    return "CIS Windows 11";
        case ComplianceFramework::CIS_Windows10:    return "CIS Windows 10";
        case ComplianceFramework::NIST_800_53:      return "NIST 800-53";
        case ComplianceFramework::PCI_DSS_4_0:      return "PCI-DSS 4.0";
        case ComplianceFramework::HIPAA:            return "HIPAA";
        case ComplianceFramework::ISO_27001:        return "ISO 27001";
        case ComplianceFramework::Custom:           return "Custom";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(CheckCategory c) noexcept {
    switch (c) {
        case CheckCategory::PasswordPolicy:        return "Password Policy";
        case CheckCategory::AccountLockout:         return "Account Lockout";
        case CheckCategory::AuditPolicy:            return "Audit Policy";
        case CheckCategory::SecurityOptions:        return "Security Options";
        case CheckCategory::UserRightsAssignment:   return "User Rights Assignment";
        case CheckCategory::FirewallProfile:        return "Firewall Profile";
        case CheckCategory::ServiceConfiguration:   return "Service Configuration";
        case CheckCategory::RegistryPermissions:    return "Registry Permissions";
        case CheckCategory::FileSystemPermissions:  return "File System Permissions";
        case CheckCategory::NetworkConfiguration:   return "Network Configuration";
        case CheckCategory::WindowsUpdate:          return "Windows Update";
        case CheckCategory::BitLocker:              return "BitLocker";
        case CheckCategory::RemoteAccess:           return "Remote Access";
        case CheckCategory::Logging:                return "Logging";
        case CheckCategory::AntiVirus:              return "Anti-Virus";
        case CheckCategory::Custom:                 return "Custom";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(CheckStatus s) noexcept {
    switch (s) {
        case CheckStatus::Pass:          return "Pass";
        case CheckStatus::Fail:          return "Fail";
        case CheckStatus::Unknown:       return "Unknown";
        case CheckStatus::NotApplicable: return "N/A";
        case CheckStatus::Error:         return "Error";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(Severity s) noexcept {
    switch (s) {
        case Severity::Critical: return "Critical";
        case Severity::High:     return "High";
        case Severity::Medium:   return "Medium";
        case Severity::Low:      return "Low";
        case Severity::Info:     return "Info";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(FixEffort e) noexcept {
    switch (e) {
        case FixEffort::Trivial: return "Trivial";
        case FixEffort::Low:     return "Low";
        case FixEffort::Medium:  return "Medium";
        case FixEffort::High:    return "High";
    }
    return "Unknown";
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

using Clock = std::chrono::system_clock;

struct ComplianceCheckDef {
    std::string checkId;
    std::string title;
    std::string description;
    ComplianceFramework framework = ComplianceFramework::CIS_Windows11;
    CheckCategory category = CheckCategory::PasswordPolicy;
    CheckType type = CheckType::RegistryValue;
    Severity severity = Severity::Medium;

    std::string registryHive;
    std::string registryKey;
    std::string registryValue;
    std::string expectedValue;
    std::string comparisonOp;

    std::string serviceName;
    std::string expectedServiceState;

    std::string policyArea;
    std::string policySetting;
    std::string expectedPolicySetting;

    std::string firewallProfile;
    std::string firewallSetting;
    std::string expectedFirewallValue;

    bool enabled = true;
};

struct ComplianceCheckResult {
    std::string checkId;
    std::string title;
    ComplianceFramework framework = ComplianceFramework::CIS_Windows11;
    CheckCategory category = CheckCategory::PasswordPolicy;
    Severity severity = Severity::Medium;
    CheckStatus status = CheckStatus::Unknown;
    std::string expectedValue;
    std::string actualValue;
    std::string detail;
    Clock::time_point evaluatedAt;
};

struct ComplianceScanResult {
    std::string scanId;
    ComplianceFramework framework = ComplianceFramework::CIS_Windows11;
    Clock::time_point startedAt;
    Clock::time_point completedAt;
    uint32_t totalChecks = 0;
    uint32_t passed = 0;
    uint32_t failed = 0;
    uint32_t unknown = 0;
    uint32_t notApplicable = 0;
    uint32_t errors = 0;
    std::vector<ComplianceCheckResult> results;

    [[nodiscard]] double ComplianceScore() const noexcept {
        if (totalChecks == 0) return 0.0;
        const auto applicable = totalChecks - notApplicable;
        if (applicable == 0) return 100.0;
        return (static_cast<double>(passed) / static_cast<double>(applicable)) * 100.0;
    }
};

struct HardeningRecommendation {
    std::string checkId;
    std::string title;
    std::string description;
    std::string fixDescription;
    Severity severity = Severity::Medium;
    FixEffort effort = FixEffort::Low;
    bool autoFixable = false;
    ComplianceFramework framework = ComplianceFramework::CIS_Windows11;
    CheckCategory category = CheckCategory::PasswordPolicy;

    std::string registryHive;
    std::string registryKey;
    std::string registryValue;
    std::string desiredRegistryData;
    uint32_t registryDataType = 0;

    std::string serviceName;
    uint32_t desiredStartType = 0;
};

} // namespace ShadowStrike::Products::PhantomEDR::Compliance

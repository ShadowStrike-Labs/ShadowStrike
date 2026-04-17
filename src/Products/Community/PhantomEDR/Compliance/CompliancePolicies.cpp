/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#include "pch.h"
#include "Products/Community/PhantomEDR/Compliance/CompliancePolicies.hpp"

#include <algorithm>
#include <format>
#include <shared_mutex>
#include <unordered_map>

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

namespace ShadowStrike::Products::PhantomEDR::Compliance {

namespace {

using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Utils::Logger;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[CompliancePolicies]";

// ============================================================================
// CIS WINDOWS 11 BENCHMARK CHECKS — REAL PRODUCTION VALUES
// ============================================================================

[[nodiscard]] std::vector<ComplianceCheckDef> BuildCISWindows11Checks() {
    std::vector<ComplianceCheckDef> checks;
    checks.reserve(40);

    // -- 1. PASSWORD POLICY --
    checks.push_back({
        .checkId = "CIS-W11-1.1.1",
        .title = "Enforce password history",
        .description = "Ensure password history is set to 24 or more passwords.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::PasswordPolicy,
        .type = CheckType::SecurityPolicy,
        .severity = Severity::Medium,
        .policyArea = "System Access",
        .policySetting = "PasswordHistorySize",
        .expectedPolicySetting = ">=24"
    });

    checks.push_back({
        .checkId = "CIS-W11-1.1.2",
        .title = "Maximum password age",
        .description = "Ensure maximum password age is set to 365 or fewer days.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::PasswordPolicy,
        .type = CheckType::SecurityPolicy,
        .severity = Severity::Medium,
        .policyArea = "System Access",
        .policySetting = "MaximumPasswordAge",
        .expectedPolicySetting = "<=365"
    });

    checks.push_back({
        .checkId = "CIS-W11-1.1.3",
        .title = "Minimum password age",
        .description = "Ensure minimum password age is set to 1 or more days.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::PasswordPolicy,
        .type = CheckType::SecurityPolicy,
        .severity = Severity::Low,
        .policyArea = "System Access",
        .policySetting = "MinimumPasswordAge",
        .expectedPolicySetting = ">=1"
    });

    checks.push_back({
        .checkId = "CIS-W11-1.1.4",
        .title = "Minimum password length",
        .description = "Ensure minimum password length is set to 14 or more characters.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::PasswordPolicy,
        .type = CheckType::SecurityPolicy,
        .severity = Severity::High,
        .policyArea = "System Access",
        .policySetting = "MinimumPasswordLength",
        .expectedPolicySetting = ">=14"
    });

    checks.push_back({
        .checkId = "CIS-W11-1.1.5",
        .title = "Password must meet complexity requirements",
        .description = "Ensure password complexity is enabled.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::PasswordPolicy,
        .type = CheckType::SecurityPolicy,
        .severity = Severity::High,
        .policyArea = "System Access",
        .policySetting = "PasswordComplexity",
        .expectedPolicySetting = "==1"
    });

    checks.push_back({
        .checkId = "CIS-W11-1.1.6",
        .title = "Store passwords using reversible encryption",
        .description = "Ensure store passwords using reversible encryption is disabled.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::PasswordPolicy,
        .type = CheckType::SecurityPolicy,
        .severity = Severity::Critical,
        .policyArea = "System Access",
        .policySetting = "ClearTextPassword",
        .expectedPolicySetting = "==0"
    });

    // -- 2. ACCOUNT LOCKOUT --
    checks.push_back({
        .checkId = "CIS-W11-1.2.1",
        .title = "Account lockout duration",
        .description = "Ensure account lockout duration is set to 15 or more minutes.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::AccountLockout,
        .type = CheckType::SecurityPolicy,
        .severity = Severity::Medium,
        .policyArea = "System Access",
        .policySetting = "LockoutDuration",
        .expectedPolicySetting = ">=15"
    });

    checks.push_back({
        .checkId = "CIS-W11-1.2.2",
        .title = "Account lockout threshold",
        .description = "Ensure account lockout threshold is set to 5 or fewer invalid logon attempts.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::AccountLockout,
        .type = CheckType::SecurityPolicy,
        .severity = Severity::High,
        .policyArea = "System Access",
        .policySetting = "LockoutBadCount",
        .expectedPolicySetting = "<=5"
    });

    checks.push_back({
        .checkId = "CIS-W11-1.2.3",
        .title = "Reset account lockout counter after",
        .description = "Ensure reset account lockout counter is set to 15 or more minutes.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::AccountLockout,
        .type = CheckType::SecurityPolicy,
        .severity = Severity::Medium,
        .policyArea = "System Access",
        .policySetting = "ResetLockoutCount",
        .expectedPolicySetting = ">=15"
    });

    // -- 3. SECURITY OPTIONS (REGISTRY) --
    checks.push_back({
        .checkId = "CIS-W11-2.3.7.1",
        .title = "LAN Manager authentication level",
        .description = "Ensure LAN Manager authentication level is set to NTLMv2 only (level 5).",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::SecurityOptions,
        .type = CheckType::RegistryValue,
        .severity = Severity::Critical,
        .registryHive = "HKLM",
        .registryKey = R"(SYSTEM\CurrentControlSet\Control\Lsa)",
        .registryValue = "LmCompatibilityLevel",
        .expectedValue = ">=5",
        .comparisonOp = ">="
    });

    checks.push_back({
        .checkId = "CIS-W11-2.3.7.2",
        .title = "Do not allow anonymous enumeration of SAM accounts",
        .description = "Ensure anonymous enumeration of SAM accounts is restricted.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::SecurityOptions,
        .type = CheckType::RegistryValue,
        .severity = Severity::High,
        .registryHive = "HKLM",
        .registryKey = R"(SYSTEM\CurrentControlSet\Control\Lsa)",
        .registryValue = "RestrictAnonymousSAM",
        .expectedValue = "1",
        .comparisonOp = "=="
    });

    checks.push_back({
        .checkId = "CIS-W11-2.3.7.3",
        .title = "Do not allow anonymous enumeration of SAM accounts and shares",
        .description = "Ensure anonymous enumeration of SAM accounts and shares is restricted.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::SecurityOptions,
        .type = CheckType::RegistryValue,
        .severity = Severity::High,
        .registryHive = "HKLM",
        .registryKey = R"(SYSTEM\CurrentControlSet\Control\Lsa)",
        .registryValue = "RestrictAnonymous",
        .expectedValue = "1",
        .comparisonOp = "=="
    });

    checks.push_back({
        .checkId = "CIS-W11-2.3.10.1",
        .title = "Disable SMBv1 client",
        .description = "Ensure SMBv1 client is disabled to prevent EternalBlue-class attacks.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::SecurityOptions,
        .type = CheckType::RegistryValue,
        .severity = Severity::Critical,
        .registryHive = "HKLM",
        .registryKey = R"(SYSTEM\CurrentControlSet\Services\mrxsmb10)",
        .registryValue = "Start",
        .expectedValue = "4",
        .comparisonOp = "=="
    });

    checks.push_back({
        .checkId = "CIS-W11-2.3.10.2",
        .title = "Disable SMBv1 server",
        .description = "Ensure SMBv1 server is disabled.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::SecurityOptions,
        .type = CheckType::RegistryValue,
        .severity = Severity::Critical,
        .registryHive = "HKLM",
        .registryKey = R"(SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters)",
        .registryValue = "SMB1",
        .expectedValue = "0",
        .comparisonOp = "=="
    });

    checks.push_back({
        .checkId = "CIS-W11-2.3.11.1",
        .title = "WDigest Authentication disabled",
        .description = "Ensure WDigest Authentication is disabled to prevent cleartext credential caching.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::SecurityOptions,
        .type = CheckType::RegistryValue,
        .severity = Severity::Critical,
        .registryHive = "HKLM",
        .registryKey = R"(SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest)",
        .registryValue = "UseLogonCredential",
        .expectedValue = "0",
        .comparisonOp = "=="
    });

    // -- 4. FIREWALL --
    checks.push_back({
        .checkId = "CIS-W11-9.1.1",
        .title = "Windows Firewall Domain Profile enabled",
        .description = "Ensure Windows Firewall Domain Profile is enabled.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::FirewallProfile,
        .type = CheckType::RegistryValue,
        .severity = Severity::High,
        .registryHive = "HKLM",
        .registryKey = R"(SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile)",
        .registryValue = "EnableFirewall",
        .expectedValue = "1",
        .comparisonOp = "=="
    });

    checks.push_back({
        .checkId = "CIS-W11-9.2.1",
        .title = "Windows Firewall Private Profile enabled",
        .description = "Ensure Windows Firewall Private Profile is enabled.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::FirewallProfile,
        .type = CheckType::RegistryValue,
        .severity = Severity::High,
        .registryHive = "HKLM",
        .registryKey = R"(SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile)",
        .registryValue = "EnableFirewall",
        .expectedValue = "1",
        .comparisonOp = "=="
    });

    checks.push_back({
        .checkId = "CIS-W11-9.3.1",
        .title = "Windows Firewall Public Profile enabled",
        .description = "Ensure Windows Firewall Public Profile is enabled.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::FirewallProfile,
        .type = CheckType::RegistryValue,
        .severity = Severity::Critical,
        .registryHive = "HKLM",
        .registryKey = R"(SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile)",
        .registryValue = "EnableFirewall",
        .expectedValue = "1",
        .comparisonOp = "=="
    });

    // -- 5. SERVICES --
    checks.push_back({
        .checkId = "CIS-W11-5.1",
        .title = "Remote Registry service disabled",
        .description = "Ensure Remote Registry service is set to Disabled.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::ServiceConfiguration,
        .type = CheckType::ServiceStatus,
        .severity = Severity::High,
        .serviceName = "RemoteRegistry",
        .expectedServiceState = "Disabled"
    });

    checks.push_back({
        .checkId = "CIS-W11-5.2",
        .title = "SSDP Discovery service disabled",
        .description = "Ensure SSDP Discovery service is set to Disabled.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::ServiceConfiguration,
        .type = CheckType::ServiceStatus,
        .severity = Severity::Medium,
        .serviceName = "SSDPSRV",
        .expectedServiceState = "Disabled"
    });

    checks.push_back({
        .checkId = "CIS-W11-5.3",
        .title = "UPnP Device Host service disabled",
        .description = "Ensure UPnP Device Host service is set to Disabled.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::ServiceConfiguration,
        .type = CheckType::ServiceStatus,
        .severity = Severity::Medium,
        .serviceName = "upnphost",
        .expectedServiceState = "Disabled"
    });

    checks.push_back({
        .checkId = "CIS-W11-5.4",
        .title = "Xbox services disabled",
        .description = "Ensure Xbox Accessory Management Service is set to Disabled.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::ServiceConfiguration,
        .type = CheckType::ServiceStatus,
        .severity = Severity::Low,
        .serviceName = "XboxGipSvc",
        .expectedServiceState = "Disabled"
    });

    checks.push_back({
        .checkId = "CIS-W11-5.5",
        .title = "Windows Remote Management (WS-Management)",
        .description = "Ensure WinRM service is disabled unless required for management.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::ServiceConfiguration,
        .type = CheckType::ServiceStatus,
        .severity = Severity::Medium,
        .serviceName = "WinRM",
        .expectedServiceState = "Disabled"
    });

    // -- 6. AUDIT POLICY --
    checks.push_back({
        .checkId = "CIS-W11-17.1.1",
        .title = "Audit Credential Validation",
        .description = "Ensure Audit Credential Validation is set to Success and Failure.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::AuditPolicy,
        .type = CheckType::AuditPolicySetting,
        .severity = Severity::High,
        .policyArea = "Account Logon",
        .policySetting = "Credential Validation",
        .expectedPolicySetting = "Success and Failure"
    });

    checks.push_back({
        .checkId = "CIS-W11-17.2.1",
        .title = "Audit Application Group Management",
        .description = "Ensure Audit Application Group Management is set to Success and Failure.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::AuditPolicy,
        .type = CheckType::AuditPolicySetting,
        .severity = Severity::Medium,
        .policyArea = "Account Management",
        .policySetting = "Application Group Management",
        .expectedPolicySetting = "Success and Failure"
    });

    checks.push_back({
        .checkId = "CIS-W11-17.5.1",
        .title = "Audit Account Lockout",
        .description = "Ensure Audit Account Lockout is set to include Failure.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::AuditPolicy,
        .type = CheckType::AuditPolicySetting,
        .severity = Severity::High,
        .policyArea = "Logon/Logoff",
        .policySetting = "Account Lockout",
        .expectedPolicySetting = "Failure"
    });

    checks.push_back({
        .checkId = "CIS-W11-17.5.2",
        .title = "Audit Logon",
        .description = "Ensure Audit Logon is set to Success and Failure.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::AuditPolicy,
        .type = CheckType::AuditPolicySetting,
        .severity = Severity::High,
        .policyArea = "Logon/Logoff",
        .policySetting = "Logon",
        .expectedPolicySetting = "Success and Failure"
    });

    checks.push_back({
        .checkId = "CIS-W11-17.9.1",
        .title = "Audit Security State Change",
        .description = "Ensure Audit Security State Change includes Success.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::AuditPolicy,
        .type = CheckType::AuditPolicySetting,
        .severity = Severity::High,
        .policyArea = "System",
        .policySetting = "Security State Change",
        .expectedPolicySetting = "Success"
    });

    // -- 7. REMOTE ACCESS --
    checks.push_back({
        .checkId = "CIS-W11-18.4.1",
        .title = "Remote Desktop connection encryption level",
        .description = "Ensure RDP connection encryption level is set to High.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::RemoteAccess,
        .type = CheckType::RegistryValue,
        .severity = Severity::High,
        .registryHive = "HKLM",
        .registryKey = R"(SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services)",
        .registryValue = "MinEncryptionLevel",
        .expectedValue = "3",
        .comparisonOp = ">="
    });

    checks.push_back({
        .checkId = "CIS-W11-18.4.2",
        .title = "Require NLA for Remote Desktop",
        .description = "Ensure Network Level Authentication is required for RDP.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::RemoteAccess,
        .type = CheckType::RegistryValue,
        .severity = Severity::High,
        .registryHive = "HKLM",
        .registryKey = R"(SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services)",
        .registryValue = "UserAuthentication",
        .expectedValue = "1",
        .comparisonOp = "=="
    });

    // -- 8. WINDOWS UPDATE --
    checks.push_back({
        .checkId = "CIS-W11-18.9.1",
        .title = "Configure Automatic Updates",
        .description = "Ensure Windows Update is configured to auto-download and install.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::WindowsUpdate,
        .type = CheckType::RegistryValue,
        .severity = Severity::High,
        .registryHive = "HKLM",
        .registryKey = R"(SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU)",
        .registryValue = "NoAutoUpdate",
        .expectedValue = "0",
        .comparisonOp = "=="
    });

    // -- 9. CREDENTIAL GUARD --
    checks.push_back({
        .checkId = "CIS-W11-18.8.1",
        .title = "Credential Guard enabled",
        .description = "Ensure Credential Guard is configured to protect LSASS.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::SecurityOptions,
        .type = CheckType::RegistryValue,
        .severity = Severity::Critical,
        .registryHive = "HKLM",
        .registryKey = R"(SOFTWARE\Policies\Microsoft\Windows\DeviceGuard)",
        .registryValue = "LsaCfgFlags",
        .expectedValue = ">=1",
        .comparisonOp = ">="
    });

    // -- 10. BITLOCKER --
    checks.push_back({
        .checkId = "CIS-W11-18.10.1",
        .title = "BitLocker drive encryption method",
        .description = "Ensure BitLocker encryption method is set to AES-256.",
        .framework = ComplianceFramework::CIS_Windows11,
        .category = CheckCategory::BitLocker,
        .type = CheckType::RegistryValue,
        .severity = Severity::High,
        .registryHive = "HKLM",
        .registryKey = R"(SOFTWARE\Policies\Microsoft\FVE)",
        .registryValue = "EncryptionMethodWithXtsOs",
        .expectedValue = "7",
        .comparisonOp = ">="
    });

    return checks;
}

} // anonymous namespace

// ============================================================================
// IMPL
// ============================================================================

class CompliancePoliciesImpl {
public:
    [[nodiscard]] bool Initialize() {
        std::unique_lock lk(m_mtx);
        if (m_initialized) return true;

        if (!CreateSchema()) return false;
        LoadBuiltinPolicies();
        LoadCustomChecksFromDb();

        m_initialized = true;
        Logger::Info("{} Initialized with {} checks", kLogPrefix, m_checks.size());
        return true;
    }

    void Shutdown() {
        std::unique_lock lk(m_mtx);
        m_checks.clear();
        m_initialized = false;
        Logger::Info("{} Shut down", kLogPrefix);
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lk(m_mtx);
        return m_initialized;
    }

    [[nodiscard]] std::vector<ComplianceCheckDef> GetChecksForFramework(ComplianceFramework fw) const {
        std::shared_lock lk(m_mtx);
        std::vector<ComplianceCheckDef> result;
        for (auto& [_, check] : m_checks) {
            if (check.framework == fw && check.enabled) {
                result.push_back(check);
            }
        }
        return result;
    }

    [[nodiscard]] std::vector<ComplianceCheckDef> GetAllChecks() const {
        std::shared_lock lk(m_mtx);
        std::vector<ComplianceCheckDef> result;
        result.reserve(m_checks.size());
        for (auto& [_, check] : m_checks) {
            result.push_back(check);
        }
        return result;
    }

    [[nodiscard]] std::optional<ComplianceCheckDef> GetCheck(std::string_view checkId) const {
        std::shared_lock lk(m_mtx);
        auto it = m_checks.find(std::string(checkId));
        if (it == m_checks.end()) return std::nullopt;
        return it->second;
    }

    [[nodiscard]] uint32_t GetCheckCount(ComplianceFramework fw) const {
        std::shared_lock lk(m_mtx);
        uint32_t count = 0;
        for (auto& [_, check] : m_checks) {
            if (check.framework == fw && check.enabled) ++count;
        }
        return count;
    }

    [[nodiscard]] bool AddCustomCheck(const ComplianceCheckDef& check) {
        if (check.checkId.empty() || check.title.empty()) {
            Logger::Warn("{} Cannot add custom check with empty ID or title", kLogPrefix);
            return false;
        }
        std::unique_lock lk(m_mtx);
        if (m_checks.contains(check.checkId)) {
            Logger::Warn("{} Check '{}' already exists", kLogPrefix, check.checkId);
            return false;
        }
        if (!PersistCustomCheck(check)) return false;
        m_checks[check.checkId] = check;
        Logger::Info("{} Added custom check: {}", kLogPrefix, check.checkId);
        return true;
    }

    [[nodiscard]] bool RemoveCustomCheck(std::string_view checkId) {
        std::unique_lock lk(m_mtx);
        auto it = m_checks.find(std::string(checkId));
        if (it == m_checks.end()) return false;
        if (!DeleteCustomCheckFromDb(checkId)) return false;
        m_checks.erase(it);
        Logger::Info("{} Removed custom check: {}", kLogPrefix, checkId);
        return true;
    }

    [[nodiscard]] bool SetCheckEnabled(std::string_view checkId, bool enabled) {
        std::unique_lock lk(m_mtx);
        auto it = m_checks.find(std::string(checkId));
        if (it == m_checks.end()) return false;
        it->second.enabled = enabled;
        Logger::Info("{} Check '{}' {}", kLogPrefix, checkId, enabled ? "enabled" : "disabled");
        return true;
    }

private:
    mutable std::shared_mutex m_mtx;
    bool m_initialized = false;
    std::unordered_map<std::string, ComplianceCheckDef> m_checks;

    [[nodiscard]] bool CreateSchema() {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        const bool ok = db.Execute(
            "CREATE TABLE IF NOT EXISTS compliance_custom_checks ("
            "  check_id TEXT PRIMARY KEY,"
            "  title TEXT NOT NULL,"
            "  description TEXT,"
            "  framework INTEGER NOT NULL DEFAULT 255,"
            "  category INTEGER NOT NULL DEFAULT 0,"
            "  check_type INTEGER NOT NULL DEFAULT 0,"
            "  severity INTEGER NOT NULL DEFAULT 2,"
            "  registry_hive TEXT,"
            "  registry_key TEXT,"
            "  registry_value TEXT,"
            "  expected_value TEXT,"
            "  comparison_op TEXT,"
            "  service_name TEXT,"
            "  expected_service_state TEXT,"
            "  policy_area TEXT,"
            "  policy_setting TEXT,"
            "  expected_policy_setting TEXT,"
            "  firewall_profile TEXT,"
            "  firewall_setting TEXT,"
            "  expected_firewall_value TEXT,"
            "  enabled INTEGER NOT NULL DEFAULT 1,"
            "  created_at INTEGER NOT NULL DEFAULT 0"
            ");", &dbErr);
        if (!ok) {
            Logger::Error("{} Failed to create schema: {}", kLogPrefix, StringUtils::ToNarrow(dbErr.message));
        }
        return ok;
    }

    void LoadBuiltinPolicies() {
        auto cisChecks = BuildCISWindows11Checks();
        for (auto& c : cisChecks) {
            m_checks[c.checkId] = std::move(c);
        }
    }

    void LoadCustomChecksFromDb() {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        auto result = db.Query(
            "SELECT check_id, title, description, framework, category, check_type, severity,"
            " registry_hive, registry_key, registry_value, expected_value, comparison_op,"
            " service_name, expected_service_state, policy_area, policy_setting,"
            " expected_policy_setting, firewall_profile, firewall_setting,"
            " expected_firewall_value, enabled FROM compliance_custom_checks;", &dbErr);

        while (result.Next()) {
            ComplianceCheckDef c;
            c.checkId = result.GetString(0);
            c.title = result.GetString(1);
            c.description = result.GetString(2);
            c.framework = static_cast<ComplianceFramework>(result.GetInt(3));
            c.category = static_cast<CheckCategory>(result.GetInt(4));
            c.type = static_cast<CheckType>(result.GetInt(5));
            c.severity = static_cast<Severity>(result.GetInt(6));
            c.registryHive = result.GetString(7);
            c.registryKey = result.GetString(8);
            c.registryValue = result.GetString(9);
            c.expectedValue = result.GetString(10);
            c.comparisonOp = result.GetString(11);
            c.serviceName = result.GetString(12);
            c.expectedServiceState = result.GetString(13);
            c.policyArea = result.GetString(14);
            c.policySetting = result.GetString(15);
            c.expectedPolicySetting = result.GetString(16);
            c.firewallProfile = result.GetString(17);
            c.firewallSetting = result.GetString(18);
            c.expectedFirewallValue = result.GetString(19);
            c.enabled = result.GetInt(20) != 0;
            m_checks[c.checkId] = std::move(c);
        }
    }

    [[nodiscard]] bool PersistCustomCheck(const ComplianceCheckDef& c) {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now().time_since_epoch()).count();
        return db.ExecuteWithParams(
            "INSERT OR REPLACE INTO compliance_custom_checks "
            "(check_id, title, description, framework, category, check_type, severity,"
            " registry_hive, registry_key, registry_value, expected_value, comparison_op,"
            " service_name, expected_service_state, policy_area, policy_setting,"
            " expected_policy_setting, firewall_profile, firewall_setting,"
            " expected_firewall_value, enabled, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            &dbErr,
            c.checkId, c.title, c.description,
            static_cast<int>(c.framework), static_cast<int>(c.category),
            static_cast<int>(c.type), static_cast<int>(c.severity),
            c.registryHive, c.registryKey, c.registryValue,
            c.expectedValue, c.comparisonOp,
            c.serviceName, c.expectedServiceState,
            c.policyArea, c.policySetting, c.expectedPolicySetting,
            c.firewallProfile, c.firewallSetting, c.expectedFirewallValue,
            c.enabled ? 1 : 0, now);
    }

    [[nodiscard]] bool DeleteCustomCheckFromDb(std::string_view checkId) {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        return db.ExecuteWithParams(
            "DELETE FROM compliance_custom_checks WHERE check_id = ?;",
            &dbErr, std::string(checkId));
    }
};

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

CompliancePolicies::CompliancePolicies() : m_impl(std::make_unique<CompliancePoliciesImpl>()) {}
CompliancePolicies::~CompliancePolicies() = default;

CompliancePolicies& CompliancePolicies::Instance() {
    static CompliancePolicies instance;
    return instance;
}

bool CompliancePolicies::Initialize() { return m_impl->Initialize(); }
void CompliancePolicies::Shutdown() { m_impl->Shutdown(); }
bool CompliancePolicies::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
std::vector<ComplianceCheckDef> CompliancePolicies::GetChecksForFramework(ComplianceFramework fw) const { return m_impl->GetChecksForFramework(fw); }
std::vector<ComplianceCheckDef> CompliancePolicies::GetAllChecks() const { return m_impl->GetAllChecks(); }
std::optional<ComplianceCheckDef> CompliancePolicies::GetCheck(std::string_view checkId) const { return m_impl->GetCheck(checkId); }
uint32_t CompliancePolicies::GetCheckCount(ComplianceFramework fw) const { return m_impl->GetCheckCount(fw); }
bool CompliancePolicies::AddCustomCheck(const ComplianceCheckDef& check) { return m_impl->AddCustomCheck(check); }
bool CompliancePolicies::RemoveCustomCheck(std::string_view checkId) { return m_impl->RemoveCustomCheck(checkId); }
bool CompliancePolicies::SetCheckEnabled(std::string_view checkId, bool enabled) { return m_impl->SetCheckEnabled(checkId, enabled); }

} // namespace ShadowStrike::Products::PhantomEDR::Compliance

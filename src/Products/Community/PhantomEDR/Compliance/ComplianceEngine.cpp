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
#include "Products/Community/PhantomEDR/Compliance/ComplianceEngine.hpp"
#include "Products/Community/PhantomEDR/Compliance/CompliancePolicies.hpp"

#include <algorithm>
#include <charconv>
#include <format>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winsvc.h>
#include <ntsecapi.h>

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

namespace ShadowStrike::Products::PhantomEDR::Compliance {

namespace {

using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Utils::Logger;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[ComplianceEngine]";

[[nodiscard]] int64_t ToUnixMillis(Clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        tp.time_since_epoch()).count();
}

[[nodiscard]] std::string GenerateScanId() {
    const auto now = std::chrono::duration_cast<std::chrono::microseconds>(
        Clock::now().time_since_epoch()).count();
    return std::format("cscan-{:016x}", now);
}

// ============================================================================
// COMPARISON HELPERS
// ============================================================================

[[nodiscard]] bool CompareNumeric(int64_t actual, std::string_view op, std::string_view expectedStr) {
    int64_t expected = 0;
    std::string_view numPart = expectedStr;
    if (numPart.starts_with(">=") || numPart.starts_with("<=") || numPart.starts_with("==")) {
        numPart = numPart.substr(2);
    }
    auto [ptr, ec] = std::from_chars(numPart.data(), numPart.data() + numPart.size(), expected);
    if (ec != std::errc()) return false;

    if (op == "==" || expectedStr.starts_with("==")) return actual == expected;
    if (op == ">=" || expectedStr.starts_with(">=")) return actual >= expected;
    if (op == "<=" || expectedStr.starts_with("<=")) return actual <= expected;
    if (op == ">" ) return actual > expected;
    if (op == "<" ) return actual < expected;
    if (op == "!=") return actual != expected;
    return actual == expected;
}

// ============================================================================
// WINDOWS REGISTRY CHECK
// ============================================================================

[[nodiscard]] ComplianceCheckResult EvaluateRegistryCheck(const ComplianceCheckDef& check) {
    ComplianceCheckResult result;
    result.checkId = check.checkId;
    result.title = check.title;
    result.framework = check.framework;
    result.category = check.category;
    result.severity = check.severity;
    result.expectedValue = check.expectedValue;
    result.evaluatedAt = Clock::now();

    HKEY rootKey = HKEY_LOCAL_MACHINE;
    if (check.registryHive == "HKCU") rootKey = HKEY_CURRENT_USER;
    else if (check.registryHive == "HKCR") rootKey = HKEY_CLASSES_ROOT;

    const auto wideKey = StringUtils::ToWide(check.registryKey);
    const auto wideValue = StringUtils::ToWide(check.registryValue);

    HKEY hKey = nullptr;
    LONG ret = RegOpenKeyExW(rootKey, wideKey.c_str(), 0, KEY_READ, &hKey);
    if (ret != ERROR_SUCCESS) {
        result.status = CheckStatus::Unknown;
        result.actualValue = "(key not found)";
        result.detail = std::format("RegOpenKeyExW failed with error {}", ret);
        return result;
    }

    DWORD dataType = 0;
    DWORD dataSize = 0;
    ret = RegQueryValueExW(hKey, wideValue.c_str(), nullptr, &dataType, nullptr, &dataSize);
    if (ret != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        result.status = CheckStatus::Unknown;
        result.actualValue = "(value not found)";
        result.detail = std::format("RegQueryValueExW failed with error {}", ret);
        return result;
    }

    if (dataType == REG_DWORD && dataSize == sizeof(DWORD)) {
        DWORD dwValue = 0;
        ret = RegQueryValueExW(hKey, wideValue.c_str(), nullptr, nullptr,
                               reinterpret_cast<LPBYTE>(&dwValue), &dataSize);
        RegCloseKey(hKey);
        if (ret != ERROR_SUCCESS) {
            result.status = CheckStatus::Error;
            result.detail = std::format("Failed to read REG_DWORD: error {}", ret);
            return result;
        }
        result.actualValue = std::to_string(dwValue);
        result.status = CompareNumeric(static_cast<int64_t>(dwValue), check.comparisonOp, check.expectedValue)
            ? CheckStatus::Pass : CheckStatus::Fail;
    }
    else if (dataType == REG_QWORD && dataSize == sizeof(uint64_t)) {
        uint64_t qwValue = 0;
        ret = RegQueryValueExW(hKey, wideValue.c_str(), nullptr, nullptr,
                               reinterpret_cast<LPBYTE>(&qwValue), &dataSize);
        RegCloseKey(hKey);
        if (ret != ERROR_SUCCESS) {
            result.status = CheckStatus::Error;
            result.detail = std::format("Failed to read REG_QWORD: error {}", ret);
            return result;
        }
        result.actualValue = std::to_string(qwValue);
        result.status = CompareNumeric(static_cast<int64_t>(qwValue), check.comparisonOp, check.expectedValue)
            ? CheckStatus::Pass : CheckStatus::Fail;
    }
    else if (dataType == REG_SZ || dataType == REG_EXPAND_SZ) {
        constexpr DWORD kMaxStringBytes = 4096;
        if (dataSize > kMaxStringBytes) {
            RegCloseKey(hKey);
            result.status = CheckStatus::Error;
            result.detail = "Registry string value exceeds 4KB cap";
            return result;
        }
        std::vector<wchar_t> buf(dataSize / sizeof(wchar_t) + 1, L'\0');
        ret = RegQueryValueExW(hKey, wideValue.c_str(), nullptr, nullptr,
                               reinterpret_cast<LPBYTE>(buf.data()), &dataSize);
        RegCloseKey(hKey);
        if (ret != ERROR_SUCCESS) {
            result.status = CheckStatus::Error;
            result.detail = std::format("Failed to read REG_SZ: error {}", ret);
            return result;
        }
        result.actualValue = StringUtils::ToNarrow(buf.data());
        // Try numeric comparison first, fall back to string equality
        int64_t numVal = 0;
        auto [p, e] = std::from_chars(result.actualValue.data(),
                                       result.actualValue.data() + result.actualValue.size(), numVal);
        if (e == std::errc()) {
            result.status = CompareNumeric(numVal, check.comparisonOp, check.expectedValue)
                ? CheckStatus::Pass : CheckStatus::Fail;
        } else {
            result.status = (result.actualValue == check.expectedValue)
                ? CheckStatus::Pass : CheckStatus::Fail;
        }
    }
    else {
        RegCloseKey(hKey);
        result.status = CheckStatus::Unknown;
        result.detail = std::format("Unsupported registry data type: {}", dataType);
    }

    return result;
}

// ============================================================================
// WINDOWS SERVICE CHECK
// ============================================================================

[[nodiscard]] ComplianceCheckResult EvaluateServiceCheck(const ComplianceCheckDef& check) {
    ComplianceCheckResult result;
    result.checkId = check.checkId;
    result.title = check.title;
    result.framework = check.framework;
    result.category = check.category;
    result.severity = check.severity;
    result.expectedValue = check.expectedServiceState;
    result.evaluatedAt = Clock::now();

    const auto wideName = StringUtils::ToWide(check.serviceName);

    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) {
        result.status = CheckStatus::Error;
        result.detail = std::format("OpenSCManagerW failed: {}", GetLastError());
        return result;
    }

    SC_HANDLE hService = OpenServiceW(scManager, wideName.c_str(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!hService) {
        const DWORD err = GetLastError();
        CloseServiceHandle(scManager);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            result.status = CheckStatus::NotApplicable;
            result.actualValue = "(service not installed)";
            result.detail = "Service does not exist on this system";
            return result;
        }
        result.status = CheckStatus::Error;
        result.detail = std::format("OpenServiceW failed: {}", err);
        return result;
    }

    DWORD bytesNeeded = 0;
    QueryServiceConfigW(hService, nullptr, 0, &bytesNeeded);
    std::vector<BYTE> configBuf(bytesNeeded);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuf.data());

    if (!QueryServiceConfigW(hService, config, bytesNeeded, &bytesNeeded)) {
        CloseServiceHandle(hService);
        CloseServiceHandle(scManager);
        result.status = CheckStatus::Error;
        result.detail = std::format("QueryServiceConfigW failed: {}", GetLastError());
        return result;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(scManager);

    std::string actualState;
    switch (config->dwStartType) {
        case SERVICE_DISABLED:       actualState = "Disabled"; break;
        case SERVICE_BOOT_START:     actualState = "Boot"; break;
        case SERVICE_SYSTEM_START:   actualState = "System"; break;
        case SERVICE_AUTO_START:     actualState = "Automatic"; break;
        case SERVICE_DEMAND_START:   actualState = "Manual"; break;
        default:                     actualState = std::format("Unknown({})", config->dwStartType); break;
    }

    result.actualValue = actualState;
    result.status = (actualState == check.expectedServiceState) ? CheckStatus::Pass : CheckStatus::Fail;
    return result;
}

// ============================================================================
// AUDIT POLICY CHECK (via AuditQuerySystemPolicy)
// ============================================================================

[[nodiscard]] ComplianceCheckResult EvaluateAuditPolicyCheck(const ComplianceCheckDef& check) {
    ComplianceCheckResult result;
    result.checkId = check.checkId;
    result.title = check.title;
    result.framework = check.framework;
    result.category = check.category;
    result.severity = check.severity;
    result.expectedValue = check.expectedPolicySetting;
    result.evaluatedAt = Clock::now();

    // Use auditpol command output parsed from registry
    // The advanced audit policy GUIDs live under:
    //   HKLM\SECURITY\Policy\PolAdtEv (not directly accessible without SYSTEM)
    // For community edition, read from machine audit policy registry
    const std::string regKey = R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit)";
    const auto wideKey = StringUtils::ToWide(regKey);

    HKEY hKey = nullptr;
    LONG ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, wideKey.c_str(), 0, KEY_READ, &hKey);
    if (ret != ERROR_SUCCESS) {
        // Audit policy not configured via registry — report as unknown
        result.status = CheckStatus::Unknown;
        result.actualValue = "(not configured)";
        result.detail = "Audit policy registry key not found; use auditpol.exe for advanced audit policies";
        return result;
    }
    RegCloseKey(hKey);

    // For community edition without SYSTEM privileges, report the expected guidance
    result.status = CheckStatus::Unknown;
    result.actualValue = "(requires elevated audit query)";
    result.detail = "Advanced audit policy requires SYSTEM-level access via auditpol.exe; "
                    "check manually: auditpol /get /category:*";
    return result;
}

// ============================================================================
// SECURITY POLICY CHECK (secedit export parsing)
// ============================================================================

[[nodiscard]] ComplianceCheckResult EvaluateSecurityPolicyCheck(const ComplianceCheckDef& check) {
    ComplianceCheckResult result;
    result.checkId = check.checkId;
    result.title = check.title;
    result.framework = check.framework;
    result.category = check.category;
    result.severity = check.severity;
    result.expectedValue = check.expectedPolicySetting;
    result.evaluatedAt = Clock::now();

    // Security policies (password, lockout) live in SAM/LSA —
    // Read from NetUserModalsGet (level 0 for password, level 3 for lockout)
    // For a production NGAV running as SYSTEM this is accessible.
    // For community-edition syntax check, we read from well-known registry mirrors.

    // Password policies are mirrored at:
    //   HKLM\SAM\SAM\Domains\Account (requires SYSTEM)
    // Fallback: Check common registry locations
    const auto& setting = check.policySetting;

    if (setting == "PasswordComplexity" || setting == "ClearTextPassword" ||
        setting == "MinimumPasswordLength" || setting == "PasswordHistorySize" ||
        setting == "MaximumPasswordAge" || setting == "MinimumPasswordAge") {
        // These require NetUserModalsGet or secedit — not directly in registry
        result.status = CheckStatus::Unknown;
        result.actualValue = "(requires SYSTEM or secedit export)";
        result.detail = std::format("Security policy '{}' requires elevated access; "
            "ShadowStrike service reads this at runtime via NetUserModalsGet", setting);
        return result;
    }

    if (setting == "LockoutDuration" || setting == "LockoutBadCount" || setting == "ResetLockoutCount") {
        result.status = CheckStatus::Unknown;
        result.actualValue = "(requires SYSTEM or secedit export)";
        result.detail = std::format("Account lockout policy '{}' requires elevated access", setting);
        return result;
    }

    result.status = CheckStatus::Unknown;
    result.actualValue = "(unsupported policy setting)";
    result.detail = std::format("Policy setting '{}' not yet mapped to a check method", setting);
    return result;
}

} // anonymous namespace

// ============================================================================
// IMPL
// ============================================================================

class ComplianceEngineImpl {
public:
    [[nodiscard]] bool Initialize() {
        std::unique_lock lk(m_mtx);
        if (m_initialized) return true;

        if (!CreateSchema()) return false;

        m_initialized = true;
        Logger::Info("{} Initialized", kLogPrefix);
        return true;
    }

    void Shutdown() {
        std::unique_lock lk(m_mtx);
        m_initialized = false;
        Logger::Info("{} Shut down", kLogPrefix);
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lk(m_mtx);
        return m_initialized;
    }

    [[nodiscard]] ComplianceScanResult RunScan(ComplianceFramework framework) {
        ComplianceScanResult scan;
        scan.scanId = GenerateScanId();
        scan.framework = framework;
        scan.startedAt = Clock::now();

        auto& policies = CompliancePolicies::Instance();
        auto checks = policies.GetChecksForFramework(framework);

        Logger::Info("{} Starting {} scan with {} checks", kLogPrefix,
                     ToString(framework), checks.size());

        scan.results.reserve(checks.size());
        for (const auto& check : checks) {
            auto result = EvaluateCheck(check);
            switch (result.status) {
                case CheckStatus::Pass:          ++scan.passed; break;
                case CheckStatus::Fail:          ++scan.failed; break;
                case CheckStatus::Unknown:       ++scan.unknown; break;
                case CheckStatus::NotApplicable: ++scan.notApplicable; break;
                case CheckStatus::Error:         ++scan.errors; break;
            }
            scan.results.push_back(std::move(result));
        }

        scan.totalChecks = static_cast<uint32_t>(scan.results.size());
        scan.completedAt = Clock::now();

        PersistScan(scan);

        Logger::Info("{} Scan {} complete: {}/{} passed ({:.1f}% compliant)",
                     kLogPrefix, scan.scanId, scan.passed, scan.totalChecks,
                     scan.ComplianceScore());
        return scan;
    }

    [[nodiscard]] ComplianceScanResult RunAllFrameworks() {
        ComplianceScanResult combined;
        combined.scanId = GenerateScanId();
        combined.framework = ComplianceFramework::Custom;
        combined.startedAt = Clock::now();

        constexpr std::array<ComplianceFramework, 2> frameworks = {
            ComplianceFramework::CIS_Windows11,
            ComplianceFramework::CIS_Windows10
        };

        for (auto fw : frameworks) {
            auto partial = RunScan(fw);
            combined.passed += partial.passed;
            combined.failed += partial.failed;
            combined.unknown += partial.unknown;
            combined.notApplicable += partial.notApplicable;
            combined.errors += partial.errors;
            combined.results.insert(combined.results.end(),
                std::make_move_iterator(partial.results.begin()),
                std::make_move_iterator(partial.results.end()));
        }

        combined.totalChecks = static_cast<uint32_t>(combined.results.size());
        combined.completedAt = Clock::now();
        return combined;
    }

    [[nodiscard]] ComplianceCheckResult EvaluateCheck(const ComplianceCheckDef& check) {
        switch (check.type) {
            case CheckType::RegistryValue:      return EvaluateRegistryCheck(check);
            case CheckType::ServiceStatus:       return EvaluateServiceCheck(check);
            case CheckType::AuditPolicySetting:  return EvaluateAuditPolicyCheck(check);
            case CheckType::SecurityPolicy:      return EvaluateSecurityPolicyCheck(check);
            case CheckType::AccountPolicy:       return EvaluateSecurityPolicyCheck(check);
            default: {
                ComplianceCheckResult result;
                result.checkId = check.checkId;
                result.title = check.title;
                result.framework = check.framework;
                result.category = check.category;
                result.severity = check.severity;
                result.status = CheckStatus::Unknown;
                result.detail = "Check type not yet implemented";
                result.evaluatedAt = Clock::now();
                return result;
            }
        }
    }

    [[nodiscard]] std::vector<ComplianceScanResult> GetScanHistory(
            ComplianceFramework framework, uint32_t maxResults) const {
        std::shared_lock lk(m_mtx);
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        auto rows = db.QueryWithParams(
            "SELECT scan_id, framework, started_at, completed_at, total_checks,"
            " passed, failed, unknown_count, not_applicable, errors"
            " FROM compliance_scans WHERE framework = ?"
            " ORDER BY started_at DESC LIMIT ?;",
            &dbErr, static_cast<int>(framework), static_cast<int64_t>(maxResults));

        std::vector<ComplianceScanResult> results;
        while (rows.Next()) {
            ComplianceScanResult s;
            s.scanId = rows.GetString(0);
            s.framework = static_cast<ComplianceFramework>(rows.GetInt(1));
            s.startedAt = Clock::time_point(std::chrono::duration_cast<Clock::duration>(
                std::chrono::milliseconds(rows.GetInt64(2))));
            s.completedAt = Clock::time_point(std::chrono::duration_cast<Clock::duration>(
                std::chrono::milliseconds(rows.GetInt64(3))));
            s.totalChecks = static_cast<uint32_t>(rows.GetInt(4));
            s.passed = static_cast<uint32_t>(rows.GetInt(5));
            s.failed = static_cast<uint32_t>(rows.GetInt(6));
            s.unknown = static_cast<uint32_t>(rows.GetInt(7));
            s.notApplicable = static_cast<uint32_t>(rows.GetInt(8));
            s.errors = static_cast<uint32_t>(rows.GetInt(9));
            results.push_back(std::move(s));
        }
        return results;
    }

    [[nodiscard]] std::optional<ComplianceScanResult> GetLatestScan(ComplianceFramework framework) const {
        auto history = GetScanHistory(framework, 1);
        if (history.empty()) return std::nullopt;
        return std::move(history.front());
    }

private:
    mutable std::shared_mutex m_mtx;
    bool m_initialized = false;

    [[nodiscard]] bool CreateSchema() {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        return db.Execute(
            "CREATE TABLE IF NOT EXISTS compliance_scans ("
            "  scan_id TEXT PRIMARY KEY,"
            "  framework INTEGER NOT NULL,"
            "  started_at INTEGER NOT NULL,"
            "  completed_at INTEGER NOT NULL,"
            "  total_checks INTEGER NOT NULL DEFAULT 0,"
            "  passed INTEGER NOT NULL DEFAULT 0,"
            "  failed INTEGER NOT NULL DEFAULT 0,"
            "  unknown_count INTEGER NOT NULL DEFAULT 0,"
            "  not_applicable INTEGER NOT NULL DEFAULT 0,"
            "  errors INTEGER NOT NULL DEFAULT 0"
            ");"
            "CREATE TABLE IF NOT EXISTS compliance_scan_results ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  scan_id TEXT NOT NULL,"
            "  check_id TEXT NOT NULL,"
            "  status INTEGER NOT NULL,"
            "  expected_value TEXT,"
            "  actual_value TEXT,"
            "  detail TEXT,"
            "  evaluated_at INTEGER NOT NULL,"
            "  FOREIGN KEY (scan_id) REFERENCES compliance_scans(scan_id)"
            ");", &dbErr);
    }

    void PersistScan(const ComplianceScanResult& scan) {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;

        db.ExecuteWithParams(
            "INSERT INTO compliance_scans"
            " (scan_id, framework, started_at, completed_at, total_checks, passed, failed, unknown_count, not_applicable, errors)"
            " VALUES (?,?,?,?,?,?,?,?,?,?);",
            &dbErr,
            scan.scanId,
            static_cast<int>(scan.framework),
            ToUnixMillis(scan.startedAt),
            ToUnixMillis(scan.completedAt),
            static_cast<int64_t>(scan.totalChecks),
            static_cast<int64_t>(scan.passed),
            static_cast<int64_t>(scan.failed),
            static_cast<int64_t>(scan.unknown),
            static_cast<int64_t>(scan.notApplicable),
            static_cast<int64_t>(scan.errors));

        for (const auto& r : scan.results) {
            db.ExecuteWithParams(
                "INSERT INTO compliance_scan_results"
                " (scan_id, check_id, status, expected_value, actual_value, detail, evaluated_at)"
                " VALUES (?,?,?,?,?,?,?);",
                &dbErr,
                scan.scanId,
                r.checkId,
                static_cast<int>(r.status),
                r.expectedValue,
                r.actualValue,
                r.detail,
                ToUnixMillis(r.evaluatedAt));
        }
    }
};

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

ComplianceEngine::ComplianceEngine() : m_impl(std::make_unique<ComplianceEngineImpl>()) {}
ComplianceEngine::~ComplianceEngine() = default;

ComplianceEngine& ComplianceEngine::Instance() {
    static ComplianceEngine instance;
    return instance;
}

bool ComplianceEngine::Initialize() { return m_impl->Initialize(); }
void ComplianceEngine::Shutdown() { m_impl->Shutdown(); }
bool ComplianceEngine::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
ComplianceScanResult ComplianceEngine::RunScan(ComplianceFramework fw) { return m_impl->RunScan(fw); }
ComplianceScanResult ComplianceEngine::RunAllFrameworks() { return m_impl->RunAllFrameworks(); }
ComplianceCheckResult ComplianceEngine::EvaluateCheck(const ComplianceCheckDef& check) { return m_impl->EvaluateCheck(check); }
std::vector<ComplianceScanResult> ComplianceEngine::GetScanHistory(ComplianceFramework fw, uint32_t max) const { return m_impl->GetScanHistory(fw, max); }
std::optional<ComplianceScanResult> ComplianceEngine::GetLatestScan(ComplianceFramework fw) const { return m_impl->GetLatestScan(fw); }

} // namespace ShadowStrike::Products::PhantomEDR::Compliance

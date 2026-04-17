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
#include "Products/Community/PhantomEDR/Compliance/HardeningAdvisor.hpp"
#include "Products/Community/PhantomEDR/Compliance/CompliancePolicies.hpp"

#include <algorithm>
#include <format>
#include <shared_mutex>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winsvc.h>

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

namespace ShadowStrike::Products::PhantomEDR::Compliance {

namespace {

using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Utils::Logger;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[HardeningAdvisor]";

// ============================================================================
// RECOMMENDATION BUILDER HELPERS
// ============================================================================

[[nodiscard]] HardeningRecommendation BuildRegistryRec(
    const ComplianceCheckResult& result,
    const ComplianceCheckDef& def)
{
    HardeningRecommendation rec;
    rec.checkId = result.checkId;
    rec.title = result.title;
    rec.severity = result.severity;
    rec.framework = result.framework;
    rec.category = result.category;

    rec.registryHive = def.registryHive;
    rec.registryKey = def.registryKey;
    rec.registryValue = def.registryValue;

    // Extract the numeric target from expectedValue (strip operator prefix)
    std::string_view ev = def.expectedValue;
    if (ev.starts_with(">=") || ev.starts_with("<=") || ev.starts_with("==")) {
        ev = ev.substr(2);
    }
    rec.desiredRegistryData = std::string(ev);
    rec.registryDataType = REG_DWORD;

    rec.autoFixable = true;
    rec.effort = FixEffort::Trivial;
    rec.description = std::format("Registry check '{}' failed: expected {} {}, got {}",
                                  def.registryValue, def.comparisonOp, def.expectedValue,
                                  result.actualValue);
    rec.fixDescription = std::format("Set {}\\{}\\{} to {}",
                                     def.registryHive, def.registryKey, def.registryValue,
                                     rec.desiredRegistryData);
    return rec;
}

[[nodiscard]] HardeningRecommendation BuildServiceRec(
    const ComplianceCheckResult& result,
    const ComplianceCheckDef& def)
{
    HardeningRecommendation rec;
    rec.checkId = result.checkId;
    rec.title = result.title;
    rec.severity = result.severity;
    rec.framework = result.framework;
    rec.category = result.category;
    rec.serviceName = def.serviceName;

    if (def.expectedServiceState == "Disabled") {
        rec.desiredStartType = SERVICE_DISABLED;
    } else if (def.expectedServiceState == "Manual") {
        rec.desiredStartType = SERVICE_DEMAND_START;
    } else if (def.expectedServiceState == "Automatic") {
        rec.desiredStartType = SERVICE_AUTO_START;
    }

    rec.autoFixable = true;
    rec.effort = FixEffort::Low;
    rec.description = std::format("Service '{}' is {} but should be {}",
                                  def.serviceName, result.actualValue, def.expectedServiceState);
    rec.fixDescription = std::format("Set service '{}' start type to {}",
                                     def.serviceName, def.expectedServiceState);
    return rec;
}

[[nodiscard]] HardeningRecommendation BuildGenericRec(
    const ComplianceCheckResult& result)
{
    HardeningRecommendation rec;
    rec.checkId = result.checkId;
    rec.title = result.title;
    rec.severity = result.severity;
    rec.framework = result.framework;
    rec.category = result.category;
    rec.autoFixable = false;
    rec.effort = FixEffort::Medium;
    rec.description = std::format("Check '{}' failed: expected {}, got {}",
                                  result.checkId, result.expectedValue, result.actualValue);
    rec.fixDescription = "Manual remediation required; consult framework documentation";
    return rec;
}

} // anonymous namespace

// ============================================================================
// IMPL
// ============================================================================

class HardeningAdvisorImpl {
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

    [[nodiscard]] std::vector<HardeningRecommendation> Analyze(const ComplianceScanResult& scan) const {
        std::vector<HardeningRecommendation> recs;
        auto& policies = CompliancePolicies::Instance();

        for (const auto& result : scan.results) {
            if (result.status != CheckStatus::Fail) continue;

            auto checkDef = policies.GetCheck(result.checkId);
            if (!checkDef.has_value()) {
                recs.push_back(BuildGenericRec(result));
                continue;
            }

            switch (checkDef->type) {
                case CheckType::RegistryValue:
                    recs.push_back(BuildRegistryRec(result, *checkDef));
                    break;
                case CheckType::ServiceStatus:
                    recs.push_back(BuildServiceRec(result, *checkDef));
                    break;
                default:
                    recs.push_back(BuildGenericRec(result));
                    break;
            }
        }

        // Sort by severity (Critical first)
        std::ranges::sort(recs, [](const auto& a, const auto& b) {
            return static_cast<uint8_t>(a.severity) < static_cast<uint8_t>(b.severity);
        });

        return recs;
    }

    [[nodiscard]] std::vector<HardeningRecommendation> GetAutoFixable(const ComplianceScanResult& scan) const {
        auto all = Analyze(scan);
        std::erase_if(all, [](const auto& r) { return !r.autoFixable; });
        return all;
    }

    [[nodiscard]] bool ApplyFix(const HardeningRecommendation& rec) {
        if (!rec.autoFixable) {
            Logger::Warn("{} Recommendation '{}' is not auto-fixable", kLogPrefix, rec.checkId);
            return false;
        }

        bool success = false;

        if (!rec.registryKey.empty()) {
            success = ApplyRegistryFix(rec);
        } else if (!rec.serviceName.empty()) {
            success = ApplyServiceFix(rec);
        } else {
            Logger::Warn("{} No applicable fix method for '{}'", kLogPrefix, rec.checkId);
            return false;
        }

        if (success) {
            LogFixApplied(rec);
            Logger::Info("{} Applied fix for '{}'", kLogPrefix, rec.checkId);
        }
        return success;
    }

    [[nodiscard]] bool DryRunFix(const HardeningRecommendation& rec, std::string& description) const {
        if (!rec.autoFixable) {
            description = "Not auto-fixable; manual remediation required";
            return false;
        }

        if (!rec.registryKey.empty()) {
            description = std::format("[DRY RUN] Would set {}\\{}\\{} = {} (type DWORD)",
                                      rec.registryHive, rec.registryKey, rec.registryValue,
                                      rec.desiredRegistryData);
            return true;
        }

        if (!rec.serviceName.empty()) {
            const char* startTypeStr = "Unknown";
            switch (rec.desiredStartType) {
                case SERVICE_DISABLED:     startTypeStr = "Disabled"; break;
                case SERVICE_DEMAND_START: startTypeStr = "Manual"; break;
                case SERVICE_AUTO_START:   startTypeStr = "Automatic"; break;
                default: break;
            }
            description = std::format("[DRY RUN] Would set service '{}' start type to {}",
                                      rec.serviceName, startTypeStr);
            return true;
        }

        description = "No applicable fix method";
        return false;
    }

    [[nodiscard]] uint32_t ApplyAllAutoFixes(const std::vector<HardeningRecommendation>& recs) {
        uint32_t applied = 0;
        for (const auto& rec : recs) {
            if (!rec.autoFixable) continue;
            if (ApplyFix(rec)) ++applied;
        }
        Logger::Info("{} Applied {} of {} auto-fix recommendations", kLogPrefix, applied, recs.size());
        return applied;
    }

private:
    mutable std::shared_mutex m_mtx;
    bool m_initialized = false;

    [[nodiscard]] bool CreateSchema() {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        return db.Execute(
            "CREATE TABLE IF NOT EXISTS compliance_fix_log ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  check_id TEXT NOT NULL,"
            "  fix_type TEXT NOT NULL,"
            "  description TEXT,"
            "  applied_at INTEGER NOT NULL,"
            "  success INTEGER NOT NULL DEFAULT 1"
            ");", &dbErr);
    }

    [[nodiscard]] bool ApplyRegistryFix(const HardeningRecommendation& rec) {
        HKEY rootKey = HKEY_LOCAL_MACHINE;
        if (rec.registryHive == "HKCU") rootKey = HKEY_CURRENT_USER;

        const auto wideKey = StringUtils::ToWide(rec.registryKey);
        const auto wideValue = StringUtils::ToWide(rec.registryValue);

        HKEY hKey = nullptr;
        LONG ret = RegOpenKeyExW(rootKey, wideKey.c_str(), 0, KEY_SET_VALUE, &hKey);
        if (ret != ERROR_SUCCESS) {
            // Try creating the key
            DWORD disposition = 0;
            ret = RegCreateKeyExW(rootKey, wideKey.c_str(), 0, nullptr,
                                  REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr,
                                  &hKey, &disposition);
            if (ret != ERROR_SUCCESS) {
                Logger::Error("{} Cannot open/create registry key {}\\{}: error {}",
                              kLogPrefix, rec.registryHive, rec.registryKey, ret);
                return false;
            }
        }

        DWORD dwValue = 0;
        try {
            dwValue = static_cast<DWORD>(std::stoul(rec.desiredRegistryData));
        } catch (...) {
            RegCloseKey(hKey);
            Logger::Error("{} Cannot parse desired value '{}' as DWORD for {}",
                          kLogPrefix, rec.desiredRegistryData, rec.checkId);
            return false;
        }

        ret = RegSetValueExW(hKey, wideValue.c_str(), 0, REG_DWORD,
                             reinterpret_cast<const BYTE*>(&dwValue), sizeof(DWORD));
        RegCloseKey(hKey);

        if (ret != ERROR_SUCCESS) {
            Logger::Error("{} RegSetValueExW failed for {}: error {}",
                          kLogPrefix, rec.checkId, ret);
            return false;
        }
        return true;
    }

    [[nodiscard]] bool ApplyServiceFix(const HardeningRecommendation& rec) {
        const auto wideName = StringUtils::ToWide(rec.serviceName);

        SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scManager) {
            Logger::Error("{} OpenSCManagerW failed: {}", kLogPrefix, GetLastError());
            return false;
        }

        SC_HANDLE hService = OpenServiceW(scManager, wideName.c_str(), SERVICE_CHANGE_CONFIG);
        if (!hService) {
            CloseServiceHandle(scManager);
            Logger::Error("{} OpenServiceW('{}') failed: {}", kLogPrefix, rec.serviceName, GetLastError());
            return false;
        }

        BOOL ok = ChangeServiceConfigW(
            hService,
            SERVICE_NO_CHANGE,
            rec.desiredStartType,
            SERVICE_NO_CHANGE,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        CloseServiceHandle(hService);
        CloseServiceHandle(scManager);

        if (!ok) {
            Logger::Error("{} ChangeServiceConfigW('{}') failed: {}",
                          kLogPrefix, rec.serviceName, GetLastError());
            return false;
        }
        return true;
    }

    void LogFixApplied(const HardeningRecommendation& rec) {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now().time_since_epoch()).count();

        std::string fixType = !rec.registryKey.empty() ? "registry" : "service";

        db.ExecuteWithParams(
            "INSERT INTO compliance_fix_log (check_id, fix_type, description, applied_at, success)"
            " VALUES (?,?,?,?,1);",
            &dbErr, rec.checkId, fixType, rec.fixDescription, now);
    }
};

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

HardeningAdvisor::HardeningAdvisor() : m_impl(std::make_unique<HardeningAdvisorImpl>()) {}
HardeningAdvisor::~HardeningAdvisor() = default;

HardeningAdvisor& HardeningAdvisor::Instance() {
    static HardeningAdvisor instance;
    return instance;
}

bool HardeningAdvisor::Initialize() { return m_impl->Initialize(); }
void HardeningAdvisor::Shutdown() { m_impl->Shutdown(); }
bool HardeningAdvisor::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
std::vector<HardeningRecommendation> HardeningAdvisor::Analyze(const ComplianceScanResult& scan) const { return m_impl->Analyze(scan); }
std::vector<HardeningRecommendation> HardeningAdvisor::GetAutoFixable(const ComplianceScanResult& scan) const { return m_impl->GetAutoFixable(scan); }
bool HardeningAdvisor::ApplyFix(const HardeningRecommendation& rec) { return m_impl->ApplyFix(rec); }
bool HardeningAdvisor::DryRunFix(const HardeningRecommendation& rec, std::string& desc) const { return m_impl->DryRunFix(rec, desc); }
uint32_t HardeningAdvisor::ApplyAllAutoFixes(const std::vector<HardeningRecommendation>& recs) { return m_impl->ApplyAllAutoFixes(recs); }

} // namespace ShadowStrike::Products::PhantomEDR::Compliance

/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#include "Products/Community/PhantomEDR/PolicyEngine/PolicyEnforcer.hpp"
#include "Products/Community/PhantomEDR/PolicyEngine/PolicyManager.hpp"
#include "Products/Community/PhantomEDR/PolicyEngine/PolicyAuditLog.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <mutex>
#include <random>
#include <regex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <Windows.h>

namespace ShadowStrike::Products::PhantomEDR::PolicyEngine {

using ShadowStrike::Utils::Logger;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::QueryResult;

static constexpr std::string_view kLogPrefix = "[PolicyEnforcer]";
static constexpr uint32_t kDefaultCheckIntervalSec = 300;  // 5 minutes
static constexpr uint32_t kMaxDriftsPerCheck = 10000;

// ============================================================================
// ID GENERATION
// ============================================================================

static std::string GenerateId(std::string_view prefix) {
    static std::mutex s_mtx;
    static std::mt19937_64 s_rng(std::random_device{}());
    std::lock_guard lk(s_mtx);
    std::uniform_int_distribution<uint64_t> dist;
    return std::format("{}-{:016X}", prefix, dist(s_rng));
}

// ============================================================================
// TIME HELPERS
// ============================================================================

static int64_t ToMillis(Clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        tp.time_since_epoch()).count();
}

static Clock::time_point FromMillis(int64_t ms) {
    return Clock::time_point(
        std::chrono::duration_cast<Clock::duration>(
            std::chrono::milliseconds(ms)));
}

// ============================================================================
// SYSTEM STATE READERS — read actual values from the system
// ============================================================================

static std::string ReadRegistryValue(std::string_view keyPath) {
    // Parse "HKLM\path\to\key:ValueName" format
    auto colonPos = keyPath.find(':');
    if (colonPos == std::string_view::npos) return {};

    std::string subKey(keyPath.substr(0, colonPos));
    std::string valueName(keyPath.substr(colonPos + 1));

    HKEY rootKey = HKEY_LOCAL_MACHINE;
    std::string_view rootPrefix;
    if (subKey.starts_with("HKLM\\")) {
        rootKey = HKEY_LOCAL_MACHINE;
        rootPrefix = "HKLM\\";
    } else if (subKey.starts_with("HKCU\\")) {
        rootKey = HKEY_CURRENT_USER;
        rootPrefix = "HKCU\\";
    } else {
        return {};
    }

    std::string actualSubKey = subKey.substr(rootPrefix.size());
    std::wstring wSubKey = SU::ToWide(actualSubKey);
    std::wstring wValueName = SU::ToWide(valueName);

    HKEY hKey = nullptr;
    if (::RegOpenKeyExW(rootKey, wSubKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return {};
    }

    DWORD type = 0;
    DWORD dataSize = 0;
    if (::RegQueryValueExW(hKey, wValueName.c_str(), nullptr, &type, nullptr, &dataSize)
        != ERROR_SUCCESS || dataSize == 0) {
        ::RegCloseKey(hKey);
        return {};
    }

    // Cap allocation
    if (dataSize > 64 * 1024) {
        ::RegCloseKey(hKey);
        return {};
    }

    std::string result;
    if (type == REG_DWORD) {
        DWORD val = 0;
        DWORD sz = sizeof(val);
        if (::RegQueryValueExW(hKey, wValueName.c_str(), nullptr, nullptr,
                               reinterpret_cast<BYTE*>(&val), &sz) == ERROR_SUCCESS) {
            result = std::to_string(val);
        }
    } else if (type == REG_SZ || type == REG_EXPAND_SZ) {
        std::vector<wchar_t> buf(dataSize / sizeof(wchar_t) + 1, L'\0');
        if (::RegQueryValueExW(hKey, wValueName.c_str(), nullptr, nullptr,
                               reinterpret_cast<BYTE*>(buf.data()), &dataSize) == ERROR_SUCCESS) {
            result = SU::ToNarrow(buf.data());
        }
    }

    ::RegCloseKey(hKey);
    return result;
}

static std::string ReadConfigValue(std::string_view key) {
    // Read from the EDR config database
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT value FROM edr_config WHERE key = ?",
        &dbErr, std::string(key));

    if (result.Next()) {
        return result.GetString(0);
    }
    return {};
}

static std::string ReadSystemValue(std::string_view key) {
    // Determine source by key prefix
    if (key.starts_with("HKLM\\") || key.starts_with("HKCU\\")) {
        return ReadRegistryValue(key);
    }
    return ReadConfigValue(key);
}

// ============================================================================
// COMPARATOR ENGINE
// ============================================================================

static bool Compare(std::string_view actual, std::string_view expected,
                    std::string_view comparator) {
    if (comparator == "eq") {
        return actual == expected;
    }
    if (comparator == "ne") {
        return actual != expected;
    }
    if (comparator == "contains") {
        return actual.find(expected) != std::string_view::npos;
    }
    if (comparator == "regex") {
        try {
            std::regex re(expected.begin(), expected.end());
            return std::regex_search(actual.begin(), actual.end(), re);
        } catch (const std::regex_error&) {
            return false;
        }
    }
    if (comparator == "gt" || comparator == "lt" || comparator == "gte" || comparator == "lte") {
        try {
            const double actualNum = std::stod(std::string(actual));
            const double expectedNum = std::stod(std::string(expected));
            if (comparator == "gt")  return actualNum > expectedNum;
            if (comparator == "lt")  return actualNum < expectedNum;
            if (comparator == "gte") return actualNum >= expectedNum;
            if (comparator == "lte") return actualNum <= expectedNum;
        } catch (...) {
            return false;
        }
    }
    // Default: exact match
    return actual == expected;
}

// ============================================================================
// IMPL
// ============================================================================

class PolicyEnforcerImpl {
public:
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized; }

    std::vector<DriftRecord> CheckCompliance() const;
    std::vector<DriftRecord> CheckPolicy(std::string_view policyId) const;
    bool Remediate(std::string_view driftId);
    std::vector<DriftRecord> QueryDrifts(const DriftQueryParams& params) const;

    void Start();
    void Stop();

private:
    bool EnsureSchema();
    void PersistDrift(const DriftRecord& drift);
    DriftRecord ReadDriftRow(QueryResult& result) const;
    std::vector<DriftRecord> CheckSinglePolicy(const PolicyDefinition& policy) const;
    void EnforcementLoop();

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
    std::atomic<bool> m_running{false};
    std::jthread m_thread;
};

// ============================================================================
// SCHEMA
// ============================================================================

bool PolicyEnforcerImpl::EnsureSchema() {
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    const char* sql = R"SQL(
        CREATE TABLE IF NOT EXISTS edr_policy_drifts (
            drift_id        TEXT PRIMARY KEY,
            policy_id       TEXT NOT NULL,
            rule_id         TEXT NOT NULL,
            severity        INTEGER NOT NULL DEFAULT 2,
            expected_value  TEXT NOT NULL DEFAULT '',
            actual_value    TEXT NOT NULL DEFAULT '',
            detected_at     INTEGER NOT NULL,
            remediated      INTEGER NOT NULL DEFAULT 0,
            remediated_at   INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_edr_policy_drifts_detected
            ON edr_policy_drifts(detected_at DESC);
        CREATE INDEX IF NOT EXISTS idx_edr_policy_drifts_policy
            ON edr_policy_drifts(policy_id);
    )SQL";

    if (!db.Execute(sql, &dbErr)) {
        Logger::Error("{} Schema creation failed: {}", kLogPrefix,
                      SU::ToNarrow(dbErr.message));
        return false;
    }
    return true;
}

// ============================================================================
// INIT / SHUTDOWN
// ============================================================================

bool PolicyEnforcerImpl::Initialize() {
    std::unique_lock lk(m_mutex);
    if (m_initialized) return true;
    if (!EnsureSchema()) return false;
    m_initialized = true;
    Logger::Info("{} Initialized", kLogPrefix);
    return true;
}

void PolicyEnforcerImpl::Shutdown() {
    Stop();
    std::unique_lock lk(m_mutex);
    m_initialized = false;
    Logger::Info("{} Shutdown complete", kLogPrefix);
}

// ============================================================================
// CHECK COMPLIANCE
// ============================================================================

std::vector<DriftRecord> PolicyEnforcerImpl::CheckSinglePolicy(
    const PolicyDefinition& policy) const {

    std::vector<DriftRecord> drifts;

    for (const auto& rule : policy.rules) {
        const std::string actual = ReadSystemValue(rule.key);
        if (Compare(actual, rule.expected, rule.comparator)) {
            continue;  // compliant
        }

        DriftRecord drift;
        drift.driftId = GenerateId("DFT");
        drift.policyId = policy.policyId;
        drift.ruleId = rule.ruleId;
        drift.expectedValue = rule.expected;
        drift.actualValue = actual;
        drift.detectedAt = Clock::now();
        drift.remediated = false;

        // Severity based on enforcement mode and scope
        if (policy.enforcement == EnforcementMode::Enforce) {
            drift.severity = DriftSeverity::High;
        } else {
            drift.severity = DriftSeverity::Medium;
        }

        drifts.push_back(std::move(drift));

        if (drifts.size() >= kMaxDriftsPerCheck) break;
    }

    return drifts;
}

std::vector<DriftRecord> PolicyEnforcerImpl::CheckCompliance() const {
    std::shared_lock lk(m_mutex);

    auto& pm = PolicyManager::Instance();
    PolicyQueryParams params;
    params.status = PolicyStatus::Active;
    params.maxResults = 1000;

    const auto policies = pm.QueryPolicies(params);
    std::vector<DriftRecord> allDrifts;

    for (const auto& policy : policies) {
        auto drifts = CheckSinglePolicy(policy);
        for (auto& d : drifts) {
            allDrifts.push_back(std::move(d));
        }
        if (allDrifts.size() >= kMaxDriftsPerCheck) break;
    }

    // Persist detected drifts
    for (const auto& d : allDrifts) {
        const_cast<PolicyEnforcerImpl*>(this)->PersistDrift(d);
    }

    if (!allDrifts.empty()) {
        Logger::Warn("{} Compliance check found {} drift(s) across {} active policies",
                     kLogPrefix, allDrifts.size(), policies.size());

        auto& audit = PolicyAuditLog::Instance();
        if (audit.IsInitialized()) {
            audit.Record(AuditAction::DriftDetected, "",  "system",
                         std::format("Detected {} drifts in {} policies",
                                     allDrifts.size(), policies.size()));
        }
    }

    return allDrifts;
}

std::vector<DriftRecord> PolicyEnforcerImpl::CheckPolicy(std::string_view policyId) const {
    std::shared_lock lk(m_mutex);

    auto& pm = PolicyManager::Instance();
    auto policy = pm.GetPolicy(policyId);
    if (!policy.has_value()) {
        Logger::Warn("{} Policy '{}' not found", kLogPrefix, policyId);
        return {};
    }

    auto drifts = CheckSinglePolicy(*policy);
    for (const auto& d : drifts) {
        const_cast<PolicyEnforcerImpl*>(this)->PersistDrift(d);
    }
    return drifts;
}

// ============================================================================
// REMEDIATE
// ============================================================================

bool PolicyEnforcerImpl::Remediate(std::string_view driftId) {
    std::unique_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    // Load drift
    auto result = db.QueryWithParams(
        "SELECT drift_id, policy_id, rule_id, severity, expected_value, actual_value, "
        "detected_at, remediated, remediated_at "
        "FROM edr_policy_drifts WHERE drift_id = ?",
        &dbErr, std::string(driftId));

    if (!result.Next()) {
        Logger::Warn("{} Drift '{}' not found", kLogPrefix, driftId);
        return false;
    }

    auto drift = ReadDriftRow(result);
    if (drift.remediated) {
        Logger::Info("{} Drift '{}' already remediated", kLogPrefix, driftId);
        return true;
    }

    // Load the corresponding rule
    auto& pm = PolicyManager::Instance();
    auto policy = pm.GetPolicy(drift.policyId);
    if (!policy.has_value()) {
        Logger::Error("{} Cannot remediate: parent policy '{}' not found",
                      kLogPrefix, drift.policyId);
        return false;
    }

    // Find the rule
    const PolicyRule* targetRule = nullptr;
    for (const auto& r : policy->rules) {
        if (r.ruleId == drift.ruleId) {
            targetRule = &r;
            break;
        }
    }

    if (!targetRule) {
        Logger::Error("{} Cannot remediate: rule '{}' not found in policy '{}'",
                      kLogPrefix, drift.ruleId, drift.policyId);
        return false;
    }

    // Attempt remediation: write expected value back to config
    if (!targetRule->key.starts_with("HKLM\\") && !targetRule->key.starts_with("HKCU\\")) {
        // Config key — write to DB
        (void)db.ExecuteWithParams(
            "INSERT OR REPLACE INTO edr_config (key, value) VALUES (?, ?)",
            &dbErr, targetRule->key, targetRule->expected);
    } else {
        // Registry remediation is risky — log and skip in Community edition
        Logger::Warn("{} Registry remediation for '{}' requires elevated privileges — skipping",
                     kLogPrefix, targetRule->key);
        return false;
    }

    // Mark remediated
    const int64_t now = ToMillis(Clock::now());
    (void)db.ExecuteWithParams(
        "UPDATE edr_policy_drifts SET remediated = 1, remediated_at = ? WHERE drift_id = ?",
        &dbErr, now, std::string(driftId));

    auto& audit = PolicyAuditLog::Instance();
    if (audit.IsInitialized()) {
        audit.Record(AuditAction::DriftRemediated, drift.policyId, "system",
                     std::format("Remediated drift '{}' (rule: {}, key: {})",
                                 driftId, drift.ruleId, targetRule->key));
    }

    Logger::Info("{} Remediated drift '{}'", kLogPrefix, driftId);
    return true;
}

// ============================================================================
// QUERY DRIFTS
// ============================================================================

DriftRecord PolicyEnforcerImpl::ReadDriftRow(QueryResult& result) const {
    DriftRecord d;
    d.driftId = result.GetString(0);
    d.policyId = result.GetString(1);
    d.ruleId = result.GetString(2);
    d.severity = static_cast<DriftSeverity>(result.GetInt(3));
    d.expectedValue = result.GetString(4);
    d.actualValue = result.GetString(5);
    d.detectedAt = FromMillis(result.GetInt64(6));
    d.remediated = (result.GetInt(7) != 0);
    d.remediatedAt = FromMillis(result.GetInt64(8));
    return d;
}

std::vector<DriftRecord> PolicyEnforcerImpl::QueryDrifts(const DriftQueryParams& params) const {
    std::shared_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    std::string sql =
        "SELECT drift_id, policy_id, rule_id, severity, expected_value, "
        "actual_value, detected_at, remediated, remediated_at "
        "FROM edr_policy_drifts WHERE 1=1";

    if (params.policyId.has_value()) {
        sql += " AND policy_id = '" + *params.policyId + "'";
    }
    if (params.minSeverity.has_value()) {
        sql += " AND severity >= " + std::to_string(static_cast<int>(*params.minSeverity));
    }
    if (params.remediated.has_value()) {
        sql += " AND remediated = " + std::to_string(*params.remediated ? 1 : 0);
    }
    if (params.detectedAfter.has_value()) {
        sql += " AND detected_at >= " + std::to_string(ToMillis(*params.detectedAfter));
    }
    sql += " ORDER BY detected_at DESC LIMIT " + std::to_string(params.maxResults);

    auto result = db.Query(sql.c_str(), &dbErr);

    std::vector<DriftRecord> out;
    while (result.Next()) {
        out.push_back(ReadDriftRow(result));
    }
    return out;
}

void PolicyEnforcerImpl::PersistDrift(const DriftRecord& drift) {
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    if (!db.ExecuteWithParams(
            "INSERT OR IGNORE INTO edr_policy_drifts "
            "(drift_id, policy_id, rule_id, severity, expected_value, actual_value, "
            "detected_at, remediated, remediated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &dbErr,
            drift.driftId,
            drift.policyId,
            drift.ruleId,
            static_cast<int>(drift.severity),
            drift.expectedValue,
            drift.actualValue,
            ToMillis(drift.detectedAt),
            drift.remediated ? 1 : 0,
            ToMillis(drift.remediatedAt))) {
        Logger::Warn("{} Failed to persist drift '{}': {}", kLogPrefix,
                     drift.driftId, SU::ToNarrow(dbErr.message));
    }
}

// ============================================================================
// BACKGROUND ENFORCEMENT LOOP
// ============================================================================

void PolicyEnforcerImpl::Start() {
    if (m_running.exchange(true)) return;

    m_thread = std::jthread([this](std::stop_token stopToken) {
        Logger::Info("{} Background enforcement loop started", kLogPrefix);
        EnforcementLoop();
    });
}

void PolicyEnforcerImpl::Stop() {
    if (!m_running.exchange(false)) return;
    if (m_thread.joinable()) {
        m_thread.request_stop();
        m_thread.join();
    }
    Logger::Info("{} Background enforcement loop stopped", kLogPrefix);
}

void PolicyEnforcerImpl::EnforcementLoop() {
    while (m_running.load()) {
        try {
            const auto drifts = CheckCompliance();

            // Auto-remediate enforced policies
            for (const auto& drift : drifts) {
                auto& pm = PolicyManager::Instance();
                auto policy = pm.GetPolicy(drift.policyId);
                if (policy.has_value() &&
                    policy->enforcement == EnforcementMode::Enforce) {
                    (void)Remediate(drift.driftId);
                }
            }
        } catch (const std::exception& ex) {
            Logger::Error("{} Enforcement loop error: {}", kLogPrefix, ex.what());
        }

        // Sleep in small increments for responsive shutdown
        for (uint32_t i = 0; i < kDefaultCheckIntervalSec && m_running.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

// ============================================================================
// SINGLETON FORWARDING
// ============================================================================

PolicyEnforcer::PolicyEnforcer() : m_impl(std::make_unique<PolicyEnforcerImpl>()) {}
PolicyEnforcer::~PolicyEnforcer() = default;

PolicyEnforcer& PolicyEnforcer::Instance() {
    static PolicyEnforcer inst;
    return inst;
}

bool PolicyEnforcer::Initialize() { return m_impl->Initialize(); }
void PolicyEnforcer::Shutdown() { m_impl->Shutdown(); }
bool PolicyEnforcer::IsInitialized() const noexcept { return m_impl->IsInitialized(); }

std::vector<DriftRecord> PolicyEnforcer::CheckCompliance() const {
    return m_impl->CheckCompliance();
}
std::vector<DriftRecord> PolicyEnforcer::CheckPolicy(std::string_view policyId) const {
    return m_impl->CheckPolicy(policyId);
}
bool PolicyEnforcer::Remediate(std::string_view driftId) {
    return m_impl->Remediate(driftId);
}
std::vector<DriftRecord> PolicyEnforcer::QueryDrifts(const DriftQueryParams& params) const {
    return m_impl->QueryDrifts(params);
}
void PolicyEnforcer::Start() { m_impl->Start(); }
void PolicyEnforcer::Stop() { m_impl->Stop(); }

} // namespace ShadowStrike::Products::PhantomEDR::PolicyEngine

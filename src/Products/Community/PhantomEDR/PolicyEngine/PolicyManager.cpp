/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#include "Products/Community/PhantomEDR/PolicyEngine/PolicyManager.hpp"
#include "Products/Community/PhantomEDR/PolicyEngine/PolicyAuditLog.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::PolicyEngine {

using ShadowStrike::Utils::Logger;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::QueryResult;

static constexpr std::string_view kLogPrefix = "[PolicyManager]";

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
// IMPL
// ============================================================================

class PolicyManagerImpl {
public:
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized; }

    std::string CreatePolicy(const PolicyDefinition& policy);
    bool UpdatePolicy(const PolicyDefinition& policy);
    bool DeletePolicy(std::string_view policyId);
    bool SetPolicyStatus(std::string_view policyId, PolicyStatus status);

    std::optional<PolicyDefinition> GetPolicy(std::string_view policyId) const;
    std::vector<PolicyDefinition> QueryPolicies(const PolicyQueryParams& params) const;
    uint32_t GetActivePolicyCount() const;

    bool AddRule(std::string_view policyId, const PolicyRule& rule);
    bool RemoveRule(std::string_view policyId, std::string_view ruleId);

private:
    bool EnsureSchema();
    PolicyDefinition ReadPolicyFromRow(QueryResult& result) const;
    std::vector<PolicyRule> LoadRulesForPolicy(std::string_view policyId) const;

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
};

// ============================================================================
// SCHEMA
// ============================================================================

bool PolicyManagerImpl::EnsureSchema() {
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    const char* sql = R"SQL(
        CREATE TABLE IF NOT EXISTS edr_policies (
            policy_id       TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            description     TEXT NOT NULL DEFAULT '',
            status          INTEGER NOT NULL DEFAULT 2,
            scope           INTEGER NOT NULL DEFAULT 0,
            enforcement     INTEGER NOT NULL DEFAULT 0,
            version         INTEGER NOT NULL DEFAULT 1,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL,
            created_by      TEXT NOT NULL DEFAULT 'system'
        );
        CREATE INDEX IF NOT EXISTS idx_edr_policies_status
            ON edr_policies(status);

        CREATE TABLE IF NOT EXISTS edr_policy_rules (
            rule_id         TEXT NOT NULL,
            policy_id       TEXT NOT NULL,
            description     TEXT NOT NULL DEFAULT '',
            key             TEXT NOT NULL,
            expected        TEXT NOT NULL DEFAULT '',
            comparator      TEXT NOT NULL DEFAULT 'eq',
            PRIMARY KEY (policy_id, rule_id),
            FOREIGN KEY (policy_id) REFERENCES edr_policies(policy_id) ON DELETE CASCADE
        );
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

bool PolicyManagerImpl::Initialize() {
    std::unique_lock lk(m_mutex);
    if (m_initialized) return true;
    if (!EnsureSchema()) return false;
    m_initialized = true;
    Logger::Info("{} Initialized", kLogPrefix);
    return true;
}

void PolicyManagerImpl::Shutdown() {
    std::unique_lock lk(m_mutex);
    m_initialized = false;
    Logger::Info("{} Shutdown complete", kLogPrefix);
}

// ============================================================================
// CREATE
// ============================================================================

std::string PolicyManagerImpl::CreatePolicy(const PolicyDefinition& policy) {
    std::unique_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    const std::string id = policy.policyId.empty()
        ? GenerateId("POL") : policy.policyId;
    const int64_t now = ToMillis(Clock::now());

    if (!db.ExecuteWithParams(
            "INSERT INTO edr_policies "
            "(policy_id, name, description, status, scope, enforcement, version, created_at, updated_at, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &dbErr,
            id,
            policy.name,
            policy.description,
            static_cast<int>(policy.status),
            static_cast<int>(policy.scope),
            static_cast<int>(policy.enforcement),
            static_cast<int>(policy.version),
            now, now,
            policy.createdBy.empty() ? std::string("system") : policy.createdBy)) {
        Logger::Error("{} Failed to create policy '{}': {}", kLogPrefix, id,
                      SU::ToNarrow(dbErr.message));
        return {};
    }

    // Insert rules
    for (const auto& rule : policy.rules) {
        const std::string ruleId = rule.ruleId.empty()
            ? GenerateId("RUL") : rule.ruleId;
        if (!db.ExecuteWithParams(
                "INSERT INTO edr_policy_rules "
                "(rule_id, policy_id, description, key, expected, comparator) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                &dbErr, ruleId, id, rule.description,
                rule.key, rule.expected, rule.comparator)) {
            Logger::Warn("{} Failed to insert rule '{}' for policy '{}': {}",
                         kLogPrefix, ruleId, id, SU::ToNarrow(dbErr.message));
        }
    }

    // Audit
    auto& audit = PolicyAuditLog::Instance();
    if (audit.IsInitialized()) {
        audit.Record(AuditAction::PolicyCreated, id,
                     policy.createdBy.empty() ? "system" : policy.createdBy,
                     std::format("Created policy '{}' with {} rules", policy.name, policy.rules.size()));
    }

    Logger::Info("{} Created policy '{}' ({})", kLogPrefix, policy.name, id);
    return id;
}

// ============================================================================
// UPDATE
// ============================================================================

bool PolicyManagerImpl::UpdatePolicy(const PolicyDefinition& policy) {
    std::unique_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    const int64_t now = ToMillis(Clock::now());

    if (!db.ExecuteWithParams(
            "UPDATE edr_policies SET name = ?, description = ?, status = ?, scope = ?, "
            "enforcement = ?, version = version + 1, updated_at = ? WHERE policy_id = ?",
            &dbErr,
            policy.name,
            policy.description,
            static_cast<int>(policy.status),
            static_cast<int>(policy.scope),
            static_cast<int>(policy.enforcement),
            now,
            policy.policyId)) {
        Logger::Error("{} Failed to update policy '{}': {}", kLogPrefix,
                      policy.policyId, SU::ToNarrow(dbErr.message));
        return false;
    }

    auto& audit = PolicyAuditLog::Instance();
    if (audit.IsInitialized()) {
        audit.Record(AuditAction::PolicyUpdated, policy.policyId,
                     "system", std::format("Updated policy '{}'", policy.name));
    }

    Logger::Info("{} Updated policy '{}'", kLogPrefix, policy.policyId);
    return true;
}

// ============================================================================
// DELETE
// ============================================================================

bool PolicyManagerImpl::DeletePolicy(std::string_view policyId) {
    std::unique_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    // Delete rules first
    (void)db.ExecuteWithParams(
        "DELETE FROM edr_policy_rules WHERE policy_id = ?",
        &dbErr, std::string(policyId));

    if (!db.ExecuteWithParams(
            "DELETE FROM edr_policies WHERE policy_id = ?",
            &dbErr, std::string(policyId))) {
        Logger::Error("{} Failed to delete policy '{}': {}", kLogPrefix,
                      policyId, SU::ToNarrow(dbErr.message));
        return false;
    }

    auto& audit = PolicyAuditLog::Instance();
    if (audit.IsInitialized()) {
        audit.Record(AuditAction::PolicyDeleted, policyId, "system",
                     std::format("Deleted policy '{}'", policyId));
    }

    Logger::Info("{} Deleted policy '{}'", kLogPrefix, policyId);
    return true;
}

// ============================================================================
// SET STATUS
// ============================================================================

bool PolicyManagerImpl::SetPolicyStatus(std::string_view policyId, PolicyStatus status) {
    std::unique_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    const int64_t now = ToMillis(Clock::now());
    if (!db.ExecuteWithParams(
            "UPDATE edr_policies SET status = ?, updated_at = ? WHERE policy_id = ?",
            &dbErr, static_cast<int>(status), now, std::string(policyId))) {
        Logger::Error("{} Failed to set status for '{}': {}", kLogPrefix,
                      policyId, SU::ToNarrow(dbErr.message));
        return false;
    }

    const AuditAction auditAction =
        (status == PolicyStatus::Active)  ? AuditAction::PolicyEnabled :
        (status == PolicyStatus::Disabled) ? AuditAction::PolicyDisabled :
        AuditAction::PolicyUpdated;

    auto& audit = PolicyAuditLog::Instance();
    if (audit.IsInitialized()) {
        audit.Record(auditAction, policyId, "system",
                     std::format("Status changed to {}", ToString(status)));
    }

    return true;
}

// ============================================================================
// GET / QUERY
// ============================================================================

PolicyDefinition PolicyManagerImpl::ReadPolicyFromRow(QueryResult& result) const {
    PolicyDefinition p;
    p.policyId = result.GetString(0);
    p.name = result.GetString(1);
    p.description = result.GetString(2);
    p.status = static_cast<PolicyStatus>(result.GetInt(3));
    p.scope = static_cast<PolicyScope>(result.GetInt(4));
    p.enforcement = static_cast<EnforcementMode>(result.GetInt(5));
    p.version = static_cast<uint32_t>(result.GetInt(6));
    p.createdAt = FromMillis(result.GetInt64(7));
    p.updatedAt = FromMillis(result.GetInt64(8));
    p.createdBy = result.GetString(9);
    return p;
}

std::vector<PolicyRule> PolicyManagerImpl::LoadRulesForPolicy(std::string_view policyId) const {
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT rule_id, description, key, expected, comparator "
        "FROM edr_policy_rules WHERE policy_id = ?",
        &dbErr, std::string(policyId));

    std::vector<PolicyRule> rules;
    while (result.Next()) {
        PolicyRule r;
        r.ruleId = result.GetString(0);
        r.description = result.GetString(1);
        r.key = result.GetString(2);
        r.expected = result.GetString(3);
        r.comparator = result.GetString(4);
        rules.push_back(std::move(r));
    }
    return rules;
}

std::optional<PolicyDefinition> PolicyManagerImpl::GetPolicy(std::string_view policyId) const {
    std::shared_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT policy_id, name, description, status, scope, enforcement, "
        "version, created_at, updated_at, created_by "
        "FROM edr_policies WHERE policy_id = ?",
        &dbErr, std::string(policyId));

    if (!result.Next()) return std::nullopt;

    auto policy = ReadPolicyFromRow(result);
    policy.rules = LoadRulesForPolicy(policyId);
    return policy;
}

std::vector<PolicyDefinition> PolicyManagerImpl::QueryPolicies(
    const PolicyQueryParams& params) const {
    std::shared_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    std::string sql =
        "SELECT policy_id, name, description, status, scope, enforcement, "
        "version, created_at, updated_at, created_by FROM edr_policies WHERE 1=1";

    // Build WHERE clauses — use simple string approach since we need dynamic binding
    // We'll use a separate query per filter combination for safety
    if (params.status.has_value()) {
        sql += " AND status = " + std::to_string(static_cast<int>(*params.status));
    }
    if (params.scope.has_value()) {
        sql += " AND scope = " + std::to_string(static_cast<int>(*params.scope));
    }
    if (params.updatedAfter.has_value()) {
        sql += " AND updated_at >= " + std::to_string(ToMillis(*params.updatedAfter));
    }
    sql += " ORDER BY updated_at DESC LIMIT " + std::to_string(params.maxResults);

    auto result = db.Query(sql.c_str(), &dbErr);

    std::vector<PolicyDefinition> out;
    while (result.Next()) {
        auto policy = ReadPolicyFromRow(result);
        policy.rules = LoadRulesForPolicy(policy.policyId);
        out.push_back(std::move(policy));
    }
    return out;
}

uint32_t PolicyManagerImpl::GetActivePolicyCount() const {
    std::shared_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT COUNT(*) FROM edr_policies WHERE status = ?",
        &dbErr, static_cast<int>(PolicyStatus::Active));

    if (result.Next()) {
        return static_cast<uint32_t>(result.GetInt(0));
    }
    return 0;
}

// ============================================================================
// RULE MANAGEMENT
// ============================================================================

bool PolicyManagerImpl::AddRule(std::string_view policyId, const PolicyRule& rule) {
    std::unique_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    const std::string ruleId = rule.ruleId.empty()
        ? GenerateId("RUL") : rule.ruleId;

    if (!db.ExecuteWithParams(
            "INSERT INTO edr_policy_rules "
            "(rule_id, policy_id, description, key, expected, comparator) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            &dbErr, ruleId, std::string(policyId),
            rule.description, rule.key, rule.expected, rule.comparator)) {
        Logger::Error("{} Failed to add rule to policy '{}': {}", kLogPrefix,
                      policyId, SU::ToNarrow(dbErr.message));
        return false;
    }

    // Update policy timestamp
    const int64_t now = ToMillis(Clock::now());
    (void)db.ExecuteWithParams(
        "UPDATE edr_policies SET updated_at = ?, version = version + 1 WHERE policy_id = ?",
        &dbErr, now, std::string(policyId));

    auto& audit = PolicyAuditLog::Instance();
    if (audit.IsInitialized()) {
        audit.Record(AuditAction::RuleAdded, policyId, "system",
                     std::format("Added rule '{}' (key: {})", ruleId, rule.key));
    }

    return true;
}

bool PolicyManagerImpl::RemoveRule(std::string_view policyId, std::string_view ruleId) {
    std::unique_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    if (!db.ExecuteWithParams(
            "DELETE FROM edr_policy_rules WHERE policy_id = ? AND rule_id = ?",
            &dbErr, std::string(policyId), std::string(ruleId))) {
        Logger::Error("{} Failed to remove rule '{}' from policy '{}': {}",
                      kLogPrefix, ruleId, policyId, SU::ToNarrow(dbErr.message));
        return false;
    }

    const int64_t now = ToMillis(Clock::now());
    (void)db.ExecuteWithParams(
        "UPDATE edr_policies SET updated_at = ?, version = version + 1 WHERE policy_id = ?",
        &dbErr, now, std::string(policyId));

    auto& audit = PolicyAuditLog::Instance();
    if (audit.IsInitialized()) {
        audit.Record(AuditAction::RuleRemoved, policyId, "system",
                     std::format("Removed rule '{}'", ruleId));
    }

    return true;
}

// ============================================================================
// SINGLETON FORWARDING
// ============================================================================

PolicyManager::PolicyManager() : m_impl(std::make_unique<PolicyManagerImpl>()) {}
PolicyManager::~PolicyManager() = default;

PolicyManager& PolicyManager::Instance() {
    static PolicyManager inst;
    return inst;
}

bool PolicyManager::Initialize() { return m_impl->Initialize(); }
void PolicyManager::Shutdown() { m_impl->Shutdown(); }
bool PolicyManager::IsInitialized() const noexcept { return m_impl->IsInitialized(); }

std::string PolicyManager::CreatePolicy(const PolicyDefinition& policy) {
    return m_impl->CreatePolicy(policy);
}
bool PolicyManager::UpdatePolicy(const PolicyDefinition& policy) {
    return m_impl->UpdatePolicy(policy);
}
bool PolicyManager::DeletePolicy(std::string_view policyId) {
    return m_impl->DeletePolicy(policyId);
}
bool PolicyManager::SetPolicyStatus(std::string_view policyId, PolicyStatus status) {
    return m_impl->SetPolicyStatus(policyId, status);
}
std::optional<PolicyDefinition> PolicyManager::GetPolicy(std::string_view policyId) const {
    return m_impl->GetPolicy(policyId);
}
std::vector<PolicyDefinition> PolicyManager::QueryPolicies(const PolicyQueryParams& params) const {
    return m_impl->QueryPolicies(params);
}
uint32_t PolicyManager::GetActivePolicyCount() const {
    return m_impl->GetActivePolicyCount();
}
bool PolicyManager::AddRule(std::string_view policyId, const PolicyRule& rule) {
    return m_impl->AddRule(policyId, rule);
}
bool PolicyManager::RemoveRule(std::string_view policyId, std::string_view ruleId) {
    return m_impl->RemoveRule(policyId, ruleId);
}

} // namespace ShadowStrike::Products::PhantomEDR::PolicyEngine

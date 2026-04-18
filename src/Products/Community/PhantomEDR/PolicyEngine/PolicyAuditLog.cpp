/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#include "Products/Community/PhantomEDR/PolicyEngine/PolicyAuditLog.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <chrono>
#include <cstdint>
#include <format>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::PolicyEngine {

using ShadowStrike::Utils::Logger;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::QueryResult;

static constexpr std::string_view kLogPrefix = "[PolicyAuditLog]";

// ============================================================================
// ID GENERATION
// ============================================================================

static std::string GenerateId() {
    static std::mutex s_mtx;
    static std::mt19937_64 s_rng(std::random_device{}());
    std::lock_guard lk(s_mtx);
    std::uniform_int_distribution<uint64_t> dist;
    return std::format("AUD-{:016X}", dist(s_rng));
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

class PolicyAuditLogImpl {
public:
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized; }

    void Record(AuditAction action, std::string_view policyId,
                std::string_view actor, std::string_view details);
    std::vector<AuditEntry> Query(const AuditQueryParams& params) const;
    uint64_t GetEntryCount() const;

private:
    bool EnsureSchema();
    AuditEntry ReadRow(QueryResult& result) const;

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
};

// ============================================================================
// SCHEMA
// ============================================================================

bool PolicyAuditLogImpl::EnsureSchema() {
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    const char* sql = R"SQL(
        CREATE TABLE IF NOT EXISTS edr_policy_audit (
            entry_id    TEXT PRIMARY KEY,
            action      INTEGER NOT NULL,
            policy_id   TEXT NOT NULL DEFAULT '',
            actor       TEXT NOT NULL DEFAULT 'system',
            details     TEXT NOT NULL DEFAULT '',
            timestamp   INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_edr_policy_audit_ts
            ON edr_policy_audit(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_edr_policy_audit_policy
            ON edr_policy_audit(policy_id);
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

bool PolicyAuditLogImpl::Initialize() {
    std::unique_lock lk(m_mutex);
    if (m_initialized) return true;
    if (!EnsureSchema()) return false;
    m_initialized = true;
    Logger::Info("{} Initialized", kLogPrefix);
    return true;
}

void PolicyAuditLogImpl::Shutdown() {
    std::unique_lock lk(m_mutex);
    m_initialized = false;
    Logger::Info("{} Shutdown complete", kLogPrefix);
}

// ============================================================================
// RECORD
// ============================================================================

void PolicyAuditLogImpl::Record(AuditAction action, std::string_view policyId,
                                std::string_view actor, std::string_view details) {
    std::unique_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    const std::string id = GenerateId();
    const int64_t now = ToMillis(Clock::now());

    if (!db.ExecuteWithParams(
            "INSERT INTO edr_policy_audit "
            "(entry_id, action, policy_id, actor, details, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            &dbErr,
            id,
            static_cast<int>(action),
            std::string(policyId),
            std::string(actor),
            std::string(details),
            now)) {
        Logger::Warn("{} Failed to record audit entry: {}", kLogPrefix,
                     SU::ToNarrow(dbErr.message));
    }
}

// ============================================================================
// QUERY
// ============================================================================

AuditEntry PolicyAuditLogImpl::ReadRow(QueryResult& result) const {
    AuditEntry e;
    e.entryId = result.GetString(0);
    e.action = static_cast<AuditAction>(result.GetInt(1));
    e.policyId = result.GetString(2);
    e.actor = result.GetString(3);
    e.details = result.GetString(4);
    e.timestamp = FromMillis(result.GetInt64(5));
    return e;
}

std::vector<AuditEntry> PolicyAuditLogImpl::Query(const AuditQueryParams& params) const {
    std::shared_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    std::string sql =
        "SELECT entry_id, action, policy_id, actor, details, timestamp "
        "FROM edr_policy_audit WHERE 1=1";

    if (params.action.has_value()) {
        sql += " AND action = " + std::to_string(static_cast<int>(*params.action));
    }
    if (params.policyId.has_value()) {
        sql += " AND policy_id = '" + *params.policyId + "'";
    }
    if (params.actor.has_value()) {
        sql += " AND actor = '" + *params.actor + "'";
    }
    if (params.after.has_value()) {
        sql += " AND timestamp >= " + std::to_string(ToMillis(*params.after));
    }
    sql += " ORDER BY timestamp DESC LIMIT " + std::to_string(params.maxResults);

    auto result = db.Query(sql.c_str(), &dbErr);

    std::vector<AuditEntry> out;
    while (result.Next()) {
        out.push_back(ReadRow(result));
    }
    return out;
}

uint64_t PolicyAuditLogImpl::GetEntryCount() const {
    std::shared_lock lk(m_mutex);
    auto& db = DatabaseManager::Instance();
    DatabaseError dbErr;

    auto result = db.Query("SELECT COUNT(*) FROM edr_policy_audit", &dbErr);
    if (result.Next()) {
        return static_cast<uint64_t>(result.GetInt64(0));
    }
    return 0;
}

// ============================================================================
// SINGLETON FORWARDING
// ============================================================================

PolicyAuditLog::PolicyAuditLog()
    : m_impl(std::make_unique<PolicyAuditLogImpl>()) {}
PolicyAuditLog::~PolicyAuditLog() = default;

PolicyAuditLog& PolicyAuditLog::Instance() {
    static PolicyAuditLog inst;
    return inst;
}

bool PolicyAuditLog::Initialize() { return m_impl->Initialize(); }
void PolicyAuditLog::Shutdown() { m_impl->Shutdown(); }
bool PolicyAuditLog::IsInitialized() const noexcept { return m_impl->IsInitialized(); }

void PolicyAuditLog::Record(AuditAction action, std::string_view policyId,
                            std::string_view actor, std::string_view details) {
    m_impl->Record(action, policyId, actor, details);
}

std::vector<AuditEntry> PolicyAuditLog::Query(const AuditQueryParams& params) const {
    return m_impl->Query(params);
}

uint64_t PolicyAuditLog::GetEntryCount() const {
    return m_impl->GetEntryCount();
}

} // namespace ShadowStrike::Products::PhantomEDR::PolicyEngine

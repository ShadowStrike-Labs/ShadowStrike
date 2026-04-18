/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

/// @file CorrelationRules.cpp
/// @brief Cross-domain correlation rule CRUD, evaluation, and default rule sets.

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/CorrelationRules.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <regex>
#include <shared_mutex>
#include <sstream>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation {

namespace {

constexpr const char* kLogPrefix = "[XDR::CorrelationRules]";

using Clock = std::chrono::system_clock;
using DB    = ShadowStrike::Database::DatabaseManager;
using DBErr = ShadowStrike::Database::DatabaseError;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Utils::Logger;

// ============================================================================
// STRING ↔ ENUM HELPERS
// ============================================================================

constexpr std::string_view DomainToString(XDREventDomain d) noexcept {
    switch (d) {
        case XDREventDomain::Endpoint:  return "Endpoint";
        case XDREventDomain::Network:   return "Network";
        case XDREventDomain::Identity:  return "Identity";
        case XDREventDomain::Email:     return "Email";
        case XDREventDomain::Cloud:     return "Cloud";
        default:                        return "Unknown";
    }
}

XDREventDomain StringToDomain(std::string_view s) noexcept {
    if (s == "Endpoint")  return XDREventDomain::Endpoint;
    if (s == "Network")   return XDREventDomain::Network;
    if (s == "Identity")  return XDREventDomain::Identity;
    if (s == "Email")     return XDREventDomain::Email;
    if (s == "Cloud")     return XDREventDomain::Cloud;
    return XDREventDomain::Unknown;
}

constexpr std::string_view OpToString(ConditionOp op) noexcept {
    switch (op) {
        case ConditionOp::Equals:       return "Equals";
        case ConditionOp::NotEquals:    return "NotEquals";
        case ConditionOp::Contains:     return "Contains";
        case ConditionOp::StartsWith:   return "StartsWith";
        case ConditionOp::EndsWith:     return "EndsWith";
        case ConditionOp::Regex:        return "Regex";
        case ConditionOp::GreaterThan:  return "GreaterThan";
        case ConditionOp::LessThan:     return "LessThan";
        case ConditionOp::InSet:        return "InSet";
        default:                        return "Equals";
    }
}

ConditionOp StringToOp(std::string_view s) noexcept {
    if (s == "NotEquals")    return ConditionOp::NotEquals;
    if (s == "Contains")     return ConditionOp::Contains;
    if (s == "StartsWith")   return ConditionOp::StartsWith;
    if (s == "EndsWith")     return ConditionOp::EndsWith;
    if (s == "Regex")        return ConditionOp::Regex;
    if (s == "GreaterThan")  return ConditionOp::GreaterThan;
    if (s == "LessThan")     return ConditionOp::LessThan;
    if (s == "InSet")        return ConditionOp::InSet;
    return ConditionOp::Equals;
}

constexpr std::string_view LinkToString(EntityLink lk) noexcept {
    switch (lk) {
        case EntityLink::SameUser:      return "SameUser";
        case EntityLink::SameHost:      return "SameHost";
        case EntityLink::SameIP:        return "SameIP";
        case EntityLink::SameProcess:   return "SameProcess";
        case EntityLink::SameFileHash:  return "SameFileHash";
        case EntityLink::SameSession:   return "SameSession";
        default:                        return "SameUser";
    }
}

EntityLink StringToLink(std::string_view s) noexcept {
    if (s == "SameHost")     return EntityLink::SameHost;
    if (s == "SameIP")       return EntityLink::SameIP;
    if (s == "SameProcess")  return EntityLink::SameProcess;
    if (s == "SameFileHash") return EntityLink::SameFileHash;
    if (s == "SameSession")  return EntityLink::SameSession;
    return EntityLink::SameUser;
}

constexpr std::string_view VerdictToString(CorrelationVerdict v) noexcept {
    switch (v) {
        case CorrelationVerdict::Benign:        return "Benign";
        case CorrelationVerdict::Informational: return "Informational";
        case CorrelationVerdict::Suspicious:    return "Suspicious";
        case CorrelationVerdict::Malicious:     return "Malicious";
        case CorrelationVerdict::Critical:      return "Critical";
        default:                                return "Suspicious";
    }
}

CorrelationVerdict StringToVerdict(std::string_view s) noexcept {
    if (s == "Benign")        return CorrelationVerdict::Benign;
    if (s == "Informational") return CorrelationVerdict::Informational;
    if (s == "Malicious")     return CorrelationVerdict::Malicious;
    if (s == "Critical")      return CorrelationVerdict::Critical;
    return CorrelationVerdict::Suspicious;
}

// ============================================================================
// FIELD VALUE EXTRACTION
// ============================================================================

/// Extract the value of a named field from an XDREvent for rule evaluation.
std::string GetEventField(const XDREvent& ev, std::string_view fieldName) {
    if (fieldName == "domain")          return std::string(DomainToString(ev.domain));
    if (fieldName == "mitreAttackId")   return ev.mitreAttackId;
    if (fieldName == "mitreTactic")     return ev.mitreTactic;
    if (fieldName == "userName")        return ev.userName;
    if (fieldName == "hostName")        return ev.hostName;
    if (fieldName == "ipAddress")       return ev.ipAddress;
    if (fieldName == "fileHash")        return ev.fileHash;
    if (fieldName == "sessionId")       return ev.sessionId;
    if (fieldName == "sourceModule")    return ev.sourceModule;
    if (fieldName == "severity")        return std::to_string(ev.severity);
    if (fieldName == "processId")       return std::to_string(ev.processId);
    // Check metadata map
    auto it = ev.metadata.find(std::string(fieldName));
    if (it != ev.metadata.end()) return it->second;
    return {};
}

/// Entity link extractor — returns the value used for entity linking.
std::string GetEntityValue(const XDREvent& ev, EntityLink link) {
    switch (link) {
        case EntityLink::SameUser:      return ev.userName;
        case EntityLink::SameHost:      return ev.hostName;
        case EntityLink::SameIP:        return ev.ipAddress;
        case EntityLink::SameProcess:   return std::to_string(ev.processId);
        case EntityLink::SameFileHash:  return ev.fileHash;
        case EntityLink::SameSession:   return ev.sessionId;
    }
    return {};
}

// ============================================================================
// CONDITION EVALUATION
// ============================================================================

/// Test if a single condition matches a single event.
bool EvaluateCondition(const RuleCondition& cond, const XDREvent& ev) {
    // Domain filter
    if (cond.domain != XDREventDomain::Unknown && cond.domain != ev.domain)
        return false;

    // Severity floor
    if (ev.severity < cond.minSeverity)
        return false;

    // Field value check
    if (cond.fieldName.empty())
        return true; // domain + severity only

    const std::string val = GetEventField(ev, cond.fieldName);

    switch (cond.op) {
        case ConditionOp::Equals:
            return val == cond.value;

        case ConditionOp::NotEquals:
            return val != cond.value;

        case ConditionOp::Contains:
            return val.find(cond.value) != std::string::npos;

        case ConditionOp::StartsWith:
            return val.starts_with(cond.value);

        case ConditionOp::EndsWith:
            return val.ends_with(cond.value);

        case ConditionOp::Regex: {
            try {
                const std::regex re(cond.value, std::regex::ECMAScript | std::regex::optimize);
                return std::regex_search(val, re);
            } catch (...) {
                return false;
            }
        }

        case ConditionOp::GreaterThan: {
            try { return std::stoi(val) > std::stoi(cond.value); }
            catch (...) { return false; }
        }

        case ConditionOp::LessThan: {
            try { return std::stoi(val) < std::stoi(cond.value); }
            catch (...) { return false; }
        }

        case ConditionOp::InSet: {
            // cond.value is comma-separated set
            std::istringstream ss(cond.value);
            std::string item;
            while (std::getline(ss, item, ',')) {
                // Trim whitespace
                auto start = item.find_first_not_of(' ');
                auto end   = item.find_last_not_of(' ');
                if (start != std::string::npos) {
                    item = item.substr(start, end - start + 1);
                    if (item == val) return true;
                }
            }
            return false;
        }
    }
    return false;
}

/// Serialize entity links to a pipe-delimited string for DB storage.
std::string SerializeEntityLinks(const std::vector<EntityLink>& links) {
    std::string result;
    for (size_t i = 0; i < links.size(); ++i) {
        if (i > 0) result += '|';
        result += LinkToString(links[i]);
    }
    return result;
}

std::vector<EntityLink> DeserializeEntityLinks(std::string_view s) {
    std::vector<EntityLink> result;
    if (s.empty()) return result;
    size_t pos = 0;
    while (pos < s.size()) {
        auto delim = s.find('|', pos);
        auto token = s.substr(pos, delim == std::string_view::npos ? std::string_view::npos : delim - pos);
        result.push_back(StringToLink(token));
        if (delim == std::string_view::npos) break;
        pos = delim + 1;
    }
    return result;
}

/// Generate a UUID-like rule ID.
std::string GenerateRuleId() {
    static std::atomic<uint64_t> seq{0};
    auto now = Clock::now().time_since_epoch().count();
    return std::format("CRL-{:X}-{:04X}", now, seq.fetch_add(1, std::memory_order_relaxed) & 0xFFFF);
}

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS
// ============================================================================

class CorrelationRulesImpl {
public:
    std::atomic<bool>   initialized{false};
    mutable std::shared_mutex mutex;

    std::unordered_map<std::string, CorrelationRule> ruleCache;

    bool Initialize();
    void Shutdown();

    bool CreateSchema();
    bool LoadRulesFromDb();
    bool PersistRule(const CorrelationRule& rule);
    bool DeleteRuleFromDb(std::string_view ruleId);

    bool AddRule(const CorrelationRule& rule);
    bool RemoveRule(std::string_view ruleId);
    bool UpdateRule(const CorrelationRule& rule);
    std::optional<CorrelationRule> GetRule(std::string_view ruleId) const;
    std::vector<CorrelationRule> GetActiveRules() const;
    std::vector<CorrelationRule> GetAllRules() const;
    uint32_t GetRuleCount() const;

    std::vector<CorrelationMatch> Evaluate(const std::vector<XDREvent>& windowEvents) const;

    bool InstallDefaultRules();

    // Per-rule evaluation
    std::vector<CorrelationMatch> EvaluateRule(
        const CorrelationRule& rule,
        const std::vector<XDREvent>& events) const;
};

// ============================================================================
// SCHEMA & PERSISTENCE
// ============================================================================

bool CorrelationRulesImpl::CreateSchema() {
    auto& db = DB::Instance();
    DBErr err;

    constexpr std::string_view kSchema = R"SQL(
        CREATE TABLE IF NOT EXISTS xdr_correlation_rules (
            rule_id         TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            description     TEXT DEFAULT '',
            status          INTEGER DEFAULT 0,
            confidence      INTEGER DEFAULT 50,
            verdict         TEXT DEFAULT 'Suspicious',
            time_window_sec INTEGER DEFAULT 300,
            entity_links    TEXT DEFAULT '',
            mitre_attack_id TEXT DEFAULT '',
            mitre_tactic    TEXT DEFAULT '',
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_rules_status ON xdr_correlation_rules(status);

        CREATE TABLE IF NOT EXISTS xdr_rule_conditions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id         TEXT NOT NULL REFERENCES xdr_correlation_rules(rule_id) ON DELETE CASCADE,
            domain          TEXT DEFAULT 'Unknown',
            field_name      TEXT DEFAULT '',
            op              TEXT DEFAULT 'Equals',
            value           TEXT DEFAULT '',
            min_severity    INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_cond_rule ON xdr_rule_conditions(rule_id);
    )SQL";

    if (!db.Execute(kSchema, &err)) {
        Logger::Error("{} Failed to create correlation rules schema: {}",
                      kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }
    return true;
}

bool CorrelationRulesImpl::PersistRule(const CorrelationRule& rule) {
    auto& db = DB::Instance();
    DBErr err;

    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now().time_since_epoch()).count();

    // UPSERT rule
    constexpr std::string_view kUpsert = R"SQL(
        INSERT INTO xdr_correlation_rules
            (rule_id, name, description, status, confidence, verdict,
             time_window_sec, entity_links, mitre_attack_id, mitre_tactic,
             created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(rule_id) DO UPDATE SET
            name = excluded.name,
            description = excluded.description,
            status = excluded.status,
            confidence = excluded.confidence,
            verdict = excluded.verdict,
            time_window_sec = excluded.time_window_sec,
            entity_links = excluded.entity_links,
            mitre_attack_id = excluded.mitre_attack_id,
            mitre_tactic = excluded.mitre_tactic,
            updated_at = excluded.updated_at
    )SQL";

    if (!db.ExecuteWithParams(kUpsert, &err,
            rule.ruleId,
            rule.name,
            rule.description,
            static_cast<int>(rule.status),
            static_cast<int>(rule.confidence),
            std::string(VerdictToString(rule.verdict)),
            static_cast<int>(rule.timeWindowSec),
            SerializeEntityLinks(rule.entityLinks),
            rule.mitreAttackId,
            rule.mitreTactic,
            nowMs, nowMs)) {
        Logger::Error("{} Failed to persist rule '{}': {}",
                      kLogPrefix, rule.ruleId, SU::ToNarrow(err.message));
        return false;
    }

    // Delete old conditions, re-insert
    db.ExecuteWithParams("DELETE FROM xdr_rule_conditions WHERE rule_id = ?", &err, rule.ruleId);

    for (const auto& cond : rule.conditions) {
        constexpr std::string_view kInsertCond = R"SQL(
            INSERT INTO xdr_rule_conditions
                (rule_id, domain, field_name, op, value, min_severity)
            VALUES (?, ?, ?, ?, ?, ?)
        )SQL";
        if (!db.ExecuteWithParams(kInsertCond, &err,
                rule.ruleId,
                std::string(DomainToString(cond.domain)),
                cond.fieldName,
                std::string(OpToString(cond.op)),
                cond.value,
                static_cast<int>(cond.minSeverity))) {
            Logger::Warn("{} Failed to persist condition for rule '{}': {}",
                         kLogPrefix, rule.ruleId, SU::ToNarrow(err.message));
        }
    }

    return true;
}

bool CorrelationRulesImpl::DeleteRuleFromDb(std::string_view ruleId) {
    auto& db = DB::Instance();
    DBErr err;
    // Conditions cascade-deleted by FK
    if (!db.ExecuteWithParams(
            "DELETE FROM xdr_correlation_rules WHERE rule_id = ?", &err,
            std::string(ruleId))) {
        Logger::Error("{} Failed to delete rule '{}': {}",
                      kLogPrefix, ruleId, SU::ToNarrow(err.message));
        return false;
    }
    return true;
}

bool CorrelationRulesImpl::LoadRulesFromDb() {
    auto& db = DB::Instance();
    DBErr err;

    auto result = db.Query("SELECT rule_id, name, description, status, confidence, "
                           "verdict, time_window_sec, entity_links, mitre_attack_id, "
                           "mitre_tactic, created_at, updated_at "
                           "FROM xdr_correlation_rules", &err);
    if (err.sqliteCode != 0) {
        Logger::Error("{} Failed to load rules: {}", kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }

    ruleCache.clear();

    while (result.Next()) {
        CorrelationRule rule;
        rule.ruleId         = result.GetString(0);
        rule.name           = result.GetString(1);
        rule.description    = result.GetString(2);
        rule.status         = static_cast<RuleStatus>(result.GetInt(3));
        rule.confidence     = static_cast<uint8_t>(result.GetInt(4));
        rule.verdict        = StringToVerdict(result.GetString(5));
        rule.timeWindowSec  = static_cast<uint32_t>(result.GetInt(6));
        rule.entityLinks    = DeserializeEntityLinks(result.GetString(7));
        rule.mitreAttackId  = result.GetString(8);
        rule.mitreTactic    = result.GetString(9);

        auto createdMs = result.GetInt64(10);
        auto updatedMs = result.GetInt64(11);
        rule.createdAt = Clock::time_point(
            std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(createdMs)));
        rule.updatedAt = Clock::time_point(
            std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(updatedMs)));

        // Load conditions
        DBErr condErr;
        auto condResult = db.QueryWithParams(
            "SELECT domain, field_name, op, value, min_severity "
            "FROM xdr_rule_conditions WHERE rule_id = ?",
            &condErr, rule.ruleId);

        while (condResult.Next()) {
            RuleCondition cond;
            cond.domain      = StringToDomain(condResult.GetString(0));
            cond.fieldName   = condResult.GetString(1);
            cond.op          = StringToOp(condResult.GetString(2));
            cond.value       = condResult.GetString(3);
            cond.minSeverity = static_cast<uint8_t>(condResult.GetInt(4));
            rule.conditions.push_back(std::move(cond));
        }

        ruleCache.emplace(rule.ruleId, std::move(rule));
    }

    Logger::Info("{} Loaded {} correlation rules from database",
                 kLogPrefix, ruleCache.size());
    return true;
}

// ============================================================================
// INIT / SHUTDOWN
// ============================================================================

bool CorrelationRulesImpl::Initialize() {
    if (initialized.load(std::memory_order_acquire)) return true;

    Logger::Info("{} Initializing correlation rule engine...", kLogPrefix);

    if (!CreateSchema()) return false;
    if (!LoadRulesFromDb()) return false;

    // Install defaults if empty
    if (ruleCache.empty()) {
        if (!InstallDefaultRules()) {
            Logger::Warn("{} Failed to install default rules (non-fatal)", kLogPrefix);
        }
    }

    initialized.store(true, std::memory_order_release);
    Logger::Info("{} Correlation rule engine initialized ({} rules active)",
                 kLogPrefix, ruleCache.size());
    return true;
}

void CorrelationRulesImpl::Shutdown() {
    if (!initialized.exchange(false, std::memory_order_acq_rel)) return;
    std::unique_lock lock(mutex);
    ruleCache.clear();
    Logger::Info("{} Correlation rule engine shut down", kLogPrefix);
}

// ============================================================================
// CRUD
// ============================================================================

bool CorrelationRulesImpl::AddRule(const CorrelationRule& rule) {
    if (rule.ruleId.empty() || rule.name.empty()) {
        Logger::Warn("{} Cannot add rule with empty ID or name", kLogPrefix);
        return false;
    }
    if (rule.conditions.empty()) {
        Logger::Warn("{} Rule '{}' has no conditions", kLogPrefix, rule.ruleId);
        return false;
    }

    std::unique_lock lock(mutex);
    if (ruleCache.contains(rule.ruleId)) {
        Logger::Warn("{} Rule '{}' already exists — use UpdateRule", kLogPrefix, rule.ruleId);
        return false;
    }

    if (!PersistRule(rule)) return false;
    ruleCache.emplace(rule.ruleId, rule);
    Logger::Info("{} Added correlation rule '{}' ({})", kLogPrefix, rule.ruleId, rule.name);
    return true;
}

bool CorrelationRulesImpl::RemoveRule(std::string_view ruleId) {
    std::unique_lock lock(mutex);
    auto it = ruleCache.find(std::string(ruleId));
    if (it == ruleCache.end()) return false;

    if (!DeleteRuleFromDb(ruleId)) return false;
    ruleCache.erase(it);
    Logger::Info("{} Removed correlation rule '{}'", kLogPrefix, ruleId);
    return true;
}

bool CorrelationRulesImpl::UpdateRule(const CorrelationRule& rule) {
    std::unique_lock lock(mutex);
    auto it = ruleCache.find(rule.ruleId);
    if (it == ruleCache.end()) {
        Logger::Warn("{} Rule '{}' not found for update", kLogPrefix, rule.ruleId);
        return false;
    }
    if (!PersistRule(rule)) return false;
    it->second = rule;
    return true;
}

std::optional<CorrelationRule> CorrelationRulesImpl::GetRule(std::string_view ruleId) const {
    std::shared_lock lock(mutex);
    auto it = ruleCache.find(std::string(ruleId));
    if (it == ruleCache.end()) return std::nullopt;
    return it->second;
}

std::vector<CorrelationRule> CorrelationRulesImpl::GetActiveRules() const {
    std::shared_lock lock(mutex);
    std::vector<CorrelationRule> result;
    for (const auto& [id, rule] : ruleCache) {
        if (rule.status == RuleStatus::Active)
            result.push_back(rule);
    }
    return result;
}

std::vector<CorrelationRule> CorrelationRulesImpl::GetAllRules() const {
    std::shared_lock lock(mutex);
    std::vector<CorrelationRule> result;
    result.reserve(ruleCache.size());
    for (const auto& [id, rule] : ruleCache)
        result.push_back(rule);
    return result;
}

uint32_t CorrelationRulesImpl::GetRuleCount() const {
    std::shared_lock lock(mutex);
    return static_cast<uint32_t>(ruleCache.size());
}

// ============================================================================
// RULE EVALUATION
// ============================================================================

std::vector<CorrelationMatch> CorrelationRulesImpl::EvaluateRule(
    const CorrelationRule& rule,
    const std::vector<XDREvent>& events) const
{
    std::vector<CorrelationMatch> matches;
    if (rule.conditions.empty() || events.empty()) return matches;

    // Group events by which condition they satisfy
    // conditions[i] → set of matching event indices
    std::vector<std::vector<size_t>> condMatches(rule.conditions.size());

    for (size_t i = 0; i < events.size(); ++i) {
        for (size_t c = 0; c < rule.conditions.size(); ++c) {
            if (EvaluateCondition(rule.conditions[c], events[i]))
                condMatches[c].push_back(i);
        }
    }

    // All conditions must have at least one matching event
    for (const auto& cm : condMatches) {
        if (cm.empty()) return matches;
    }

    // Entity linking: find sets of events where entity values align
    // For simplicity with multi-condition rules, pick the first condition's matches
    // and filter through entity linking and time window constraints
    const auto& primaryMatches = condMatches[0];

    for (size_t pi : primaryMatches) {
        const auto& primary = events[pi];
        std::vector<uint64_t> matchedIds;
        matchedIds.push_back(primary.eventId);
        bool allSatisfied = true;

        auto primaryTime = primary.timestamp;

        for (size_t c = 1; c < rule.conditions.size(); ++c) {
            bool foundLink = false;
            for (size_t si : condMatches[c]) {
                const auto& secondary = events[si];

                // Time window check
                auto delta = std::chrono::abs(secondary.timestamp - primaryTime);
                if (delta > std::chrono::seconds(rule.timeWindowSec))
                    continue;

                // Entity link check
                bool entityOk = rule.entityLinks.empty(); // no links = auto-pass
                for (auto link : rule.entityLinks) {
                    auto pv = GetEntityValue(primary, link);
                    auto sv = GetEntityValue(secondary, link);
                    if (!pv.empty() && !sv.empty() && pv == sv) {
                        entityOk = true;
                        break;
                    }
                }
                if (!entityOk) continue;

                matchedIds.push_back(secondary.eventId);
                foundLink = true;
                break; // one match per condition suffices
            }
            if (!foundLink) { allSatisfied = false; break; }
        }

        if (!allSatisfied) continue;

        // Build the CorrelationMatch
        CorrelationMatch match;
        match.matchId       = GenerateRuleId();
        match.ruleId        = rule.ruleId;
        match.ruleName      = rule.name;
        match.verdict       = rule.verdict;
        match.confidence    = rule.confidence;
        match.matchedEventIds = std::move(matchedIds);

        // Determine time range
        TimePoint earliest = primary.timestamp;
        TimePoint latest   = primary.timestamp;
        for (auto eid : match.matchedEventIds) {
            for (const auto& ev : events) {
                if (ev.eventId == eid) {
                    if (ev.timestamp < earliest) earliest = ev.timestamp;
                    if (ev.timestamp > latest)   latest   = ev.timestamp;
                }
            }
        }
        match.firstEventTime = earliest;
        match.lastEventTime  = latest;

        // Entity info
        if (!rule.entityLinks.empty()) {
            match.linkDimension = rule.entityLinks[0];
            match.linkedEntity  = GetEntityValue(primary, rule.entityLinks[0]);
        }

        matches.push_back(std::move(match));
    }

    return matches;
}

std::vector<CorrelationMatch> CorrelationRulesImpl::Evaluate(
    const std::vector<XDREvent>& windowEvents) const
{
    std::shared_lock lock(mutex);
    std::vector<CorrelationMatch> allMatches;

    for (const auto& [id, rule] : ruleCache) {
        if (rule.status != RuleStatus::Active) continue;

        auto ruleMatches = EvaluateRule(rule, windowEvents);
        for (auto& m : ruleMatches)
            allMatches.push_back(std::move(m));
    }

    return allMatches;
}

// ============================================================================
// DEFAULT RULES
// ============================================================================

bool CorrelationRulesImpl::InstallDefaultRules() {
    Logger::Info("{} Installing default correlation rules...", kLogPrefix);

    std::vector<CorrelationRule> defaults;

    // Rule 1: Phishing → Execution chain
    {
        CorrelationRule r;
        r.ruleId        = "DEFAULT-PHISH-EXEC";
        r.name          = "Phishing Email to Endpoint Execution";
        r.description   = "Detects when a phishing email attachment hash matches an "
                          "executable launched on the endpoint within 30 minutes.";
        r.confidence    = 85;
        r.verdict       = CorrelationVerdict::Malicious;
        r.timeWindowSec = 1800;
        r.entityLinks   = { EntityLink::SameUser, EntityLink::SameFileHash };
        r.mitreAttackId = "T1566.001";
        r.mitreTactic   = "InitialAccess";

        RuleCondition c1;
        c1.domain    = XDREventDomain::Email;
        c1.fieldName = "mitreTactic";
        c1.op        = ConditionOp::Equals;
        c1.value     = "InitialAccess";
        r.conditions.push_back(c1);

        RuleCondition c2;
        c2.domain    = XDREventDomain::Endpoint;
        c2.fieldName = "mitreTactic";
        c2.op        = ConditionOp::Equals;
        c2.value     = "Execution";
        r.conditions.push_back(c2);

        defaults.push_back(std::move(r));
    }

    // Rule 2: Credential theft → Lateral movement
    {
        CorrelationRule r;
        r.ruleId        = "DEFAULT-CRED-LATERAL";
        r.name          = "Credential Access to Lateral Movement";
        r.description   = "Detects credential dumping followed by lateral movement "
                          "from the same host within 15 minutes.";
        r.confidence    = 80;
        r.verdict       = CorrelationVerdict::Malicious;
        r.timeWindowSec = 900;
        r.entityLinks   = { EntityLink::SameHost };
        r.mitreAttackId = "T1003";
        r.mitreTactic   = "CredentialAccess";

        RuleCondition c1;
        c1.domain    = XDREventDomain::Identity;
        c1.fieldName = "mitreTactic";
        c1.op        = ConditionOp::Equals;
        c1.value     = "CredentialAccess";
        r.conditions.push_back(c1);

        RuleCondition c2;
        c2.domain    = XDREventDomain::Network;
        c2.fieldName = "mitreTactic";
        c2.op        = ConditionOp::Equals;
        c2.value     = "LateralMovement";
        r.conditions.push_back(c2);

        defaults.push_back(std::move(r));
    }

    // Rule 3: C2 Beacon + Endpoint execution
    {
        CorrelationRule r;
        r.ruleId        = "DEFAULT-C2-EXEC";
        r.name          = "C2 Beacon with Endpoint Execution";
        r.description   = "Correlates detected C2 beacon traffic with suspicious "
                          "process execution on the same host.";
        r.confidence    = 75;
        r.verdict       = CorrelationVerdict::Critical;
        r.timeWindowSec = 600;
        r.entityLinks   = { EntityLink::SameHost };
        r.mitreAttackId = "T1071";
        r.mitreTactic   = "CommandAndControl";

        RuleCondition c1;
        c1.domain    = XDREventDomain::Network;
        c1.fieldName = "mitreTactic";
        c1.op        = ConditionOp::Equals;
        c1.value     = "CommandAndControl";
        r.conditions.push_back(c1);

        RuleCondition c2;
        c2.domain       = XDREventDomain::Endpoint;
        c2.fieldName    = "mitreTactic";
        c2.op           = ConditionOp::Equals;
        c2.value        = "Execution";
        c2.minSeverity  = 40;
        r.conditions.push_back(c2);

        defaults.push_back(std::move(r));
    }

    // Rule 4: Brute force → Successful logon
    {
        CorrelationRule r;
        r.ruleId        = "DEFAULT-BRUTE-LOGON";
        r.name          = "Brute Force Followed by Successful Logon";
        r.description   = "Detects multiple failed identity events followed by a "
                          "successful endpoint logon for the same user.";
        r.confidence    = 70;
        r.verdict       = CorrelationVerdict::Suspicious;
        r.timeWindowSec = 600;
        r.entityLinks   = { EntityLink::SameUser };
        r.mitreAttackId = "T1110";
        r.mitreTactic   = "CredentialAccess";

        RuleCondition c1;
        c1.domain       = XDREventDomain::Identity;
        c1.fieldName    = "mitreAttackId";
        c1.op           = ConditionOp::StartsWith;
        c1.value        = "T1110";
        r.conditions.push_back(c1);

        RuleCondition c2;
        c2.domain       = XDREventDomain::Endpoint;
        c2.fieldName    = "mitreTactic";
        c2.op           = ConditionOp::Equals;
        c2.value        = "InitialAccess";
        r.conditions.push_back(c2);

        defaults.push_back(std::move(r));
    }

    // Rule 5: Discovery + Exfiltration chain
    {
        CorrelationRule r;
        r.ruleId        = "DEFAULT-DISC-EXFIL";
        r.name          = "Discovery Activity to Data Exfiltration";
        r.description   = "Detects discovery commands followed by large data transfers "
                          "or suspicious network exfiltration patterns.";
        r.confidence    = 65;
        r.verdict       = CorrelationVerdict::Malicious;
        r.timeWindowSec = 1800;
        r.entityLinks   = { EntityLink::SameHost, EntityLink::SameUser };
        r.mitreAttackId = "T1041";
        r.mitreTactic   = "Exfiltration";

        RuleCondition c1;
        c1.domain    = XDREventDomain::Endpoint;
        c1.fieldName = "mitreTactic";
        c1.op        = ConditionOp::Equals;
        c1.value     = "Discovery";
        r.conditions.push_back(c1);

        RuleCondition c2;
        c2.domain    = XDREventDomain::Network;
        c2.fieldName = "mitreTactic";
        c2.op        = ConditionOp::Equals;
        c2.value     = "Exfiltration";
        r.conditions.push_back(c2);

        defaults.push_back(std::move(r));
    }

    // Rule 6: DNS tunneling + C2
    {
        CorrelationRule r;
        r.ruleId        = "DEFAULT-DNS-C2";
        r.name          = "DNS Tunneling with C2 Communication";
        r.description   = "Correlates DNS tunneling indicators with C2 beacon patterns "
                          "on the same host.";
        r.confidence    = 80;
        r.verdict       = CorrelationVerdict::Critical;
        r.timeWindowSec = 300;
        r.entityLinks   = { EntityLink::SameHost };
        r.mitreAttackId = "T1071.004";
        r.mitreTactic   = "CommandAndControl";

        RuleCondition c1;
        c1.domain    = XDREventDomain::Network;
        c1.fieldName = "mitreAttackId";
        c1.op        = ConditionOp::Equals;
        c1.value     = "T1071.004";
        r.conditions.push_back(c1);

        RuleCondition c2;
        c2.domain    = XDREventDomain::Network;
        c2.fieldName = "mitreTactic";
        c2.op        = ConditionOp::Equals;
        c2.value     = "CommandAndControl";
        c2.minSeverity = 50;
        r.conditions.push_back(c2);

        defaults.push_back(std::move(r));
    }

    uint32_t installed = 0;
    for (auto& rule : defaults) {
        if (AddRule(rule)) ++installed;
    }

    Logger::Info("{} Installed {}/{} default correlation rules",
                 kLogPrefix, installed, defaults.size());
    return installed > 0;
}

// ============================================================================
// PUBLIC INTERFACE (FORWARDING TO IMPL)
// ============================================================================

CorrelationRules& CorrelationRules::Instance() {
    static CorrelationRules inst;
    return inst;
}

bool CorrelationRules::HasInstance() noexcept {
    return Instance().IsInitialized();
}

CorrelationRules::CorrelationRules()  : m_impl(std::make_unique<CorrelationRulesImpl>()) {}
CorrelationRules::~CorrelationRules() { Shutdown(); }

bool CorrelationRules::Initialize() { return m_impl->Initialize(); }
void CorrelationRules::Shutdown()   { m_impl->Shutdown(); }
bool CorrelationRules::IsInitialized() const noexcept { return m_impl->initialized.load(std::memory_order_acquire); }

bool CorrelationRules::AddRule(const CorrelationRule& rule) { return m_impl->AddRule(rule); }
bool CorrelationRules::RemoveRule(std::string_view ruleId) { return m_impl->RemoveRule(ruleId); }
bool CorrelationRules::UpdateRule(const CorrelationRule& rule) { return m_impl->UpdateRule(rule); }

std::optional<CorrelationRule> CorrelationRules::GetRule(std::string_view ruleId) const {
    return m_impl->GetRule(ruleId);
}

std::vector<CorrelationRule> CorrelationRules::GetActiveRules() const {
    return m_impl->GetActiveRules();
}

std::vector<CorrelationRule> CorrelationRules::GetAllRules() const {
    return m_impl->GetAllRules();
}

uint32_t CorrelationRules::GetRuleCount() const {
    return m_impl->GetRuleCount();
}

std::vector<CorrelationMatch> CorrelationRules::Evaluate(
    const std::vector<XDREvent>& windowEvents) const {
    return m_impl->Evaluate(windowEvents);
}

bool CorrelationRules::InstallDefaultRules() { return m_impl->InstallDefaultRules(); }

uint32_t CorrelationRules::ImportRulesFromJson(std::string_view /*json*/) {
    // JSON import deferred — requires nlohmann::json integration already in codebase
    Logger::Warn("{} JSON rule import not yet available in Community edition", kLogPrefix);
    return 0;
}

std::string CorrelationRules::ExportRulesToJson() const {
    Logger::Warn("{} JSON rule export not yet available in Community edition", kLogPrefix);
    return "{}";
}

} // namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation

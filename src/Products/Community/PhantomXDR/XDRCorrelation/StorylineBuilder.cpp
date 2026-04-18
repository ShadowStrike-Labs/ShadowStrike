/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

/// @file StorylineBuilder.cpp
/// @brief Attack-chain reconstruction — builds directed acyclic graphs of
///        attack progression mapped to MITRE ATT&CK kill chain phases.

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/StorylineBuilder.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation {

namespace {

constexpr const char* kLogPrefix = "[XDR::StorylineBuilder]";
constexpr size_t kMaxActiveStorylines = 10000;

using Clock = std::chrono::system_clock;
using DB    = ShadowStrike::Database::DatabaseManager;
using DBErr = ShadowStrike::Database::DatabaseError;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Utils::Logger;

std::string GenerateStorylineId() {
    static std::atomic<uint64_t> seq{0};
    auto now = Clock::now().time_since_epoch().count();
    return std::format("SL-{:X}-{:04X}", now,
                       seq.fetch_add(1, std::memory_order_relaxed) & 0xFFFF);
}

/// Map a MITRE tactic string to a StorylinePhase enum.
StorylinePhase TacticToPhase(std::string_view tactic) {
    if (tactic == "Reconnaissance")         return StorylinePhase::Reconnaissance;
    if (tactic == "ResourceDevelopment")     return StorylinePhase::ResourceDevelopment;
    if (tactic == "InitialAccess")           return StorylinePhase::InitialAccess;
    if (tactic == "Execution")              return StorylinePhase::Execution;
    if (tactic == "Persistence")            return StorylinePhase::Persistence;
    if (tactic == "PrivilegeEscalation")    return StorylinePhase::PrivilegeEscalation;
    if (tactic == "DefenseEvasion")         return StorylinePhase::DefenseEvasion;
    if (tactic == "CredentialAccess")       return StorylinePhase::CredentialAccess;
    if (tactic == "Discovery")              return StorylinePhase::Discovery;
    if (tactic == "LateralMovement")        return StorylinePhase::LateralMovement;
    if (tactic == "Collection")             return StorylinePhase::Collection;
    if (tactic == "CommandAndControl")      return StorylinePhase::CommandAndControl;
    if (tactic == "Exfiltration")           return StorylinePhase::Exfiltration;
    if (tactic == "Impact")                 return StorylinePhase::Impact;
    return StorylinePhase::Unknown;
}

std::string_view PhaseToString(StorylinePhase phase) {
    switch (phase) {
        case StorylinePhase::Reconnaissance:      return "Reconnaissance";
        case StorylinePhase::ResourceDevelopment:  return "Resource Development";
        case StorylinePhase::InitialAccess:        return "Initial Access";
        case StorylinePhase::Execution:            return "Execution";
        case StorylinePhase::Persistence:          return "Persistence";
        case StorylinePhase::PrivilegeEscalation:  return "Privilege Escalation";
        case StorylinePhase::DefenseEvasion:       return "Defense Evasion";
        case StorylinePhase::CredentialAccess:     return "Credential Access";
        case StorylinePhase::Discovery:            return "Discovery";
        case StorylinePhase::LateralMovement:      return "Lateral Movement";
        case StorylinePhase::Collection:           return "Collection";
        case StorylinePhase::CommandAndControl:     return "Command and Control";
        case StorylinePhase::Exfiltration:         return "Exfiltration";
        case StorylinePhase::Impact:               return "Impact";
        default:                                   return "Unknown";
    }
}

std::string_view DomainStr(XDREventDomain d) {
    switch (d) {
        case XDREventDomain::Endpoint: return "endpoint";
        case XDREventDomain::Network:  return "network";
        case XDREventDomain::Identity: return "identity";
        case XDREventDomain::Email:    return "email";
        case XDREventDomain::Cloud:    return "cloud";
        default:                       return "unknown";
    }
}

/// Determine severity from kill-chain coverage percentage.
IncidentSeverity CoverageToSeverity(uint8_t coverage) {
    if (coverage >= 60) return IncidentSeverity::Critical;
    if (coverage >= 40) return IncidentSeverity::High;
    if (coverage >= 20) return IncidentSeverity::Medium;
    if (coverage >= 10) return IncidentSeverity::Low;
    return IncidentSeverity::Info;
}

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS
// ============================================================================

class StorylineBuilderImpl {
public:
    std::atomic<bool>       initialized{false};
    mutable std::shared_mutex mutex;

    // Active storylines keyed by ID
    std::unordered_map<std::string, Storyline> storylines;

    bool Initialize();
    void Shutdown();
    bool CreateSchema();

    std::optional<std::string> BuildStoryline(
        const CorrelationMatch& match,
        const std::vector<XDREvent>& events);

    bool UpdateStoryline(std::string_view storylineId,
                         const std::vector<XDREvent>& newEvents);

    std::optional<Storyline> GetStoryline(std::string_view storylineId) const;
    std::vector<Storyline> GetActiveStorylines() const;
    std::string GenerateNarrative(std::string_view storylineId) const;
    std::string GenerateNarrative(const Storyline& sl) const;
    uint32_t GetActiveCount() const;

private:
    void ComputeStorylineMetadata(Storyline& sl) const;
    void PersistStoryline(const Storyline& sl);

    StorylineNode EventToNode(const XDREvent& ev,
                              const std::vector<uint64_t>& parentIds) const;
};

// ============================================================================
// SCHEMA
// ============================================================================

bool StorylineBuilderImpl::CreateSchema() {
    auto& db = DB::Instance();
    DBErr err;

    constexpr std::string_view kSchema = R"SQL(
        CREATE TABLE IF NOT EXISTS xdr_storylines (
            storyline_id        TEXT PRIMARY KEY,
            title               TEXT NOT NULL,
            severity            INTEGER DEFAULT 0,
            start_time_ms       INTEGER NOT NULL,
            end_time_ms         INTEGER NOT NULL,
            narrative           TEXT DEFAULT '',
            mitre_tactics       TEXT DEFAULT '',
            mitre_techniques    TEXT DEFAULT '',
            affected_users      TEXT DEFAULT '',
            affected_hosts      TEXT DEFAULT '',
            kill_chain_coverage INTEGER DEFAULT 0,
            node_count          INTEGER DEFAULT 0,
            created_at_ms       INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_sl_sev ON xdr_storylines(severity);
        CREATE INDEX IF NOT EXISTS idx_xdr_sl_time ON xdr_storylines(created_at_ms);

        CREATE TABLE IF NOT EXISTS xdr_storyline_nodes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            storyline_id    TEXT NOT NULL REFERENCES xdr_storylines(storyline_id) ON DELETE CASCADE,
            event_id        INTEGER NOT NULL,
            domain          TEXT NOT NULL,
            phase           TEXT NOT NULL,
            timestamp_ms    INTEGER NOT NULL,
            description     TEXT DEFAULT '',
            mitre_attack_id TEXT DEFAULT '',
            parent_ids      TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_slnode_sl ON xdr_storyline_nodes(storyline_id);
    )SQL";

    if (!db.Execute(kSchema, &err)) {
        Logger::Error("{} Failed to create storyline schema: {}",
                      kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }
    return true;
}

// ============================================================================
// INIT / SHUTDOWN
// ============================================================================

bool StorylineBuilderImpl::Initialize() {
    if (initialized.load(std::memory_order_acquire)) return true;
    Logger::Info("{} Initializing storyline builder...", kLogPrefix);

    if (!CreateSchema()) return false;

    initialized.store(true, std::memory_order_release);
    Logger::Info("{} Storyline builder initialized", kLogPrefix);
    return true;
}

void StorylineBuilderImpl::Shutdown() {
    if (!initialized.exchange(false, std::memory_order_acq_rel)) return;
    std::unique_lock lock(mutex);
    Logger::Info("{} Storyline builder shut down ({} active storylines flushed)",
                 kLogPrefix, storylines.size());
    storylines.clear();
}

// ============================================================================
// BUILD STORYLINE
// ============================================================================

StorylineNode StorylineBuilderImpl::EventToNode(
    const XDREvent& ev,
    const std::vector<uint64_t>& parentIds) const
{
    StorylineNode node;
    node.eventId        = ev.eventId;
    node.domain         = ev.domain;
    node.phase          = TacticToPhase(ev.mitreTactic);
    node.timestamp      = ev.timestamp;
    node.mitreAttackId  = ev.mitreAttackId;
    node.parentEventIds = parentIds;

    // Build description from event attributes
    std::ostringstream desc;
    desc << PhaseToString(node.phase) << " activity detected via " << DomainStr(ev.domain);
    if (!ev.mitreAttackId.empty()) desc << " [" << ev.mitreAttackId << "]";
    if (!ev.userName.empty()) desc << " by user '" << ev.userName << "'";
    if (!ev.hostName.empty()) desc << " on host '" << ev.hostName << "'";
    node.description = desc.str();

    return node;
}

void StorylineBuilderImpl::ComputeStorylineMetadata(Storyline& sl) const {
    std::unordered_set<std::string> tactics;
    std::unordered_set<std::string> techniques;
    std::unordered_set<std::string> users;
    std::unordered_set<std::string> hosts;

    TimePoint earliest = Clock::now();
    TimePoint latest   = Clock::time_point{};

    for (const auto& node : sl.nodes) {
        if (!node.mitreAttackId.empty()) {
            techniques.insert(node.mitreAttackId);
            auto phaseStr = std::string(PhaseToString(node.phase));
            tactics.insert(phaseStr);
        }
        if (node.timestamp < earliest) earliest = node.timestamp;
        if (node.timestamp > latest)   latest   = node.timestamp;
    }

    sl.startTime = earliest;
    sl.endTime   = latest;
    sl.mitreTactics.assign(tactics.begin(), tactics.end());
    sl.mitreTechniques.assign(techniques.begin(), techniques.end());

    // Collect user/host from narrative context (stored in description)
    // We'll extract from original events — stored in node descriptions
    sl.affectedUsers.assign(users.begin(), users.end());
    sl.affectedHosts.assign(hosts.begin(), hosts.end());

    // Kill chain coverage: count unique tactic phases out of 14
    constexpr uint8_t kTotalTactics = 14;
    sl.killChainCoverage = static_cast<uint8_t>(
        std::min<size_t>(tactics.size() * 100 / kTotalTactics, 100));

    sl.severity = CoverageToSeverity(sl.killChainCoverage);
}

std::optional<std::string> StorylineBuilderImpl::BuildStoryline(
    const CorrelationMatch& match,
    const std::vector<XDREvent>& events)
{
    if (match.matchedEventIds.empty()) return std::nullopt;

    // Build event lookup
    std::unordered_map<uint64_t, const XDREvent*> eventMap;
    for (const auto& ev : events) {
        eventMap[ev.eventId] = &ev;
    }

    // Sort matched event IDs by timestamp
    std::vector<uint64_t> sortedIds = match.matchedEventIds;
    std::sort(sortedIds.begin(), sortedIds.end(),
        [&](uint64_t a, uint64_t b) {
            auto itA = eventMap.find(a);
            auto itB = eventMap.find(b);
            if (itA == eventMap.end() || itB == eventMap.end()) return a < b;
            return itA->second->timestamp < itB->second->timestamp;
        });

    Storyline sl;
    sl.storylineId = GenerateStorylineId();
    sl.title = std::format("Attack Chain: {} (rule: {})", match.ruleName, match.ruleId);

    // Build DAG nodes — each event links to the previous as parent
    uint64_t prevId = 0;
    std::unordered_set<std::string> users;
    std::unordered_set<std::string> hosts;

    for (auto eid : sortedIds) {
        auto it = eventMap.find(eid);
        if (it == eventMap.end()) continue;

        const auto& ev = *it->second;
        std::vector<uint64_t> parents;
        if (prevId != 0) parents.push_back(prevId);

        sl.nodes.push_back(EventToNode(ev, parents));
        prevId = eid;

        if (!ev.userName.empty()) users.insert(ev.userName);
        if (!ev.hostName.empty()) hosts.insert(ev.hostName);
    }

    if (sl.nodes.empty()) return std::nullopt;

    sl.affectedUsers.assign(users.begin(), users.end());
    sl.affectedHosts.assign(hosts.begin(), hosts.end());

    ComputeStorylineMetadata(sl);

    // Generate narrative
    sl.narrative = GenerateNarrative(sl);

    {
        std::unique_lock lock(mutex);

        // Cap active storylines
        if (storylines.size() >= kMaxActiveStorylines) {
            // Evict oldest
            auto oldest = storylines.begin();
            for (auto it = storylines.begin(); it != storylines.end(); ++it) {
                if (it->second.startTime < oldest->second.startTime) oldest = it;
            }
            storylines.erase(oldest);
        }

        PersistStoryline(sl);
        auto id = sl.storylineId;
        storylines.emplace(id, std::move(sl));
        Logger::Info("{} Built storyline '{}' ({} nodes, {}% kill chain coverage)",
                     kLogPrefix, id, storylines[id].nodes.size(),
                     storylines[id].killChainCoverage);
        return id;
    }
}

// ============================================================================
// UPDATE STORYLINE
// ============================================================================

bool StorylineBuilderImpl::UpdateStoryline(
    std::string_view storylineId,
    const std::vector<XDREvent>& newEvents)
{
    std::unique_lock lock(mutex);
    auto it = storylines.find(std::string(storylineId));
    if (it == storylines.end()) return false;

    auto& sl = it->second;

    // Find the latest existing node to use as parent
    uint64_t lastId = 0;
    if (!sl.nodes.empty()) lastId = sl.nodes.back().eventId;

    for (const auto& ev : newEvents) {
        std::vector<uint64_t> parents;
        if (lastId != 0) parents.push_back(lastId);
        sl.nodes.push_back(EventToNode(ev, parents));
        lastId = ev.eventId;

        if (!ev.userName.empty()) {
            auto& users = sl.affectedUsers;
            if (std::find(users.begin(), users.end(), ev.userName) == users.end())
                users.push_back(ev.userName);
        }
        if (!ev.hostName.empty()) {
            auto& hosts = sl.affectedHosts;
            if (std::find(hosts.begin(), hosts.end(), ev.hostName) == hosts.end())
                hosts.push_back(ev.hostName);
        }
    }

    ComputeStorylineMetadata(sl);
    sl.narrative = GenerateNarrative(sl);
    PersistStoryline(sl);

    Logger::Debug("{} Updated storyline '{}' (+{} nodes, total={})",
                  kLogPrefix, storylineId, newEvents.size(), sl.nodes.size());
    return true;
}

// ============================================================================
// NARRATIVE GENERATION
// ============================================================================

std::string StorylineBuilderImpl::GenerateNarrative(std::string_view storylineId) const {
    std::shared_lock lock(mutex);
    auto it = storylines.find(std::string(storylineId));
    if (it == storylines.end()) return "Storyline not found.";
    return GenerateNarrative(it->second);
}

namespace {

/// Generate narrative from a Storyline object (internal, no locking).
std::string GenerateNarrativeFromStoryline(const Storyline& sl) {
    if (sl.nodes.empty()) return "No events in storyline.";

    std::ostringstream nar;
    nar << "## Attack Storyline: " << sl.title << "\n\n";

    // Summary
    nar << "**Severity:** ";
    switch (sl.severity) {
        case IncidentSeverity::Critical: nar << "CRITICAL"; break;
        case IncidentSeverity::High:     nar << "HIGH"; break;
        case IncidentSeverity::Medium:   nar << "MEDIUM"; break;
        case IncidentSeverity::Low:      nar << "LOW"; break;
        default:                         nar << "INFO"; break;
    }
    nar << " | **Kill Chain Coverage:** " << static_cast<int>(sl.killChainCoverage) << "%\n";

    if (!sl.affectedUsers.empty()) {
        nar << "**Affected Users:** ";
        for (size_t i = 0; i < sl.affectedUsers.size(); ++i) {
            if (i > 0) nar << ", ";
            nar << sl.affectedUsers[i];
        }
        nar << "\n";
    }

    if (!sl.affectedHosts.empty()) {
        nar << "**Affected Hosts:** ";
        for (size_t i = 0; i < sl.affectedHosts.size(); ++i) {
            if (i > 0) nar << ", ";
            nar << sl.affectedHosts[i];
        }
        nar << "\n";
    }

    nar << "\n### Attack Timeline\n\n";

    // Chronological events
    for (size_t i = 0; i < sl.nodes.size(); ++i) {
        const auto& node = sl.nodes[i];
        nar << (i + 1) << ". **" << PhaseToString(node.phase) << "** — "
            << node.description << "\n";
    }

    // MITRE mapping
    if (!sl.mitreTechniques.empty()) {
        nar << "\n### MITRE ATT&CK Techniques\n";
        for (const auto& tech : sl.mitreTechniques) {
            nar << "- " << tech << "\n";
        }
    }

    return nar.str();
}

} // anonymous namespace

// Overload for direct Storyline access (called from BuildStoryline)
std::string StorylineBuilderImpl::GenerateNarrative(const Storyline& sl) const {
    return GenerateNarrativeFromStoryline(sl);
}

// ============================================================================
// PERSISTENCE
// ============================================================================

void StorylineBuilderImpl::PersistStoryline(const Storyline& sl) {
    auto& db = DB::Instance();
    DBErr err;

    auto startMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        sl.startTime.time_since_epoch()).count();
    auto endMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        sl.endTime.time_since_epoch()).count();
    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now().time_since_epoch()).count();

    // Serialize lists
    auto join = [](const std::vector<std::string>& v) {
        std::string r;
        for (size_t i = 0; i < v.size(); ++i) {
            if (i > 0) r += '|';
            r += v[i];
        }
        return r;
    };

    constexpr std::string_view kUpsert = R"SQL(
        INSERT INTO xdr_storylines
            (storyline_id, title, severity, start_time_ms, end_time_ms,
             narrative, mitre_tactics, mitre_techniques,
             affected_users, affected_hosts, kill_chain_coverage,
             node_count, created_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(storyline_id) DO UPDATE SET
            severity = excluded.severity,
            end_time_ms = excluded.end_time_ms,
            narrative = excluded.narrative,
            mitre_tactics = excluded.mitre_tactics,
            mitre_techniques = excluded.mitre_techniques,
            affected_users = excluded.affected_users,
            affected_hosts = excluded.affected_hosts,
            kill_chain_coverage = excluded.kill_chain_coverage,
            node_count = excluded.node_count
    )SQL";

    if (!db.ExecuteWithParams(kUpsert, &err,
            sl.storylineId, sl.title, static_cast<int>(sl.severity),
            startMs, endMs, sl.narrative,
            join(sl.mitreTactics), join(sl.mitreTechniques),
            join(sl.affectedUsers), join(sl.affectedHosts),
            static_cast<int>(sl.killChainCoverage),
            static_cast<int>(sl.nodes.size()), nowMs)) {
        Logger::Warn("{} Failed to persist storyline '{}': {}",
                     kLogPrefix, sl.storylineId, SU::ToNarrow(err.message));
    }

    // Persist nodes (delete-reinsert for simplicity)
    db.ExecuteWithParams("DELETE FROM xdr_storyline_nodes WHERE storyline_id = ?",
                         &err, sl.storylineId);

    for (const auto& node : sl.nodes) {
        auto tsMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            node.timestamp.time_since_epoch()).count();

        std::string parentStr;
        for (size_t i = 0; i < node.parentEventIds.size(); ++i) {
            if (i > 0) parentStr += ',';
            parentStr += std::to_string(node.parentEventIds[i]);
        }

        db.ExecuteWithParams(
            "INSERT INTO xdr_storyline_nodes "
            "(storyline_id, event_id, domain, phase, timestamp_ms, "
            "description, mitre_attack_id, parent_ids) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            &err,
            sl.storylineId,
            static_cast<int64_t>(node.eventId),
            std::string(DomainStr(node.domain)),
            std::string(PhaseToString(node.phase)),
            tsMs,
            node.description,
            node.mitreAttackId,
            parentStr);
    }
}

// ============================================================================
// QUERIES
// ============================================================================

std::optional<Storyline> StorylineBuilderImpl::GetStoryline(
    std::string_view storylineId) const
{
    std::shared_lock lock(mutex);
    auto it = storylines.find(std::string(storylineId));
    if (it == storylines.end()) return std::nullopt;
    return it->second;
}

std::vector<Storyline> StorylineBuilderImpl::GetActiveStorylines() const {
    std::shared_lock lock(mutex);
    std::vector<Storyline> result;
    result.reserve(storylines.size());
    for (const auto& [id, sl] : storylines)
        result.push_back(sl);
    return result;
}

uint32_t StorylineBuilderImpl::GetActiveCount() const {
    std::shared_lock lock(mutex);
    return static_cast<uint32_t>(storylines.size());
}

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

StorylineBuilder& StorylineBuilder::Instance() {
    static StorylineBuilder inst;
    return inst;
}

bool StorylineBuilder::HasInstance() noexcept {
    return Instance().IsInitialized();
}

StorylineBuilder::StorylineBuilder()  : m_impl(std::make_unique<StorylineBuilderImpl>()) {}
StorylineBuilder::~StorylineBuilder() { Shutdown(); }

bool StorylineBuilder::Initialize() { return m_impl->Initialize(); }
void StorylineBuilder::Shutdown()   { m_impl->Shutdown(); }
bool StorylineBuilder::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

std::optional<std::string> StorylineBuilder::BuildStoryline(
    const CorrelationMatch& match, const std::vector<XDREvent>& events) {
    return m_impl->BuildStoryline(match, events);
}

bool StorylineBuilder::UpdateStoryline(
    std::string_view storylineId, const std::vector<XDREvent>& newEvents) {
    return m_impl->UpdateStoryline(storylineId, newEvents);
}

std::optional<Storyline> StorylineBuilder::GetStoryline(std::string_view storylineId) const {
    return m_impl->GetStoryline(storylineId);
}

std::vector<Storyline> StorylineBuilder::GetActiveStorylines() const {
    return m_impl->GetActiveStorylines();
}

std::string StorylineBuilder::GenerateNarrative(std::string_view storylineId) const {
    return m_impl->GenerateNarrative(storylineId);
}

uint32_t StorylineBuilder::GetActiveCount() const {
    return m_impl->GetActiveCount();
}

} // namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation

/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

/// @file IncidentScorer.cpp
/// @brief MITRE ATT&CK–based incident scoring with tactic coverage,
///        temporal ordering bonuses, cross-domain multipliers, and
///        severity classification.

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/IncidentScorer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation {

namespace {

constexpr const char* kLogPrefix = "[XDR::IncidentScorer]";

using Clock = std::chrono::system_clock;
using DB    = ShadowStrike::Database::DatabaseManager;
using DBErr = ShadowStrike::Database::DatabaseError;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Utils::Logger;

// ── Scoring weights ──────────────────────────────────────────────
constexpr double kTacticBaseWeight         = 5.0;
constexpr double kTechniqueWeight          = 3.0;
constexpr double kCrossDomainMultiplier    = 1.5;
constexpr double kTemporalOrderBonus       = 1.2;
constexpr double kKillChainProgressBonus   = 2.0;
constexpr double kHighSeverityEventBonus   = 1.0;

// ── Severity thresholds ──────────────────────────────────────────
constexpr double kCriticalThreshold  = 80.0;
constexpr double kHighThreshold      = 55.0;
constexpr double kMediumThreshold    = 30.0;
constexpr double kLowThreshold       = 10.0;

// ── Kill chain phase ordering (used for temporal bonus) ──────────
constexpr int PhaseOrder(StorylinePhase phase) {
    switch (phase) {
        case StorylinePhase::Reconnaissance:      return 1;
        case StorylinePhase::ResourceDevelopment:  return 2;
        case StorylinePhase::InitialAccess:        return 3;
        case StorylinePhase::Execution:            return 4;
        case StorylinePhase::Persistence:          return 5;
        case StorylinePhase::PrivilegeEscalation:  return 6;
        case StorylinePhase::DefenseEvasion:       return 7;
        case StorylinePhase::CredentialAccess:     return 8;
        case StorylinePhase::Discovery:            return 9;
        case StorylinePhase::LateralMovement:      return 10;
        case StorylinePhase::Collection:           return 11;
        case StorylinePhase::CommandAndControl:     return 12;
        case StorylinePhase::Exfiltration:         return 13;
        case StorylinePhase::Impact:               return 14;
        default:                                   return 0;
    }
}

StorylinePhase TacticToPhase(std::string_view tactic) {
    if (tactic == "Reconnaissance")         return StorylinePhase::Reconnaissance;
    if (tactic == "ResourceDevelopment")     return StorylinePhase::ResourceDevelopment;
    if (tactic == "InitialAccess")          return StorylinePhase::InitialAccess;
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

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS
// ============================================================================

class IncidentScorerImpl {
public:
    std::atomic<bool>       initialized{false};
    mutable std::shared_mutex mutex;

    // Custom technique severity overrides (technique_id → severity_boost)
    std::unordered_map<std::string, double> techniqueOverrides;

    // Score cache (storyline_id → score)
    std::unordered_map<std::string, IncidentScore> scoreCache;
    std::atomic<uint64_t>   totalScored{0};

    bool Initialize();
    void Shutdown();
    bool CreateSchema();

    IncidentScore ScoreStoryline(const Storyline& storyline);
    IncidentScore ScoreCorrelationMatch(const CorrelationMatch& match,
                                         const std::vector<XDREvent>& events);

    std::optional<IncidentScore> GetCachedScore(std::string_view storylineId) const;
    void SetTechniqueOverride(std::string_view techniqueId, double severityBoost);
    void ClearTechniqueOverrides();

    void PersistScore(const IncidentScore& score);
};

// ============================================================================
// SCHEMA
// ============================================================================

bool IncidentScorerImpl::CreateSchema() {
    auto& db = DB::Instance();
    DBErr err;

    constexpr std::string_view kSchema = R"SQL(
        CREATE TABLE IF NOT EXISTS xdr_incident_scores (
            storyline_id        TEXT PRIMARY KEY,
            raw_score           REAL NOT NULL,
            normalized_score    REAL NOT NULL,
            severity            INTEGER NOT NULL,
            tactic_score        REAL DEFAULT 0,
            technique_score     REAL DEFAULT 0,
            cross_domain_score  REAL DEFAULT 0,
            temporal_score      REAL DEFAULT 0,
            kill_chain_score    REAL DEFAULT 0,
            unique_tactics      INTEGER DEFAULT 0,
            unique_techniques   INTEGER DEFAULT 0,
            domains_involved    INTEGER DEFAULT 0,
            temporal_order_ok   INTEGER DEFAULT 0,
            explanation         TEXT DEFAULT '',
            scored_at_ms        INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_score_sev ON xdr_incident_scores(severity);
    )SQL";

    if (!db.Execute(kSchema, &err)) {
        Logger::Error("{} Failed to create scorer schema: {}",
                      kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }
    return true;
}

// ============================================================================
// INIT / SHUTDOWN
// ============================================================================

bool IncidentScorerImpl::Initialize() {
    if (initialized.load(std::memory_order_acquire)) return true;
    Logger::Info("{} Initializing incident scorer...", kLogPrefix);

    if (!CreateSchema()) return false;

    // Load default technique severity overrides for high-impact techniques
    techniqueOverrides["T1059"]   = 5.0;  // Command and Scripting Interpreter
    techniqueOverrides["T1053"]   = 4.0;  // Scheduled Task/Job
    techniqueOverrides["T1078"]   = 6.0;  // Valid Accounts (credential abuse)
    techniqueOverrides["T1486"]   = 10.0; // Data Encrypted for Impact (ransomware)
    techniqueOverrides["T1003"]   = 7.0;  // OS Credential Dumping
    techniqueOverrides["T1021"]   = 5.0;  // Remote Services (lateral movement)
    techniqueOverrides["T1071"]   = 4.0;  // Application Layer Protocol (C2)
    techniqueOverrides["T1547"]   = 5.0;  // Boot or Logon Autostart Execution
    techniqueOverrides["T1055"]   = 6.0;  // Process Injection
    techniqueOverrides["T1082"]   = 2.0;  // System Information Discovery

    initialized.store(true, std::memory_order_release);
    Logger::Info("{} Incident scorer initialized ({} technique overrides loaded)",
                 kLogPrefix, techniqueOverrides.size());
    return true;
}

void IncidentScorerImpl::Shutdown() {
    if (!initialized.exchange(false, std::memory_order_acq_rel)) return;
    std::unique_lock lock(mutex);
    Logger::Info("{} Incident scorer shut down (scored {} incidents total)",
                 kLogPrefix, totalScored.load(std::memory_order_relaxed));
    scoreCache.clear();
    techniqueOverrides.clear();
}

// ============================================================================
// SCORING LOGIC
// ============================================================================

IncidentScore IncidentScorerImpl::ScoreStoryline(const Storyline& sl) {
    IncidentScore score;
    score.storylineId = sl.storylineId;

    if (sl.nodes.empty()) {
        score.severity = IncidentSeverity::Info;
        return score;
    }

    // ── 1) Tactic coverage ──────────────────────────────────────
    std::unordered_set<int> tacticPhases;
    for (const auto& node : sl.nodes) {
        int order = PhaseOrder(node.phase);
        if (order > 0) tacticPhases.insert(order);
    }
    score.uniqueTactics = static_cast<uint32_t>(tacticPhases.size());
    score.tacticScore = tacticPhases.size() * kTacticBaseWeight;

    // ── 2) Technique diversity ──────────────────────────────────
    std::unordered_set<std::string> techniques;
    for (const auto& node : sl.nodes) {
        if (!node.mitreAttackId.empty())
            techniques.insert(node.mitreAttackId);
    }
    score.uniqueTechniques = static_cast<uint32_t>(techniques.size());
    score.techniqueScore = techniques.size() * kTechniqueWeight;

    // Add technique override bonuses
    {
        std::shared_lock lock(mutex);
        for (const auto& tech : techniques) {
            // Check exact match and parent technique (T1059.001 → T1059)
            auto it = techniqueOverrides.find(tech);
            if (it != techniqueOverrides.end()) {
                score.techniqueScore += it->second;
            }
            // Try parent technique
            auto dot = tech.find('.');
            if (dot != std::string::npos) {
                auto parent = tech.substr(0, dot);
                auto pit = techniqueOverrides.find(parent);
                if (pit != techniqueOverrides.end()) {
                    score.techniqueScore += pit->second * 0.5; // Half credit for sub-technique
                }
            }
        }
    }

    // ── 3) Cross-domain multiplier ──────────────────────────────
    std::unordered_set<int> domains;
    for (const auto& node : sl.nodes) {
        domains.insert(static_cast<int>(node.domain));
    }
    score.domainsInvolved = static_cast<uint32_t>(domains.size());
    score.crossDomainScore = 0.0;
    if (domains.size() > 1) {
        score.crossDomainScore = (domains.size() - 1) * kCrossDomainMultiplier *
                                  (score.tacticScore + score.techniqueScore);
        // Cross-domain is a multiplier effect: the more domains, the more suspicious
    }

    // ── 4) Temporal ordering bonus ──────────────────────────────
    // Check if attack phases happen in rough kill-chain order
    std::vector<int> phaseSequence;
    for (const auto& node : sl.nodes) {
        int order = PhaseOrder(node.phase);
        if (order > 0) phaseSequence.push_back(order);
    }

    // Count longest increasing subsequence as fraction of total
    size_t longestIncreasing = 0;
    if (!phaseSequence.empty()) {
        std::vector<size_t> dp(phaseSequence.size(), 1);
        for (size_t i = 1; i < phaseSequence.size(); ++i) {
            for (size_t j = 0; j < i; ++j) {
                if (phaseSequence[j] <= phaseSequence[i])
                    dp[i] = std::max(dp[i], dp[j] + 1);
            }
        }
        longestIncreasing = *std::max_element(dp.begin(), dp.end());
    }

    score.temporalOrderCorrect = false;
    score.temporalScore = 0.0;
    if (phaseSequence.size() >= 2) {
        double orderFraction = static_cast<double>(longestIncreasing) /
                               static_cast<double>(phaseSequence.size());
        if (orderFraction > 0.6) {
            score.temporalOrderCorrect = true;
            score.temporalScore = orderFraction * kTemporalOrderBonus *
                                  score.tacticScore;
        }
    }

    // ── 5) Kill chain progression bonus ─────────────────────────
    // If we see multiple consecutive kill-chain phases, add bonus
    score.killChainScore = 0.0;
    if (tacticPhases.size() >= 3) {
        // Find longest consecutive run
        std::vector<int> sorted(tacticPhases.begin(), tacticPhases.end());
        std::sort(sorted.begin(), sorted.end());
        int longestRun = 1, currentRun = 1;
        for (size_t i = 1; i < sorted.size(); ++i) {
            if (sorted[i] == sorted[i - 1] + 1) {
                ++currentRun;
                longestRun = std::max(longestRun, currentRun);
            } else {
                currentRun = 1;
            }
        }
        if (longestRun >= 3) {
            score.killChainScore = longestRun * kKillChainProgressBonus;
        }
    }

    // ── 6) Raw + normalized score ───────────────────────────────
    score.rawScore = score.tacticScore + score.techniqueScore +
                     score.crossDomainScore + score.temporalScore +
                     score.killChainScore;

    // Normalize to 0-100 scale using sigmoid-like mapping
    // This ensures the score saturates at 100 for extreme attack chains
    score.normalizedScore = 100.0 * (1.0 - std::exp(-score.rawScore / 60.0));
    score.normalizedScore = std::clamp(score.normalizedScore, 0.0, 100.0);

    // ── 7) Severity classification ──────────────────────────────
    if (score.normalizedScore >= kCriticalThreshold)
        score.severity = IncidentSeverity::Critical;
    else if (score.normalizedScore >= kHighThreshold)
        score.severity = IncidentSeverity::High;
    else if (score.normalizedScore >= kMediumThreshold)
        score.severity = IncidentSeverity::Medium;
    else if (score.normalizedScore >= kLowThreshold)
        score.severity = IncidentSeverity::Low;
    else
        score.severity = IncidentSeverity::Info;

    // ── 8) Explanation ──────────────────────────────────────────
    score.explanation = std::format(
        "Score={:.1f}/100 (raw={:.1f}): {} tactics ({:.1f}pts) + "
        "{} techniques ({:.1f}pts) + {} domains ({:.1f}pts) + "
        "temporal ({:.1f}pts) + kill-chain ({:.1f}pts). "
        "Temporal order {}. Severity={}.",
        score.normalizedScore, score.rawScore,
        score.uniqueTactics, score.tacticScore,
        score.uniqueTechniques, score.techniqueScore,
        score.domainsInvolved, score.crossDomainScore,
        score.temporalScore, score.killChainScore,
        score.temporalOrderCorrect ? "CORRECT" : "scattered",
        static_cast<int>(score.severity));

    // Cache and persist
    {
        std::unique_lock lock(mutex);
        scoreCache[score.storylineId] = score;
    }
    PersistScore(score);
    totalScored.fetch_add(1, std::memory_order_relaxed);

    Logger::Info("{} Scored storyline '{}': {:.1f}/100 ({} severity)",
                 kLogPrefix, score.storylineId, score.normalizedScore,
                 static_cast<int>(score.severity));

    return score;
}

IncidentScore IncidentScorerImpl::ScoreCorrelationMatch(
    const CorrelationMatch& match,
    const std::vector<XDREvent>& events)
{
    // Build a mini-storyline from the match + events
    Storyline sl;
    sl.storylineId = std::format("SCORE-{}", match.matchId);
    sl.title = match.ruleName;

    std::unordered_map<uint64_t, const XDREvent*> lookup;
    for (const auto& ev : events) lookup[ev.eventId] = &ev;

    for (auto eid : match.matchedEventIds) {
        auto it = lookup.find(eid);
        if (it == lookup.end()) continue;

        const auto& ev = *it->second;
        StorylineNode node;
        node.eventId       = ev.eventId;
        node.domain        = ev.domain;
        node.phase         = TacticToPhase(ev.mitreTactic);
        node.timestamp     = ev.timestamp;
        node.mitreAttackId = ev.mitreAttackId;
        sl.nodes.push_back(std::move(node));
    }

    return ScoreStoryline(sl);
}

// ============================================================================
// QUERIES & OVERRIDES
// ============================================================================

std::optional<IncidentScore> IncidentScorerImpl::GetCachedScore(
    std::string_view storylineId) const
{
    std::shared_lock lock(mutex);
    auto it = scoreCache.find(std::string(storylineId));
    if (it == scoreCache.end()) return std::nullopt;
    return it->second;
}

void IncidentScorerImpl::SetTechniqueOverride(
    std::string_view techniqueId, double severityBoost)
{
    std::unique_lock lock(mutex);
    techniqueOverrides[std::string(techniqueId)] = severityBoost;
    Logger::Info("{} Technique override set: {} → {:.1f}",
                 kLogPrefix, techniqueId, severityBoost);
}

void IncidentScorerImpl::ClearTechniqueOverrides() {
    std::unique_lock lock(mutex);
    techniqueOverrides.clear();
    Logger::Info("{} All technique overrides cleared", kLogPrefix);
}

// ============================================================================
// PERSISTENCE
// ============================================================================

void IncidentScorerImpl::PersistScore(const IncidentScore& score) {
    auto& db = DB::Instance();
    DBErr err;

    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now().time_since_epoch()).count();

    constexpr std::string_view kUpsert = R"SQL(
        INSERT INTO xdr_incident_scores
            (storyline_id, raw_score, normalized_score, severity,
             tactic_score, technique_score, cross_domain_score,
             temporal_score, kill_chain_score,
             unique_tactics, unique_techniques, domains_involved,
             temporal_order_ok, explanation, scored_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(storyline_id) DO UPDATE SET
            raw_score = excluded.raw_score,
            normalized_score = excluded.normalized_score,
            severity = excluded.severity,
            tactic_score = excluded.tactic_score,
            technique_score = excluded.technique_score,
            cross_domain_score = excluded.cross_domain_score,
            temporal_score = excluded.temporal_score,
            kill_chain_score = excluded.kill_chain_score,
            unique_tactics = excluded.unique_tactics,
            unique_techniques = excluded.unique_techniques,
            domains_involved = excluded.domains_involved,
            temporal_order_ok = excluded.temporal_order_ok,
            explanation = excluded.explanation,
            scored_at_ms = excluded.scored_at_ms
    )SQL";

    if (!db.ExecuteWithParams(kUpsert, &err,
            score.storylineId,
            score.rawScore, score.normalizedScore,
            static_cast<int>(score.severity),
            score.tacticScore, score.techniqueScore,
            score.crossDomainScore, score.temporalScore,
            score.killChainScore,
            static_cast<int>(score.uniqueTactics),
            static_cast<int>(score.uniqueTechniques),
            static_cast<int>(score.domainsInvolved),
            score.temporalOrderCorrect ? 1 : 0,
            score.explanation,
            nowMs)) {
        Logger::Warn("{} Failed to persist score for '{}': {}",
                     kLogPrefix, score.storylineId, SU::ToNarrow(err.message));
    }
}

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

IncidentScorer& IncidentScorer::Instance() {
    static IncidentScorer inst;
    return inst;
}

bool IncidentScorer::HasInstance() noexcept {
    return Instance().IsInitialized();
}

IncidentScorer::IncidentScorer()  : m_impl(std::make_unique<IncidentScorerImpl>()) {}
IncidentScorer::~IncidentScorer() { Shutdown(); }

bool IncidentScorer::Initialize() { return m_impl->Initialize(); }
void IncidentScorer::Shutdown()   { m_impl->Shutdown(); }
bool IncidentScorer::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

IncidentScore IncidentScorer::ScoreStoryline(const Storyline& storyline) {
    return m_impl->ScoreStoryline(storyline);
}

IncidentScore IncidentScorer::ScoreCorrelationMatch(
    const CorrelationMatch& match, const std::vector<XDREvent>& events) {
    return m_impl->ScoreCorrelationMatch(match, events);
}

std::optional<IncidentScore> IncidentScorer::GetCachedScore(
    std::string_view storylineId) const {
    return m_impl->GetCachedScore(storylineId);
}

void IncidentScorer::SetTechniqueOverride(
    std::string_view techniqueId, double severityBoost) {
    m_impl->SetTechniqueOverride(techniqueId, severityBoost);
}

void IncidentScorer::ClearTechniqueOverrides() {
    m_impl->ClearTechniqueOverrides();
}

} // namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation

/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

/// @file CorrelationEngine.cpp
/// @brief Cross-domain event correlation engine with sliding window,
///        background rule evaluation, and incident production.

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/CorrelationEngine.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/CorrelationRules.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <condition_variable>

namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation {

namespace {

constexpr const char* kLogPrefix = "[XDR::CorrelationEngine]";
constexpr uint32_t kDefaultWindowSec       = 900;   // 15 minutes
constexpr uint32_t kEvalIntervalMs         = 5000;  // Evaluate every 5 seconds
constexpr size_t   kMaxWindowEvents        = 100000; // Cap window to avoid OOM
constexpr size_t   kMaxActiveCorrelations  = 50000;

using Clock = std::chrono::system_clock;
using DB    = ShadowStrike::Database::DatabaseManager;
using DBErr = ShadowStrike::Database::DatabaseError;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Utils::Logger;

std::string GenerateMatchId() {
    static std::atomic<uint64_t> seq{0};
    auto now = Clock::now().time_since_epoch().count();
    return std::format("CMATCH-{:X}-{:04X}", now,
                       seq.fetch_add(1, std::memory_order_relaxed) & 0xFFFF);
}

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS
// ============================================================================

class CorrelationEngineImpl {
public:
    std::atomic<bool>       initialized{false};
    std::atomic<bool>       running{false};
    mutable std::shared_mutex mutex;

    // Sliding event window
    std::deque<XDREvent>    eventWindow;
    uint32_t                windowSec{kDefaultWindowSec};

    // Active correlation matches
    std::vector<CorrelationMatch> activeMatches;

    // Background evaluation thread
    std::jthread            evalThread;
    std::mutex              evalMutex;
    std::condition_variable_any evalCv;

    // Statistics
    std::atomic<uint64_t>   totalEventsIngested{0};
    std::atomic<uint64_t>   totalRulesEvaluated{0};
    std::atomic<uint64_t>   totalMatchesProduced{0};

    bool Initialize();
    void Shutdown();

    bool CreateSchema();
    bool IngestEvent(const XDREvent& event);
    void PruneWindow();
    void EvaluateCycle();
    void PersistMatch(const CorrelationMatch& match);

    void BackgroundLoop(std::stop_token stoken);

    std::vector<CorrelationMatch> GetActiveCorrelations() const;
    std::optional<CorrelationMatch> GetCorrelationById(std::string_view matchId) const;
    std::vector<CorrelationMatch> GetCorrelationsByRule(std::string_view ruleId) const;

    CorrelationStatistics GetStatistics() const;
};

// ============================================================================
// SCHEMA
// ============================================================================

bool CorrelationEngineImpl::CreateSchema() {
    auto& db = DB::Instance();
    DBErr err;

    constexpr std::string_view kSchema = R"SQL(
        CREATE TABLE IF NOT EXISTS xdr_correlation_matches (
            match_id            TEXT PRIMARY KEY,
            rule_id             TEXT NOT NULL,
            rule_name           TEXT NOT NULL,
            verdict             TEXT NOT NULL,
            confidence          INTEGER DEFAULT 0,
            first_event_time_ms INTEGER NOT NULL,
            last_event_time_ms  INTEGER NOT NULL,
            matched_event_ids   TEXT NOT NULL,
            linked_entity       TEXT DEFAULT '',
            link_dimension      TEXT DEFAULT 'SameUser',
            created_at_ms       INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_match_rule ON xdr_correlation_matches(rule_id);
        CREATE INDEX IF NOT EXISTS idx_xdr_match_time ON xdr_correlation_matches(created_at_ms);

        CREATE TABLE IF NOT EXISTS xdr_event_window_log (
            event_id        INTEGER PRIMARY KEY,
            domain          TEXT NOT NULL,
            timestamp_ms    INTEGER NOT NULL,
            severity        INTEGER DEFAULT 0,
            user_name       TEXT DEFAULT '',
            host_name       TEXT DEFAULT '',
            ip_address      TEXT DEFAULT '',
            mitre_attack_id TEXT DEFAULT '',
            mitre_tactic    TEXT DEFAULT '',
            source_module   TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_evlog_ts ON xdr_event_window_log(timestamp_ms);
    )SQL";

    if (!db.Execute(kSchema, &err)) {
        Logger::Error("{} Failed to create correlation engine schema: {}",
                      kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }
    return true;
}

// ============================================================================
// INIT / SHUTDOWN
// ============================================================================

bool CorrelationEngineImpl::Initialize() {
    if (initialized.load(std::memory_order_acquire)) return true;

    Logger::Info("{} Initializing correlation engine (window={}s, eval_interval={}ms)...",
                 kLogPrefix, windowSec, kEvalIntervalMs);

    if (!CreateSchema()) return false;

    initialized.store(true, std::memory_order_release);
    running.store(true, std::memory_order_release);

    // Start background evaluation thread
    evalThread = std::jthread([this](std::stop_token st) { BackgroundLoop(st); });

    Logger::Info("{} Correlation engine initialized successfully", kLogPrefix);
    return true;
}

void CorrelationEngineImpl::Shutdown() {
    if (!initialized.exchange(false, std::memory_order_acq_rel)) return;

    Logger::Info("{} Shutting down correlation engine...", kLogPrefix);
    running.store(false, std::memory_order_release);

    // Signal and join background thread
    evalCv.notify_all();
    if (evalThread.joinable()) {
        evalThread.request_stop();
        evalThread.join();
    }

    {
        std::unique_lock lock(mutex);
        eventWindow.clear();
        activeMatches.clear();
    }

    Logger::Info("{} Correlation engine shut down (ingested={}, matches={})",
                 kLogPrefix,
                 totalEventsIngested.load(std::memory_order_relaxed),
                 totalMatchesProduced.load(std::memory_order_relaxed));
}

// ============================================================================
// EVENT INGESTION
// ============================================================================

bool CorrelationEngineImpl::IngestEvent(const XDREvent& event) {
    if (!initialized.load(std::memory_order_acquire)) return false;

    {
        std::unique_lock lock(mutex);

        // Enforce window cap to prevent OOM
        if (eventWindow.size() >= kMaxWindowEvents) {
            eventWindow.pop_front();
        }

        eventWindow.push_back(event);
    }

    totalEventsIngested.fetch_add(1, std::memory_order_relaxed);

    // Log high-severity events for audit
    if (event.severity >= 70) {
        Logger::Debug("{} High-severity event ingested: domain={}, technique={}, user={}, host={}",
                      kLogPrefix,
                      static_cast<int>(event.domain),
                      event.mitreAttackId,
                      event.userName,
                      event.hostName);
    }

    // Notify eval thread of new data
    evalCv.notify_one();
    return true;
}

// ============================================================================
// WINDOW PRUNING
// ============================================================================

void CorrelationEngineImpl::PruneWindow() {
    std::unique_lock lock(mutex);
    if (eventWindow.empty()) return;

    auto cutoff = Clock::now() - std::chrono::seconds(windowSec);
    size_t pruned = 0;

    while (!eventWindow.empty() && eventWindow.front().timestamp < cutoff) {
        eventWindow.pop_front();
        ++pruned;
    }

    if (pruned > 0) {
        Logger::Debug("{} Pruned {} expired events from window (remaining={})",
                      kLogPrefix, pruned, eventWindow.size());
    }
}

// ============================================================================
// EVALUATION CYCLE
// ============================================================================

void CorrelationEngineImpl::EvaluateCycle() {
    // Copy current window snapshot for evaluation
    std::vector<XDREvent> windowSnapshot;
    {
        std::shared_lock lock(mutex);
        windowSnapshot.assign(eventWindow.begin(), eventWindow.end());
    }

    if (windowSnapshot.empty()) return;

    // Run rules
    auto& rulesEngine = CorrelationRules::Instance();
    if (!rulesEngine.IsInitialized()) return;

    auto matches = rulesEngine.Evaluate(windowSnapshot);
    totalRulesEvaluated.fetch_add(rulesEngine.GetRuleCount(), std::memory_order_relaxed);

    if (matches.empty()) return;

    // Deduplicate: skip matches whose event-id set is already in activeMatches
    std::vector<CorrelationMatch> newMatches;
    {
        std::shared_lock lock(mutex);
        for (auto& m : matches) {
            bool isDuplicate = false;
            for (const auto& existing : activeMatches) {
                if (existing.ruleId == m.ruleId &&
                    existing.matchedEventIds == m.matchedEventIds) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) newMatches.push_back(std::move(m));
        }
    }

    if (newMatches.empty()) return;

    // Add new matches
    {
        std::unique_lock lock(mutex);
        for (auto& m : newMatches) {
            // Cap active matches
            if (activeMatches.size() >= kMaxActiveCorrelations) {
                activeMatches.erase(activeMatches.begin());
            }

            PersistMatch(m);
            activeMatches.push_back(std::move(m));
            totalMatchesProduced.fetch_add(1, std::memory_order_relaxed);
        }
    }

    Logger::Info("{} Evaluation cycle produced {} new correlation matches",
                 kLogPrefix, newMatches.size());
}

// ============================================================================
// PERSISTENCE
// ============================================================================

void CorrelationEngineImpl::PersistMatch(const CorrelationMatch& match) {
    auto& db = DB::Instance();
    DBErr err;

    // Serialize event IDs as comma-separated
    std::string eventIds;
    for (size_t i = 0; i < match.matchedEventIds.size(); ++i) {
        if (i > 0) eventIds += ',';
        eventIds += std::to_string(match.matchedEventIds[i]);
    }

    auto firstMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        match.firstEventTime.time_since_epoch()).count();
    auto lastMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        match.lastEventTime.time_since_epoch()).count();
    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now().time_since_epoch()).count();

    constexpr std::string_view kInsert = R"SQL(
        INSERT OR IGNORE INTO xdr_correlation_matches
            (match_id, rule_id, rule_name, verdict, confidence,
             first_event_time_ms, last_event_time_ms, matched_event_ids,
             linked_entity, link_dimension, created_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )SQL";

    // Determine verdict string
    std::string_view verdictStr;
    switch (match.verdict) {
        case CorrelationVerdict::Benign:        verdictStr = "Benign"; break;
        case CorrelationVerdict::Informational: verdictStr = "Informational"; break;
        case CorrelationVerdict::Suspicious:    verdictStr = "Suspicious"; break;
        case CorrelationVerdict::Malicious:     verdictStr = "Malicious"; break;
        case CorrelationVerdict::Critical:      verdictStr = "Critical"; break;
    }

    // Determine link dimension string
    std::string_view linkStr;
    switch (match.linkDimension) {
        case EntityLink::SameUser:      linkStr = "SameUser"; break;
        case EntityLink::SameHost:      linkStr = "SameHost"; break;
        case EntityLink::SameIP:        linkStr = "SameIP"; break;
        case EntityLink::SameProcess:   linkStr = "SameProcess"; break;
        case EntityLink::SameFileHash:  linkStr = "SameFileHash"; break;
        case EntityLink::SameSession:   linkStr = "SameSession"; break;
    }

    if (!db.ExecuteWithParams(kInsert, &err,
            match.matchId,
            match.ruleId,
            match.ruleName,
            std::string(verdictStr),
            static_cast<int>(match.confidence),
            firstMs, lastMs,
            eventIds,
            match.linkedEntity,
            std::string(linkStr),
            nowMs)) {
        Logger::Warn("{} Failed to persist match '{}': {}",
                     kLogPrefix, match.matchId, SU::ToNarrow(err.message));
    }
}

// ============================================================================
// BACKGROUND LOOP
// ============================================================================

void CorrelationEngineImpl::BackgroundLoop(std::stop_token stoken) {
    Logger::Info("{} Background evaluation thread started", kLogPrefix);

    while (!stoken.stop_requested() && running.load(std::memory_order_acquire)) {
        {
            std::unique_lock lock(evalMutex);
            evalCv.wait_for(lock, std::chrono::milliseconds(kEvalIntervalMs),
                            [&] { return stoken.stop_requested() ||
                                         !running.load(std::memory_order_acquire); });
        }

        if (stoken.stop_requested() || !running.load(std::memory_order_acquire))
            break;

        PruneWindow();
        EvaluateCycle();
    }

    Logger::Info("{} Background evaluation thread exiting", kLogPrefix);
}

// ============================================================================
// QUERIES
// ============================================================================

std::vector<CorrelationMatch> CorrelationEngineImpl::GetActiveCorrelations() const {
    std::shared_lock lock(mutex);
    return activeMatches;
}

std::optional<CorrelationMatch> CorrelationEngineImpl::GetCorrelationById(
    std::string_view matchId) const
{
    std::shared_lock lock(mutex);
    for (const auto& m : activeMatches) {
        if (m.matchId == matchId) return m;
    }
    return std::nullopt;
}

std::vector<CorrelationMatch> CorrelationEngineImpl::GetCorrelationsByRule(
    std::string_view ruleId) const
{
    std::shared_lock lock(mutex);
    std::vector<CorrelationMatch> result;
    for (const auto& m : activeMatches) {
        if (m.ruleId == ruleId) result.push_back(m);
    }
    return result;
}

CorrelationStatistics CorrelationEngineImpl::GetStatistics() const {
    CorrelationStatistics stats;
    stats.totalEventsIngested  = totalEventsIngested.load(std::memory_order_relaxed);
    stats.totalRulesEvaluated  = totalRulesEvaluated.load(std::memory_order_relaxed);
    stats.totalMatchesProduced = totalMatchesProduced.load(std::memory_order_relaxed);

    {
        std::shared_lock lock(mutex);
        stats.activeWindowEvents    = eventWindow.size();
        stats.activeStorylineCount  = 0; // populated by StorylineBuilder
    }

    if (CorrelationRules::Instance().IsInitialized()) {
        stats.activeRuleCount = CorrelationRules::Instance().GetRuleCount();
    }

    return stats;
}

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

CorrelationEngine& CorrelationEngine::Instance() {
    static CorrelationEngine inst;
    return inst;
}

bool CorrelationEngine::HasInstance() noexcept {
    return Instance().IsInitialized();
}

CorrelationEngine::CorrelationEngine()  : m_impl(std::make_unique<CorrelationEngineImpl>()) {}
CorrelationEngine::~CorrelationEngine() { Shutdown(); }

bool CorrelationEngine::Initialize() { return m_impl->Initialize(); }
void CorrelationEngine::Shutdown()   { m_impl->Shutdown(); }
bool CorrelationEngine::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

bool CorrelationEngine::IngestEvent(const XDREvent& event) {
    return m_impl->IngestEvent(event);
}

std::vector<CorrelationMatch> CorrelationEngine::GetActiveCorrelations() const {
    return m_impl->GetActiveCorrelations();
}

std::optional<CorrelationMatch> CorrelationEngine::GetCorrelationById(
    std::string_view matchId) const {
    return m_impl->GetCorrelationById(matchId);
}

std::vector<CorrelationMatch> CorrelationEngine::GetCorrelationsByRule(
    std::string_view ruleId) const {
    return m_impl->GetCorrelationsByRule(ruleId);
}

void CorrelationEngine::SetTimeWindowSeconds(uint32_t seconds) {
    if (seconds == 0 || seconds > 86400) {
        Logger::Warn("{} Invalid window seconds {} (must be 1-86400)", kLogPrefix, seconds);
        return;
    }
    m_impl->windowSec = seconds;
    Logger::Info("{} Sliding window set to {} seconds", kLogPrefix, seconds);
}

uint32_t CorrelationEngine::GetTimeWindowSeconds() const noexcept {
    return m_impl->windowSec;
}

void CorrelationEngine::EvaluateNow() {
    m_impl->EvaluateCycle();
}

CorrelationStatistics CorrelationEngine::GetStatistics() const {
    return m_impl->GetStatistics();
}

} // namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation

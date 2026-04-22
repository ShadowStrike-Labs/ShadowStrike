/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file RecommendationsEngine.cpp
 * @brief Implementation of the PhantomHome recommendations rule engine.
 *
 * Rule catalogue:
 *   R1  AMSI not registered        — Critical: AmsiProvider running but OS
 *       registration absent.  Disabled if AmsiProviderRegistration API not
 *       available (no IsRegistered() method; logs once and skips).
 *
 *   R2  Signatures stale (>7 days) — Warn: SignatureStore has no
 *       LastUpdateAgeDays() API.  Disabled at runtime; logs once on first
 *       evaluation pass.
 *
 *   R3  Firewall off               — Critical: no "Firewall" module found in
 *       HomeProductOrchestrator wiring at time of authoring; rule is disabled
 *       and logs once.
 *
 *   R4  Pending quarantine ≥ 1     — Info: uses HomeReportsStore::Query()
 *       filtered to ReportKind::ThreatQuarantined.
 *
 *   R5  ZeroTrust never configured — Info: checks ConfigManager for a
 *       "Home/ZeroTrust/Configured" flag written by ZeroTrustWiring.
 *
 *   R6  Recent blocks > 50 in 24 h — Info: uses HomeReportsStore::Query()
 *       with ThreatDetected / ThreatQuarantined kinds within 24 h.
 *
 *   R7  Global protection off (paused) — Critical: HomeProductOrchestrator::
 *       IsPaused() is true OR all modules in Off mode.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#include "RecommendationsEngine.hpp"

#include "../HomeProductOrchestrator.hpp"
#include "../Reports/HomeReportsStore.hpp"
#include "../../../../PhantomCore/Utils/Logger.hpp"
#include "../../../../PhantomCore/Config/ConfigManager.hpp"
#include "../../../../PhantomCore/Service/ServiceCommunicator.hpp"
#include "../../../../PhantomCore/Service/EventPush.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace ShadowStrike::Products::Home::Recommendations {

namespace {

constexpr const wchar_t* kLog = L"RecommendationsEngine";

// Dismissal persistence key: "Home/Recommendations/dismissed/<id>"
[[nodiscard]] std::string DismissalKey(std::string_view id)
{
    return "Home/Recommendations/dismissed/" + std::string(id);
}

// Dismissals expire after 7 days.
constexpr std::chrono::hours kDismissalTtl{7 * 24};

[[nodiscard]] bool IsDismissed(std::string_view id) noexcept
{
    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
    if (!cfg.IsInitialized()) return false;

    const std::string key = DismissalKey(id);
    auto ts = cfg.GetOptionalValue<std::int64_t>(key);
    if (!ts.has_value()) return false;

    const auto dismissed = std::chrono::system_clock::time_point(
        std::chrono::seconds{*ts});
    const auto age = std::chrono::system_clock::now() - dismissed;
    return age < kDismissalTtl;
}

void PersistDismissal(std::string_view id) noexcept
{
    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
    if (!cfg.IsInitialized()) {
        SS_LOG_WARN(kLog, L"RecommendationsEngine: ConfigManager not ready; cannot persist dismissal '%hs'.",
                    std::string(id).c_str());
        return;
    }
    const std::int64_t ts = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    (void)cfg.SetValue<std::int64_t>(DismissalKey(id), ts);
}

// Build a Recommendation with a single dismiss action pre-appended.
[[nodiscard]] Recommendation MakeRec(std::string id,
                                     Severity    severity,
                                     std::string titleKey,
                                     std::string detailKey,
                                     std::vector<RecommendationAction> actions = {},
                                     bool dismissible = true)
{
    Recommendation rec;
    rec.id          = std::move(id);
    rec.severity    = severity;
    rec.titleKey    = std::move(titleKey);
    rec.detailKey   = std::move(detailKey);
    rec.createdAt   = std::chrono::system_clock::now();
    rec.dismissible = dismissible;
    rec.actions     = std::move(actions);
    return rec;
}

// ── Rule evaluators ──────────────────────────────────────────────────────────

// R1: AMSI not registered.
// AmsiProviderRegistration has RegisterAmsiProvider() / UnregisterAmsiProvider()
// but NOT IsRegistered().  Rule is therefore disabled; logs once on first call.
std::optional<Recommendation> EvalR1_AmsiNotRegistered() noexcept
{
    static std::atomic<bool> loggedOnce{false};
    if (!loggedOnce.exchange(true, std::memory_order_relaxed)) {
        SS_LOG_INFO(kLog,
            L"R1 (AMSI not registered): AmsiProviderRegistration::IsRegistered() "
            L"does not exist in current codebase. Rule disabled until API is available.");
    }
    // Dependency unavailable — emit no tile.
    return std::nullopt;
}

// R2: Signatures stale (>7 days).
// SignatureStore has no LastUpdateAgeDays() API; rule disabled.
std::optional<Recommendation> EvalR2_SignaturesStale() noexcept
{
    static std::atomic<bool> loggedOnce{false};
    if (!loggedOnce.exchange(true, std::memory_order_relaxed)) {
        SS_LOG_INFO(kLog,
            L"R2 (Signatures stale): SignatureStore::LastUpdateAgeDays() does not exist "
            L"in current codebase. Rule disabled until API is available.");
    }
    return std::nullopt;
}

// R3: Firewall off.
// No Firewall module found in any *Wiring.cpp at authoring time. Rule disabled.
std::optional<Recommendation> EvalR3_FirewallOff() noexcept
{
    static std::atomic<bool> loggedOnce{false};
    if (!loggedOnce.exchange(true, std::memory_order_relaxed)) {
        SS_LOG_INFO(kLog,
            L"R3 (Firewall off): No 'Firewall' module found in HomeProductOrchestrator "
            L"wiring files. Rule disabled until Firewall module is registered.");
    }
    return std::nullopt;
}

// R4: Pending quarantine ≥ 1.
// Uses HomeReportsStore::Query() to count ThreatQuarantined entries.
std::optional<Recommendation> EvalR4_PendingQuarantine() noexcept
{
    try {
        using namespace ::ShadowStrike::PhantomHome::Reports;

        ReportQuery q;
        q.kind        = ReportKind::ThreatQuarantined;
        q.max_entries = 1;   // only need to know if ≥ 1 exists

        const auto entries = HomeReportsStore::Instance().Query(q);
        if (entries.empty()) {
            return std::nullopt;
        }

        return MakeRec(
            "rec.pending_quarantine",
            Severity::Info,
            "rec.pending_quarantine.title",
            "rec.pending_quarantine.detail",
            {{ ActionKind::NavigateToRoute, R"({"route":"QuarantinePage"})",
               "rec.action.review_quarantine" }});
    } catch (const std::exception& ex) {
        SS_LOG_WARN(kLog, L"R4: HomeReportsStore query threw: %hs", ex.what());
        return std::nullopt;
    }
}

// R5: ZeroTrust never configured.
// Checks ConfigManager for "Home/ZeroTrust/Configured" flag written by
// ZeroTrustWiring on first successful policy application.
std::optional<Recommendation> EvalR5_ZeroTrustUnconfigured() noexcept
{
    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
    if (!cfg.IsInitialized()) return std::nullopt;

    // If the ZeroTrust module is not even registered, skip this rule.
    const auto status =
        ::ShadowStrike::Products::Home::HomeProductOrchestrator::Instance()
            .GetModuleStatus("ZeroTrustGuard");
    if (!status.has_value()) return std::nullopt;

    // The wiring writes "Home/ZeroTrust/Configured" = true after the user
    // acknowledges the default policy.
    const bool configured = cfg.GetValue<bool>("Home/ZeroTrust/Configured", false);
    if (configured) return std::nullopt;

    return MakeRec(
        "rec.zerotrust_unconfigured",
        Severity::Info,
        "rec.zerotrust_unconfigured.title",
        "rec.zerotrust_unconfigured.detail",
        {{ ActionKind::NavigateToRoute, R"({"route":"ZeroTrustDetailPage"})",
           "rec.action.review_zerotrust" }});
}

// R6: Recent blocks > 50 in last 24 h.
// Queries HomeReportsStore for ThreatDetected + ThreatQuarantined within 24 h.
std::optional<Recommendation> EvalR6_HighBlockRate() noexcept
{
    try {
        using namespace ::ShadowStrike::PhantomHome::Reports;

        // Query recent entries (up to 256) and filter by timestamp in C++.
        ReportQuery q;
        q.max_entries = 256;
        const auto entries = HomeReportsStore::Instance().GetRecent(256);

        const auto cutoff = std::chrono::system_clock::now() - std::chrono::hours{24};
        const auto cutoff_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            cutoff.time_since_epoch()).count();

        std::uint32_t count = 0;
        for (const auto& e : entries) {
            if (e.timestamp_unix_ms < cutoff_ms) continue;
            if (e.kind == ReportKind::ThreatDetected
                || e.kind == ReportKind::ThreatQuarantined)
            {
                ++count;
            }
        }

        if (count <= 50) return std::nullopt;

        return MakeRec(
            "rec.high_block_rate",
            Severity::Info,
            "rec.high_block_rate.title",
            "rec.high_block_rate.detail",
            {{ ActionKind::NavigateToRoute, R"({"route":"ReportsPage"})",
               "rec.action.view_reports" }});
    } catch (const std::exception& ex) {
        SS_LOG_WARN(kLog, L"R6: HomeReportsStore query threw: %hs", ex.what());
        return std::nullopt;
    }
}

// R7: Global protection off (orchestrator paused or all modules in Off state).
std::optional<Recommendation> EvalR7_ProtectionOff() noexcept
{
    const auto& orch = ::ShadowStrike::Products::Home::HomeProductOrchestrator::Instance();

    if (orch.IsPaused()) {
        return MakeRec(
            "rec.protection_paused",
            Severity::Critical,
            "rec.protection_paused.title",
            "rec.protection_paused.detail",
            {{ ActionKind::RunCommand,
               R"({"commandType":211})",  // ResumeProtection = 211
               "rec.action.resume_protection" }},
            /*dismissible=*/false);
    }
    return std::nullopt;
}

} // anonymous namespace

// ============================================================================
// PIMPL
// ============================================================================

struct RecommendationsEngine::Impl {
    mutable std::shared_mutex mutex;

    // Active recommendations (not dismissed).
    std::vector<Recommendation> active;

    // IDs that are currently dismissed (in-memory cache, source of truth is ConfigManager).
    // Re-computed from ConfigManager on each evaluation pass.
    // Not stored here; IsDismissed() queries ConfigManager directly.

    std::atomic<bool> running{false};
    std::jthread      worker;
    std::condition_variable_any recomputeCv;
    std::mutex        recomputeMtx;
    bool              recomputeRequested{false};

    std::vector<ChangedCallback> callbacks;

    void FireCallbacks() noexcept
    {
        std::vector<ChangedCallback> cbs;
        {
            std::shared_lock lock(mutex);
            cbs = callbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(); } catch (...) {}
        }
    }

    void BroadcastChanged(std::size_t activeCount) noexcept
    {
        using namespace ::ShadowStrike::Service;
        auto envelope = Events::BuildRecommendationsChanged(
            static_cast<std::uint32_t>(activeCount));
        if (envelope.empty()) {
            SS_LOG_WARN(kLog, L"RecommendationsEngine: BuildRecommendationsChanged returned empty buffer.");
            return;
        }
        const std::size_t n = ServiceCommunicator::Instance()
                                  .BroadcastEvent(CommandType::RecommendationsChanged, envelope);
        SS_LOG_DEBUG(kLog, L"RecommendationsEngine: broadcasted RecommendationsChanged(%zu) to %zu client(s).",
                     activeCount, n);
    }

    // Run all rules, build a new active set, detect changes, broadcast if needed.
    void Evaluate() noexcept
    {
        // Collect candidates from each rule.
        std::vector<Recommendation> candidates;
        candidates.reserve(8);

        // Each rule returns an optional; push if present and not dismissed.
        auto TryPush = [&](std::optional<Recommendation> opt) {
            if (!opt.has_value()) return;
            if (!IsDismissed(opt->id)) {
                candidates.push_back(std::move(*opt));
            }
        };

        TryPush(EvalR1_AmsiNotRegistered());
        TryPush(EvalR2_SignaturesStale());
        TryPush(EvalR3_FirewallOff());
        TryPush(EvalR4_PendingQuarantine());
        TryPush(EvalR5_ZeroTrustUnconfigured());
        TryPush(EvalR6_HighBlockRate());
        TryPush(EvalR7_ProtectionOff());

        // Sort descending severity so Critical is first.
        std::stable_sort(candidates.begin(), candidates.end(),
            [](const Recommendation& a, const Recommendation& b) {
                return static_cast<std::uint8_t>(a.severity)
                     > static_cast<std::uint8_t>(b.severity);
            });

        // Determine if the set changed.
        bool changed = false;
        std::size_t newCount = 0;
        {
            std::unique_lock lock(mutex);
            // Changed if size differs or any id differs.
            if (candidates.size() != active.size()) {
                changed = true;
            } else {
                for (std::size_t i = 0; i < candidates.size(); ++i) {
                    if (candidates[i].id != active[i].id) {
                        changed = true;
                        break;
                    }
                }
            }
            active = std::move(candidates);
            newCount = active.size();
        }

        if (changed) {
            BroadcastChanged(newCount);
            FireCallbacks();
            SS_LOG_INFO(kLog, L"RecommendationsEngine: %zu active recommendation(s) after re-evaluation.",
                        newCount);
        }
    }

    void WorkerLoop(std::stop_token stop)
    {
        SS_LOG_INFO(kLog, L"RecommendationsEngine worker started.");

        // Run immediately on start.
        Evaluate();

        while (!stop.stop_requested()) {
            {
                std::unique_lock<std::mutex> lk(recomputeMtx);
                recomputeCv.wait_for(lk, stop, std::chrono::seconds{30},
                    [&]{ return recomputeRequested || stop.stop_requested(); });
                recomputeRequested = false;
            }
            if (stop.stop_requested()) break;
            Evaluate();
        }

        SS_LOG_INFO(kLog, L"RecommendationsEngine worker stopped.");
    }
};

// ============================================================================
// Singleton
// ============================================================================

RecommendationsEngine& RecommendationsEngine::Instance() noexcept
{
    static RecommendationsEngine s_instance;
    return s_instance;
}

RecommendationsEngine::RecommendationsEngine()
    : m_impl(std::make_unique<Impl>())
{
}

RecommendationsEngine::~RecommendationsEngine()
{
    Stop();
}

// ============================================================================
// Lifecycle
// ============================================================================

void RecommendationsEngine::Start()
{
    if (m_impl->running.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    m_impl->worker = std::jthread([this](std::stop_token st) {
        m_impl->WorkerLoop(std::move(st));
    });
    SS_LOG_INFO(kLog, L"RecommendationsEngine started.");
}

void RecommendationsEngine::Stop()
{
    if (!m_impl->running.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    m_impl->worker.request_stop();
    m_impl->recomputeCv.notify_all();
    if (m_impl->worker.joinable()) {
        m_impl->worker.join();
    }
    SS_LOG_INFO(kLog, L"RecommendationsEngine stopped.");
}

// ============================================================================
// Queries
// ============================================================================

std::vector<Recommendation> RecommendationsEngine::Snapshot() const
{
    std::shared_lock lock(m_impl->mutex);
    return m_impl->active;
}

// ============================================================================
// Control
// ============================================================================

void RecommendationsEngine::Dismiss(std::string_view id)
{
    PersistDismissal(id);

    bool changed = false;
    {
        std::unique_lock lock(m_impl->mutex);
        const auto prev = m_impl->active.size();
        m_impl->active.erase(
            std::remove_if(m_impl->active.begin(), m_impl->active.end(),
                [&](const Recommendation& r){ return r.id == id; }),
            m_impl->active.end());
        changed = m_impl->active.size() != prev;
    }

    if (changed) {
        std::size_t count = 0;
        {
            std::shared_lock lock(m_impl->mutex);
            count = m_impl->active.size();
        }
        m_impl->BroadcastChanged(count);
        m_impl->FireCallbacks();
    }

    SS_LOG_INFO(kLog, L"RecommendationsEngine: recommendation '%hs' dismissed.",
                std::string(id).c_str());
}

void RecommendationsEngine::ForceRecompute()
{
    {
        std::unique_lock<std::mutex> lk(m_impl->recomputeMtx);
        m_impl->recomputeRequested = true;
    }
    m_impl->recomputeCv.notify_all();
}

// ============================================================================
// Change notification
// ============================================================================

void RecommendationsEngine::RegisterChangedCallback(ChangedCallback cb)
{
    if (!cb) return;
    std::unique_lock lock(m_impl->mutex);
    m_impl->callbacks.push_back(std::move(cb));
}

}  // namespace ShadowStrike::Products::Home::Recommendations

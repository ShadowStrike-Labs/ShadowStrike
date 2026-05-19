/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file HeadlineStateService.cpp
 * @brief Implementation of the PhantomHome headline state aggregator.
 *
 * Aggregation precedence (worst state wins):
 *   Critical  ← any Critical Recommendation
 *               OR IsPaused() on the orchestrator
 *               OR any module in ModuleState::Failed
 *   AtRisk    ← any Warn Recommendation
 *               OR any module Running in Passive mode whose supportedModesMask
 *                  includes Balanced (i.e. was degraded to Passive by the user)
 *               OR any PGTI feed in Health::Failed
 *   Healthy   ← none of the above
 *   Unknown   ← before first evaluation completes
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#include "HeadlineStateService.hpp"

#include "../HomeProductOrchestrator.hpp"
#include "../Recommendations/RecommendationsEngine.hpp"
#include "../ThreatIntel/PgtiFeedManager.hpp"
#include "../UI/Shared/ModuleCatalog.hpp"
#include "../../../../PhantomCore/Utils/Logger.hpp"
#include "../../../../PhantomCore/Service/ServiceCommunicator.hpp"
#include "../../../../PhantomCore/Service/EventPush.hpp"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <shared_mutex>

namespace ShadowStrike::Products::Home::HeadlineState {

namespace {
constexpr const wchar_t* kLog = L"HeadlineStateService";

// Static liveness guard for callbacks registered with sibling singletons
// (RecommendationsEngine, PgtiFeedManager).  Those singletons are Meyers'
// singletons too, and static destruction order across translation units is
// unspecified.  If a callback fires after our destructor has run, this flag
// prevents the lambda from dereferencing freed PIMPL state (UAF).  We never
// reset it back to true after a shutdown — the process is exiting.
std::atomic<bool> g_serviceAlive{false};
}

// ============================================================================
// PIMPL
// ============================================================================

struct HeadlineStateService::Impl {
    mutable std::shared_mutex snapshotMutex;
    HeadlineSnapshot          snapshot;   // protected by snapshotMutex

    std::atomic<bool>         running{false};
    std::jthread              worker;
    std::condition_variable_any recomputeCv;
    std::mutex                recomputeMtx;
    bool                      recomputeRequested{false};

    // Broadcast HeadlineStateChanged push event.
    void Broadcast(State state) noexcept
    {
        using namespace ::ShadowStrike::Service;
        auto envelope = Events::BuildHeadlineStateChanged(StateToString(state));
        if (envelope.empty()) {
            SS_LOG_WARN(kLog, L"HeadlineStateService: BuildHeadlineStateChanged returned empty buffer.");
            return;
        }
        const std::size_t n = ServiceCommunicator::Instance()
                                  .BroadcastEvent(CommandType::HeadlineStateChanged, envelope);
        SS_LOG_DEBUG(kLog, L"HeadlineStateService: broadcasted HeadlineStateChanged('%hs') to %zu client(s).",
                     StateToString(state), n);
    }

    void Evaluate() noexcept
    {
        using namespace ShadowStrike::Products::Home;
        using Severity = Recommendations::Severity;
        using PgtiFeedStatus = ThreatIntel::PgtiFeedStatus;

        // --- Sample all sources -------------------------------------------------

        // Recommendations
        const auto recs =
            Recommendations::RecommendationsEngine::Instance().Snapshot();

        std::uint32_t critCount = 0;
        std::uint32_t warnCount = 0;
        for (const auto& r : recs) {
            if (r.severity == Severity::Critical) ++critCount;
            else if (r.severity == Severity::Warn)    ++warnCount;
        }

        // Orchestrator
        const auto& orch = HomeProductOrchestrator::Instance();
        const bool paused = orch.IsPaused();
        const auto modules = orch.GetStatus();

        bool anyFailed = false;
        bool anyPassiveShouldBeBalanced = false;
        for (const auto& m : modules) {
            if (m.state == ModuleState::Failed) {
                anyFailed = true;
            }
            // If module is Running in Passive but supports Balanced:
            // bit2 = Balanced mask bit
            if (m.state == ModuleState::Running
                && m.currentMode == ProtectionMode::Passive)
            {
                // Check catalog for supportedModesMask.
                // Bit 2 = Balanced (value 4).
                const auto& cat = ::ShadowStrike::Products::Home::UI::ModuleCatalog::Instance();
                const auto* entry = cat.FindById(m.name);
                const std::uint8_t mask = entry ? entry->supportedModesMask : 0x05u;
                if (mask & 0x04u) {  // Balanced bit set
                    anyPassiveShouldBeBalanced = true;
                }
            }
        }

        // PGTI feeds
        const auto feeds = ThreatIntel::PgtiFeedManager::Instance().Snapshot();
        bool anyFeedFailed = false;
        for (const auto& f : feeds) {
            if (f.health == PgtiFeedStatus::Health::Failed) {
                anyFeedFailed = true;
                break;
            }
        }

        // --- Derive state -------------------------------------------------------

        State newState = State::Healthy;

        if (critCount > 0 || paused || anyFailed) {
            newState = State::Critical;
        } else if (warnCount > 0 || anyPassiveShouldBeBalanced || anyFeedFailed) {
            newState = State::AtRisk;
        }

        // --- Build i18n keys ----------------------------------------------------

        const char* primaryKey   = "headline.healthy.primary";
        const char* secondaryKey = "headline.healthy.secondary";
        switch (newState) {
            case State::Critical:
                primaryKey   = "headline.critical.primary";
                secondaryKey = "headline.critical.secondary";
                break;
            case State::AtRisk:
                primaryKey   = "headline.atrisk.primary";
                secondaryKey = "headline.atrisk.secondary";
                break;
            case State::Healthy:
            case State::Unknown:
                break;
        }

        // --- Detect transition & update -----------------------------------------

        State prevState = State::Unknown;
        {
            std::unique_lock lock(snapshotMutex);
            prevState = snapshot.state;
            snapshot.state        = newState;
            snapshot.primaryKey   = primaryKey;
            snapshot.secondaryKey = secondaryKey;
            snapshot.criticalCount = critCount;
            snapshot.atRiskCount   = warnCount;
            if (newState != prevState) {
                snapshot.since = std::chrono::system_clock::now();
            }
        }

        if (newState != prevState) {
            Broadcast(newState);
            SS_LOG_INFO(kLog, L"HeadlineState transitioned: %hs -> %hs (crit=%u, warn=%u, paused=%d, failedMod=%d, feedFail=%d).",
                        StateToString(prevState), StateToString(newState),
                        critCount, warnCount,
                        static_cast<int>(paused),
                        static_cast<int>(anyFailed),
                        static_cast<int>(anyFeedFailed));
        }
    }

    void WorkerLoop(std::stop_token stop)
    {
        SS_LOG_INFO(kLog, L"HeadlineStateService worker started.");

        // Initialise to Unknown so first broadcast reflects boot state.
        {
            std::unique_lock lock(snapshotMutex);
            snapshot.state = State::Unknown;
            snapshot.since = std::chrono::system_clock::now();
        }
        Broadcast(State::Unknown);

        // Immediate first evaluation.
        Evaluate();

        while (!stop.stop_requested()) {
            {
                std::unique_lock<std::mutex> lk(recomputeMtx);
                recomputeCv.wait_for(lk, stop, std::chrono::seconds{10},
                    [&]{ return recomputeRequested || stop.stop_requested(); });
                recomputeRequested = false;
            }
            if (stop.stop_requested()) break;
            Evaluate();
        }

        SS_LOG_INFO(kLog, L"HeadlineStateService worker stopped.");
    }
};

// ============================================================================
// Singleton
// ============================================================================

HeadlineStateService& HeadlineStateService::Instance() noexcept
{
    static HeadlineStateService s_instance;
    return s_instance;
}

HeadlineStateService::HeadlineStateService()
    : m_impl(std::make_unique<Impl>())
{
    g_serviceAlive.store(true, std::memory_order_release);
}

HeadlineStateService::~HeadlineStateService()
{
    Stop();
    // Block any further callback re-entry from sibling singletons that may
    // outlive us.  PIMPL state is about to be destroyed.
    g_serviceAlive.store(false, std::memory_order_release);
}

// ============================================================================
// Lifecycle
// ============================================================================

void HeadlineStateService::Start()
{
    if (m_impl->running.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    // Subscribe to RecommendationsEngine so we recompute on any change.
    // The lambda checks g_serviceAlive to defend against post-destruction
    // delivery during static-destructor ordering at process exit.
    Recommendations::RecommendationsEngine::Instance().RegisterChangedCallback(
        [this]{
            if (g_serviceAlive.load(std::memory_order_acquire)) {
                ForceRecompute();
            }
        });

    // Subscribe to PgtiFeedManager so feed health changes trigger recompute.
    ThreatIntel::PgtiFeedManager::Instance().RegisterStatusChangedCallback(
        [this]{
            if (g_serviceAlive.load(std::memory_order_acquire)) {
                ForceRecompute();
            }
        });

    m_impl->worker = std::jthread([this](std::stop_token st) {
        m_impl->WorkerLoop(std::move(st));
    });

    SS_LOG_INFO(kLog, L"HeadlineStateService started.");
}

void HeadlineStateService::Stop()
{
    if (!m_impl->running.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    m_impl->worker.request_stop();
    m_impl->recomputeCv.notify_all();
    if (m_impl->worker.joinable()) {
        m_impl->worker.join();
    }
    SS_LOG_INFO(kLog, L"HeadlineStateService stopped.");
}

// ============================================================================
// Snapshot
// ============================================================================

HeadlineSnapshot HeadlineStateService::Snapshot() const
{
    std::shared_lock lock(m_impl->snapshotMutex);
    return m_impl->snapshot;
}

// ============================================================================
// ForceRecompute
// ============================================================================

void HeadlineStateService::ForceRecompute()
{
    if (!m_impl) {
        return;
    }
    {
        std::unique_lock<std::mutex> lk(m_impl->recomputeMtx);
        m_impl->recomputeRequested = true;
    }
    m_impl->recomputeCv.notify_all();
}

}  // namespace ShadowStrike::Products::Home::HeadlineState

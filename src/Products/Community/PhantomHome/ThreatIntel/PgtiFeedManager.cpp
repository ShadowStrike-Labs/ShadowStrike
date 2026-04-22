/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file PgtiFeedManager.cpp
 * @brief Implementation of the PGTI feed aggregator.
 *
 * PGTI feed set seeded from five canonical threat-intelligence categories.
 * The pull interval defaults to 900 s (15 min) for active feeds and 3600 s
 * for background feeds, matching the PhantomCore ThreatIntelFeedManager
 * scheduling tiers.
 *
 * Interaction with PhantomCore:
 *   PhantomCore's ThreatIntelFeedManager owns the actual HTTP client and
 *   IOC ingestion pipeline.  This class is a lightweight UI-tier status
 *   aggregator.  The ThreatIntel pull layer (or its adaptor) calls
 *   OnFeedPullCompleted() after each pull attempt so this manager can update
 *   its status records and broadcast push events.  We deliberately do NOT
 *   duplicate PhantomCore's puller.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#include "PgtiFeedManager.hpp"

#include "../../../../PhantomCore/Utils/Logger.hpp"
#include "../../../../PhantomCore/Config/ConfigManager.hpp"
#include "../../../../PhantomCore/Service/ServiceCommunicator.hpp"
#include "../../../../PhantomCore/Service/EventPush.hpp"

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

namespace ShadowStrike::Products::Home::ThreatIntel {

namespace {
constexpr const wchar_t* kLog = L"PgtiFeedManager";

// ConfigManager key template: "Home/PGTI/<feedId>/enabled"
constexpr const char* kConfigPrefix = "Home/PGTI/";
constexpr const char* kConfigSuffix = "/enabled";

[[nodiscard]] std::string FeedConfigKey(std::string_view feedId)
{
    return std::string(kConfigPrefix) + std::string(feedId) + kConfigSuffix;
}

// Default PGTI feed set — canonical IDs agreed between ThreatIntel team and UI.
std::vector<PgtiFeedDescriptor> BuildDefaultFeeds()
{
    std::vector<PgtiFeedDescriptor> feeds;

    feeds.push_back({
        .id           = "malware_ip",
        .displayName  = "Malware IP Blocklist",
        .sourceUrl    = "https://pgti.shadowstrike.internal/feeds/malware-ip/v2/iocs.json",
        .pullInterval = std::chrono::seconds{900},
        .enabled      = true,
    });

    feeds.push_back({
        .id           = "phishing_urls",
        .displayName  = "Phishing URL Feed",
        .sourceUrl    = "https://pgti.shadowstrike.internal/feeds/phishing-urls/v2/iocs.json",
        .pullInterval = std::chrono::seconds{600},   // 10 min – higher priority
        .enabled      = true,
    });

    feeds.push_back({
        .id           = "botnet_c2",
        .displayName  = "Botnet C2 Infrastructure",
        .sourceUrl    = "https://pgti.shadowstrike.internal/feeds/botnet-c2/v2/iocs.json",
        .pullInterval = std::chrono::seconds{900},
        .enabled      = true,
    });

    feeds.push_back({
        .id           = "ransomware_hashes",
        .displayName  = "Ransomware File Hashes",
        .sourceUrl    = "https://pgti.shadowstrike.internal/feeds/ransomware-hashes/v2/iocs.json",
        .pullInterval = std::chrono::seconds{1800},  // 30 min – hash DB changes slowly
        .enabled      = true,
    });

    feeds.push_back({
        .id           = "exploit_kits",
        .displayName  = "Exploit Kit Indicators",
        .sourceUrl    = "https://pgti.shadowstrike.internal/feeds/exploit-kits/v2/iocs.json",
        .pullInterval = std::chrono::seconds{3600},  // 1 h – background tier
        .enabled      = true,
    });

    feeds.push_back({
        .id           = "cryptominer_pools",
        .displayName  = "Cryptocurrency Mining Pool Blocklist",
        .sourceUrl    = "https://pgti.shadowstrike.internal/feeds/crypto-pools/v2/iocs.json",
        .pullInterval = std::chrono::seconds{3600},
        .enabled      = true,
    });

    feeds.push_back({
        .id           = "malvertising_domains",
        .displayName  = "Malvertising Domain Feed",
        .sourceUrl    = "https://pgti.shadowstrike.internal/feeds/malvertising/v2/iocs.json",
        .pullInterval = std::chrono::seconds{1800},
        .enabled      = true,
    });

    return feeds;
}

} // anonymous namespace

// ============================================================================
// PIMPL
// ============================================================================

struct PgtiFeedManager::Impl {
    mutable std::shared_mutex mutex;

    std::vector<PgtiFeedDescriptor> descriptors;
    std::vector<PgtiFeedStatus>     statuses;

    std::atomic<bool>       running{false};
    std::jthread            worker;
    std::condition_variable_any refreshCv;
    std::mutex              refreshMtx;
    bool                    refreshRequested{false};

    // Status-change callbacks — stored under mutex.
    std::vector<StatusChangedCallback> callbacks;

    explicit Impl()
        : descriptors(BuildDefaultFeeds())
    {
        statuses.resize(descriptors.size());
        for (std::size_t i = 0; i < descriptors.size(); ++i) {
            statuses[i].id     = descriptors[i].id;
            statuses[i].health = descriptors[i].enabled
                                    ? PgtiFeedStatus::Health::Degraded
                                    : PgtiFeedStatus::Health::Disabled;
        }
    }

    // Load per-feed enable/disable state from ConfigManager.
    void LoadPersistedEnabledState() noexcept
    {
        auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
        if (!cfg.IsInitialized()) {
            SS_LOG_WARN(kLog, L"PgtiFeedManager: ConfigManager not ready; using defaults.");
            return;
        }
        std::unique_lock lock(mutex);
        for (std::size_t i = 0; i < descriptors.size(); ++i) {
            const std::string key = FeedConfigKey(descriptors[i].id);
            descriptors[i].enabled = cfg.GetValue<bool>(key, descriptors[i].enabled);
            statuses[i].health = descriptors[i].enabled
                                    ? PgtiFeedStatus::Health::Degraded
                                    : PgtiFeedStatus::Health::Disabled;
        }
    }

    // Persist single feed's enabled flag.
    void PersistEnabledFlag(std::string_view feedId, bool enabled) noexcept
    {
        auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
        if (!cfg.IsInitialized()) {
            SS_LOG_WARN(kLog, L"PgtiFeedManager: ConfigManager not ready; cannot persist '%hs' enabled=%d.",
                        std::string(feedId).c_str(), static_cast<int>(enabled));
            return;
        }
        const std::string key = FeedConfigKey(feedId);
        (void)cfg.SetValue<bool>(key, enabled);
    }

    // Broadcast PgtiFeedUpdated event.
    void BroadcastFeedUpdated(std::string_view feedId, PgtiFeedStatus::Health health) noexcept
    {
        using namespace ::ShadowStrike::Service;
        const char* healthStr = "disabled";
        switch (health) {
            case PgtiFeedStatus::Health::Healthy:  healthStr = "healthy";  break;
            case PgtiFeedStatus::Health::Degraded: healthStr = "degraded"; break;
            case PgtiFeedStatus::Health::Failed:   healthStr = "failed";   break;
            case PgtiFeedStatus::Health::Disabled: healthStr = "disabled"; break;
        }

        auto envelope = Events::BuildPgtiFeedUpdated(feedId, healthStr);
        if (envelope.empty()) {
            SS_LOG_WARN(kLog, L"PgtiFeedManager: BuildPgtiFeedUpdated returned empty buffer for '%hs'.",
                        std::string(feedId).c_str());
            return;
        }
        const std::size_t n = ServiceCommunicator::Instance()
                                  .BroadcastEvent(CommandType::PgtiFeedUpdated, envelope);
        SS_LOG_DEBUG(kLog, L"PgtiFeedManager: broadcasted PgtiFeedUpdated('%hs', %hs) to %zu client(s).",
                     std::string(feedId).c_str(), healthStr, n);
    }

    void FireCallbacks() noexcept
    {
        std::vector<StatusChangedCallback> cbs;
        {
            std::shared_lock lock(mutex);
            cbs = callbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(); } catch (...) {}
        }
    }

    // Worker: periodically checks if any feed is due for a pull request.
    // Since PhantomCore owns the actual HTTP client, we only update our
    // internal scheduling state and log when a feed is overdue.
    void WorkerLoop(std::stop_token stop)
    {
        SS_LOG_INFO(kLog, L"PgtiFeedManager worker started.");

        while (!stop.stop_requested()) {
            // Wait up to 30 s, or until a refresh is requested.
            {
                std::unique_lock<std::mutex> lk(refreshMtx);
                refreshCv.wait_for(lk, stop, std::chrono::seconds{30},
                    [&]{ return refreshRequested || stop.stop_requested(); });
                refreshRequested = false;
            }
            if (stop.stop_requested()) break;

            // Walk feeds and log overdue ones.  Actual pulling is done by
            // the PhantomCore ThreatIntelFeedManager; this loop exists so
            // that if a feed has not reported a pull in >2× its interval,
            // we mark it Degraded to surface the issue in the UI.
            const auto now = std::chrono::system_clock::now();
            bool anyChanged = false;

            {
                std::unique_lock lock(mutex);
                for (std::size_t i = 0; i < descriptors.size(); ++i) {
                    if (!descriptors[i].enabled) continue;
                    if (statuses[i].health == PgtiFeedStatus::Health::Disabled) continue;

                    const auto deadline = statuses[i].lastAttempt
                                        + descriptors[i].pullInterval * 2;
                    if (statuses[i].lastAttempt.time_since_epoch().count() != 0
                        && now > deadline
                        && statuses[i].health == PgtiFeedStatus::Health::Healthy)
                    {
                        statuses[i].health = PgtiFeedStatus::Health::Degraded;
                        anyChanged = true;
                        SS_LOG_WARN(kLog,
                            L"PgtiFeedManager: feed '%hs' has not pulled in >2× interval; marking Degraded.",
                            descriptors[i].id.c_str());
                    }
                }
            }

            if (anyChanged) {
                FireCallbacks();
            }
        }

        SS_LOG_INFO(kLog, L"PgtiFeedManager worker stopped.");
    }
};

// ============================================================================
// Singleton
// ============================================================================

PgtiFeedManager& PgtiFeedManager::Instance() noexcept
{
    static PgtiFeedManager s_instance;
    return s_instance;
}

PgtiFeedManager::PgtiFeedManager()
    : m_impl(std::make_unique<Impl>())
{
}

PgtiFeedManager::~PgtiFeedManager()
{
    Stop();
}

// ============================================================================
// Lifecycle
// ============================================================================

void PgtiFeedManager::Start()
{
    if (m_impl->running.exchange(true, std::memory_order_acq_rel)) {
        return; // already running
    }
    m_impl->LoadPersistedEnabledState();
    m_impl->worker = std::jthread([this](std::stop_token st) {
        m_impl->WorkerLoop(std::move(st));
    });
    SS_LOG_INFO(kLog, L"PgtiFeedManager started (%zu feeds configured).",
                m_impl->descriptors.size());
}

void PgtiFeedManager::Stop()
{
    if (!m_impl->running.exchange(false, std::memory_order_acq_rel)) {
        return; // already stopped
    }
    m_impl->worker.request_stop();
    m_impl->refreshCv.notify_all();
    if (m_impl->worker.joinable()) {
        m_impl->worker.join();
    }
    SS_LOG_INFO(kLog, L"PgtiFeedManager stopped.");
}

// ============================================================================
// Status snapshot
// ============================================================================

std::vector<PgtiFeedStatus> PgtiFeedManager::Snapshot() const
{
    std::shared_lock lock(m_impl->mutex);
    return m_impl->statuses;
}

// ============================================================================
// Control
// ============================================================================

bool PgtiFeedManager::RefreshNow(std::string_view feedId)
{
    bool found = false;
    {
        std::shared_lock lock(m_impl->mutex);
        if (feedId.empty()) {
            // Refresh all enabled feeds.
            for (const auto& d : m_impl->descriptors) {
                if (d.enabled) { found = true; break; }
            }
        } else {
            for (const auto& d : m_impl->descriptors) {
                if (d.id == feedId) { found = true; break; }
            }
        }
    }
    if (!found) {
        SS_LOG_WARN(kLog, L"PgtiFeedManager::RefreshNow: feed '%hs' not found.",
                    std::string(feedId).c_str());
        return false;
    }
    {
        std::unique_lock<std::mutex> lk(m_impl->refreshMtx);
        m_impl->refreshRequested = true;
    }
    m_impl->refreshCv.notify_all();
    return true;
}

void PgtiFeedManager::SetFeedEnabled(std::string_view feedId, bool enabled)
{
    std::size_t idx = SIZE_MAX;
    {
        std::unique_lock lock(m_impl->mutex);
        for (std::size_t i = 0; i < m_impl->descriptors.size(); ++i) {
            if (m_impl->descriptors[i].id == feedId) {
                idx = i;
                break;
            }
        }
        if (idx == SIZE_MAX) {
            SS_LOG_WARN(kLog, L"PgtiFeedManager::SetFeedEnabled: feed '%hs' not found.",
                        std::string(feedId).c_str());
            return;
        }
        m_impl->descriptors[idx].enabled = enabled;
        m_impl->statuses[idx].health = enabled
                                        ? PgtiFeedStatus::Health::Degraded
                                        : PgtiFeedStatus::Health::Disabled;
    }
    m_impl->PersistEnabledFlag(feedId, enabled);

    if (enabled && m_impl->running.load(std::memory_order_acquire)) {
        RefreshNow(feedId);
    }

    const auto health = enabled ? PgtiFeedStatus::Health::Degraded
                                : PgtiFeedStatus::Health::Disabled;
    m_impl->BroadcastFeedUpdated(feedId, health);
    m_impl->FireCallbacks();

    SS_LOG_INFO(kLog, L"PgtiFeedManager: feed '%hs' %ls.",
                std::string(feedId).c_str(), enabled ? L"enabled" : L"disabled");
}

// ============================================================================
// Completion callback
// ============================================================================

void PgtiFeedManager::OnFeedPullCompleted(std::string_view feedId,
                                          bool             success,
                                          std::uint64_t    entriesLoaded,
                                          std::uint64_t    bytesPulled,
                                          std::uint32_t    latencyMs,
                                          std::string_view errCode,
                                          std::string_view errMsg)
{
    PgtiFeedStatus::Health prevHealth = PgtiFeedStatus::Health::Disabled;
    PgtiFeedStatus::Health newHealth  = PgtiFeedStatus::Health::Disabled;

    {
        std::unique_lock lock(m_impl->mutex);
        bool found = false;
        for (auto& s : m_impl->statuses) {
            if (s.id != feedId) continue;
            found = true;
            prevHealth = s.health;

            const auto now = std::chrono::system_clock::now();
            s.lastAttempt = now;
            if (success) {
                s.lastSuccess    = now;
                s.entriesLoaded  = entriesLoaded;
                s.bytesPulled    = bytesPulled;
                s.latencyMs      = latencyMs;
                s.lastErrorCode.clear();
                s.lastErrorMessage.clear();
                s.health = PgtiFeedStatus::Health::Healthy;
            } else {
                s.lastErrorCode    = std::string(errCode);
                s.lastErrorMessage = std::string(errMsg);
                s.health = PgtiFeedStatus::Health::Failed;
            }
            newHealth = s.health;
            break;
        }
        if (!found) {
            SS_LOG_WARN(kLog,
                L"OnFeedPullCompleted: unknown feed id '%hs'; status not updated.",
                std::string(feedId).c_str());
            return;
        }
    }

    if (newHealth != prevHealth) {
        m_impl->BroadcastFeedUpdated(feedId, newHealth);
        m_impl->FireCallbacks();
    }

    SS_LOG_INFO(kLog,
        L"PgtiFeedManager: feed '%hs' pull %ls: entries=%llu, bytes=%llu, latency=%ums.",
        std::string(feedId).c_str(),
        success ? L"succeeded" : L"FAILED",
        static_cast<unsigned long long>(entriesLoaded),
        static_cast<unsigned long long>(bytesPulled),
        latencyMs);
}

// ============================================================================
// Change notification
// ============================================================================

void PgtiFeedManager::RegisterStatusChangedCallback(StatusChangedCallback cb)
{
    if (!cb) return;
    std::unique_lock lock(m_impl->mutex);
    m_impl->callbacks.push_back(std::move(cb));
}

}  // namespace ShadowStrike::Products::Home::ThreatIntel

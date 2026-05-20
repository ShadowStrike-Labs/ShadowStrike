/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file PgtiFeedManager.hpp
 * @brief Phantom Global Threat Intelligence (PGTI) feed aggregator.
 *
 * Subscribes to and manages the status of PGTI threat-intel feed sources,
 * exposes per-feed health for UI display, and broadcasts `PgtiFeedUpdated`
 * push events to connected clients.
 *
 * Architecture:
 *   - Meyers' singleton.
 *   - std::shared_mutex for concurrent status reads / exclusive writes.
 *   - std::jthread worker for periodic feed polling / status refresh.
 *   - ConfigManager persistence for per-feed enabled/disabled state under
 *     "Home/PGTI/<feedId>/enabled".
 *   - ServiceCommunicator::BroadcastEvent for push notification on status
 *     changes (CommandType::PgtiFeedUpdated = 105).
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace ShadowStrike::Products::Home::ThreatIntel {

// ============================================================================
// PgtiFeedDescriptor — static configuration for one feed source
// ============================================================================

/**
 * @brief Static descriptor for a PGTI feed source.
 *
 * Instances are created at manager construction and do not change at runtime
 * (except for the `enabled` flag which is persisted in ConfigManager).
 */
struct PgtiFeedDescriptor {
    /// Stable canonical feed id (e.g. "malware_ip", "phishing_urls").
    std::string id;

    /// Human-readable feed name shown in the UI.
    std::string displayName;

    /// Source URL (used for logging; not exposed to UI in full).
    std::string sourceUrl;

    /// How often the feed should be refreshed (default 15 min).
    std::chrono::seconds pullInterval{900};

    /// Whether this feed is currently enabled (persisted via ConfigManager).
    bool enabled{true};
};

// ============================================================================
// PgtiFeedStatus — runtime per-feed status snapshot
// ============================================================================

/**
 * @brief Runtime health and statistics snapshot for a single PGTI feed.
 *
 * Returned by Snapshot() for UI binding.  All fields are value-copyable.
 */
struct PgtiFeedStatus {
    std::string id;

    enum class Health : std::uint8_t {
        Healthy  = 0,  ///< Last pull succeeded within the pull interval.
        Degraded = 1,  ///< Pull succeeded but entries count or latency is abnormal.
        Failed   = 2,  ///< Last pull attempt returned an error.
        Disabled = 3,  ///< Feed is administratively disabled.
    };

    Health health{Health::Disabled};

    /// Timestamp of the last successful pull.
    std::chrono::system_clock::time_point lastSuccess{};

    /// Timestamp of the last pull attempt (success or failure).
    std::chrono::system_clock::time_point lastAttempt{};

    /// Number of IOC entries loaded in the last pull.
    std::uint64_t entriesLoaded{0};

    /// Bytes transferred in the last pull.
    std::uint64_t bytesPulled{0};

    /// End-to-end pull latency in milliseconds.
    std::uint32_t latencyMs{0};

    /// Machine-readable error code from the last failed pull (empty on success).
    std::string lastErrorCode;

    /// Human-readable description of the last error (empty on success).
    std::string lastErrorMessage;
};

// ============================================================================
// PgtiFeedManager
// ============================================================================

/**
 * @class PgtiFeedManager
 * @brief Meyers' singleton that manages PGTI feed lifecycle and status.
 *
 * Callers in the ThreatIntel pull layer notify this manager via
 * OnFeedPullCompleted() after each pull attempt (success or failure).
 * The manager aggregates status, persists enabled/disabled state, and
 * broadcasts PgtiFeedUpdated events to UI clients.
 */
class PgtiFeedManager final {
public:
    [[nodiscard]] static PgtiFeedManager& Instance() noexcept;

    PgtiFeedManager(const PgtiFeedManager&)            = delete;
    PgtiFeedManager& operator=(const PgtiFeedManager&) = delete;
    PgtiFeedManager(PgtiFeedManager&&)                 = delete;
    PgtiFeedManager& operator=(PgtiFeedManager&&)      = delete;

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /**
     * @brief Start the feed polling worker thread.
     *
     * Loads persisted enabled/disabled state from ConfigManager.
     * Idempotent — safe to call multiple times.
     */
    void Start();

    /**
     * @brief Stop the feed polling worker thread.
     *
     * Blocks until the worker exits.  Idempotent.
     */
    void Stop();

    // ========================================================================
    // Status queries
    // ========================================================================

    /**
     * @brief Return a snapshot of all feed statuses.
     *
     * Thread-safe (shared lock).  Returns by value so callers are not
     * blocked while the caller processes the data.
     */
    [[nodiscard]] std::vector<PgtiFeedStatus> Snapshot() const;

    // ========================================================================
    // Control
    // ========================================================================

    /**
     * @brief Queue an immediate refresh of a named feed, or all feeds.
     *
     * @param feedId  Feed id to refresh.  Pass empty string to refresh all
     *                enabled feeds.
     * @return true if at least one feed was queued for refresh; false if
     *         feedId was specified but not found.
     */
    [[nodiscard]] bool RefreshNow(std::string_view feedId = {});

    /**
     * @brief Enable or disable a named feed.
     *
     * Persists the new state to ConfigManager under
     * "Home/PGTI/<feedId>/enabled".  If the manager is running and the feed
     * is being enabled, a refresh is queued immediately.
     */
    void SetFeedEnabled(std::string_view feedId, bool enabled);

    // ========================================================================
    // Completion callback (called from ThreatIntel pull layer)
    // ========================================================================

    /**
     * @brief Record the result of a feed pull attempt.
     *
     * Thread-safe.  Should be called by the ThreatIntelFeedManager (or its
     * polling delegate) after each synchronisation attempt.  Updates the
     * in-memory status record and broadcasts a PgtiFeedUpdated push event
     * if the health state changed.
     *
     * @param feedId        Canonical feed id matching PgtiFeedDescriptor::id.
     * @param success       true if the pull succeeded; false on error.
     * @param entriesLoaded Number of IOC entries loaded (0 on failure).
     * @param bytesPulled   Bytes transferred (0 on failure).
     * @param latencyMs     End-to-end pull latency in milliseconds.
     * @param errCode       Machine-readable error code (empty on success).
     * @param errMsg        Human-readable error description (empty on success).
     */
    void OnFeedPullCompleted(std::string_view feedId,
                             bool             success,
                             std::uint64_t    entriesLoaded,
                             std::uint64_t    bytesPulled,
                             std::uint32_t    latencyMs,
                             std::string_view errCode = {},
                             std::string_view errMsg  = {});

    // ========================================================================
    // Change notification (used by HeadlineStateService)
    // ========================================================================

    using StatusChangedCallback = std::function<void()>;

    /**
     * @brief Register a callback to invoke on any feed status change.
     *
     * The callback is invoked from the worker thread under no lock; it MUST
     * NOT call back into PgtiFeedManager synchronously.
     */
    void RegisterStatusChangedCallback(StatusChangedCallback cb);

private:
    PgtiFeedManager();
    ~PgtiFeedManager();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace ShadowStrike::Products::Home::ThreatIntel

/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file RecommendationsEngine.hpp
 * @brief Actionable security recommendation tile engine for PhantomHome.
 *
 * Produces `Recommendation` objects surfaced on the main page when security
 * conditions warrant user attention (disabled modules, stale signatures,
 * pending quarantine items, etc.).
 *
 * Design:
 *   - Meyers' singleton.
 *   - Rule evaluation runs on a 30-second timer AND on-demand.
 *   - Each rule emits or retracts a stable Recommendation::id.
 *   - Dismissals are persisted in ConfigManager under
 *     "Home/Recommendations/dismissed/<id>" with a timestamp; they expire
 *     after 7 days so tiles can re-surface if still valid.
 *   - Broadcasts RecommendationsChanged (CommandType::RecommendationsChanged=106)
 *     via ServiceCommunicator::BroadcastEvent when the active set changes.
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
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace ShadowStrike::Products::Home::Recommendations {

// ============================================================================
// Severity / ActionKind
// ============================================================================

enum class Severity : std::uint8_t {
    Info     = 0,
    Warn     = 1,
    Critical = 2,
};

enum class ActionKind : std::uint8_t {
    NavigateToRoute = 0,  ///< args: QML route string
    SetModuleMode   = 1,  ///< args: { "moduleId": "...", "mode": "..." }
    RunCommand      = 2,  ///< args: { "commandType": <uint32>, "payload": "..." }
    ExternalUrl     = 3,  ///< args: URL string
    Dismiss         = 4,  ///< args: none
};

// ============================================================================
// RecommendationAction / Recommendation
// ============================================================================

struct RecommendationAction {
    ActionKind  kind;
    std::string argsJson;  ///< JSON payload for the action (format per ActionKind).
    std::string labelKey;  ///< i18n key for the button / link label.
};

struct Recommendation {
    /// Stable, engine-assigned id used for deduplication and dismissal.
    std::string id;

    Severity severity;

    /// i18n key for the tile title (e.g. "rec.amsi_unregistered.title").
    std::string titleKey;

    /// i18n key for the tile detail text.
    std::string detailKey;

    std::vector<RecommendationAction> actions;

    std::chrono::system_clock::time_point createdAt;

    /// Whether the user can dismiss this tile.
    bool dismissible{true};
};

// ============================================================================
// RecommendationsEngine
// ============================================================================

/**
 * @class RecommendationsEngine
 * @brief Meyers' singleton that evaluates security rules and maintains the
 *        active recommendation set.
 */
class RecommendationsEngine final {
public:
    [[nodiscard]] static RecommendationsEngine& Instance() noexcept;

    RecommendationsEngine(const RecommendationsEngine&)            = delete;
    RecommendationsEngine& operator=(const RecommendationsEngine&) = delete;
    RecommendationsEngine(RecommendationsEngine&&)                 = delete;
    RecommendationsEngine& operator=(RecommendationsEngine&&)      = delete;

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /**
     * @brief Start the periodic rule evaluation timer (every 30 s).
     * Idempotent.
     */
    void Start();

    /**
     * @brief Stop the timer thread.
     * Idempotent; blocks until the worker exits.
     */
    void Stop();

    // ========================================================================
    // Queries
    // ========================================================================

    /**
     * @brief Return the current active recommendation set.
     *
     * Thread-safe (shared lock).  Dismissed items are excluded.
     * Sorted by descending severity (Critical first).
     */
    [[nodiscard]] std::vector<Recommendation> Snapshot() const;

    // ========================================================================
    // Control
    // ========================================================================

    /**
     * @brief Dismiss a recommendation by id.
     *
     * Persists the dismissal timestamp to ConfigManager.  The tile will
     * re-surface after 7 days if the underlying condition persists.
     *
     * @param id  Stable recommendation id (Recommendation::id).
     */
    void Dismiss(std::string_view id);

    /**
     * @brief Trigger an immediate rule re-evaluation.
     *
     * Non-blocking; the evaluation runs on the internal worker thread.
     */
    void ForceRecompute();

    // ========================================================================
    // Change notification (used by HeadlineStateService)
    // ========================================================================

    using ChangedCallback = std::function<void()>;

    /**
     * @brief Register a callback invoked whenever the active set changes.
     *
     * The callback is invoked from the worker thread under no lock.  It MUST
     * NOT call back into RecommendationsEngine synchronously.
     */
    void RegisterChangedCallback(ChangedCallback cb);

private:
    RecommendationsEngine();
    ~RecommendationsEngine();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace ShadowStrike::Products::Home::Recommendations

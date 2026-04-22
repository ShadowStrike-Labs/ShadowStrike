/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file HeadlineStateService.hpp
 * @brief Aggregates module, recommendation, and feed status into a single
 *        top-of-MainPage "hero" protection state indicator.
 *
 * The service recomputes the headline state (Healthy / AtRisk / Critical /
 * Unknown) on a 10-second timer, on RecommendationsEngine changes, and on
 * PgtiFeedManager status changes.  When the state changes it broadcasts a
 * HeadlineStateChanged push event (CommandType=104) via
 * ServiceCommunicator::BroadcastEvent.
 *
 * Aggregation rules (worst of):
 *   Critical: any Critical Recommendation, OR global protection paused,
 *             OR any module in Failed state.
 *   AtRisk:   any Warn Recommendation, OR any module Passive that defaults
 *             Balanced, OR any PGTI feed in Failed health.
 *   Healthy:  none of the above.
 *   Unknown:  only during initial boot before first evaluation completes.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <thread>

namespace ShadowStrike::Products::Home::HeadlineState {

// ============================================================================
// State / HeadlineSnapshot
// ============================================================================

enum class State : std::uint8_t {
    Healthy  = 0,
    AtRisk   = 1,
    Critical = 2,
    Unknown  = 3,  ///< Before first evaluation completes.
};

[[nodiscard]] constexpr const char* StateToString(State s) noexcept
{
    switch (s) {
        case State::Healthy:  return "healthy";
        case State::AtRisk:   return "at_risk";
        case State::Critical: return "critical";
        case State::Unknown:  return "unknown";
    }
    return "unknown";
}

struct HeadlineSnapshot {
    State  state{State::Unknown};

    /// i18n key for the main headline line (e.g. "headline.healthy.primary").
    std::string primaryKey;

    /// i18n key for the sub-headline (e.g. "headline.healthy.secondary").
    std::string secondaryKey;

    /// Number of Critical-severity active recommendations.
    std::uint32_t criticalCount{0};

    /// Number of Warn-severity active recommendations.
    std::uint32_t atRiskCount{0};

    /// When the state last transitioned.
    std::chrono::system_clock::time_point since{};
};

// ============================================================================
// HeadlineStateService
// ============================================================================

/**
 * @class HeadlineStateService
 * @brief Meyers' singleton driving the MainPage hero state indicator.
 */
class HeadlineStateService final {
public:
    [[nodiscard]] static HeadlineStateService& Instance() noexcept;

    HeadlineStateService(const HeadlineStateService&)            = delete;
    HeadlineStateService& operator=(const HeadlineStateService&) = delete;
    HeadlineStateService(HeadlineStateService&&)                 = delete;
    HeadlineStateService& operator=(HeadlineStateService&&)      = delete;

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /**
     * @brief Start the 10-second recompute timer.
     *
     * Registers callbacks with RecommendationsEngine and PgtiFeedManager so
     * state changes trigger an immediate recompute rather than waiting for
     * the next timer tick.  Idempotent.
     */
    void Start();

    /**
     * @brief Stop the timer thread.
     *
     * Idempotent; blocks until the worker exits.
     */
    void Stop();

    // ========================================================================
    // Queries
    // ========================================================================

    /**
     * @brief Return the latest headline snapshot.
     *
     * Thread-safe (atomic load of snapshot ptr).
     */
    [[nodiscard]] HeadlineSnapshot Snapshot() const;

    // ========================================================================
    // Control
    // ========================================================================

    /**
     * @brief Trigger an immediate recompute.
     *
     * Non-blocking; runs on the internal worker thread.
     */
    void ForceRecompute();

private:
    HeadlineStateService();
    ~HeadlineStateService();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace ShadowStrike::Products::Home::HeadlineState

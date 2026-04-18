/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

/// @file CorrelationEngine.hpp
/// @brief Cross-domain event correlation engine — sliding window, background
///        rule evaluation, and incident production.

#include "XDRTypes.hpp"
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation {

class CorrelationEngineImpl;

/// Meyers' singleton correlation engine.
/// Ingests XDREvents, evaluates rules on a background thread, and produces
/// CorrelationMatch objects when cross-domain attack patterns are detected.
class CorrelationEngine final {
public:
    [[nodiscard]] static CorrelationEngine& Instance();
    [[nodiscard]] static bool HasInstance() noexcept;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    // ── Event ingestion ──────────────────────────────────────────
    [[nodiscard]] bool IngestEvent(const XDREvent& event);

    // ── Queries ──────────────────────────────────────────────────
    [[nodiscard]] std::vector<CorrelationMatch> GetActiveCorrelations() const;
    [[nodiscard]] std::optional<CorrelationMatch> GetCorrelationById(std::string_view matchId) const;
    [[nodiscard]] std::vector<CorrelationMatch> GetCorrelationsByRule(std::string_view ruleId) const;

    // ── Window control ───────────────────────────────────────────
    void SetTimeWindowSeconds(uint32_t seconds);
    [[nodiscard]] uint32_t GetTimeWindowSeconds() const noexcept;

    // ── Manual trigger ───────────────────────────────────────────
    void EvaluateNow();

    // ── Statistics ───────────────────────────────────────────────
    [[nodiscard]] CorrelationStatistics GetStatistics() const;

private:
    CorrelationEngine();
    ~CorrelationEngine();
    CorrelationEngine(const CorrelationEngine&) = delete;
    CorrelationEngine& operator=(const CorrelationEngine&) = delete;

    std::unique_ptr<CorrelationEngineImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation

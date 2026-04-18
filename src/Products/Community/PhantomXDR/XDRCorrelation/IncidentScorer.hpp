/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

/// @file IncidentScorer.hpp
/// @brief MITRE ATT&CK–based incident scoring with tactic coverage,
///        cross-domain multipliers, and severity classification.

#include "XDRTypes.hpp"
#include <memory>
#include <optional>
#include <string_view>

namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation {

class IncidentScorerImpl;

/// Meyers' singleton incident scorer.
/// Scores storylines and correlation matches based on MITRE ATT&CK coverage,
/// cross-domain activity, temporal ordering, and kill-chain progression.
class IncidentScorer final {
public:
    [[nodiscard]] static IncidentScorer& Instance();
    [[nodiscard]] static bool HasInstance() noexcept;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    // ── Scoring ──────────────────────────────────────────────────
    [[nodiscard]] IncidentScore ScoreStoryline(const Storyline& storyline);
    [[nodiscard]] IncidentScore ScoreCorrelationMatch(
        const CorrelationMatch& match,
        const std::vector<XDREvent>& events);

    // ── Cache ────────────────────────────────────────────────────
    [[nodiscard]] std::optional<IncidentScore> GetCachedScore(
        std::string_view storylineId) const;

    // ── Technique overrides ──────────────────────────────────────
    void SetTechniqueOverride(std::string_view techniqueId, double severityBoost);
    void ClearTechniqueOverrides();

private:
    IncidentScorer();
    ~IncidentScorer();
    IncidentScorer(const IncidentScorer&) = delete;
    IncidentScorer& operator=(const IncidentScorer&) = delete;

    std::unique_ptr<IncidentScorerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation

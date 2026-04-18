/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

/// @file StorylineBuilder.hpp
/// @brief Attack-chain reconstruction — builds directed acyclic graphs
///        of correlated events mapped to MITRE ATT&CK kill chain phases.

#include "XDRTypes.hpp"
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation {

class StorylineBuilderImpl;

/// Meyers' singleton storyline builder.
/// Constructs Storyline DAGs from CorrelationMatch objects, computes kill-chain
/// coverage, and generates human-readable attack narratives.
class StorylineBuilder final {
public:
    [[nodiscard]] static StorylineBuilder& Instance();
    [[nodiscard]] static bool HasInstance() noexcept;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    // ── Build & update ───────────────────────────────────────────
    [[nodiscard]] std::optional<std::string> BuildStoryline(
        const CorrelationMatch& match,
        const std::vector<XDREvent>& events);

    [[nodiscard]] bool UpdateStoryline(
        std::string_view storylineId,
        const std::vector<XDREvent>& newEvents);

    // ── Queries ──────────────────────────────────────────────────
    [[nodiscard]] std::optional<Storyline>  GetStoryline(std::string_view storylineId) const;
    [[nodiscard]] std::vector<Storyline>    GetActiveStorylines() const;
    [[nodiscard]] std::string               GenerateNarrative(std::string_view storylineId) const;
    [[nodiscard]] uint32_t                  GetActiveCount() const;

private:
    StorylineBuilder();
    ~StorylineBuilder();
    StorylineBuilder(const StorylineBuilder&) = delete;
    StorylineBuilder& operator=(const StorylineBuilder&) = delete;

    std::unique_ptr<StorylineBuilderImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation

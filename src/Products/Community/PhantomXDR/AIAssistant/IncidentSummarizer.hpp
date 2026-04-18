/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

#include "Products/Community/PhantomXDR/AIAssistant/AssistantTypes.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/XDRTypes.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::AIAssistant {

using ShadowStrike::Products::PhantomXDR::XDRCorrelation::CorrelationMatch;
using ShadowStrike::Products::PhantomXDR::XDRCorrelation::Storyline;
using ShadowStrike::Products::PhantomXDR::XDRCorrelation::XDREvent;

class IncidentSummarizerImpl;

class IncidentSummarizer final {
public:
    [[nodiscard]] static IncidentSummarizer& Instance();
    [[nodiscard]] static bool HasInstance() noexcept;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] IncidentSummary             SummarizeStoryline(const Storyline& sl, SummaryLevel level);
    [[nodiscard]] IncidentSummary             SummarizeCorrelationMatch(const CorrelationMatch& match,
                                                                       const std::vector<XDREvent>& events,
                                                                       SummaryLevel level);
    [[nodiscard]] std::string                 GenerateExecutiveBrief(const std::vector<IncidentSummary>& summaries) const;
    [[nodiscard]] std::optional<IncidentSummary> GetCachedSummary(std::string_view storylineId) const;

private:
    IncidentSummarizer();
    ~IncidentSummarizer();
    IncidentSummarizer(const IncidentSummarizer&) = delete;
    IncidentSummarizer& operator=(const IncidentSummarizer&) = delete;

    std::unique_ptr<IncidentSummarizerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::AIAssistant

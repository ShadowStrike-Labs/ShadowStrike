/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::AIAssistant {

using TimePoint = std::chrono::system_clock::time_point;

enum class QueryLanguage : uint8_t {
    Natural = 0,
    SSQL    = 1,
    KQL     = 2,
    Sigma   = 3
};

enum class SummaryLevel : uint8_t {
    Brief     = 0,
    Standard  = 1,
    Detailed  = 2,
    Executive = 3
};

struct HuntQuery {
    std::string   queryId;
    std::string   naturalLanguage;
    std::string   translatedQuery;
    QueryLanguage targetLang{QueryLanguage::SSQL};
    double        confidence{0.0};
    std::string   explanation;
};

struct IncidentSummary {
    std::string              summaryId;
    std::string              storylineId;
    SummaryLevel             level{SummaryLevel::Standard};
    std::string              title;
    std::string              narrative;
    std::vector<std::string> recommendations;
    std::vector<std::string> affectedAssets;
    std::string              mitreMappingSummary;
    TimePoint                generatedAt{};
};

struct AssistantContext {
    std::string                                           sessionId;
    std::vector<std::pair<std::string, std::string>>      conversationHistory;
    std::map<std::string, std::string>                    sessionVariables;
};

struct AssistantResponse {
    std::string              responseId;
    std::string              content;
    std::vector<std::string> suggestedFollowups;
    double                   confidence{0.0};
    std::string              reasoning;
};

} // namespace ShadowStrike::Products::PhantomXDR::AIAssistant

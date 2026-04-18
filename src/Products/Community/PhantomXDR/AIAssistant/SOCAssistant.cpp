/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "Products/Community/PhantomXDR/AIAssistant/AssistantTypes.hpp"
#include "Products/Community/PhantomXDR/AIAssistant/SOCAssistant.hpp"

#include "Products/Community/PhantomXDR/AIAssistant/IncidentSummarizer.hpp"
#include "Products/Community/PhantomXDR/AIAssistant/QueryTranslator.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/StorylineBuilder.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::AIAssistant {

namespace {

constexpr const char* kLogPrefix = "[XDR::AIAssistant::SOC]";

using Clock = std::chrono::system_clock;
using DB    = ShadowStrike::Database::DatabaseManager;
using DBErr = ShadowStrike::Database::DatabaseError;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Utils::Logger;
namespace XDR = ShadowStrike::Products::PhantomXDR::XDRCorrelation;

enum class AssistantIntent : uint8_t {
    IncidentSummary = 0,
    ThreatBrief,
    Recommendations,
    Timeline,
    Hunt,
    ExecutiveBrief,
    ActiveIncidents,
    StorylineLookup,
    AssetImpact,
    SeverityOverview,
    MitreExplanation,
    RemediationChecklist,
    QueryHistory,
    SessionStatus,
    CorrelationDetails,
    Unknown
};

struct IntentPattern final {
    AssistantIntent         intent{AssistantIntent::Unknown};
    std::vector<std::string> triggers;
    double                  baseConfidence{0.0};
};

[[nodiscard]] int64_t ToUnixMilliseconds(const TimePoint timePoint) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch()).count();
}

[[nodiscard]] std::string NormalizeText(std::string_view text) {
    std::string normalized;
    normalized.reserve(text.size());

    bool previousSpace = true;
    for (const unsigned char ch : text) {
        if (std::isalnum(ch) != 0) {
            normalized.push_back(static_cast<char>(std::tolower(ch)));
            previousSpace = false;
        } else if (!previousSpace) {
            normalized.push_back(' ');
            previousSpace = true;
        }
    }

    while (!normalized.empty() && normalized.back() == ' ') {
        normalized.pop_back();
    }

    return normalized;
}

[[nodiscard]] std::string GenerateSessionId() {
    static std::atomic<uint64_t> sequence{0};
    return std::format("SOC-{:X}-{:04X}",
                       static_cast<uint64_t>(Clock::now().time_since_epoch().count()),
                       sequence.fetch_add(1, std::memory_order_relaxed) & 0xFFFFULL);
}

[[nodiscard]] std::string GenerateResponseId() {
    static std::atomic<uint64_t> sequence{0};
    return std::format("SOCR-{:X}-{:04X}",
                       static_cast<uint64_t>(Clock::now().time_since_epoch().count()),
                       sequence.fetch_add(1, std::memory_order_relaxed) & 0xFFFFULL);
}

[[nodiscard]] std::string GenerateMessageId() {
    static std::atomic<uint64_t> sequence{0};
    return std::format("SOCM-{:X}-{:04X}",
                       static_cast<uint64_t>(Clock::now().time_since_epoch().count()),
                       sequence.fetch_add(1, std::memory_order_relaxed) & 0xFFFFULL);
}

[[nodiscard]] const char* IntentToString(const AssistantIntent intent) noexcept {
    switch (intent) {
        case AssistantIntent::IncidentSummary:      return "incident-summary";
        case AssistantIntent::ThreatBrief:          return "threat-brief";
        case AssistantIntent::Recommendations:      return "recommendations";
        case AssistantIntent::Timeline:             return "timeline";
        case AssistantIntent::Hunt:                 return "hunt";
        case AssistantIntent::ExecutiveBrief:       return "executive-brief";
        case AssistantIntent::ActiveIncidents:      return "active-incidents";
        case AssistantIntent::StorylineLookup:      return "storyline-lookup";
        case AssistantIntent::AssetImpact:          return "asset-impact";
        case AssistantIntent::SeverityOverview:     return "severity-overview";
        case AssistantIntent::MitreExplanation:     return "mitre-explanation";
        case AssistantIntent::RemediationChecklist: return "remediation-checklist";
        case AssistantIntent::QueryHistory:         return "query-history";
        case AssistantIntent::SessionStatus:        return "session-status";
        case AssistantIntent::CorrelationDetails:   return "correlation-details";
        case AssistantIntent::Unknown:              return "unknown";
    }
    return "unknown";
}

[[nodiscard]] QueryLanguage InferTargetLanguage(std::string_view question) {
    const std::string normalized = NormalizeText(question);
    if (normalized.find(" sigma") != std::string::npos || normalized.rfind("sigma", 0) == 0) {
        return QueryLanguage::Sigma;
    }
    if (normalized.find(" kql") != std::string::npos || normalized.rfind("kql", 0) == 0) {
        return QueryLanguage::KQL;
    }
    return QueryLanguage::SSQL;
}

[[nodiscard]] std::optional<std::string> ExtractStorylineId(const AssistantContext& ctx, std::string_view question) {
    auto it = ctx.sessionVariables.find("storylineId");
    if (it != ctx.sessionVariables.end() && !it->second.empty()) {
        return it->second;
    }

    const std::string normalized = NormalizeText(question);
    constexpr std::string_view markers[] = { "storyline ", "incident ", "match " };
    for (const auto marker : markers) {
        const auto position = normalized.find(marker);
        if (position == std::string::npos) {
            continue;
        }
        const auto start = position + marker.size();
        const auto end = normalized.find(' ', start);
        const auto token = normalized.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!token.empty()) {
            return token;
        }
    }

    return std::nullopt;
}

[[nodiscard]] const std::vector<IntentPattern>& GetIntentPatterns() {
    static const std::vector<IntentPattern> kPatterns{
        { AssistantIntent::IncidentSummary,      { "what happened", "summarize the incident", "incident summary" }, 0.96 },
        { AssistantIntent::ActiveIncidents,      { "recent incidents", "show incidents", "active incidents" }, 0.94 },
        { AssistantIntent::ThreatBrief,          { "threat brief", "threat posture", "current threat posture" }, 0.96 },
        { AssistantIntent::Recommendations,      { "what should i do", "recommend actions", "recommended actions" }, 0.97 },
        { AssistantIntent::RemediationChecklist, { "remediation checklist", "containment steps", "what do i remediate" }, 0.95 },
        { AssistantIntent::Timeline,             { "show me the timeline", "incident timeline", "attack timeline" }, 0.97 },
        { AssistantIntent::Hunt,                 { "hunt for", "search for", "look for", "translate to kql", "translate to sigma" }, 0.95 },
        { AssistantIntent::ExecutiveBrief,       { "executive brief", "brief leadership", "leadership summary" }, 0.95 },
        { AssistantIntent::StorylineLookup,      { "show storyline", "storyline details", "incident details" }, 0.92 },
        { AssistantIntent::AssetImpact,          { "affected assets", "who is impacted", "what assets are impacted" }, 0.94 },
        { AssistantIntent::SeverityOverview,     { "how severe", "severity overview", "risk level" }, 0.90 },
        { AssistantIntent::MitreExplanation,     { "mitre mapping", "what techniques", "attack techniques" }, 0.91 },
        { AssistantIntent::QueryHistory,         { "query history", "recent hunts", "translation history" }, 0.89 },
        { AssistantIntent::SessionStatus,        { "session status", "what is this session", "conversation context" }, 0.85 },
        { AssistantIntent::CorrelationDetails,   { "correlation details", "why did this correlate", "correlation match" }, 0.88 }
    };

    return kPatterns;
}

} // anonymous namespace

class SOCAssistantImpl final {
public:
    std::atomic<bool>         initialized{false};
    mutable std::shared_mutex mutex;
    std::unordered_set<std::string> activeSessions;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool CreateSchema() const;
    [[nodiscard]] AssistantResponse Ask(const AssistantContext& ctx, std::string_view question);
    [[nodiscard]] std::string GetThreatBrief() const;
    [[nodiscard]] std::vector<std::string> GetRecommendations(std::string_view storylineId) const;
    [[nodiscard]] std::string StartSession();
    void EndSession(std::string_view sessionId);

private:
    [[nodiscard]] std::pair<AssistantIntent, double> ClassifyIntent(std::string_view question) const;
    void PersistMessage(std::string_view sessionId,
                        std::string_view role,
                        std::string_view content,
                        double confidence,
                        std::string_view reasoning) const;
    void UpsertSession(std::string_view sessionId, bool active) const;
    [[nodiscard]] std::optional<XDR::Storyline> ResolveStoryline(const AssistantContext& ctx,
                                                                 std::string_view question) const;
};

[[nodiscard]] bool SOCAssistantImpl::CreateSchema() const {
    auto& db = DB::Instance();
    DBErr err;

    constexpr std::string_view kSchema = R"SQL(
        CREATE TABLE IF NOT EXISTS xdr_assistant_sessions (
            session_id        TEXT PRIMARY KEY,
            started_at_ms     INTEGER NOT NULL,
            last_activity_ms  INTEGER NOT NULL,
            ended_at_ms       INTEGER DEFAULT 0,
            is_active         INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_assistant_sessions_active
            ON xdr_assistant_sessions(is_active, last_activity_ms DESC);

        CREATE TABLE IF NOT EXISTS xdr_assistant_messages (
            message_id        TEXT PRIMARY KEY,
            session_id        TEXT NOT NULL,
            role              TEXT NOT NULL,
            content           TEXT NOT NULL,
            confidence        REAL NOT NULL,
            reasoning         TEXT DEFAULT '',
            created_at_ms     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_assistant_messages_session
            ON xdr_assistant_messages(session_id, created_at_ms DESC);
    )SQL";

    if (!db.Execute(kSchema, &err)) {
        Logger::Error("{} Failed to create SOC assistant schema: {}",
                      kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }

    return true;
}

[[nodiscard]] bool SOCAssistantImpl::Initialize() {
    if (initialized.load(std::memory_order_acquire)) {
        return true;
    }

    Logger::Info("{} Initializing SOC assistant...", kLogPrefix);

    if (!CreateSchema()) {
        return false;
    }

    if (!QueryTranslator::Instance().IsInitialized() && !QueryTranslator::Instance().Initialize()) {
        Logger::Warn("{} Query translator dependency failed to initialize", kLogPrefix);
    }
    if (!IncidentSummarizer::Instance().IsInitialized() && !IncidentSummarizer::Instance().Initialize()) {
        Logger::Warn("{} Incident summarizer dependency failed to initialize", kLogPrefix);
    }
    if (!XDR::StorylineBuilder::Instance().IsInitialized()
        && !XDR::StorylineBuilder::Instance().Initialize()) {
        Logger::Warn("{} Storyline builder dependency failed to initialize", kLogPrefix);
    }

    initialized.store(true, std::memory_order_release);
    Logger::Info("{} SOC assistant initialized", kLogPrefix);
    return true;
}

void SOCAssistantImpl::Shutdown() {
    if (!initialized.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    std::unique_lock lock(mutex);
    for (const auto& sessionId : activeSessions) {
        UpsertSession(sessionId, false);
    }
    Logger::Info("{} SOC assistant shut down ({} active sessions closed)",
                 kLogPrefix, activeSessions.size());
    activeSessions.clear();
}

[[nodiscard]] std::pair<AssistantIntent, double> SOCAssistantImpl::ClassifyIntent(std::string_view question) const {
    const std::string normalized = NormalizeText(question);
    AssistantIntent bestIntent = AssistantIntent::Unknown;
    size_t bestMatches = 0;
    double bestConfidence = 0.35;

    for (const auto& pattern : GetIntentPatterns()) {
        size_t matches = 0;
        for (const auto& trigger : pattern.triggers) {
            if (normalized.find(trigger) != std::string::npos) {
                ++matches;
            }
        }

        if (matches == 0) {
            continue;
        }

        const double confidence = pattern.baseConfidence + static_cast<double>(matches - 1) * 0.02;
        if (matches > bestMatches || (matches == bestMatches && confidence > bestConfidence)) {
            bestIntent = pattern.intent;
            bestMatches = matches;
            bestConfidence = confidence;
        }
    }

    if (bestIntent == AssistantIntent::Unknown && normalized.find("hunt") != std::string::npos) {
        bestIntent = AssistantIntent::Hunt;
        bestConfidence = 0.78;
    }

    return { bestIntent, std::min(0.99, bestConfidence) };
}

void SOCAssistantImpl::PersistMessage(std::string_view sessionId,
                                      std::string_view role,
                                      std::string_view content,
                                      const double confidence,
                                      std::string_view reasoning) const {
    if (sessionId.empty()) {
        return;
    }

    auto& db = DB::Instance();
    DBErr err;
    const bool stored = db.ExecuteWithParams(
        "INSERT INTO xdr_assistant_messages "
        "(message_id, session_id, role, content, confidence, reasoning, created_at_ms) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        &err,
        GenerateMessageId(),
        std::string(sessionId),
        std::string(role),
        std::string(content),
        confidence,
        std::string(reasoning),
        ToUnixMilliseconds(Clock::now()));

    if (!stored) {
        Logger::Warn("{} Failed to persist {} message for session '{}': {}",
                     kLogPrefix, std::string(role), std::string(sessionId), SU::ToNarrow(err.message));
    }
}

void SOCAssistantImpl::UpsertSession(std::string_view sessionId, const bool active) const {
    auto& db = DB::Instance();
    DBErr err;
    const int64_t nowMs = ToUnixMilliseconds(Clock::now());

    const bool stored = db.ExecuteWithParams(
        "INSERT INTO xdr_assistant_sessions (session_id, started_at_ms, last_activity_ms, ended_at_ms, is_active) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(session_id) DO UPDATE SET "
        "last_activity_ms = excluded.last_activity_ms, "
        "ended_at_ms = excluded.ended_at_ms, "
        "is_active = excluded.is_active",
        &err,
        std::string(sessionId),
        nowMs,
        nowMs,
        active ? 0LL : nowMs,
        active ? 1 : 0);

    if (!stored) {
        Logger::Warn("{} Failed to persist session '{}': {}",
                     kLogPrefix, std::string(sessionId), SU::ToNarrow(err.message));
    }
}

[[nodiscard]] std::optional<XDR::Storyline> SOCAssistantImpl::ResolveStoryline(const AssistantContext& ctx,
                                                                                std::string_view question) const {
    if (const auto storylineId = ExtractStorylineId(ctx, question); storylineId.has_value()) {
        if (auto storyline = XDR::StorylineBuilder::Instance().GetStoryline(*storylineId); storyline.has_value()) {
            return storyline;
        }
        if (auto summary = IncidentSummarizer::Instance().GetCachedSummary(*storylineId); summary.has_value()) {
            auto activeStorylines = XDR::StorylineBuilder::Instance().GetActiveStorylines();
            auto it = std::find_if(activeStorylines.begin(), activeStorylines.end(),
                                   [&](const XDR::Storyline& storyline) {
                                       return storyline.storylineId == summary->storylineId;
                                   });
            if (it != activeStorylines.end()) {
                return *it;
            }
        }
    }

    auto activeStorylines = XDR::StorylineBuilder::Instance().GetActiveStorylines();
    if (activeStorylines.empty()) {
        return std::nullopt;
    }

    std::sort(activeStorylines.begin(), activeStorylines.end(),
              [](const XDR::Storyline& left, const XDR::Storyline& right) {
                  return left.endTime > right.endTime;
              });
    return activeStorylines.front();
}

[[nodiscard]] std::string SOCAssistantImpl::StartSession() {
    const std::string sessionId = GenerateSessionId();
    {
        std::unique_lock lock(mutex);
        activeSessions.insert(sessionId);
    }
    UpsertSession(sessionId, true);
    Logger::Info("{} Started session '{}'", kLogPrefix, sessionId);
    return sessionId;
}

void SOCAssistantImpl::EndSession(std::string_view sessionId) {
    if (sessionId.empty()) {
        return;
    }

    {
        std::unique_lock lock(mutex);
        activeSessions.erase(std::string(sessionId));
    }
    UpsertSession(sessionId, false);
    Logger::Info("{} Ended session '{}'", kLogPrefix, std::string(sessionId));
}

[[nodiscard]] std::vector<std::string> SOCAssistantImpl::GetRecommendations(std::string_view storylineId) const {
    if (storylineId.empty()) {
        return {
            "Select the highest-severity active storyline and validate whether containment is required.",
            "Preserve endpoint, network, and identity evidence before disruptive response actions.",
            "Reset or revoke any exposed privileged credentials linked to the activity."
        };
    }

    if (auto cached = IncidentSummarizer::Instance().GetCachedSummary(storylineId); cached.has_value()) {
        return cached->recommendations;
    }

    if (auto storyline = XDR::StorylineBuilder::Instance().GetStoryline(storylineId); storyline.has_value()) {
        return IncidentSummarizer::Instance().SummarizeStoryline(*storyline, SummaryLevel::Detailed).recommendations;
    }

    return {
        std::format("No cached storyline '{}' was found; validate the identifier and inspect recent active incidents.", std::string(storylineId)),
        "Review telemetry integrity and confirm the incident scope before issuing containment actions."
    };
}

[[nodiscard]] std::string SOCAssistantImpl::GetThreatBrief() const {
    auto storylines = XDR::StorylineBuilder::Instance().GetActiveStorylines();
    if (storylines.empty()) {
        return "Threat posture is currently stable: no active XDR storylines are present.";
    }

    std::sort(storylines.begin(), storylines.end(),
              [](const XDR::Storyline& left, const XDR::Storyline& right) {
                  if (left.severity != right.severity) {
                      return static_cast<int>(left.severity) > static_cast<int>(right.severity);
                  }
                  return left.endTime > right.endTime;
              });

    size_t criticalOrHigh = 0;
    std::set<std::string> topTechniques;
    for (const auto& storyline : storylines) {
        if (storyline.severity >= XDR::IncidentSeverity::High) {
            ++criticalOrHigh;
        }
        for (size_t index = 0; index < std::min<size_t>(2, storyline.mitreTechniques.size()); ++index) {
            topTechniques.insert(storyline.mitreTechniques[index]);
        }
    }

    std::ostringstream stream;
    stream << std::format("Threat posture: {} active storyline(s), {} high-or-critical. ",
                          storylines.size(), criticalOrHigh);
    stream << "Top storyline: " << storylines.front().title << ".";

    if (!topTechniques.empty()) {
        stream << " Dominant ATT&CK techniques: ";
        size_t index = 0;
        for (const auto& technique : topTechniques) {
            if (index++ != 0) {
                stream << ", ";
            }
            stream << technique;
            if (index >= 5) {
                break;
            }
        }
    }

    return stream.str();
}

[[nodiscard]] AssistantResponse SOCAssistantImpl::Ask(const AssistantContext& ctx, std::string_view question) {
    AssistantResponse response;
    response.responseId = GenerateResponseId();

    if (!initialized.load(std::memory_order_acquire)) {
        response.content = "SOC assistant is not initialized.";
        response.reasoning = "Initialization guard blocked request processing.";
        return response;
    }

    const std::string sessionId = !ctx.sessionId.empty() ? ctx.sessionId : StartSession();
    UpsertSession(sessionId, true);
    PersistMessage(sessionId, "user", question, 1.0, "Analyst prompt");

    const auto [intent, intentConfidence] = ClassifyIntent(question);
    response.confidence = intentConfidence;
    response.reasoning = std::format("Intent classified as '{}' with {:.2f} confidence.",
                                     IntentToString(intent), intentConfidence);

    switch (intent) {
        case AssistantIntent::IncidentSummary:
        case AssistantIntent::ActiveIncidents: {
            auto storylines = XDR::StorylineBuilder::Instance().GetActiveStorylines();
            if (storylines.empty()) {
                response.content = "No active XDR storylines are available to summarize.";
                response.suggestedFollowups = { "Get the threat brief", "Hunt for suspicious activity" };
                break;
            }

            std::sort(storylines.begin(), storylines.end(),
                      [](const XDR::Storyline& left, const XDR::Storyline& right) {
                          if (left.severity != right.severity) {
                              return static_cast<int>(left.severity) > static_cast<int>(right.severity);
                          }
                          return left.endTime > right.endTime;
                      });

            std::ostringstream stream;
            const size_t limit = std::min<size_t>(3, storylines.size());
            for (size_t index = 0; index < limit; ++index) {
                const auto summary = IncidentSummarizer::Instance().SummarizeStoryline(storylines[index], SummaryLevel::Brief);
                stream << std::format("[{}] {}", index + 1, summary.title);
                if (!summary.affectedAssets.empty()) {
                    stream << " — " << summary.affectedAssets.front();
                }
                if (index + 1 < limit) {
                    stream << '\n';
                }
            }
            response.content = stream.str();
            response.suggestedFollowups = { "Show me the timeline", "What should I do?", "Generate an executive brief" };
            break;
        }
        case AssistantIntent::ThreatBrief:
        case AssistantIntent::SeverityOverview: {
            response.content = GetThreatBrief();
            response.suggestedFollowups = { "Summarize the most severe incident", "What should I do?", "Show me the timeline" };
            break;
        }
        case AssistantIntent::Recommendations:
        case AssistantIntent::RemediationChecklist: {
            const auto storyline = ResolveStoryline(ctx, question);
            const auto recommendations = GetRecommendations(storyline.has_value() ? storyline->storylineId : std::string_view{});
            std::ostringstream stream;
            stream << "Recommended actions:";
            for (size_t index = 0; index < recommendations.size(); ++index) {
                stream << std::format("\n{}. {}", index + 1, recommendations[index]);
            }
            response.content = stream.str();
            response.suggestedFollowups = { "Why are these actions recommended?", "Show me the timeline" };
            break;
        }
        case AssistantIntent::Timeline:
        case AssistantIntent::StorylineLookup: {
            const auto storyline = ResolveStoryline(ctx, question);
            if (!storyline.has_value()) {
                response.content = "No storyline is available to build a timeline.";
                response.suggestedFollowups = { "What happened?", "Get the threat brief" };
                break;
            }

            response.content = XDR::StorylineBuilder::Instance().GenerateNarrative(storyline->storylineId);
            response.suggestedFollowups = { "What should I do?", "Which MITRE techniques are involved?" };
            break;
        }
        case AssistantIntent::Hunt: {
            std::optional<HuntQuery> translated;
            switch (InferTargetLanguage(question)) {
                case QueryLanguage::KQL:
                    translated = QueryTranslator::Instance().TranslateToKQL(question);
                    break;
                case QueryLanguage::Sigma:
                    translated = QueryTranslator::Instance().TranslateToSigma(question);
                    break;
                case QueryLanguage::SSQL:
                case QueryLanguage::Natural:
                default:
                    translated = QueryTranslator::Instance().TranslateToSSQL(question);
                    break;
            }

            if (!translated.has_value()) {
                response.content = "I could not map that hunt request to a validated XDR query template.";
                response.suggestedFollowups = { "Hunt for lateral movement", "Show failed logins in the last hour" };
                break;
            }

            response.content = std::format("{}\n\nExplanation: {}",
                                           translated->translatedQuery,
                                           translated->explanation);
            response.confidence = translated->confidence;
            response.reasoning = std::format("Delegated hunt translation to QueryTranslator with query '{}'.",
                                             translated->queryId);
            response.suggestedFollowups = { "Translate the same hunt to KQL", "Show recent hunt history" };
            break;
        }
        case AssistantIntent::ExecutiveBrief: {
            auto storylines = XDR::StorylineBuilder::Instance().GetActiveStorylines();
            std::vector<IncidentSummary> summaries;
            summaries.reserve(std::min<size_t>(5, storylines.size()));
            for (size_t index = 0; index < std::min<size_t>(5, storylines.size()); ++index) {
                summaries.push_back(IncidentSummarizer::Instance().SummarizeStoryline(storylines[index], SummaryLevel::Executive));
            }
            response.content = IncidentSummarizer::Instance().GenerateExecutiveBrief(summaries);
            response.suggestedFollowups = { "What happened?", "What should I do?" };
            break;
        }
        case AssistantIntent::AssetImpact: {
            const auto storyline = ResolveStoryline(ctx, question);
            if (!storyline.has_value()) {
                response.content = "No active storyline is available to assess impacted assets.";
                response.suggestedFollowups = { "What happened?", "Get the threat brief" };
                break;
            }

            const auto summary = IncidentSummarizer::Instance().SummarizeStoryline(*storyline, SummaryLevel::Standard);
            std::ostringstream stream;
            stream << "Impacted assets:";
            for (size_t index = 0; index < summary.affectedAssets.size(); ++index) {
                stream << std::format("\n{}. {}", index + 1, summary.affectedAssets[index]);
            }
            response.content = stream.str();
            response.suggestedFollowups = { "Show me the timeline", "What should I do?" };
            break;
        }
        case AssistantIntent::MitreExplanation:
        case AssistantIntent::CorrelationDetails: {
            const auto storyline = ResolveStoryline(ctx, question);
            if (!storyline.has_value()) {
                response.content = "No active storyline is available for MITRE or correlation detail review.";
                response.suggestedFollowups = { "What happened?", "Get the threat brief" };
                break;
            }

            const auto summary = IncidentSummarizer::Instance().SummarizeStoryline(*storyline, SummaryLevel::Detailed);
            response.content = summary.mitreMappingSummary;
            response.suggestedFollowups = { "Show me the timeline", "What should I do?" };
            break;
        }
        case AssistantIntent::QueryHistory: {
            const auto history = QueryTranslator::Instance().GetTranslationHistory(5);
            if (history.empty()) {
                response.content = "No hunt translation history is available.";
                response.suggestedFollowups = { "Hunt for lateral movement", "Show failed logins in the last hour" };
                break;
            }

            std::ostringstream stream;
            for (size_t index = 0; index < history.size(); ++index) {
                stream << std::format("[{}] {} -> {}", index + 1, history[index].naturalLanguage, history[index].queryId);
                if (index + 1 < history.size()) {
                    stream << '\n';
                }
            }
            response.content = stream.str();
            response.suggestedFollowups = { "Translate the latest hunt to Sigma", "Get the threat brief" };
            break;
        }
        case AssistantIntent::SessionStatus: {
            response.content = std::format("Session '{}' contains {} historical turn(s) and {} session variable(s).",
                                           sessionId, ctx.conversationHistory.size(), ctx.sessionVariables.size());
            response.suggestedFollowups = { "What happened?", "Get the threat brief" };
            break;
        }
        case AssistantIntent::Unknown:
        default: {
            response.content =
                "I can summarize incidents, build hunt queries, explain timelines, provide recommendations, and generate executive briefs.";
            response.suggestedFollowups = { "What happened?", "Hunt for lateral movement", "What should I do?" };
            break;
        }
    }

    PersistMessage(sessionId, "assistant", response.content, response.confidence, response.reasoning);
    Logger::Info("{} Answered session '{}' with intent '{}'",
                 kLogPrefix, sessionId, IntentToString(intent));
    return response;
}

SOCAssistant& SOCAssistant::Instance() {
    static SOCAssistant instance;
    return instance;
}

bool SOCAssistant::HasInstance() noexcept {
    return Instance().IsInitialized();
}

SOCAssistant::SOCAssistant()
    : m_impl(std::make_unique<SOCAssistantImpl>()) {
}

SOCAssistant::~SOCAssistant() {
    Shutdown();
}

bool SOCAssistant::Initialize() {
    return m_impl->Initialize();
}

void SOCAssistant::Shutdown() {
    m_impl->Shutdown();
}

bool SOCAssistant::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

AssistantResponse SOCAssistant::Ask(const AssistantContext& ctx, std::string_view question) {
    return m_impl->Ask(ctx, question);
}

std::string SOCAssistant::GetThreatBrief() const {
    return m_impl->GetThreatBrief();
}

std::vector<std::string> SOCAssistant::GetRecommendations(std::string_view storylineId) const {
    return m_impl->GetRecommendations(storylineId);
}

std::string SOCAssistant::StartSession() {
    return m_impl->StartSession();
}

void SOCAssistant::EndSession(std::string_view sessionId) {
    m_impl->EndSession(sessionId);
}

} // namespace ShadowStrike::Products::PhantomXDR::AIAssistant

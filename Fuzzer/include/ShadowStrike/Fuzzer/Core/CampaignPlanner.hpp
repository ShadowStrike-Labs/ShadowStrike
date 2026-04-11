#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

enum class PlannedCampaignScope {
    Kernel,
    UserMode
};

enum class PlannedInputKind {
    WorkspaceArtifact,
    LogicalCorpusManifest
};

[[nodiscard]] std::string_view ToString(PlannedCampaignScope scope);
[[nodiscard]] std::string_view ToString(PlannedInputKind kind);

struct CampaignInputReference {
    std::string sourceId;
    PlannedInputKind kind;
    std::string relativePath;
    std::string sourceKey;
    std::string schemaId;
    std::string surfaceId;
    std::string description;
};

struct PlannedCampaignStep {
    std::uint32_t order;
    std::string deliveryPhase;
    std::string objective;
    std::string expectation;
    bool resetConnectionAfter{ false };
    CampaignInputReference input;
};

struct CampaignExecutionPlan {
    std::string id;
    PlannedCampaignScope scope;
    std::string targetId;
    std::string campaignId;
    std::string campaignName;
    std::string executionLane;
    std::string isolation;
    std::string snapshotProfile;
    std::string harness;
    bool requiresFreshSession{ false };
    std::uint32_t maxIterationsPerCycle{ 0 };
    std::uint32_t maxArtifactsPerIteration{ 0 };
    std::string objective;
    std::vector<std::string> guardrails;
    std::vector<std::string> telemetry;
    std::vector<std::string> crashSignals;
    std::vector<CampaignInputReference> seedSources;
    std::vector<PlannedCampaignStep> steps;
};

class CampaignPlanner final {
public:
    [[nodiscard]] static const std::vector<CampaignExecutionPlan>& GetDefaultPlans();
    [[nodiscard]] static const CampaignExecutionPlan* FindById(std::string_view id);
    [[nodiscard]] static std::string RenderJson(const std::vector<CampaignExecutionPlan>& plans);
    [[nodiscard]] static std::string RenderJson(const CampaignExecutionPlan& plan);
};

}  // namespace ShadowStrike::Fuzzer

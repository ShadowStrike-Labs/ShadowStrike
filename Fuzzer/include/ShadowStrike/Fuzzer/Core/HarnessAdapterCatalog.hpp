#pragma once

#include "ShadowStrike/Fuzzer/Core/CampaignPlanner.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

enum class HarnessAdapterKind {
    KernelVmCampaign,
    BrokerSession,
    ParserFrontDoor,
    DifferentialParser
};

[[nodiscard]] std::string_view ToString(HarnessAdapterKind kind);

struct HarnessAdapterDescriptor {
    std::string id;
    HarnessAdapterKind kind;
    std::string laneId;
    std::string workerImage;
    std::string description;
    std::vector<std::string> acceptedHarnessNames;
    std::vector<std::string> acceptedTargetIds;
    std::vector<std::string> requiredWorkspaceDirectories;
    std::vector<std::string> preflightChecks;
    std::vector<std::string> outputs;
    std::vector<std::string> failureSignals;
    std::vector<std::string> guardrails;
};

class HarnessAdapterCatalog final {
public:
    [[nodiscard]] static const std::vector<HarnessAdapterDescriptor>& GetDefaultAdapters();
    [[nodiscard]] static const HarnessAdapterDescriptor* FindById(std::string_view id);
    [[nodiscard]] static const HarnessAdapterDescriptor* FindForPlan(const CampaignExecutionPlan& plan);
    [[nodiscard]] static std::string DescribeText(const HarnessAdapterDescriptor& adapter);
    [[nodiscard]] static std::string RenderJson(const std::vector<HarnessAdapterDescriptor>& adapters);
};

}  // namespace ShadowStrike::Fuzzer

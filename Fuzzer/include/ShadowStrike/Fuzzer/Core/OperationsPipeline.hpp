#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

enum class PipelineStageLane {
    ControlPlane,
    KernelVm,
    UserModeBroker,
    UserModeParser,
    Triage
};

[[nodiscard]] std::string_view ToString(PipelineStageLane lane);

struct WorkspaceDirectoryDescriptor {
    std::string relativePath;
    std::string purpose;
    std::string retentionPolicy;
    bool mutableData{ true };
};

struct PipelineStageDescriptor {
    std::string id;
    PipelineStageLane lane;
    std::string description;
    std::vector<std::string> inputs;
    std::vector<std::string> outputs;
    std::vector<std::string> guardrails;
};

struct OperationsPipelineDescriptor {
    std::string id;
    std::string description;
    std::vector<WorkspaceDirectoryDescriptor> workspaceDirectories;
    std::vector<PipelineStageDescriptor> stages;
    std::vector<std::string> metrics;
    std::vector<std::string> stopConditions;
};

class OperationsPipelineCatalog final {
public:
    [[nodiscard]] static const OperationsPipelineDescriptor& GetDefaultPipeline();
    [[nodiscard]] static std::string DescribeText(const OperationsPipelineDescriptor& pipeline);
    [[nodiscard]] static std::string RenderJson(const OperationsPipelineDescriptor& pipeline);
};

}  // namespace ShadowStrike::Fuzzer

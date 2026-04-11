#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

enum class DispatchReadiness {
    Ready,
    Blocked
};

[[nodiscard]] std::string_view ToString(DispatchReadiness readiness);

struct DispatchLaneBinding {
    std::string laneId;
    std::string laneKind;
    std::string isolation;
    std::uint32_t maxConcurrentWorkers{ 0 };
    std::string schedulerPolicy;
    std::string queueDirectory;
    std::string runStateDirectory;
    std::string telemetryDirectory;
    std::string crashArtifactRoot;
    std::vector<std::string> guardrails;
};

struct PlannedDispatchItem {
    std::string planId;
    std::string targetId;
    std::string scope;
    std::string harness;
    std::string adapterId;
    std::string laneId;
    std::string queueRelativePath;
    std::string runStateRelativePath;
    std::string telemetryRelativePath;
    std::string crashArtifactRelativePath;
    bool requiresFreshSession{ false };
    std::uint32_t maxIterationsPerCycle{ 0 };
    std::uint32_t maxArtifactsPerIteration{ 0 };
    DispatchReadiness readiness{ DispatchReadiness::Blocked };
    std::string readinessReason;
    std::vector<std::string> requiredInputs;
};

struct DispatchManifest {
    std::string id;
    std::string description;
    std::vector<std::string> prerequisites;
    std::vector<DispatchLaneBinding> lanes;
    std::vector<PlannedDispatchItem> items;
};

class DispatchRuntime final {
public:
    [[nodiscard]] static DispatchManifest BuildWorkspaceManifest(const std::filesystem::path& workspaceRoot);
    [[nodiscard]] static std::string DescribeText(const DispatchManifest& manifest);
    [[nodiscard]] static std::string RenderJson(const DispatchManifest& manifest);
    [[nodiscard]] static bool MaterializeWorkspaceState(
        const std::filesystem::path& workspaceRoot,
        std::string& errorMessage);
};

}  // namespace ShadowStrike::Fuzzer

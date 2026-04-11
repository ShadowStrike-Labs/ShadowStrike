#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

enum class RunnerExecutionStatus {
    Ready,
    Running,
    Completed,
    Crashed,
    Quarantined,
    Blocked
};

[[nodiscard]] std::string_view ToString(RunnerExecutionStatus status);

struct ReplayArtifactDescriptor {
    std::string planId;
    std::string relativePath;
    std::string reason;
};

struct CrashBucketDescriptor {
    std::string bucketId;
    std::string planId;
    std::string relativePath;
    std::string signal;
};

struct QuarantineArtifactDescriptor {
    std::string planId;
    std::string relativePath;
    std::string reason;
};

struct RunnerExecutionRecord {
    std::string planId;
    std::string targetId;
    std::string laneId;
    std::string adapterId;
    std::string workerImage;
    std::string executionMode;
    RunnerExecutionStatus status{ RunnerExecutionStatus::Blocked };
    std::string statusReason;
    std::string queueRelativePath;
    std::string executionArtifactRelativePath;
    std::string telemetryArtifactRelativePath;
    std::string replayArtifactRelativePath;
    std::string crashBucketRelativePath;
    bool requiresFreshSession{ false };
    std::uint32_t maxIterationsPerCycle{ 0 };
    std::uint32_t maxArtifactsPerIteration{ 0 };
    std::vector<std::string> requiredWorkspaceDirectories;
    std::vector<std::string> requiredInputs;
    std::vector<std::string> preflightChecks;
    std::vector<std::string> guardrails;
};

struct RunnerExecutionLedger {
    std::string id;
    std::string description;
    std::vector<std::string> invariants;
    std::vector<RunnerExecutionRecord> records;
    std::vector<ReplayArtifactDescriptor> pendingReplays;
    std::vector<CrashBucketDescriptor> crashBuckets;
    std::vector<QuarantineArtifactDescriptor> quarantines;
};

class RunnerExecutionRuntime final {
public:
    [[nodiscard]] static RunnerExecutionLedger ExecuteWorkspace(
        const std::filesystem::path& workspaceRoot,
        std::string& errorMessage);
    [[nodiscard]] static std::string DescribeText(const RunnerExecutionLedger& ledger);
    [[nodiscard]] static std::string RenderJson(const RunnerExecutionLedger& ledger);
};

}  // namespace ShadowStrike::Fuzzer

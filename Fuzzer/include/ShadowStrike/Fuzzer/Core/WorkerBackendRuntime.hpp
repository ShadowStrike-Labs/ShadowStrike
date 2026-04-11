#pragma once

#include "ShadowStrike/Fuzzer/Core/HarnessAdapterCatalog.hpp"
#include "ShadowStrike/Fuzzer/Core/RunnerExecutionRuntime.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace ShadowStrike::Fuzzer {

enum class WorkerCommandKind {
    KernelVm,
    Broker,
    Parser
};

[[nodiscard]] std::string_view ToString(WorkerCommandKind kind);

struct WorkerProcessResult {
    std::string planId;
    std::string laneId;
    std::string adapterId;
    std::string workerImage;
    std::string resultRelativePath;
    std::string logRelativePath;
    std::string statusReason;
    std::string failureSignal;
    std::uint32_t exitCode{ 0 };
    RunnerExecutionStatus status{ RunnerExecutionStatus::Blocked };
};

class WorkerBackendRuntime final {
public:
    [[nodiscard]] static bool LaunchWorkerProcess(
        const std::filesystem::path& workspaceRoot,
        const CampaignExecutionPlan& plan,
        const HarnessAdapterDescriptor& adapter,
        std::string& errorMessage,
        WorkerProcessResult& result);

    [[nodiscard]] static int RunWorkerCommand(
        WorkerCommandKind kind,
        const std::filesystem::path& workspaceRoot,
        std::string_view planId);
};

}  // namespace ShadowStrike::Fuzzer

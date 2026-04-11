#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

enum class EngineStageKind {
    CorpusIntake,
    SchemaPlanning,
    Mutation,
    StatefulSequencing,
    IsolatedExecution,
    CoverageCollection,
    CrashTriage,
    Minimization,
    CorpusPromotion
};

enum class EngineLaneKind {
    KernelVm,
    UserModeBroker,
    UserModeParser,
    DifferentialDecoder
};

enum class EngineLaneIsolation {
    SnapshotVm,
    ProcessIsolated,
    InProcess
};

[[nodiscard]] std::string_view ToString(EngineStageKind kind);
[[nodiscard]] std::string_view ToString(EngineLaneKind kind);
[[nodiscard]] std::string_view ToString(EngineLaneIsolation isolation);

struct EngineStageDescriptor {
    std::string id;
    EngineStageKind kind;
    std::string owner;
    std::string description;
    std::vector<std::string> inputs;
    std::vector<std::string> outputs;
    std::vector<std::string> invariants;
};

struct EngineLaneDescriptor {
    std::string id;
    EngineLaneKind kind;
    EngineLaneIsolation isolation;
    std::string schedulerPolicy;
    std::uint32_t maxConcurrentWorkers;
    std::vector<std::string> boundTargetIds;
    std::vector<std::string> coverageSignals;
    std::vector<std::string> crashArtifacts;
    std::vector<std::string> guardrails;
};

struct EngineArchitectureDescriptor {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> guardrails;
    std::vector<std::string> telemetry;
    std::vector<EngineStageDescriptor> stages;
    std::vector<EngineLaneDescriptor> lanes;
};

class EngineArchitectureCatalog final {
public:
    [[nodiscard]] static const EngineArchitectureDescriptor& GetDefaultArchitecture();
    [[nodiscard]] static std::string DescribeText(const EngineArchitectureDescriptor& architecture);
    [[nodiscard]] static std::string RenderJson(const EngineArchitectureDescriptor& architecture);
};

}  // namespace ShadowStrike::Fuzzer

#include "ShadowStrike/Fuzzer/Core/EngineArchitecture.hpp"

#include "ShadowStrike/Fuzzer/Targets/KernelTargetCatalog.hpp"
#include "ShadowStrike/Fuzzer/Targets/UserModeTargetCatalog.hpp"

#include <sstream>
#include <string_view>

namespace ShadowStrike::Fuzzer {

namespace {

[[nodiscard]] std::string EscapeJson(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);

    for (const char ch : value) {
        switch (ch) {
        case '\\': escaped += "\\\\"; break;
        case '"': escaped += "\\\""; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            escaped.push_back(ch);
            break;
        }
    }

    return escaped;
}

void RenderStringArray(std::ostringstream& stream,
    std::string_view name,
    const std::vector<std::string>& values,
    std::string_view indent)
{
    stream << indent << '"' << name << "\": [";
    if (!values.empty()) {
        stream << '\n';
        for (std::size_t index = 0; index < values.size(); ++index) {
            stream << indent << "  \"" << EscapeJson(values[index]) << '"';
            if (index + 1 != values.size()) {
                stream << ',';
            }
            stream << '\n';
        }
        stream << indent;
    }
    stream << ']';
}

[[nodiscard]] EngineArchitectureDescriptor BuildArchitecture() {
    const auto& kernelTargets = KernelTargetCatalog::GetDefaultTargets();

    std::vector<std::string> kernelTargetIds;
    kernelTargetIds.reserve(kernelTargets.size());
    for (const auto& target : kernelTargets) {
        kernelTargetIds.push_back(target.id);
    }

    const auto& userModeTargets = UserModeTargetCatalog::GetDefaultTargets();
    std::vector<std::string> userModeBrokerTargetIds;
    std::vector<std::string> userModeParserTargetIds;
    userModeBrokerTargetIds.reserve(userModeTargets.size());
    userModeParserTargetIds.reserve(userModeTargets.size());

    for (const auto& target : userModeTargets) {
        switch (target.execution) {
        case UserModeExecutionKind::BrokerProcess:
            userModeBrokerTargetIds.push_back(target.id);
            break;
        case UserModeExecutionKind::InProcessParser:
        case UserModeExecutionKind::DifferentialHarness:
            userModeParserTargetIds.push_back(target.id);
            break;
        }
    }

    return EngineArchitectureDescriptor{
        "shadowstrike-fuzzer-v1",
        "ShadowStrike Custom Fuzzer",
        "Windows-first, schema-aware, stateful fuzzing architecture specialized for PhantomSensor, PhantomCore, PhantomEmulator, and PhantomDisassembler.",
        {
            "Kernel lanes may execute only inside snapshot-backed virtual machines.",
            "Every crash bucket must capture the responsible target, campaign, artifact id, schema id, and VM snapshot lineage.",
            "No corpus promotion is allowed until the input has passed crash triage and deterministic replay."
        },
        {
            "iteration-throughput",
            "queue-depth",
            "artifact-reject-rate",
            "coverage-delta",
            "crash-bucket-count",
            "replay-success-rate"
        },
        {
            EngineStageDescriptor{
                "corpus-intake",
                EngineStageKind::CorpusIntake,
                "Seed corpus manager",
                "Loads baseline seeds, structured-invalid variants, and future reproducers into a normalized artifact catalog.",
                { "kernel-seeds", "kernel-variants", "reproducers" },
                { "normalized-artifact-catalog" },
                { "Every artifact must retain stable id, schemaId, parentId, and surfaceId metadata." }
            },
            EngineStageDescriptor{
                "schema-planning",
                EngineStageKind::SchemaPlanning,
                "Protocol schema planner",
                "Maps each artifact to the authoritative ShadowStrike schema and selects mutation axes and campaign eligibility.",
                { "normalized-artifact-catalog", "kernel-message-schemas", "kernel-targets" },
                { "schema-bound-mutation-plan", "campaign-artifact-bindings" },
                { "No artifact may be scheduled against a target whose surfaceId does not match its schema." }
            },
            EngineStageDescriptor{
                "mutation",
                EngineStageKind::Mutation,
                "Structure-aware mutator",
                "Applies deterministic boundary, truncation, overclaim, flag-confusion, and state-transition mutations before execution.",
                { "schema-bound-mutation-plan" },
                { "mutated-artifact-batches" },
                { "Mutations must preserve enough structure to reach the intended parser or state transition." }
            },
            EngineStageDescriptor{
                "stateful-sequencing",
                EngineStageKind::StatefulSequencing,
                "Campaign sequencer",
                "Builds ordered session plans from kernel target campaigns, including fresh-session requirements and per-boot budgets.",
                { "kernel-targets", "mutated-artifact-batches" },
                { "execution-itineraries" },
                { "Fresh-session campaigns may not reuse a connection after a fault-injection step marked resetConnectionAfter." }
            },
            EngineStageDescriptor{
                "isolated-execution",
                EngineStageKind::IsolatedExecution,
                "Worker orchestrator",
                "Dispatches itineraries to the appropriate execution lane, enforces VM guardrails, and tracks per-lane health.",
                { "execution-itineraries", "engine-lanes" },
                { "lane-results", "replay-artifacts", "crash-events" },
                { "Kernel execution must halt immediately when the VM health monitor reports a crash, hang, or stale snapshot state." }
            },
            EngineStageDescriptor{
                "coverage-collection",
                EngineStageKind::CoverageCollection,
                "Coverage and health collector",
                "Collects lightweight coverage proxies, queue telemetry, reply latencies, disconnect reasons, and driver health counters.",
                { "lane-results" },
                { "coverage-deltas", "health-metrics" },
                { "Coverage signals must never suppress crash handling or snapshot restoration." }
            },
            EngineStageDescriptor{
                "crash-triage",
                EngineStageKind::CrashTriage,
                "Crash triage pipeline",
                "Buckets bugchecks, hangs, and disconnect storms by target, campaign, artifact lineage, and stack fingerprint.",
                { "crash-events", "health-metrics" },
                { "crash-buckets", "replay-queue" },
                { "Every bucket must remain reproducible against the originating snapshot profile." }
            },
            EngineStageDescriptor{
                "minimization",
                EngineStageKind::Minimization,
                "Input minimizer",
                "Shrinks reproducing artifacts while preserving the same crash or rejection signature.",
                { "replay-queue" },
                { "minimized-reproducers" },
                { "Minimization may not cross schema boundaries or rewrite the target campaign." }
            },
            EngineStageDescriptor{
                "corpus-promotion",
                EngineStageKind::CorpusPromotion,
                "Corpus promotion gate",
                "Promotes stable, non-crashing, coverage-increasing artifacts into the long-lived corpus and archives blockers.",
                { "coverage-deltas", "minimized-reproducers", "health-metrics" },
                { "promoted-corpus", "blocked-artifact-ledger" },
                { "Artifacts linked to unresolved crash buckets are never promoted." }
            }
        },
        {
            EngineLaneDescriptor{
                "kernel-vm-lane",
                EngineLaneKind::KernelVm,
                EngineLaneIsolation::SnapshotVm,
                "snapshot-sharded round robin with crash quarantine",
                4u,
                kernelTargetIds,
                {
                    "bugcheck code",
                    "reply latency",
                    "disconnect reason",
                    "driver-status delta"
                },
                {
                    "kernel memory dump",
                    "hypervisor console log",
                    "campaign itinerary",
                    "artifact manifest"
                },
                {
                    "Never schedule more than one kernel campaign concurrently inside the same VM snapshot lineage.",
                    "Restore a clean snapshot before replaying any crash bucket.",
                    "Quarantine the VM instance after repeated unexplained reconnect failures."
                }
            },
            EngineLaneDescriptor{
                "usermode-broker-lane",
                EngineLaneKind::UserModeBroker,
                EngineLaneIsolation::ProcessIsolated,
                "process pool with per-target backpressure",
                8u,
                userModeBrokerTargetIds,
                {
                    "coverage bitmap",
                    "exit code",
                    "exception code",
                    "heap diagnostics"
                },
                {
                    "user-mode minidump",
                    "stderr log",
                    "artifact manifest"
                },
                {
                    "Restart the broker worker on any unhandled exception or heap corruption signal."
                }
            },
            EngineLaneDescriptor{
                "usermode-parser-lane",
                EngineLaneKind::UserModeParser,
                EngineLaneIsolation::ProcessIsolated,
                "parser worker pool with corpus bucketing",
                6u,
                userModeParserTargetIds,
                {
                    "coverage bitmap",
                    "decision divergence",
                    "exception code",
                    "parse latency"
                },
                {
                    "user-mode minidump",
                    "artifact manifest",
                    "normalization diff report"
                },
                {
                    "Every crashing parser sample must replay in a fresh worker process before triage.",
                    "Differential harnesses may not share mutable parser state across iterations."
                }
            },
            EngineLaneDescriptor{
                "differential-decoder-lane",
                EngineLaneKind::DifferentialDecoder,
                EngineLaneIsolation::InProcess,
                "low-latency differential scheduler",
                1u,
                {},
                {
                    "decode divergence",
                    "formatting mismatch",
                    "latency percentile"
                },
                {
                    "artifact manifest",
                    "decoder diff report"
                },
                {
                    "Only deterministic decoders may execute in-process."
                }
            }
        }
    };
}

}  // namespace

std::string_view ToString(const EngineStageKind kind) {
    switch (kind) {
    case EngineStageKind::CorpusIntake:
        return "corpus-intake";
    case EngineStageKind::SchemaPlanning:
        return "schema-planning";
    case EngineStageKind::Mutation:
        return "mutation";
    case EngineStageKind::StatefulSequencing:
        return "stateful-sequencing";
    case EngineStageKind::IsolatedExecution:
        return "isolated-execution";
    case EngineStageKind::CoverageCollection:
        return "coverage-collection";
    case EngineStageKind::CrashTriage:
        return "crash-triage";
    case EngineStageKind::Minimization:
        return "minimization";
    case EngineStageKind::CorpusPromotion:
        return "corpus-promotion";
    }

    return "unknown";
}

std::string_view ToString(const EngineLaneKind kind) {
    switch (kind) {
    case EngineLaneKind::KernelVm:
        return "kernel-vm";
    case EngineLaneKind::UserModeBroker:
        return "user-mode-broker";
    case EngineLaneKind::UserModeParser:
        return "user-mode-parser";
    case EngineLaneKind::DifferentialDecoder:
        return "differential-decoder";
    }

    return "unknown";
}

std::string_view ToString(const EngineLaneIsolation isolation) {
    switch (isolation) {
    case EngineLaneIsolation::SnapshotVm:
        return "snapshot-vm";
    case EngineLaneIsolation::ProcessIsolated:
        return "process-isolated";
    case EngineLaneIsolation::InProcess:
        return "in-process";
    }

    return "unknown";
}

const EngineArchitectureDescriptor& EngineArchitectureCatalog::GetDefaultArchitecture() {
    static const EngineArchitectureDescriptor architecture = BuildArchitecture();
    return architecture;
}

std::string EngineArchitectureCatalog::DescribeText(const EngineArchitectureDescriptor& architecture) {
    std::ostringstream stream;
    stream << "Engine Architecture: " << architecture.id << '\n'
           << "Name: " << architecture.name << '\n'
           << "Description: " << architecture.description << "\n\n"
           << "Stages:\n";

    for (const auto& stage : architecture.stages) {
        stream << "  - " << stage.id << " (" << ToString(stage.kind) << ")\n"
               << "    Owner: " << stage.owner << '\n'
               << "    Description: " << stage.description << '\n';
    }

    stream << "\nLanes:\n";
    for (const auto& lane : architecture.lanes) {
        stream << "  - " << lane.id << " (" << ToString(lane.kind) << ", " << ToString(lane.isolation) << ")\n"
               << "    Scheduler: " << lane.schedulerPolicy << '\n'
               << "    Max Concurrent Workers: " << lane.maxConcurrentWorkers << '\n';
    }

    return stream.str();
}

std::string EngineArchitectureCatalog::RenderJson(const EngineArchitectureDescriptor& architecture) {
    std::ostringstream stream;
    stream << "{\n"
           << "  \"id\": \"" << EscapeJson(architecture.id) << "\",\n"
           << "  \"name\": \"" << EscapeJson(architecture.name) << "\",\n"
           << "  \"description\": \"" << EscapeJson(architecture.description) << "\",\n";

    RenderStringArray(stream, "guardrails", architecture.guardrails, "  ");
    stream << ",\n";
    RenderStringArray(stream, "telemetry", architecture.telemetry, "  ");
    stream << ",\n";

    stream << "  \"stages\": [\n";
    for (std::size_t stageIndex = 0; stageIndex < architecture.stages.size(); ++stageIndex) {
        const auto& stage = architecture.stages[stageIndex];
        stream << "    {\n"
               << "      \"id\": \"" << EscapeJson(stage.id) << "\",\n"
               << "      \"kind\": \"" << ToString(stage.kind) << "\",\n"
               << "      \"owner\": \"" << EscapeJson(stage.owner) << "\",\n"
               << "      \"description\": \"" << EscapeJson(stage.description) << "\",\n";
        RenderStringArray(stream, "inputs", stage.inputs, "      ");
        stream << ",\n";
        RenderStringArray(stream, "outputs", stage.outputs, "      ");
        stream << ",\n";
        RenderStringArray(stream, "invariants", stage.invariants, "      ");
        stream << '\n'
               << "    }";
        if (stageIndex + 1 != architecture.stages.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ],\n";

    stream << "  \"lanes\": [\n";
    for (std::size_t laneIndex = 0; laneIndex < architecture.lanes.size(); ++laneIndex) {
        const auto& lane = architecture.lanes[laneIndex];
        stream << "    {\n"
               << "      \"id\": \"" << EscapeJson(lane.id) << "\",\n"
               << "      \"kind\": \"" << ToString(lane.kind) << "\",\n"
               << "      \"isolation\": \"" << ToString(lane.isolation) << "\",\n"
               << "      \"schedulerPolicy\": \"" << EscapeJson(lane.schedulerPolicy) << "\",\n"
               << "      \"maxConcurrentWorkers\": " << lane.maxConcurrentWorkers << ",\n";
        RenderStringArray(stream, "boundTargetIds", lane.boundTargetIds, "      ");
        stream << ",\n";
        RenderStringArray(stream, "coverageSignals", lane.coverageSignals, "      ");
        stream << ",\n";
        RenderStringArray(stream, "crashArtifacts", lane.crashArtifacts, "      ");
        stream << ",\n";
        RenderStringArray(stream, "guardrails", lane.guardrails, "      ");
        stream << '\n'
               << "    }";
        if (laneIndex + 1 != architecture.lanes.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ]\n}\n";

    return stream.str();
}

}  // namespace ShadowStrike::Fuzzer

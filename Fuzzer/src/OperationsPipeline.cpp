#include "ShadowStrike/Fuzzer/Core/OperationsPipeline.hpp"

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

[[nodiscard]] OperationsPipelineDescriptor BuildPipeline() {
    return OperationsPipelineDescriptor{
        "shadowstrike-fuzzer-ops-v1",
        "Operational workspace and promotion pipeline for ShadowStrike fuzzing artifacts, crash buckets, and replay queues.",
        {
            { "corpora\\kernel\\baseline", "Long-lived canonical kernel seeds.", "Promoted artifacts only; retain indefinitely.", true },
            { "corpora\\kernel\\variants", "Structured-invalid kernel variants staged for execution.", "Retain until superseded by a minimized replacement.", true },
            { "corpora\\usermode\\broker", "User-mode IPC corpora for brokered targets.", "Retain while campaigns remain active.", true },
            { "corpora\\usermode\\parser", "Parser and normalization corpora for PE and threat-intel targets.", "Retain while campaigns remain active.", true },
            { "crashes\\incoming", "Raw crash captures awaiting bucketing.", "Purge only after successful bucketing and archival.", true },
            { "crashes\\buckets", "Crash bucket metadata and deduplicated repro lineage.", "Retain indefinitely for regression protection.", true },
            { "reproducers\\pending", "Artifacts queued for deterministic replay.", "Retain until replay outcome is decided.", true },
            { "reproducers\\stable", "Deterministic minimized reproducers.", "Retain indefinitely.", true },
            { "telemetry\\coverage", "Coverage and divergence snapshots.", "Rotate by campaign window.", true },
            { "telemetry\\health", "Queue depth, latency, crash, and worker-health telemetry.", "Rotate by campaign window.", true },
            { "vm\\profiles", "VM profile manifests and snapshot names.", "Version with environment changes.", false },
            { "vm\\crash-collection", "Kernel dump and hypervisor side-channel collection.", "Retain until bucketed and archived.", true },
            { "pipeline\\queue", "Execution itineraries awaiting dispatch.", "Transient; clear after dispatch.", true },
            { "pipeline\\quarantine", "Artifacts or workers blocked from promotion.", "Retain until manually triaged.", true },
            { "pipeline\\promotion", "Artifacts approved for long-lived corpus promotion.", "Drain into corpora and archive metadata.", true },
            { "state", "Run manifests, counters, and last-successful replay markers.", "Retain latest plus recent rollback points.", true }
        },
        {
            PipelineStageDescriptor{
                "artifact-intake",
                PipelineStageLane::ControlPlane,
                "Normalize generated seeds, variants, and future harness output into the workspace staging queues.",
                { "generated artifacts", "external reproducers" },
                { "corpora\\*", "pipeline\\queue" },
                { "Artifact ids must remain stable across reruns.", "Every staged artifact must carry schema and surface metadata." }
            },
            PipelineStageDescriptor{
                "kernel-vm-dispatch",
                PipelineStageLane::KernelVm,
                "Dispatch kernel campaigns onto VM-isolated workers using snapshot-bounded itineraries.",
                { "pipeline\\queue", "vm\\profiles" },
                { "telemetry\\health", "crashes\\incoming", "reproducers\\pending" },
                { "Never execute kernel campaigns on the host.", "Reset to a clean snapshot after crash or stale-state detection." }
            },
            PipelineStageDescriptor{
                "usermode-broker-dispatch",
                PipelineStageLane::UserModeBroker,
                "Run brokered user-mode campaigns inside process-isolated workers with churn and protocol stress enabled.",
                { "pipeline\\queue", "corpora\\usermode\\broker" },
                { "telemetry\\coverage", "crashes\\incoming", "reproducers\\pending" },
                { "Recycle workers after unhandled exceptions or heap corruption." }
            },
            PipelineStageDescriptor{
                "parser-dispatch",
                PipelineStageLane::UserModeParser,
                "Execute parser and differential campaigns in fresh worker processes with corpus bucketing.",
                { "pipeline\\queue", "corpora\\usermode\\parser" },
                { "telemetry\\coverage", "crashes\\incoming", "reproducers\\pending" },
                { "Crashing parser inputs must replay in a fresh worker before bucketing." }
            },
            PipelineStageDescriptor{
                "crash-bucketing",
                PipelineStageLane::Triage,
                "Bucket raw crashes, disconnect storms, and hangs by stack fingerprint, target, and artifact lineage.",
                { "crashes\\incoming", "telemetry\\health" },
                { "crashes\\buckets", "pipeline\\quarantine", "reproducers\\pending" },
                { "Every bucket must point back to the originating snapshot or worker image." }
            },
            PipelineStageDescriptor{
                "deterministic-replay",
                PipelineStageLane::Triage,
                "Replay pending reproducers until stability is proven or the artifact is quarantined.",
                { "reproducers\\pending", "crashes\\buckets" },
                { "reproducers\\stable", "pipeline\\quarantine", "pipeline\\promotion" },
                { "Only deterministic reproducers may enter the stable set.", "Replay may not mutate the original artifact lineage." }
            },
            PipelineStageDescriptor{
                "promotion-gate",
                PipelineStageLane::Triage,
                "Promote non-crashing, coverage-increasing artifacts into the long-lived corpora and persist run state.",
                { "pipeline\\promotion", "telemetry\\coverage", "state" },
                { "corpora\\*", "state" },
                { "Artifacts associated with unresolved crash buckets are never promoted.", "Promotion decisions must be reproducible from stored telemetry." }
            }
        },
        {
            "dispatch-latency",
            "snapshot-restore-time",
            "coverage-delta",
            "crash-bucket-count",
            "replay-success-rate",
            "promotion-throughput"
        },
        {
            "Kernel bugcheck without dump capture",
            "Repeated worker initialization failure",
            "Snapshot restore drift",
            "Promotion gate inconsistency"
        }
    };
}

}  // namespace

std::string_view ToString(const PipelineStageLane lane) {
    switch (lane) {
    case PipelineStageLane::ControlPlane:
        return "control-plane";
    case PipelineStageLane::KernelVm:
        return "kernel-vm";
    case PipelineStageLane::UserModeBroker:
        return "user-mode-broker";
    case PipelineStageLane::UserModeParser:
        return "user-mode-parser";
    case PipelineStageLane::Triage:
        return "triage";
    }

    return "unknown";
}

const OperationsPipelineDescriptor& OperationsPipelineCatalog::GetDefaultPipeline() {
    static const OperationsPipelineDescriptor pipeline = BuildPipeline();
    return pipeline;
}

std::string OperationsPipelineCatalog::DescribeText(const OperationsPipelineDescriptor& pipeline) {
    std::ostringstream stream;
    stream << "Operations Pipeline: " << pipeline.id << '\n'
           << "Description: " << pipeline.description << "\n\n"
           << "Workspace Directories:\n";

    for (const auto& directory : pipeline.workspaceDirectories) {
        stream << "  - " << directory.relativePath << '\n'
               << "    Purpose: " << directory.purpose << '\n';
    }

    stream << "\nStages:\n";
    for (const auto& stage : pipeline.stages) {
        stream << "  - " << stage.id << " (" << ToString(stage.lane) << ")\n"
               << "    Description: " << stage.description << '\n';
    }

    return stream.str();
}

std::string OperationsPipelineCatalog::RenderJson(const OperationsPipelineDescriptor& pipeline) {
    std::ostringstream stream;
    stream << "{\n"
           << "  \"id\": \"" << EscapeJson(pipeline.id) << "\",\n"
           << "  \"description\": \"" << EscapeJson(pipeline.description) << "\",\n"
           << "  \"workspaceDirectories\": [\n";

    for (std::size_t index = 0; index < pipeline.workspaceDirectories.size(); ++index) {
        const auto& directory = pipeline.workspaceDirectories[index];
        stream << "    {\n"
               << "      \"relativePath\": \"" << EscapeJson(directory.relativePath) << "\",\n"
               << "      \"purpose\": \"" << EscapeJson(directory.purpose) << "\",\n"
               << "      \"retentionPolicy\": \"" << EscapeJson(directory.retentionPolicy) << "\",\n"
               << "      \"mutableData\": " << (directory.mutableData ? "true" : "false") << "\n"
               << "    }";
        if (index + 1 != pipeline.workspaceDirectories.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ],\n"
           << "  \"stages\": [\n";

    for (std::size_t index = 0; index < pipeline.stages.size(); ++index) {
        const auto& stage = pipeline.stages[index];
        stream << "    {\n"
               << "      \"id\": \"" << EscapeJson(stage.id) << "\",\n"
               << "      \"lane\": \"" << ToString(stage.lane) << "\",\n"
               << "      \"description\": \"" << EscapeJson(stage.description) << "\",\n";
        RenderStringArray(stream, "inputs", stage.inputs, "      ");
        stream << ",\n";
        RenderStringArray(stream, "outputs", stage.outputs, "      ");
        stream << ",\n";
        RenderStringArray(stream, "guardrails", stage.guardrails, "      ");
        stream << '\n'
               << "    }";
        if (index + 1 != pipeline.stages.size()) {
            stream << ',';
        }
        stream << '\n';
    }

    stream << "  ],\n";
    RenderStringArray(stream, "metrics", pipeline.metrics, "  ");
    stream << ",\n";
    RenderStringArray(stream, "stopConditions", pipeline.stopConditions, "  ");
    stream << "\n}\n";
    return stream.str();
}

}  // namespace ShadowStrike::Fuzzer

#include "ShadowStrike/Fuzzer/Core/RunnerExecutionRuntime.hpp"

#include "ShadowStrike/Fuzzer/Core/CampaignPlanner.hpp"
#include "ShadowStrike/Fuzzer/Core/DispatchRuntime.hpp"
#include "ShadowStrike/Fuzzer/Core/HarnessAdapterCatalog.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string_view>
#include <system_error>

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

[[nodiscard]] bool WriteTextFile(const std::filesystem::path& path, const std::string& text) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    return stream.good();
}

[[nodiscard]] std::vector<std::string> BuildRequiredDirectories(const HarnessAdapterDescriptor& adapter) {
    std::vector<std::string> directories = adapter.requiredWorkspaceDirectories;
    if (std::find(directories.begin(), directories.end(), "state\\executions") == directories.end()) {
        directories.push_back("state\\executions");
    }
    return directories;
}

[[nodiscard]] std::string BuildStatusJson(const RunnerExecutionRecord& record) {
    std::ostringstream stream;
    stream << "{\n"
           << "  \"planId\": \"" << EscapeJson(record.planId) << "\",\n"
           << "  \"targetId\": \"" << EscapeJson(record.targetId) << "\",\n"
           << "  \"laneId\": \"" << EscapeJson(record.laneId) << "\",\n"
           << "  \"adapterId\": \"" << EscapeJson(record.adapterId) << "\",\n"
           << "  \"workerImage\": \"" << EscapeJson(record.workerImage) << "\",\n"
           << "  \"executionMode\": \"" << EscapeJson(record.executionMode) << "\",\n"
           << "  \"status\": \"" << ToString(record.status) << "\",\n"
           << "  \"statusReason\": \"" << EscapeJson(record.statusReason) << "\",\n"
           << "  \"queueRelativePath\": \"" << EscapeJson(record.queueRelativePath) << "\",\n"
           << "  \"executionArtifactRelativePath\": \"" << EscapeJson(record.executionArtifactRelativePath) << "\",\n"
           << "  \"telemetryArtifactRelativePath\": \"" << EscapeJson(record.telemetryArtifactRelativePath) << "\",\n"
           << "  \"replayArtifactRelativePath\": \"" << EscapeJson(record.replayArtifactRelativePath) << "\",\n"
           << "  \"crashBucketRelativePath\": \"" << EscapeJson(record.crashBucketRelativePath) << "\",\n"
           << "  \"requiresFreshSession\": " << (record.requiresFreshSession ? "true" : "false") << ",\n"
           << "  \"maxIterationsPerCycle\": " << record.maxIterationsPerCycle << ",\n"
           << "  \"maxArtifactsPerIteration\": " << record.maxArtifactsPerIteration << ",\n";
    RenderStringArray(stream, "requiredWorkspaceDirectories", record.requiredWorkspaceDirectories, "  ");
    stream << ",\n";
    RenderStringArray(stream, "requiredInputs", record.requiredInputs, "  ");
    stream << ",\n";
    RenderStringArray(stream, "preflightChecks", record.preflightChecks, "  ");
    stream << ",\n";
    RenderStringArray(stream, "guardrails", record.guardrails, "  ");
    stream << "\n}\n";
    return stream.str();
}

[[nodiscard]] std::string BuildTelemetryJson(
    const RunnerExecutionRecord& record,
    const CampaignExecutionPlan& plan,
    const HarnessAdapterDescriptor& adapter)
{
    std::ostringstream stream;
    stream << "{\n"
           << "  \"planId\": \"" << EscapeJson(record.planId) << "\",\n"
           << "  \"targetId\": \"" << EscapeJson(record.targetId) << "\",\n"
           << "  \"adapterId\": \"" << EscapeJson(record.adapterId) << "\",\n"
           << "  \"workerImage\": \"" << EscapeJson(record.workerImage) << "\",\n"
           << "  \"executionMode\": \"" << EscapeJson(record.executionMode) << "\",\n"
           << "  \"status\": \"" << ToString(record.status) << "\",\n"
           << "  \"queueRelativePath\": \"" << EscapeJson(record.queueRelativePath) << "\",\n"
           << "  \"requiredInputCount\": " << record.requiredInputs.size() << ",\n"
           << "  \"kernelStepCount\": " << plan.steps.size() << ",\n"
           << "  \"userModeSeedSourceCount\": " << plan.seedSources.size() << ",\n";
    RenderStringArray(stream, "failureSignals", adapter.failureSignals, "  ");
    stream << "\n}\n";
    return stream.str();
}

[[nodiscard]] std::string BuildExecutionManifestJson(
    const RunnerExecutionRecord& record,
    const CampaignExecutionPlan& plan,
    const HarnessAdapterDescriptor& adapter)
{
    std::ostringstream stream;
    stream << "{\n"
           << "  \"planId\": \"" << EscapeJson(record.planId) << "\",\n"
           << "  \"targetId\": \"" << EscapeJson(record.targetId) << "\",\n"
           << "  \"laneId\": \"" << EscapeJson(record.laneId) << "\",\n"
           << "  \"adapterId\": \"" << EscapeJson(record.adapterId) << "\",\n"
           << "  \"workerImage\": \"" << EscapeJson(record.workerImage) << "\",\n"
           << "  \"executionMode\": \"" << EscapeJson(record.executionMode) << "\",\n"
           << "  \"campaignName\": \"" << EscapeJson(plan.campaignName) << "\",\n"
           << "  \"objective\": \"" << EscapeJson(plan.objective) << "\",\n"
           << "  \"snapshotProfile\": \"" << EscapeJson(plan.snapshotProfile) << "\",\n"
           << "  \"queueRelativePath\": \"" << EscapeJson(record.queueRelativePath) << "\",\n"
           << "  \"requiresFreshSession\": " << (record.requiresFreshSession ? "true" : "false") << ",\n"
           << "  \"maxIterationsPerCycle\": " << record.maxIterationsPerCycle << ",\n"
           << "  \"maxArtifactsPerIteration\": " << record.maxArtifactsPerIteration << ",\n";
    RenderStringArray(stream, "requiredInputs", record.requiredInputs, "  ");
    stream << ",\n";
    RenderStringArray(stream, "preflightChecks", adapter.preflightChecks, "  ");
    stream << ",\n";
    RenderStringArray(stream, "outputs", adapter.outputs, "  ");
    stream << ",\n";

    if (!plan.steps.empty()) {
        stream << "  \"kernelSteps\": [\n";
        for (std::size_t index = 0; index < plan.steps.size(); ++index) {
            const auto& step = plan.steps[index];
            stream << "    {\n"
                   << "      \"order\": " << step.order << ",\n"
                   << "      \"deliveryPhase\": \"" << EscapeJson(step.deliveryPhase) << "\",\n"
                   << "      \"objective\": \"" << EscapeJson(step.objective) << "\",\n"
                   << "      \"expectation\": \"" << EscapeJson(step.expectation) << "\",\n"
                   << "      \"resetConnectionAfter\": " << (step.resetConnectionAfter ? "true" : "false") << ",\n"
                   << "      \"relativePath\": \"" << EscapeJson(step.input.relativePath) << "\"\n"
                   << "    }";
            if (index + 1 != plan.steps.size()) {
                stream << ',';
            }
            stream << '\n';
        }
        stream << "  ]\n";
    } else {
        stream << "  \"userModeInputs\": [\n";
        for (std::size_t index = 0; index < plan.seedSources.size(); ++index) {
            const auto& input = plan.seedSources[index];
            stream << "    {\n"
                   << "      \"sourceId\": \"" << EscapeJson(input.sourceId) << "\",\n"
                   << "      \"kind\": \"" << ToString(input.kind) << "\",\n"
                   << "      \"relativePath\": \"" << EscapeJson(input.relativePath) << "\",\n"
                   << "      \"sourceKey\": \"" << EscapeJson(input.sourceKey) << "\"\n"
                   << "    }";
            if (index + 1 != plan.seedSources.size()) {
                stream << ',';
            }
            stream << '\n';
        }
        stream << "  ]\n";
    }

    stream << "}\n";
    return stream.str();
}

[[nodiscard]] std::string BuildReplayJson(
    const RunnerExecutionRecord& record,
    const CampaignExecutionPlan& plan)
{
    std::ostringstream stream;
    stream << "{\n"
           << "  \"planId\": \"" << EscapeJson(record.planId) << "\",\n"
           << "  \"targetId\": \"" << EscapeJson(record.targetId) << "\",\n"
           << "  \"reason\": \"Replay template reserved for deterministic crash or divergence promotion.\",\n"
           << "  \"queueRelativePath\": \"" << EscapeJson(record.queueRelativePath) << "\",\n"
           << "  \"snapshotProfile\": \"" << EscapeJson(plan.snapshotProfile) << "\"\n"
           << "}\n";
    return stream.str();
}

[[nodiscard]] std::string BuildQuarantineJson(
    const RunnerExecutionRecord& record,
    const std::string& reason)
{
    std::ostringstream stream;
    stream << "{\n"
           << "  \"planId\": \"" << EscapeJson(record.planId) << "\",\n"
           << "  \"adapterId\": \"" << EscapeJson(record.adapterId) << "\",\n"
           << "  \"laneId\": \"" << EscapeJson(record.laneId) << "\",\n"
           << "  \"reason\": \"" << EscapeJson(reason) << "\"\n"
           << "}\n";
    return stream.str();
}

[[nodiscard]] std::string BuildCrashBucketJson(
    const RunnerExecutionRecord& record,
    const std::string& signal)
{
    std::ostringstream stream;
    stream << "{\n"
           << "  \"bucketId\": \"" << EscapeJson(record.planId) << "-bucket\",\n"
           << "  \"planId\": \"" << EscapeJson(record.planId) << "\",\n"
           << "  \"signal\": \"" << EscapeJson(signal) << "\",\n"
           << "  \"status\": \"pending-triage\"\n"
           << "}\n";
    return stream.str();
}

[[nodiscard]] bool ValidateDirectories(
    const std::filesystem::path& workspaceRoot,
    const std::vector<std::string>& directories,
    std::string& missingDirectory)
{
    for (const auto& directory : directories) {
        if (!std::filesystem::exists(workspaceRoot / directory)) {
            missingDirectory = directory;
            return false;
        }
    }

    return true;
}

[[nodiscard]] bool ValidatePlanInputs(
    const std::filesystem::path& workspaceRoot,
    const RunnerExecutionRecord& record,
    std::string& missingInput)
{
    for (const auto& input : record.requiredInputs) {
        if (!std::filesystem::exists(workspaceRoot / input)) {
            missingInput = input;
            return false;
        }
    }

    return true;
}

[[nodiscard]] std::string ResolveExecutionMode(const HarnessAdapterKind kind) {
    switch (kind) {
    case HarnessAdapterKind::KernelVmCampaign:
        return "vm-launch-contract";
    case HarnessAdapterKind::BrokerSession:
        return "broker-launch-contract";
    case HarnessAdapterKind::ParserFrontDoor:
        return "parser-launch-contract";
    case HarnessAdapterKind::DifferentialParser:
        return "differential-launch-contract";
    }

    return "unknown";
}

void RenderReplayDescriptor(std::ostringstream& stream,
    const ReplayArtifactDescriptor& descriptor,
    std::string_view indent)
{
    stream << indent << "{\n"
           << indent << "  \"planId\": \"" << EscapeJson(descriptor.planId) << "\",\n"
           << indent << "  \"relativePath\": \"" << EscapeJson(descriptor.relativePath) << "\",\n"
           << indent << "  \"reason\": \"" << EscapeJson(descriptor.reason) << "\"\n"
           << indent << '}';
}

void RenderCrashBucketDescriptor(std::ostringstream& stream,
    const CrashBucketDescriptor& descriptor,
    std::string_view indent)
{
    stream << indent << "{\n"
           << indent << "  \"bucketId\": \"" << EscapeJson(descriptor.bucketId) << "\",\n"
           << indent << "  \"planId\": \"" << EscapeJson(descriptor.planId) << "\",\n"
           << indent << "  \"relativePath\": \"" << EscapeJson(descriptor.relativePath) << "\",\n"
           << indent << "  \"signal\": \"" << EscapeJson(descriptor.signal) << "\"\n"
           << indent << '}';
}

void RenderQuarantineDescriptor(std::ostringstream& stream,
    const QuarantineArtifactDescriptor& descriptor,
    std::string_view indent)
{
    stream << indent << "{\n"
           << indent << "  \"planId\": \"" << EscapeJson(descriptor.planId) << "\",\n"
           << indent << "  \"relativePath\": \"" << EscapeJson(descriptor.relativePath) << "\",\n"
           << indent << "  \"reason\": \"" << EscapeJson(descriptor.reason) << "\"\n"
           << indent << '}';
}

void RenderExecutionRecord(std::ostringstream& stream,
    const RunnerExecutionRecord& record,
    std::string_view indent)
{
    stream << indent << "{\n"
           << indent << "  \"planId\": \"" << EscapeJson(record.planId) << "\",\n"
           << indent << "  \"targetId\": \"" << EscapeJson(record.targetId) << "\",\n"
           << indent << "  \"laneId\": \"" << EscapeJson(record.laneId) << "\",\n"
           << indent << "  \"adapterId\": \"" << EscapeJson(record.adapterId) << "\",\n"
           << indent << "  \"workerImage\": \"" << EscapeJson(record.workerImage) << "\",\n"
           << indent << "  \"executionMode\": \"" << EscapeJson(record.executionMode) << "\",\n"
           << indent << "  \"status\": \"" << ToString(record.status) << "\",\n"
           << indent << "  \"statusReason\": \"" << EscapeJson(record.statusReason) << "\",\n"
           << indent << "  \"queueRelativePath\": \"" << EscapeJson(record.queueRelativePath) << "\",\n"
           << indent << "  \"executionArtifactRelativePath\": \"" << EscapeJson(record.executionArtifactRelativePath) << "\",\n"
           << indent << "  \"telemetryArtifactRelativePath\": \"" << EscapeJson(record.telemetryArtifactRelativePath) << "\",\n"
           << indent << "  \"replayArtifactRelativePath\": \"" << EscapeJson(record.replayArtifactRelativePath) << "\",\n"
           << indent << "  \"crashBucketRelativePath\": \"" << EscapeJson(record.crashBucketRelativePath) << "\",\n"
           << indent << "  \"requiresFreshSession\": " << (record.requiresFreshSession ? "true" : "false") << ",\n"
           << indent << "  \"maxIterationsPerCycle\": " << record.maxIterationsPerCycle << ",\n"
           << indent << "  \"maxArtifactsPerIteration\": " << record.maxArtifactsPerIteration << ",\n";
    RenderStringArray(stream, "requiredWorkspaceDirectories", record.requiredWorkspaceDirectories, std::string(indent) + "  ");
    stream << ",\n";
    RenderStringArray(stream, "requiredInputs", record.requiredInputs, std::string(indent) + "  ");
    stream << ",\n";
    RenderStringArray(stream, "preflightChecks", record.preflightChecks, std::string(indent) + "  ");
    stream << ",\n";
    RenderStringArray(stream, "guardrails", record.guardrails, std::string(indent) + "  ");
    stream << '\n' << indent << '}';
}

[[nodiscard]] bool MaterializeEmptyManifest(
    const std::filesystem::path& workspaceRoot,
    const std::filesystem::path& relativePath,
    std::string_view key)
{
    std::ostringstream stream;
    stream << "{\n  \"" << key << "\": []\n}\n";
    return WriteTextFile(workspaceRoot / relativePath, stream.str());
}

}  // namespace

std::string_view ToString(const RunnerExecutionStatus status) {
    switch (status) {
    case RunnerExecutionStatus::Ready:
        return "ready";
    case RunnerExecutionStatus::Running:
        return "running";
    case RunnerExecutionStatus::Completed:
        return "completed";
    case RunnerExecutionStatus::Crashed:
        return "crashed";
    case RunnerExecutionStatus::Quarantined:
        return "quarantined";
    case RunnerExecutionStatus::Blocked:
        return "blocked";
    }

    return "unknown";
}

RunnerExecutionLedger RunnerExecutionRuntime::ExecuteWorkspace(
    const std::filesystem::path& workspaceRoot,
    std::string& errorMessage)
{
    RunnerExecutionLedger ledger{};
    ledger.id = "shadowstrike-runner-execution-v1";
    ledger.description =
        "Workspace execution ledger for launch-contract generation, telemetry emission, quarantine routing, and deterministic replay/crash metadata.";
    ledger.invariants = {
        "Runner execution never silently drops a ready plan.",
        "A plan may complete only after its execution manifest, telemetry artifact, and run-state file are written.",
        "Preflight failures must route the plan into quarantine with explicit metadata."
    };

    std::error_code ec;
    std::filesystem::create_directories(workspaceRoot / "state\\executions", ec);
    if (ec) {
        errorMessage = "Failed to create state\\executions.";
        return ledger;
    }

    if (!MaterializeEmptyManifest(workspaceRoot, "pipeline\\quarantine\\manifest.json", "quarantinedPlans")) {
        errorMessage = "Failed to initialize pipeline\\quarantine\\manifest.json.";
        return ledger;
    }
    if (!MaterializeEmptyManifest(workspaceRoot, "reproducers\\pending\\manifest.json", "pendingReplays")) {
        errorMessage = "Failed to initialize reproducers\\pending\\manifest.json.";
        return ledger;
    }
    if (!MaterializeEmptyManifest(workspaceRoot, "crashes\\buckets\\manifest.json", "buckets")) {
        errorMessage = "Failed to initialize crashes\\buckets\\manifest.json.";
        return ledger;
    }

    const DispatchManifest dispatchManifest = DispatchRuntime::BuildWorkspaceManifest(workspaceRoot);
    for (const auto& item : dispatchManifest.items) {
        RunnerExecutionRecord record{};
        record.planId = item.planId;
        record.targetId = item.targetId;
        record.laneId = item.laneId;
        record.adapterId = item.adapterId;
        record.queueRelativePath = item.queueRelativePath;
        record.executionArtifactRelativePath = "state\\executions\\" + item.planId + ".json";
        record.telemetryArtifactRelativePath = item.telemetryRelativePath;
        record.replayArtifactRelativePath = "reproducers\\pending\\" + item.planId + ".json";
        record.crashBucketRelativePath = "crashes\\buckets\\" + item.planId + ".json";
        record.requiresFreshSession = item.requiresFreshSession;
        record.maxIterationsPerCycle = item.maxIterationsPerCycle;
        record.maxArtifactsPerIteration = item.maxArtifactsPerIteration;
        record.requiredInputs = item.requiredInputs;

        const auto* plan = CampaignPlanner::FindById(item.planId);
        if (plan == nullptr) {
            record.status = RunnerExecutionStatus::Blocked;
            record.statusReason = "Campaign plan metadata is missing.";
            ledger.records.push_back(std::move(record));
            continue;
        }

        const auto* adapter = HarnessAdapterCatalog::FindById(item.adapterId);
        if (adapter == nullptr) {
            record.status = RunnerExecutionStatus::Blocked;
            record.statusReason = "Harness adapter metadata is missing.";
            ledger.records.push_back(std::move(record));
            continue;
        }

        record.workerImage = adapter->workerImage;
        record.executionMode = ResolveExecutionMode(adapter->kind);
        record.preflightChecks = adapter->preflightChecks;
        record.guardrails = adapter->guardrails;
        record.requiredWorkspaceDirectories = BuildRequiredDirectories(*adapter);

        if (item.readiness != DispatchReadiness::Ready) {
            record.status = RunnerExecutionStatus::Blocked;
            record.statusReason = item.readinessReason;
            if (!WriteTextFile(workspaceRoot / ("state\\runs\\" + item.planId + ".json"), BuildStatusJson(record))) {
                errorMessage = "Failed to update blocked run-state for " + item.planId + '.';
                return ledger;
            }
            ledger.records.push_back(std::move(record));
            continue;
        }

        record.status = RunnerExecutionStatus::Running;
        record.statusReason = "Preflight validation in progress.";
        if (!WriteTextFile(workspaceRoot / ("state\\runs\\" + item.planId + ".json"), BuildStatusJson(record))) {
            errorMessage = "Failed to write running run-state for " + item.planId + '.';
            return ledger;
        }

        std::string missingPath;
        if (!ValidateDirectories(workspaceRoot, record.requiredWorkspaceDirectories, missingPath)) {
            record.status = RunnerExecutionStatus::Quarantined;
            record.statusReason = "Missing required workspace directory: " + missingPath;
        } else if (!ValidatePlanInputs(workspaceRoot, record, missingPath)) {
            record.status = RunnerExecutionStatus::Quarantined;
            record.statusReason = "Missing required plan input: " + missingPath;
        } else if (!plan->snapshotProfile.empty() &&
            !std::filesystem::exists(workspaceRoot / ("vm\\profiles\\" + plan->snapshotProfile + ".json"))) {
            record.status = RunnerExecutionStatus::Quarantined;
            record.statusReason = "Missing snapshot profile manifest for kernel campaign.";
        } else {
            record.status = RunnerExecutionStatus::Completed;
            record.statusReason = "Execution contract emitted for worker consumption.";
        }

        if (record.status == RunnerExecutionStatus::Completed) {
            if (!WriteTextFile(
                    workspaceRoot / record.executionArtifactRelativePath,
                    BuildExecutionManifestJson(record, *plan, *adapter))) {
                errorMessage = "Failed to write execution manifest for " + item.planId + '.';
                return ledger;
            }

            if (!WriteTextFile(
                    workspaceRoot / record.telemetryArtifactRelativePath,
                    BuildTelemetryJson(record, *plan, *adapter))) {
                errorMessage = "Failed to write telemetry artifact for " + item.planId + '.';
                return ledger;
            }

            if (!WriteTextFile(
                    workspaceRoot / record.replayArtifactRelativePath,
                    BuildReplayJson(record, *plan))) {
                errorMessage = "Failed to write replay artifact for " + item.planId + '.';
                return ledger;
            }

            ledger.pendingReplays.push_back(ReplayArtifactDescriptor{
                item.planId,
                record.replayArtifactRelativePath,
                "Reserved replay template for crash or divergence promotion."
            });
        } else if (record.status == RunnerExecutionStatus::Quarantined) {
            if (!WriteTextFile(
                    workspaceRoot / ("pipeline\\quarantine\\" + item.planId + ".json"),
                    BuildQuarantineJson(record, record.statusReason))) {
                errorMessage = "Failed to write quarantine artifact for " + item.planId + '.';
                return ledger;
            }

            ledger.quarantines.push_back(QuarantineArtifactDescriptor{
                item.planId,
                "pipeline\\quarantine\\" + item.planId + ".json",
                record.statusReason
            });
        }

        if (!WriteTextFile(workspaceRoot / ("state\\runs\\" + item.planId + ".json"), BuildStatusJson(record))) {
            errorMessage = "Failed to update final run-state for " + item.planId + '.';
            return ledger;
        }

        ledger.records.push_back(std::move(record));
    }

    if (!WriteTextFile(workspaceRoot / "state\\execution-ledger.json", RenderJson(ledger))) {
        errorMessage = "Failed to write state\\execution-ledger.json.";
        return ledger;
    }

    std::ostringstream quarantineManifest;
    quarantineManifest << "{\n  \"quarantinedPlans\": [\n";
    for (std::size_t index = 0; index < ledger.quarantines.size(); ++index) {
        RenderQuarantineDescriptor(quarantineManifest, ledger.quarantines[index], "    ");
        if (index + 1 != ledger.quarantines.size()) {
            quarantineManifest << ',';
        }
        quarantineManifest << '\n';
    }
    quarantineManifest << "  ]\n}\n";
    if (!WriteTextFile(workspaceRoot / "pipeline\\quarantine\\manifest.json", quarantineManifest.str())) {
        errorMessage = "Failed to write quarantine manifest.";
        return ledger;
    }

    std::ostringstream replayManifest;
    replayManifest << "{\n  \"pendingReplays\": [\n";
    for (std::size_t index = 0; index < ledger.pendingReplays.size(); ++index) {
        RenderReplayDescriptor(replayManifest, ledger.pendingReplays[index], "    ");
        if (index + 1 != ledger.pendingReplays.size()) {
            replayManifest << ',';
        }
        replayManifest << '\n';
    }
    replayManifest << "  ]\n}\n";
    if (!WriteTextFile(workspaceRoot / "reproducers\\pending\\manifest.json", replayManifest.str())) {
        errorMessage = "Failed to write replay manifest.";
        return ledger;
    }

    std::ostringstream crashManifest;
    crashManifest << "{\n  \"buckets\": [\n";
    for (std::size_t index = 0; index < ledger.crashBuckets.size(); ++index) {
        RenderCrashBucketDescriptor(crashManifest, ledger.crashBuckets[index], "    ");
        if (index + 1 != ledger.crashBuckets.size()) {
            crashManifest << ',';
        }
        crashManifest << '\n';
    }
    crashManifest << "  ]\n}\n";
    if (!WriteTextFile(workspaceRoot / "crashes\\buckets\\manifest.json", crashManifest.str())) {
        errorMessage = "Failed to write crash-bucket manifest.";
        return ledger;
    }

    errorMessage.clear();
    return ledger;
}

std::string RunnerExecutionRuntime::DescribeText(const RunnerExecutionLedger& ledger) {
    const auto completedCount = static_cast<std::size_t>(std::count_if(
        ledger.records.begin(),
        ledger.records.end(),
        [](const RunnerExecutionRecord& record) { return record.status == RunnerExecutionStatus::Completed; }));
    const auto quarantinedCount = static_cast<std::size_t>(std::count_if(
        ledger.records.begin(),
        ledger.records.end(),
        [](const RunnerExecutionRecord& record) { return record.status == RunnerExecutionStatus::Quarantined; }));
    const auto blockedCount = static_cast<std::size_t>(std::count_if(
        ledger.records.begin(),
        ledger.records.end(),
        [](const RunnerExecutionRecord& record) { return record.status == RunnerExecutionStatus::Blocked; }));

    std::ostringstream stream;
    stream << ledger.id << '\n'
           << "Description: " << ledger.description << '\n'
           << "Completed plans: " << completedCount << '\n'
           << "Quarantined plans: " << quarantinedCount << '\n'
           << "Blocked plans: " << blockedCount << '\n'
           << "Pending replay artifacts: " << ledger.pendingReplays.size() << '\n'
           << "Crash buckets: " << ledger.crashBuckets.size() << '\n';

    for (const auto& record : ledger.records) {
        if (record.status == RunnerExecutionStatus::Completed) {
            continue;
        }

        stream << "  - " << record.planId << " | " << ToString(record.status)
               << " | " << record.statusReason << '\n';
    }

    return stream.str();
}

std::string RunnerExecutionRuntime::RenderJson(const RunnerExecutionLedger& ledger) {
    std::ostringstream stream;
    stream << "{\n"
           << "  \"id\": \"" << EscapeJson(ledger.id) << "\",\n"
           << "  \"description\": \"" << EscapeJson(ledger.description) << "\",\n";
    RenderStringArray(stream, "invariants", ledger.invariants, "  ");
    stream << ",\n"
           << "  \"records\": [\n";
    for (std::size_t index = 0; index < ledger.records.size(); ++index) {
        RenderExecutionRecord(stream, ledger.records[index], "    ");
        if (index + 1 != ledger.records.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ],\n"
           << "  \"pendingReplays\": [\n";
    for (std::size_t index = 0; index < ledger.pendingReplays.size(); ++index) {
        RenderReplayDescriptor(stream, ledger.pendingReplays[index], "    ");
        if (index + 1 != ledger.pendingReplays.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ],\n"
           << "  \"crashBuckets\": [\n";
    for (std::size_t index = 0; index < ledger.crashBuckets.size(); ++index) {
        RenderCrashBucketDescriptor(stream, ledger.crashBuckets[index], "    ");
        if (index + 1 != ledger.crashBuckets.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ],\n"
           << "  \"quarantines\": [\n";
    for (std::size_t index = 0; index < ledger.quarantines.size(); ++index) {
        RenderQuarantineDescriptor(stream, ledger.quarantines[index], "    ");
        if (index + 1 != ledger.quarantines.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ]\n}\n";
    return stream.str();
}

}  // namespace ShadowStrike::Fuzzer

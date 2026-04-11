#include "ShadowStrike/Fuzzer/Core/DispatchRuntime.hpp"

#include "ShadowStrike/Fuzzer/Core/CampaignPlanner.hpp"
#include "ShadowStrike/Fuzzer/Core/EngineArchitecture.hpp"
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

[[nodiscard]] std::string ResolveLaneId(std::string_view executionLane) {
    if (executionLane == "kernel-vm") {
        return "kernel-vm-lane";
    }
    if (executionLane == "user-mode-broker") {
        return "usermode-broker-lane";
    }
    if (executionLane == "user-mode-parser") {
        return "usermode-parser-lane";
    }
    if (executionLane == "differential-decoder") {
        return "differential-decoder-lane";
    }

    return {};
}

[[nodiscard]] const EngineLaneDescriptor* FindLaneById(std::string_view laneId) {
    const auto& architecture = EngineArchitectureCatalog::GetDefaultArchitecture();
    const auto match = std::find_if(architecture.lanes.begin(), architecture.lanes.end(),
        [&](const EngineLaneDescriptor& lane) { return lane.id == laneId; });
    return match == architecture.lanes.end() ? nullptr : &(*match);
}

[[nodiscard]] std::string ResolveTelemetryDirectory(std::string_view laneId) {
    if (laneId == "kernel-vm-lane") {
        return "telemetry\\health";
    }
    if (laneId == "usermode-broker-lane" || laneId == "usermode-parser-lane") {
        return "telemetry\\coverage";
    }

    return "telemetry\\health";
}

[[nodiscard]] std::string ResolveCrashArtifactRoot(std::string_view laneId) {
    if (laneId == "kernel-vm-lane") {
        return "vm\\crash-collection";
    }

    return "crashes\\incoming";
}

[[nodiscard]] std::vector<std::string> CollectRequiredInputs(const CampaignExecutionPlan& plan) {
    std::vector<std::string> requiredInputs;

    for (const auto& seedSource : plan.seedSources) {
        if (std::find(requiredInputs.begin(), requiredInputs.end(), seedSource.relativePath) == requiredInputs.end()) {
            requiredInputs.push_back(seedSource.relativePath);
        }
    }

    for (const auto& step : plan.steps) {
        if (std::find(requiredInputs.begin(), requiredInputs.end(), step.input.relativePath) == requiredInputs.end()) {
            requiredInputs.push_back(step.input.relativePath);
        }
    }

    return requiredInputs;
}

[[nodiscard]] DispatchLaneBinding BuildLaneBinding(const EngineLaneDescriptor& lane) {
    return DispatchLaneBinding{
        lane.id,
        std::string(ToString(lane.kind)),
        std::string(ToString(lane.isolation)),
        lane.maxConcurrentWorkers,
        lane.schedulerPolicy,
        "pipeline\\queue",
        "state\\runs",
        ResolveTelemetryDirectory(lane.id),
        ResolveCrashArtifactRoot(lane.id),
        lane.guardrails
    };
}

[[nodiscard]] std::string ValidateDispatchItem(
    const std::filesystem::path& workspaceRoot,
    const PlannedDispatchItem& item)
{
    if (!std::filesystem::exists(workspaceRoot / item.queueRelativePath)) {
        return "Missing queued campaign plan JSON.";
    }

    for (const auto& input : item.requiredInputs) {
        if (!std::filesystem::exists(workspaceRoot / input)) {
            return "Missing required input artifact or logical corpus manifest: " + input;
        }
    }

    return {};
}

void RenderDispatchItem(std::ostringstream& stream,
    const PlannedDispatchItem& item,
    std::string_view indent)
{
    stream << indent << "{\n"
           << indent << "  \"planId\": \"" << EscapeJson(item.planId) << "\",\n"
           << indent << "  \"targetId\": \"" << EscapeJson(item.targetId) << "\",\n"
           << indent << "  \"scope\": \"" << EscapeJson(item.scope) << "\",\n"
           << indent << "  \"harness\": \"" << EscapeJson(item.harness) << "\",\n"
           << indent << "  \"adapterId\": \"" << EscapeJson(item.adapterId) << "\",\n"
           << indent << "  \"laneId\": \"" << EscapeJson(item.laneId) << "\",\n"
           << indent << "  \"queueRelativePath\": \"" << EscapeJson(item.queueRelativePath) << "\",\n"
           << indent << "  \"runStateRelativePath\": \"" << EscapeJson(item.runStateRelativePath) << "\",\n"
           << indent << "  \"telemetryRelativePath\": \"" << EscapeJson(item.telemetryRelativePath) << "\",\n"
           << indent << "  \"crashArtifactRelativePath\": \"" << EscapeJson(item.crashArtifactRelativePath) << "\",\n"
           << indent << "  \"requiresFreshSession\": " << (item.requiresFreshSession ? "true" : "false") << ",\n"
           << indent << "  \"maxIterationsPerCycle\": " << item.maxIterationsPerCycle << ",\n"
           << indent << "  \"maxArtifactsPerIteration\": " << item.maxArtifactsPerIteration << ",\n"
           << indent << "  \"readiness\": \"" << ToString(item.readiness) << "\",\n"
           << indent << "  \"readinessReason\": \"" << EscapeJson(item.readinessReason) << "\",\n";
    RenderStringArray(stream, "requiredInputs", item.requiredInputs, std::string(indent) + "  ");
    stream << '\n' << indent << '}';
}

void RenderLaneBinding(std::ostringstream& stream,
    const DispatchLaneBinding& lane,
    std::string_view indent)
{
    stream << indent << "{\n"
           << indent << "  \"laneId\": \"" << EscapeJson(lane.laneId) << "\",\n"
           << indent << "  \"laneKind\": \"" << EscapeJson(lane.laneKind) << "\",\n"
           << indent << "  \"isolation\": \"" << EscapeJson(lane.isolation) << "\",\n"
           << indent << "  \"maxConcurrentWorkers\": " << lane.maxConcurrentWorkers << ",\n"
           << indent << "  \"schedulerPolicy\": \"" << EscapeJson(lane.schedulerPolicy) << "\",\n"
           << indent << "  \"queueDirectory\": \"" << EscapeJson(lane.queueDirectory) << "\",\n"
           << indent << "  \"runStateDirectory\": \"" << EscapeJson(lane.runStateDirectory) << "\",\n"
           << indent << "  \"telemetryDirectory\": \"" << EscapeJson(lane.telemetryDirectory) << "\",\n"
           << indent << "  \"crashArtifactRoot\": \"" << EscapeJson(lane.crashArtifactRoot) << "\",\n";
    RenderStringArray(stream, "guardrails", lane.guardrails, std::string(indent) + "  ");
    stream << '\n' << indent << '}';
}

[[nodiscard]] std::string BuildRunStateJson(const PlannedDispatchItem& item) {
    std::ostringstream stream;
    stream << "{\n"
           << "  \"planId\": \"" << EscapeJson(item.planId) << "\",\n"
           << "  \"targetId\": \"" << EscapeJson(item.targetId) << "\",\n"
           << "  \"laneId\": \"" << EscapeJson(item.laneId) << "\",\n"
           << "  \"adapterId\": \"" << EscapeJson(item.adapterId) << "\",\n"
           << "  \"status\": \"" << ToString(item.readiness) << "\",\n"
           << "  \"reason\": \"" << EscapeJson(item.readinessReason) << "\",\n"
           << "  \"queueRelativePath\": \"" << EscapeJson(item.queueRelativePath) << "\",\n"
           << "  \"telemetryRelativePath\": \"" << EscapeJson(item.telemetryRelativePath) << "\",\n"
           << "  \"crashArtifactRelativePath\": \"" << EscapeJson(item.crashArtifactRelativePath) << "\",\n"
           << "  \"requiresFreshSession\": " << (item.requiresFreshSession ? "true" : "false") << ",\n"
           << "  \"maxIterationsPerCycle\": " << item.maxIterationsPerCycle << ",\n"
           << "  \"maxArtifactsPerIteration\": " << item.maxArtifactsPerIteration << ",\n";
    RenderStringArray(stream, "requiredInputs", item.requiredInputs, "  ");
    stream << "\n}\n";
    return stream.str();
}

}  // namespace

std::string_view ToString(const DispatchReadiness readiness) {
    switch (readiness) {
    case DispatchReadiness::Ready:
        return "ready";
    case DispatchReadiness::Blocked:
        return "blocked";
    }

    return "unknown";
}

DispatchManifest DispatchRuntime::BuildWorkspaceManifest(const std::filesystem::path& workspaceRoot) {
    const auto& plans = CampaignPlanner::GetDefaultPlans();
    const auto& architecture = EngineArchitectureCatalog::GetDefaultArchitecture();

    DispatchManifest manifest{};
    manifest.id = "shadowstrike-workspace-dispatch-v1";
    manifest.description =
        "Workspace-bound dispatch manifest that assigns queued campaign plans to execution lanes, validates required inputs, and materializes deterministic run-state metadata.";
    manifest.prerequisites = {
        "Workspace layout must be initialized before dispatch materialization.",
        "Every queued plan must have its plan JSON present under pipeline\\queue.",
        "Every required artifact or logical corpus manifest must exist before the plan can be marked ready."
    };

    manifest.lanes.reserve(architecture.lanes.size());
    for (const auto& lane : architecture.lanes) {
        manifest.lanes.push_back(BuildLaneBinding(lane));
    }

    manifest.items.reserve(plans.size());
    for (const auto& plan : plans) {
        PlannedDispatchItem item{};
        item.planId = plan.id;
        item.targetId = plan.targetId;
        item.scope = std::string(ToString(plan.scope));
        item.harness = plan.harness;
        item.laneId = ResolveLaneId(plan.executionLane);
        item.queueRelativePath = "pipeline\\queue\\" + plan.id + ".json";
        item.runStateRelativePath = "state\\runs\\" + plan.id + ".json";
        item.telemetryRelativePath = ResolveTelemetryDirectory(item.laneId) + "\\" + plan.id + ".json";
        item.crashArtifactRelativePath = ResolveCrashArtifactRoot(item.laneId) + "\\" + plan.id;
        item.requiresFreshSession = plan.requiresFreshSession;
        item.maxIterationsPerCycle = plan.maxIterationsPerCycle;
        item.maxArtifactsPerIteration = plan.maxArtifactsPerIteration;
        item.requiredInputs = CollectRequiredInputs(plan);

        if (item.laneId.empty()) {
            item.readiness = DispatchReadiness::Blocked;
            item.readinessReason = "Plan execution lane is not wired to an engine lane.";
            manifest.items.push_back(std::move(item));
            continue;
        }

        if (FindLaneById(item.laneId) == nullptr) {
            item.readiness = DispatchReadiness::Blocked;
            item.readinessReason = "Dispatch lane descriptor is missing from the engine architecture.";
            manifest.items.push_back(std::move(item));
            continue;
        }

        if (const auto* adapter = HarnessAdapterCatalog::FindForPlan(plan); adapter == nullptr) {
            item.readiness = DispatchReadiness::Blocked;
            item.readinessReason = "No harness adapter is wired for this plan.";
            manifest.items.push_back(std::move(item));
            continue;
        } else {
            item.adapterId = adapter->id;
        }

        const std::string validationFailure = ValidateDispatchItem(workspaceRoot, item);
        item.readiness = validationFailure.empty() ? DispatchReadiness::Ready : DispatchReadiness::Blocked;
        item.readinessReason = validationFailure.empty()
            ? "Plan is ready for lane assignment."
            : validationFailure;
        manifest.items.push_back(std::move(item));
    }

    return manifest;
}

std::string DispatchRuntime::DescribeText(const DispatchManifest& manifest) {
    std::ostringstream stream;

    const auto readyCount = static_cast<std::size_t>(std::count_if(
        manifest.items.begin(),
        manifest.items.end(),
        [](const PlannedDispatchItem& item) { return item.readiness == DispatchReadiness::Ready; }));
    const auto blockedCount = manifest.items.size() - readyCount;

    stream << manifest.id << '\n'
           << "Description: " << manifest.description << '\n'
           << "Lanes: " << manifest.lanes.size() << '\n'
           << "Ready plans: " << readyCount << '\n'
           << "Blocked plans: " << blockedCount << '\n';

    for (const auto& lane : manifest.lanes) {
        const auto lanePlanCount = static_cast<std::size_t>(std::count_if(
            manifest.items.begin(),
            manifest.items.end(),
            [&](const PlannedDispatchItem& item) { return item.laneId == lane.laneId; }));
        stream << "  - " << lane.laneId
               << " | kind=" << lane.laneKind
               << " | maxWorkers=" << lane.maxConcurrentWorkers
               << " | plans=" << lanePlanCount << '\n';
    }

    for (const auto& item : manifest.items) {
        if (item.readiness != DispatchReadiness::Blocked) {
            continue;
        }

        stream << "BLOCKED " << item.planId << ": " << item.readinessReason << '\n';
    }

    return stream.str();
}

std::string DispatchRuntime::RenderJson(const DispatchManifest& manifest) {
    std::ostringstream stream;
    stream << "{\n"
           << "  \"id\": \"" << EscapeJson(manifest.id) << "\",\n"
           << "  \"description\": \"" << EscapeJson(manifest.description) << "\",\n";
    RenderStringArray(stream, "prerequisites", manifest.prerequisites, "  ");
    stream << ",\n"
           << "  \"lanes\": [\n";

    for (std::size_t index = 0; index < manifest.lanes.size(); ++index) {
        RenderLaneBinding(stream, manifest.lanes[index], "    ");
        if (index + 1 != manifest.lanes.size()) {
            stream << ',';
        }
        stream << '\n';
    }

    stream << "  ],\n"
           << "  \"items\": [\n";

    for (std::size_t index = 0; index < manifest.items.size(); ++index) {
        RenderDispatchItem(stream, manifest.items[index], "    ");
        if (index + 1 != manifest.items.size()) {
            stream << ',';
        }
        stream << '\n';
    }

    stream << "  ]\n}\n";
    return stream.str();
}

bool DispatchRuntime::MaterializeWorkspaceState(
    const std::filesystem::path& workspaceRoot,
    std::string& errorMessage)
{
    const DispatchManifest manifest = BuildWorkspaceManifest(workspaceRoot);

    std::error_code ec;
    std::filesystem::create_directories(workspaceRoot / "state\\runs", ec);
    if (ec) {
        errorMessage = "Failed to create workspace run-state directory.";
        return false;
    }

    if (!WriteTextFile(workspaceRoot / "state\\dispatch-manifest.json", RenderJson(manifest))) {
        errorMessage = "Failed to write state\\dispatch-manifest.json.";
        return false;
    }

    for (const auto& item : manifest.items) {
        if (!WriteTextFile(workspaceRoot / item.runStateRelativePath, BuildRunStateJson(item))) {
            errorMessage = "Failed to write run-state file for plan " + item.planId + '.';
            return false;
        }
    }

    return true;
}

}  // namespace ShadowStrike::Fuzzer

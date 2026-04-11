#include "ShadowStrike/Fuzzer/Core/CampaignPlanner.hpp"

#include "ShadowStrike/Fuzzer/Protocol/KernelMessageFactory.hpp"
#include "ShadowStrike/Fuzzer/Targets/KernelTargetCatalog.hpp"
#include "ShadowStrike/Fuzzer/Targets/UserModeTargetCatalog.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

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

[[nodiscard]] const std::vector<BinarySeedArtifact>& GetArtifactCatalog() {
    static const std::vector<BinarySeedArtifact> artifacts = KernelMessageFactory::BuildFullSeedSet();
    return artifacts;
}

[[nodiscard]] const BinarySeedArtifact* FindArtifactById(std::string_view id) {
    const auto& artifacts = GetArtifactCatalog();
    const auto match = std::find_if(artifacts.begin(), artifacts.end(),
        [&](const BinarySeedArtifact& artifact) { return artifact.id == id; });
    return match == artifacts.end() ? nullptr : &(*match);
}

[[nodiscard]] const BinarySeedArtifact* FindArtifactByFileName(std::string_view fileName) {
    const auto& artifacts = GetArtifactCatalog();
    const auto match = std::find_if(artifacts.begin(), artifacts.end(),
        [&](const BinarySeedArtifact& artifact) { return artifact.fileName == fileName; });
    return match == artifacts.end() ? nullptr : &(*match);
}

[[nodiscard]] std::string SanitizeKey(std::string_view value) {
    std::string key;
    key.reserve(value.size());

    bool lastWasDash = false;
    for (const unsigned char raw : value) {
        if (std::isalnum(raw) != 0) {
            key.push_back(static_cast<char>(std::tolower(raw)));
            lastWasDash = false;
            continue;
        }

        if (!lastWasDash) {
            key.push_back('-');
            lastWasDash = true;
        }
    }

    while (!key.empty() && key.front() == '-') {
        key.erase(key.begin());
    }
    while (!key.empty() && key.back() == '-') {
        key.pop_back();
    }

    return key.empty() ? "logical-corpus" : key;
}

[[nodiscard]] CampaignInputReference MakeWorkspaceArtifactReference(const BinarySeedArtifact& artifact) {
    return CampaignInputReference{
        artifact.id,
        PlannedInputKind::WorkspaceArtifact,
        artifact.kind == BinarySeedKind::Baseline
            ? "corpora\\kernel\\baseline\\" + artifact.fileName
            : "corpora\\kernel\\variants\\" + artifact.fileName,
        {},
        artifact.schemaId,
        artifact.surfaceId,
        artifact.description
    };
}

[[nodiscard]] CampaignInputReference ResolveUserModeSeedSource(
    const UserModeExecutionKind executionKind,
    const std::string& sourceId)
{
    const std::filesystem::path sourcePath(sourceId);
    const std::string fileName = sourcePath.filename().string();
    if (!fileName.empty()) {
        if (const auto* artifact = FindArtifactByFileName(fileName); artifact != nullptr) {
            return MakeWorkspaceArtifactReference(*artifact);
        }
    }

    return CampaignInputReference{
        sourceId,
        PlannedInputKind::LogicalCorpusManifest,
        executionKind == UserModeExecutionKind::BrokerProcess
            ? "corpora\\usermode\\broker\\manifest.json"
            : "corpora\\usermode\\parser\\manifest.json",
        SanitizeKey(sourceId),
        {},
        {},
        "Logical corpus source declared by the user-mode target catalog."
    };
}

[[nodiscard]] CampaignExecutionPlan BuildKernelPlan(
    const KernelTargetDescriptor& target,
    const KernelCampaign& campaign)
{
    CampaignExecutionPlan plan{};
    plan.id = "plan." + campaign.id;
    plan.scope = PlannedCampaignScope::Kernel;
    plan.targetId = target.id;
    plan.campaignId = campaign.id;
    plan.campaignName = campaign.name;
    plan.executionLane = "kernel-vm";
    plan.isolation = ToString(target.isolation);
    plan.snapshotProfile = target.snapshotProfile;
    plan.harness = "phantomsensor-vm-campaign";
    plan.requiresFreshSession = campaign.requiresFreshSession;
    plan.maxIterationsPerCycle = target.maxIterationsPerBoot;
    plan.maxArtifactsPerIteration = campaign.maxArtifactsPerIteration;
    plan.objective = campaign.objective;
    plan.guardrails = target.guardrails;
    plan.guardrails.insert(plan.guardrails.end(), campaign.guardrails.begin(), campaign.guardrails.end());
    plan.telemetry = campaign.telemetry;
    plan.crashSignals = campaign.crashSignals;

    for (const auto& step : campaign.steps) {
        const auto* artifact = FindArtifactById(step.artifactId);
        if (artifact == nullptr) {
            throw std::logic_error("Kernel campaign references unknown artifact id");
        }

        plan.steps.push_back(PlannedCampaignStep{
            step.order,
            step.deliveryPhase,
            step.objective,
            step.expectation,
            step.resetConnectionAfter,
            MakeWorkspaceArtifactReference(*artifact)
        });
    }

    return plan;
}

[[nodiscard]] CampaignExecutionPlan BuildUserModePlan(
    const UserModeTargetDescriptor& target,
    const UserModeCampaign& campaign)
{
    CampaignExecutionPlan plan{};
    plan.id = "plan." + campaign.id;
    plan.scope = PlannedCampaignScope::UserMode;
    plan.targetId = target.id;
    plan.campaignId = campaign.id;
    plan.campaignName = campaign.name;
    plan.executionLane = target.execution == UserModeExecutionKind::BrokerProcess
        ? "user-mode-broker"
        : "user-mode-parser";
    plan.isolation = target.execution == UserModeExecutionKind::BrokerProcess
        ? "process-isolated"
        : "process-isolated-parser";
    plan.snapshotProfile.clear();
    plan.harness = campaign.harness;
    plan.requiresFreshSession = false;
    plan.maxIterationsPerCycle = 0u;
    plan.maxArtifactsPerIteration = static_cast<std::uint32_t>(campaign.seedSources.size());
    plan.objective = campaign.objective;
    plan.guardrails = target.guardrails;
    plan.guardrails.insert(plan.guardrails.end(), campaign.invariants.begin(), campaign.invariants.end());
    plan.telemetry = campaign.telemetry;

    for (const auto& source : campaign.seedSources) {
        plan.seedSources.push_back(ResolveUserModeSeedSource(target.execution, source));
    }

    return plan;
}

[[nodiscard]] std::vector<CampaignExecutionPlan> BuildPlans() {
    std::vector<CampaignExecutionPlan> plans;

    for (const auto& target : KernelTargetCatalog::GetDefaultTargets()) {
        for (const auto& campaign : target.campaigns) {
            plans.push_back(BuildKernelPlan(target, campaign));
        }
    }

    for (const auto& target : UserModeTargetCatalog::GetDefaultTargets()) {
        for (const auto& campaign : target.campaigns) {
            plans.push_back(BuildUserModePlan(target, campaign));
        }
    }

    return plans;
}

void RenderInputReference(std::ostringstream& stream,
    const CampaignInputReference& reference,
    std::string_view indent)
{
    stream << indent << "{\n"
           << indent << "  \"sourceId\": \"" << EscapeJson(reference.sourceId) << "\",\n"
           << indent << "  \"kind\": \"" << ToString(reference.kind) << "\",\n"
           << indent << "  \"relativePath\": \"" << EscapeJson(reference.relativePath) << "\",\n"
           << indent << "  \"sourceKey\": \"" << EscapeJson(reference.sourceKey) << "\",\n"
           << indent << "  \"schemaId\": \"" << EscapeJson(reference.schemaId) << "\",\n"
           << indent << "  \"surfaceId\": \"" << EscapeJson(reference.surfaceId) << "\",\n"
           << indent << "  \"description\": \"" << EscapeJson(reference.description) << "\"\n"
           << indent << '}';
}

void RenderPlan(std::ostringstream& stream,
    const CampaignExecutionPlan& plan,
    std::string_view indent)
{
    stream << indent << "{\n"
           << indent << "  \"id\": \"" << EscapeJson(plan.id) << "\",\n"
           << indent << "  \"scope\": \"" << ToString(plan.scope) << "\",\n"
           << indent << "  \"targetId\": \"" << EscapeJson(plan.targetId) << "\",\n"
           << indent << "  \"campaignId\": \"" << EscapeJson(plan.campaignId) << "\",\n"
           << indent << "  \"campaignName\": \"" << EscapeJson(plan.campaignName) << "\",\n"
           << indent << "  \"executionLane\": \"" << EscapeJson(plan.executionLane) << "\",\n"
           << indent << "  \"isolation\": \"" << EscapeJson(plan.isolation) << "\",\n"
           << indent << "  \"snapshotProfile\": \"" << EscapeJson(plan.snapshotProfile) << "\",\n"
           << indent << "  \"harness\": \"" << EscapeJson(plan.harness) << "\",\n"
           << indent << "  \"requiresFreshSession\": " << (plan.requiresFreshSession ? "true" : "false") << ",\n"
           << indent << "  \"maxIterationsPerCycle\": " << plan.maxIterationsPerCycle << ",\n"
           << indent << "  \"maxArtifactsPerIteration\": " << plan.maxArtifactsPerIteration << ",\n"
           << indent << "  \"objective\": \"" << EscapeJson(plan.objective) << "\",\n";
    RenderStringArray(stream, "guardrails", plan.guardrails, std::string(indent) + "  ");
    stream << ",\n";
    RenderStringArray(stream, "telemetry", plan.telemetry, std::string(indent) + "  ");
    stream << ",\n";
    RenderStringArray(stream, "crashSignals", plan.crashSignals, std::string(indent) + "  ");
    stream << ",\n";

    stream << indent << "  \"seedSources\": [";
    if (!plan.seedSources.empty()) {
        stream << '\n';
        for (std::size_t index = 0; index < plan.seedSources.size(); ++index) {
            RenderInputReference(stream, plan.seedSources[index], std::string(indent) + "    ");
            if (index + 1 != plan.seedSources.size()) {
                stream << ',';
            }
            stream << '\n';
        }
        stream << indent << "  ";
    }
    stream << "],\n";

    stream << indent << "  \"steps\": [";
    if (!plan.steps.empty()) {
        stream << '\n';
        for (std::size_t index = 0; index < plan.steps.size(); ++index) {
            const auto& step = plan.steps[index];
            stream << indent << "    {\n"
                   << indent << "      \"order\": " << step.order << ",\n"
                   << indent << "      \"deliveryPhase\": \"" << EscapeJson(step.deliveryPhase) << "\",\n"
                   << indent << "      \"objective\": \"" << EscapeJson(step.objective) << "\",\n"
                   << indent << "      \"expectation\": \"" << EscapeJson(step.expectation) << "\",\n"
                   << indent << "      \"resetConnectionAfter\": " << (step.resetConnectionAfter ? "true" : "false") << ",\n"
                   << indent << "      \"input\":\n";
            RenderInputReference(stream, step.input, std::string(indent) + "        ");
            stream << '\n'
                   << indent << "    }";
            if (index + 1 != plan.steps.size()) {
                stream << ',';
            }
            stream << '\n';
        }
        stream << indent << "  ";
    }
    stream << "]\n"
           << indent << '}';
}

}  // namespace

std::string_view ToString(const PlannedCampaignScope scope) {
    switch (scope) {
    case PlannedCampaignScope::Kernel:
        return "kernel";
    case PlannedCampaignScope::UserMode:
        return "user-mode";
    }

    return "unknown";
}

std::string_view ToString(const PlannedInputKind kind) {
    switch (kind) {
    case PlannedInputKind::WorkspaceArtifact:
        return "workspace-artifact";
    case PlannedInputKind::LogicalCorpusManifest:
        return "logical-corpus-manifest";
    }

    return "unknown";
}

const std::vector<CampaignExecutionPlan>& CampaignPlanner::GetDefaultPlans() {
    static const std::vector<CampaignExecutionPlan> plans = BuildPlans();
    return plans;
}

const CampaignExecutionPlan* CampaignPlanner::FindById(const std::string_view id) {
    const auto& plans = GetDefaultPlans();
    const auto match = std::find_if(plans.begin(), plans.end(),
        [&](const CampaignExecutionPlan& plan) { return plan.id == id; });
    return match == plans.end() ? nullptr : &(*match);
}

std::string CampaignPlanner::RenderJson(const std::vector<CampaignExecutionPlan>& plans) {
    std::ostringstream stream;
    stream << "{\n  \"plans\": [\n";

    for (std::size_t index = 0; index < plans.size(); ++index) {
        RenderPlan(stream, plans[index], "    ");
        if (index + 1 != plans.size()) {
            stream << ',';
        }
        stream << '\n';
    }

    stream << "  ]\n}\n";
    return stream.str();
}

std::string CampaignPlanner::RenderJson(const CampaignExecutionPlan& plan) {
    return RenderJson(std::vector<CampaignExecutionPlan>{ plan });
}

}  // namespace ShadowStrike::Fuzzer

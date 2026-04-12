#include "ShadowStrike/Fuzzer/Core/AttackSurface.hpp"
#include "ShadowStrike/Fuzzer/Core/CampaignPlanner.hpp"
#include "ShadowStrike/Fuzzer/Core/DispatchRuntime.hpp"
#include "ShadowStrike/Fuzzer/Core/EngineArchitecture.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "ShadowStrike/Fuzzer/Core/HarnessAdapterCatalog.hpp"
#include "ShadowStrike/Fuzzer/Core/MutationEngine.hpp"
#include "ShadowStrike/Fuzzer/Core/OperationsPipeline.hpp"
#include "ShadowStrike/Fuzzer/Core/RunnerExecutionRuntime.hpp"
#include "ShadowStrike/Fuzzer/Core/WorkerBackendRuntime.hpp"
#include "ShadowStrike/Fuzzer/Harnesses/PEParserHarness.hpp"
#include "ShadowStrike/Fuzzer/Harnesses/DisassemblerHarness.hpp"
#include "ShadowStrike/Fuzzer/Harnesses/EmulatorDecoderHarness.hpp"
#include "ShadowStrike/Fuzzer/Protocol/KernelMessageFactory.hpp"
#include "ShadowStrike/Fuzzer/Protocol/KernelMessageSchema.hpp"
#include "ShadowStrike/Fuzzer/Targets/KernelTargetCatalog.hpp"
#include "ShadowStrike/Fuzzer/Targets/UserModeTargetCatalog.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace SSF = ShadowStrike::Fuzzer;

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

void PrintUsage() {
    std::cout
        << "ShadowStrikeFuzzer\n"
        << "Usage:\n"
        << "  ShadowStrikeFuzzer --fuzz-pe <workspace-dir> [--iterations N] [--duration N] [--max-size N]\n"
        << "  ShadowStrikeFuzzer --fuzz-disasm <workspace-dir> [--iterations N] [--duration N] [--max-size N]\n"
        << "  ShadowStrikeFuzzer --fuzz-emu-decoder <workspace-dir> [--iterations N] [--duration N] [--max-size N]\n"
        << "  ShadowStrikeFuzzer --list-targets\n"
        << "  ShadowStrikeFuzzer --describe-target <id>\n"
        << "  ShadowStrikeFuzzer --describe-campaign-plan <id>\n"
        << "  ShadowStrikeFuzzer --describe-dispatch-runtime <workspace>\n"
        << "  ShadowStrikeFuzzer --describe-engine-architecture\n"
        << "  ShadowStrikeFuzzer --describe-harness-adapter <id>\n"
        << "  ShadowStrikeFuzzer --describe-ops-pipeline\n"
        << "  ShadowStrikeFuzzer --describe-runner-execution <workspace>\n"
        << "  ShadowStrikeFuzzer --export-dispatch-runtime <workspace> <json-path>\n"
        << "  ShadowStrikeFuzzer --export-campaign-plans <json-path>\n"
        << "  ShadowStrikeFuzzer --export-engine-architecture <json-path>\n"
        << "  ShadowStrikeFuzzer --export-harness-adapters <json-path>\n"
        << "  ShadowStrikeFuzzer --export-ops-pipeline <json-path>\n"
        << "  ShadowStrikeFuzzer --export-runner-execution <workspace> <json-path>\n"
        << "  ShadowStrikeFuzzer --initialize-workspace <directory>\n"
        << "  ShadowStrikeFuzzer --list-harness-adapters\n"
        << "  ShadowStrikeFuzzer --list-kernel-targets\n"
        << "  ShadowStrikeFuzzer --describe-kernel-target <id>\n"
        << "  ShadowStrikeFuzzer --list-usermode-targets\n"
        << "  ShadowStrikeFuzzer --describe-usermode-target <id>\n"
        << "  ShadowStrikeFuzzer --export-surface-map <json-path>\n"
        << "  ShadowStrikeFuzzer --export-kernel-schemas <json-path>\n"
        << "  ShadowStrikeFuzzer --export-kernel-targets <json-path>\n"
        << "  ShadowStrikeFuzzer --export-usermode-targets <json-path>\n"
        << "  ShadowStrikeFuzzer --export-kernel-seeds <directory>\n"
        << "  ShadowStrikeFuzzer --export-kernel-variants <directory>\n"
        << "  ShadowStrikeFuzzer --run-workspace <directory>\n"
        << "  ShadowStrikeFuzzer --bootstrap <directory>\n";
}

[[nodiscard]] bool WriteBinaryFile(
    const std::filesystem::path& path,
    const std::vector<std::uint8_t>& bytes)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream.good();
}

[[nodiscard]] bool WriteTextFile(const std::filesystem::path& path, const std::string& text) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    return stream.good();
}

[[nodiscard]] std::string NarrowAscii(std::wstring_view value) {
    std::string narrow;
    narrow.reserve(value.size());

    for (const wchar_t ch : value) {
        if (ch > 0x7F) {
            return {};
        }

        narrow.push_back(static_cast<char>(ch));
    }

    return narrow;
}

[[nodiscard]] std::string BuildSeedManifestJson(const std::vector<SSF::BinarySeedArtifact>& seeds) {
    std::ostringstream stream;
    stream << "{\n  \"seeds\": [\n";

    for (std::size_t index = 0; index < seeds.size(); ++index) {
        const auto& seed = seeds[index];
        stream << "    {\n"
               << "      \"id\": \"" << EscapeJson(seed.id) << "\",\n"
               << "      \"surfaceId\": \"" << EscapeJson(seed.surfaceId) << "\",\n"
               << "      \"kind\": \"" << SSF::ToString(seed.kind) << "\",\n"
               << "      \"schemaId\": \"" << EscapeJson(seed.schemaId) << "\",\n"
               << "      \"parentId\": \"" << EscapeJson(seed.parentId) << "\",\n"
               << "      \"fileName\": \"" << EscapeJson(seed.fileName) << "\",\n"
               << "      \"description\": \"" << EscapeJson(seed.description) << "\",\n"
               << "      \"size\": " << seed.bytes.size() << "\n"
               << "    }";

        if (index + 1 != seeds.size()) {
            stream << ',';
        }

        stream << '\n';
    }

    stream << "  ]\n}\n";
    return stream.str();
}

[[nodiscard]] int ExportBinaryArtifacts(
    const std::filesystem::path& outputDirectory,
    const std::vector<SSF::BinarySeedArtifact>& artifacts,
    const std::string_view description)
{
    std::error_code ec;
    std::filesystem::create_directories(outputDirectory, ec);
    if (ec) {
        std::cerr << "Failed to create seed output directory: " << outputDirectory << '\n';
        return 1;
    }

    for (const auto& artifact : artifacts) {
        const auto path = outputDirectory / artifact.fileName;
        if (!WriteBinaryFile(path, artifact.bytes)) {
            std::cerr << "Failed to write seed: " << path << '\n';
            return 1;
        }
    }

    const auto manifestPath = outputDirectory / "manifest.json";
    if (!WriteTextFile(manifestPath, BuildSeedManifestJson(artifacts))) {
        std::cerr << "Failed to write seed manifest: " << manifestPath << '\n';
        return 1;
    }

    std::cout << "Exported " << artifacts.size() << ' ' << description << " to "
              << outputDirectory.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportKernelSeeds(const std::filesystem::path& outputDirectory) {
    return ExportBinaryArtifacts(
        outputDirectory,
        SSF::KernelMessageFactory::BuildBaselineSeedSet(),
        "kernel-protocol baseline seeds");
}

[[nodiscard]] int ExportKernelVariants(const std::filesystem::path& outputDirectory) {
    return ExportBinaryArtifacts(
        outputDirectory,
        SSF::KernelMessageFactory::BuildStructuredVariantSeedSet(),
        "kernel-protocol structured variants");
}

[[nodiscard]] int ExportSurfaceMap(const std::filesystem::path& outputPath) {
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create surface-map directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    const auto json = SSF::AttackSurfaceRegistry::RenderJson(SSF::AttackSurfaceRegistry::GetDefaultRegistry());
    if (!WriteTextFile(outputPath, json)) {
        std::cerr << "Failed to write surface map: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported attack-surface map to " << outputPath.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportKernelSchemas(const std::filesystem::path& outputPath) {
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create schema directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    const auto json = SSF::KernelMessageSchemaCatalog::RenderJson(SSF::KernelMessageSchemaCatalog::GetSchemas());
    if (!WriteTextFile(outputPath, json)) {
        std::cerr << "Failed to write kernel schema catalog: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported kernel message schema catalog to " << outputPath.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportKernelTargets(const std::filesystem::path& outputPath) {
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create kernel-target directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    const auto json = SSF::KernelTargetCatalog::RenderJson(SSF::KernelTargetCatalog::GetDefaultTargets());
    if (!WriteTextFile(outputPath, json)) {
        std::cerr << "Failed to write kernel target catalog: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported kernel target catalog to " << outputPath.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportEngineArchitecture(const std::filesystem::path& outputPath) {
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create engine-architecture directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    const auto json = SSF::EngineArchitectureCatalog::RenderJson(SSF::EngineArchitectureCatalog::GetDefaultArchitecture());
    if (!WriteTextFile(outputPath, json)) {
        std::cerr << "Failed to write engine architecture: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported engine architecture to " << outputPath.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportUserModeTargets(const std::filesystem::path& outputPath) {
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create usermode-target directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    const auto json = SSF::UserModeTargetCatalog::RenderJson(SSF::UserModeTargetCatalog::GetDefaultTargets());
    if (!WriteTextFile(outputPath, json)) {
        std::cerr << "Failed to write user-mode target catalog: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported user-mode target catalog to " << outputPath.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportOpsPipeline(const std::filesystem::path& outputPath) {
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create ops-pipeline directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    const auto json = SSF::OperationsPipelineCatalog::RenderJson(SSF::OperationsPipelineCatalog::GetDefaultPipeline());
    if (!WriteTextFile(outputPath, json)) {
        std::cerr << "Failed to write operations pipeline: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported operations pipeline to " << outputPath.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportCampaignPlans(const std::filesystem::path& outputPath) {
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create campaign-plan directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    const auto json = SSF::CampaignPlanner::RenderJson(SSF::CampaignPlanner::GetDefaultPlans());
    if (!WriteTextFile(outputPath, json)) {
        std::cerr << "Failed to write campaign plans: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported campaign plans to " << outputPath.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportDispatchRuntime(
    const std::filesystem::path& workspaceRoot,
    const std::filesystem::path& outputPath)
{
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create dispatch-runtime directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    const auto manifest = SSF::DispatchRuntime::BuildWorkspaceManifest(workspaceRoot);
    if (!WriteTextFile(outputPath, SSF::DispatchRuntime::RenderJson(manifest))) {
        std::cerr << "Failed to write dispatch runtime manifest: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported dispatch runtime manifest to " << outputPath.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportHarnessAdapters(const std::filesystem::path& outputPath) {
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create harness-adapter directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    const auto json = SSF::HarnessAdapterCatalog::RenderJson(SSF::HarnessAdapterCatalog::GetDefaultAdapters());
    if (!WriteTextFile(outputPath, json)) {
        std::cerr << "Failed to write harness adapters: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported harness adapters to " << outputPath.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportRunnerExecution(
    const std::filesystem::path& workspaceRoot,
    const std::filesystem::path& outputPath)
{
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create runner-execution directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    std::string errorMessage;
    const auto ledger = SSF::RunnerExecutionRuntime::ExecuteWorkspace(workspaceRoot, errorMessage);
    if (!errorMessage.empty()) {
        std::cerr << errorMessage << '\n';
        return 1;
    }

    if (!WriteTextFile(outputPath, SSF::RunnerExecutionRuntime::RenderJson(ledger))) {
        std::cerr << "Failed to write runner execution ledger: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported runner execution ledger to " << outputPath.string() << '\n';
    return 0;
}

struct LogicalCorpusManifestEntry {
    std::string sourceKey;
    std::string sourceId;
    std::string description;
    std::vector<std::string> consumerPlanIds;
};

[[nodiscard]] std::string BuildLogicalCorpusManifestJson(
    const std::vector<SSF::CampaignExecutionPlan>& plans,
    const std::string_view manifestRelativePath)
{
    std::vector<LogicalCorpusManifestEntry> entries;

    for (const auto& plan : plans) {
        for (const auto& input : plan.seedSources) {
            if (input.kind != SSF::PlannedInputKind::LogicalCorpusManifest ||
                input.relativePath != manifestRelativePath) {
                continue;
            }

            auto match = std::find_if(entries.begin(), entries.end(),
                [&](const LogicalCorpusManifestEntry& entry) { return entry.sourceKey == input.sourceKey; });

            if (match == entries.end()) {
                entries.push_back(LogicalCorpusManifestEntry{
                    input.sourceKey,
                    input.sourceId,
                    input.description,
                    { plan.id }
                });
                continue;
            }

            if (std::find(match->consumerPlanIds.begin(), match->consumerPlanIds.end(), plan.id) ==
                match->consumerPlanIds.end()) {
                match->consumerPlanIds.push_back(plan.id);
            }
        }
    }

    std::ostringstream stream;
    stream << "{\n  \"logicalCorpora\": [\n";

    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index];
        stream << "    {\n"
               << "      \"sourceKey\": \"" << EscapeJson(entry.sourceKey) << "\",\n"
               << "      \"sourceId\": \"" << EscapeJson(entry.sourceId) << "\",\n"
               << "      \"description\": \"" << EscapeJson(entry.description) << "\",\n"
               << "      \"consumerPlanIds\": [";

        if (!entry.consumerPlanIds.empty()) {
            stream << '\n';
            for (std::size_t consumerIndex = 0; consumerIndex < entry.consumerPlanIds.size(); ++consumerIndex) {
                stream << "        \"" << EscapeJson(entry.consumerPlanIds[consumerIndex]) << '"';
                if (consumerIndex + 1 != entry.consumerPlanIds.size()) {
                    stream << ',';
                }
                stream << '\n';
            }
            stream << "      ";
        }

        stream << "]\n"
               << "    }";

        if (index + 1 != entries.size()) {
            stream << ',';
        }
        stream << '\n';
    }

    stream << "  ]\n}\n";
    return stream.str();
}

[[nodiscard]] int WriteCampaignQueue(const std::filesystem::path& rootDirectory) {
    const auto& plans = SSF::CampaignPlanner::GetDefaultPlans();
    const auto queueDirectory = rootDirectory / "pipeline\\queue";

    std::ostringstream manifest;
    manifest << "{\n  \"plans\": [\n";

    for (std::size_t index = 0; index < plans.size(); ++index) {
        const auto& plan = plans[index];
        const auto fileName = plan.id + ".json";
        if (!WriteTextFile(queueDirectory / fileName, SSF::CampaignPlanner::RenderJson(plan))) {
            std::cerr << "Failed to write queued campaign plan: " << (queueDirectory / fileName) << '\n';
            return 1;
        }

        manifest << "    {\n"
                 << "      \"id\": \"" << EscapeJson(plan.id) << "\",\n"
                 << "      \"fileName\": \"" << EscapeJson(fileName) << "\",\n"
                 << "      \"scope\": \"" << SSF::ToString(plan.scope) << "\",\n"
                 << "      \"targetId\": \"" << EscapeJson(plan.targetId) << "\",\n"
                 << "      \"executionLane\": \"" << EscapeJson(plan.executionLane) << "\"\n"
                 << "    }";

        if (index + 1 != plans.size()) {
            manifest << ',';
        }
        manifest << '\n';
    }

    manifest << "  ]\n}\n";

    if (!WriteTextFile(queueDirectory / "manifest.json", manifest.str())) {
        std::cerr << "Failed to write queue manifest\n";
        return 1;
    }

    if (!WriteTextFile(rootDirectory / "state\\campaign-index.json", SSF::CampaignPlanner::RenderJson(plans))) {
        std::cerr << "Failed to write campaign index\n";
        return 1;
    }

    return 0;
}

[[nodiscard]] std::string BuildSnapshotProfileManifestJson(
    const std::string_view snapshotProfile,
    const std::vector<std::string>& planIds)
{
    std::ostringstream stream;
    stream << "{\n"
           << "  \"snapshotProfile\": \"" << EscapeJson(snapshotProfile) << "\",\n"
           << "  \"plans\": [";
    if (!planIds.empty()) {
        stream << '\n';
        for (std::size_t index = 0; index < planIds.size(); ++index) {
            stream << "    \"" << EscapeJson(planIds[index]) << '"';
            if (index + 1 != planIds.size()) {
                stream << ',';
            }
            stream << '\n';
        }
        stream << "  ";
    }
    stream << "]\n}\n";
    return stream.str();
}

[[nodiscard]] int WriteSnapshotProfileCatalog(const std::filesystem::path& rootDirectory) {
    std::vector<std::string> snapshotProfiles;
    const auto& plans = SSF::CampaignPlanner::GetDefaultPlans();

    for (const auto& plan : plans) {
        if (plan.snapshotProfile.empty()) {
            continue;
        }

        if (std::find(snapshotProfiles.begin(), snapshotProfiles.end(), plan.snapshotProfile) == snapshotProfiles.end()) {
            snapshotProfiles.push_back(plan.snapshotProfile);
        }
    }

    for (const auto& snapshotProfile : snapshotProfiles) {
        std::vector<std::string> boundPlanIds;
        for (const auto& plan : plans) {
            if (plan.snapshotProfile == snapshotProfile) {
                boundPlanIds.push_back(plan.id);
            }
        }

        const auto path = rootDirectory / ("vm\\profiles\\" + snapshotProfile + ".json");
        if (!WriteTextFile(path, BuildSnapshotProfileManifestJson(snapshotProfile, boundPlanIds))) {
            std::cerr << "Failed to write snapshot profile manifest: " << path << '\n';
            return 1;
        }
    }

    std::ostringstream stream;
    stream << "{\n  \"snapshotProfiles\": [";
    if (!snapshotProfiles.empty()) {
        stream << '\n';
        for (std::size_t index = 0; index < snapshotProfiles.size(); ++index) {
            stream << "    \"" << EscapeJson(snapshotProfiles[index]) << '"';
            if (index + 1 != snapshotProfiles.size()) {
                stream << ',';
            }
            stream << '\n';
        }
        stream << "  ";
    }
    stream << "]\n}\n";

    if (!WriteTextFile(rootDirectory / "vm\\profiles\\manifest.json", stream.str())) {
        std::cerr << "Failed to write snapshot profile catalog\n";
        return 1;
    }

    return 0;
}

[[nodiscard]] int InitializeWorkspace(const std::filesystem::path& rootDirectory) {
    std::error_code ec;
    std::filesystem::create_directories(rootDirectory, ec);
    if (ec) {
        std::cerr << "Failed to create workspace root: " << rootDirectory << '\n';
        return 1;
    }

    const auto& pipeline = SSF::OperationsPipelineCatalog::GetDefaultPipeline();
    for (const auto& directory : pipeline.workspaceDirectories) {
        std::filesystem::create_directories(rootDirectory / directory.relativePath, ec);
        if (ec) {
            std::cerr << "Failed to create workspace directory: " << (rootDirectory / directory.relativePath) << '\n';
            return 1;
        }
    }

    if (!WriteTextFile(rootDirectory / "layout.json", SSF::OperationsPipelineCatalog::RenderJson(pipeline))) {
        std::cerr << "Failed to write workspace layout manifest\n";
        return 1;
    }

    if (const int baselineStatus = ExportBinaryArtifacts(
            rootDirectory / "corpora\\kernel\\baseline",
            SSF::KernelMessageFactory::BuildBaselineSeedSet(),
            "workspace kernel baseline corpus");
        baselineStatus != 0) {
        return baselineStatus;
    }

    if (const int variantStatus = ExportBinaryArtifacts(
            rootDirectory / "corpora\\kernel\\variants",
            SSF::KernelMessageFactory::BuildStructuredVariantSeedSet(),
            "workspace kernel variant corpus");
        variantStatus != 0) {
        return variantStatus;
    }

    const auto& plans = SSF::CampaignPlanner::GetDefaultPlans();
    if (!WriteTextFile(rootDirectory / "corpora\\usermode\\broker\\manifest.json",
            BuildLogicalCorpusManifestJson(plans, "corpora\\usermode\\broker\\manifest.json"))) {
        std::cerr << "Failed to write user-mode broker corpus manifest\n";
        return 1;
    }

    if (!WriteTextFile(rootDirectory / "corpora\\usermode\\parser\\manifest.json",
            BuildLogicalCorpusManifestJson(plans, "corpora\\usermode\\parser\\manifest.json"))) {
        std::cerr << "Failed to write user-mode parser corpus manifest\n";
        return 1;
    }

    if (const int queueStatus = WriteCampaignQueue(rootDirectory); queueStatus != 0) {
        return queueStatus;
    }

    if (const int snapshotStatus = WriteSnapshotProfileCatalog(rootDirectory); snapshotStatus != 0) {
        return snapshotStatus;
    }

    std::string dispatchError;
    if (!SSF::DispatchRuntime::MaterializeWorkspaceState(rootDirectory, dispatchError)) {
        std::cerr << dispatchError << '\n';
        return 1;
    }

    std::cout << "Initialized fuzz workspace at " << rootDirectory.string() << '\n';
    return 0;
}

[[nodiscard]] int Bootstrap(const std::filesystem::path& outputDirectory) {
    std::error_code ec;
    std::filesystem::create_directories(outputDirectory, ec);
    if (ec) {
        std::cerr << "Failed to create bootstrap directory: " << outputDirectory << '\n';
        return 1;
    }

    if (const int surfaceStatus = ExportSurfaceMap(outputDirectory / "attack-surface-map.json");
        surfaceStatus != 0) {
        return surfaceStatus;
    }

    if (const int schemaStatus = ExportKernelSchemas(outputDirectory / "kernel-message-schemas.json");
        schemaStatus != 0) {
        return schemaStatus;
    }

    if (const int targetStatus = ExportKernelTargets(outputDirectory / "kernel-targets.json");
        targetStatus != 0) {
        return targetStatus;
    }

    if (const int engineStatus = ExportEngineArchitecture(outputDirectory / "engine-architecture.json");
        engineStatus != 0) {
        return engineStatus;
    }

    if (const int userModeStatus = ExportUserModeTargets(outputDirectory / "usermode-targets.json");
        userModeStatus != 0) {
        return userModeStatus;
    }

    if (const int opsStatus = ExportOpsPipeline(outputDirectory / "ops-pipeline.json");
        opsStatus != 0) {
        return opsStatus;
    }

    if (const int campaignStatus = ExportCampaignPlans(outputDirectory / "campaign-plans.json");
        campaignStatus != 0) {
        return campaignStatus;
    }

    if (const int harnessStatus = ExportHarnessAdapters(outputDirectory / "harness-adapters.json");
        harnessStatus != 0) {
        return harnessStatus;
    }

    if (const int seedStatus = ExportKernelSeeds(outputDirectory / "kernel-seeds");
        seedStatus != 0) {
        return seedStatus;
    }

    return ExportKernelVariants(outputDirectory / "kernel-variants");
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
    if (argc <= 1) {
        PrintUsage();
        return 0;
    }

    const std::wstring_view command = argv[1];

    // PE Parser Fuzzing Command
    if (command == L"--fuzz-pe") {
        if (argc < 3) {
            std::cerr << "--fuzz-pe requires a workspace directory\n";
            return 1;
        }

        SSF::FuzzLoopConfig config;
        config.maxIterations = 0;      // Unlimited by default
        config.maxDurationSeconds = 0; // Unlimited by default
        config.maxInputSize = 16 * 1024 * 1024;  // 16MB
        config.reportIntervalIterations = 1000;

        // Parse optional arguments
        for (int i = 3; i < argc; ++i) {
            const std::wstring_view arg = argv[i];
            
            if (arg == L"--iterations" && i + 1 < argc) {
                try {
                    config.maxIterations = std::stoull(NarrowAscii(argv[++i]));
                } catch (...) {
                    std::cerr << "Invalid --iterations value\n";
                    return 1;
                }
            } else if (arg == L"--duration" && i + 1 < argc) {
                try {
                    config.maxDurationSeconds = std::stoull(NarrowAscii(argv[++i]));
                } catch (...) {
                    std::cerr << "Invalid --duration value\n";
                    return 1;
                }
            } else if (arg == L"--max-size" && i + 1 < argc) {
                try {
                    config.maxInputSize = std::stoull(NarrowAscii(argv[++i]));
                } catch (...) {
                    std::cerr << "Invalid --max-size value\n";
                    return 1;
                }
            } else {
                std::cerr << "Unknown option: " << NarrowAscii(arg) << '\n';
                return 1;
            }
        }

        return SSF::RunPEParserFuzzer(argv[2], config);
    }

    // Disassembler Fuzzing Command
    if (command == L"--fuzz-disasm") {
        if (argc < 3) {
            std::cerr << "--fuzz-disasm requires a workspace directory\n";
            return 1;
        }

        SSF::FuzzLoopConfig config;
        config.maxIterations = 0;
        config.maxDurationSeconds = 0;
        config.maxInputSize = 4096;  // Instruction streams are small
        config.reportIntervalIterations = 1000;

        for (int i = 3; i < argc; ++i) {
            const std::wstring_view arg = argv[i];

            if (arg == L"--iterations" && i + 1 < argc) {
                try {
                    config.maxIterations = std::stoull(NarrowAscii(argv[++i]));
                } catch (...) {
                    std::cerr << "Invalid --iterations value\n";
                    return 1;
                }
            } else if (arg == L"--duration" && i + 1 < argc) {
                try {
                    config.maxDurationSeconds = std::stoull(NarrowAscii(argv[++i]));
                } catch (...) {
                    std::cerr << "Invalid --duration value\n";
                    return 1;
                }
            } else if (arg == L"--max-size" && i + 1 < argc) {
                try {
                    config.maxInputSize = std::stoull(NarrowAscii(argv[++i]));
                } catch (...) {
                    std::cerr << "Invalid --max-size value\n";
                    return 1;
                }
            } else {
                std::cerr << "Unknown option: " << NarrowAscii(arg) << '\n';
                return 1;
            }
        }

        return SSF::RunDisassemblerFuzzer(argv[2], config);
    }

    // Emulator Instruction Decoder Fuzzing Command
    if (command == L"--fuzz-emu-decoder") {
        if (argc < 3) {
            std::cerr << "--fuzz-emu-decoder requires a workspace directory\n";
            return 1;
        }

        SSF::FuzzLoopConfig config;
        config.maxIterations = 0;
        config.maxDurationSeconds = 0;
        config.maxInputSize = 4096;
        config.reportIntervalIterations = 1000;

        for (int i = 3; i < argc; ++i) {
            const std::wstring_view arg = argv[i];

            if (arg == L"--iterations" && i + 1 < argc) {
                try {
                    config.maxIterations = std::stoull(NarrowAscii(argv[++i]));
                } catch (...) {
                    std::cerr << "Invalid --iterations value\n";
                    return 1;
                }
            } else if (arg == L"--duration" && i + 1 < argc) {
                try {
                    config.maxDurationSeconds = std::stoull(NarrowAscii(argv[++i]));
                } catch (...) {
                    std::cerr << "Invalid --duration value\n";
                    return 1;
                }
            } else if (arg == L"--max-size" && i + 1 < argc) {
                try {
                    config.maxInputSize = std::stoull(NarrowAscii(argv[++i]));
                } catch (...) {
                    std::cerr << "Invalid --max-size value\n";
                    return 1;
                }
            } else {
                std::cerr << "Unknown option: " << NarrowAscii(arg) << '\n';
                return 1;
            }
        }

        return SSF::RunEmulatorDecoderFuzzer(argv[2], config);
    }

    if (command == L"--list-targets") {
        for (const auto& surface : SSF::AttackSurfaceRegistry::GetDefaultRegistry()) {
            std::cout << surface.id << " | " << surface.component << " | "
                      << surface.protocolOrFormat << '\n';
        }
        return 0;
    }

    if (command == L"--describe-target") {
        if (argc < 3) {
            std::cerr << "--describe-target requires an id\n";
            return 1;
        }

        const std::string id = NarrowAscii(argv[2]);
        if (id.empty()) {
            std::cerr << "Target ids must be ASCII\n";
            return 1;
        }

        const auto* surface = SSF::AttackSurfaceRegistry::FindById(id);
        if (surface == nullptr) {
            std::cerr << "Unknown target id: " << id << '\n';
            return 1;
        }

        std::cout << SSF::AttackSurfaceRegistry::DescribeText(*surface);
        return 0;
    }

    if (command == L"--describe-campaign-plan") {
        if (argc < 3) {
            std::cerr << "--describe-campaign-plan requires an id\n";
            return 1;
        }

        const std::string id = NarrowAscii(argv[2]);
        if (id.empty()) {
            std::cerr << "Campaign plan ids must be ASCII\n";
            return 1;
        }

        const auto* plan = SSF::CampaignPlanner::FindById(id);
        if (plan == nullptr) {
            std::cerr << "Unknown campaign plan id: " << id << '\n';
            return 1;
        }

        std::cout << SSF::CampaignPlanner::RenderJson(*plan);
        return 0;
    }

    if (command == L"--describe-dispatch-runtime") {
        if (argc < 3) {
            std::cerr << "--describe-dispatch-runtime requires a workspace path\n";
            return 1;
        }

        const auto manifest = SSF::DispatchRuntime::BuildWorkspaceManifest(argv[2]);
        std::cout << SSF::DispatchRuntime::DescribeText(manifest);
        return 0;
    }

    if (command == L"--describe-engine-architecture") {
        std::cout << SSF::EngineArchitectureCatalog::DescribeText(SSF::EngineArchitectureCatalog::GetDefaultArchitecture());
        return 0;
    }

    if (command == L"--list-harness-adapters") {
        for (const auto& adapter : SSF::HarnessAdapterCatalog::GetDefaultAdapters()) {
            std::cout << adapter.id << " | " << adapter.laneId << " | "
                      << SSF::ToString(adapter.kind) << '\n';
        }
        return 0;
    }

    if (command == L"--describe-harness-adapter") {
        if (argc < 3) {
            std::cerr << "--describe-harness-adapter requires an id\n";
            return 1;
        }

        const std::string id = NarrowAscii(argv[2]);
        if (id.empty()) {
            std::cerr << "Harness adapter ids must be ASCII\n";
            return 1;
        }

        const auto* adapter = SSF::HarnessAdapterCatalog::FindById(id);
        if (adapter == nullptr) {
            std::cerr << "Unknown harness adapter id: " << id << '\n';
            return 1;
        }

        std::cout << SSF::HarnessAdapterCatalog::DescribeText(*adapter);
        return 0;
    }

    if (command == L"--describe-ops-pipeline") {
        std::cout << SSF::OperationsPipelineCatalog::DescribeText(SSF::OperationsPipelineCatalog::GetDefaultPipeline());
        return 0;
    }

    if (command == L"--describe-runner-execution") {
        if (argc < 3) {
            std::cerr << "--describe-runner-execution requires a workspace path\n";
            return 1;
        }

        std::string errorMessage;
        const auto ledger = SSF::RunnerExecutionRuntime::ExecuteWorkspace(argv[2], errorMessage);
        if (!errorMessage.empty()) {
            std::cerr << errorMessage << '\n';
            return 1;
        }

        std::cout << SSF::RunnerExecutionRuntime::DescribeText(ledger);
        return 0;
    }

    if (command == L"--list-kernel-targets") {
        for (const auto& target : SSF::KernelTargetCatalog::GetDefaultTargets()) {
            std::cout << target.id << " | " << target.surfaceId << " | "
                      << SSF::ToString(target.transport) << '\n';
        }
        return 0;
    }

    if (command == L"--describe-kernel-target") {
        if (argc < 3) {
            std::cerr << "--describe-kernel-target requires an id\n";
            return 1;
        }

        const std::string id = NarrowAscii(argv[2]);
        if (id.empty()) {
            std::cerr << "Kernel target ids must be ASCII\n";
            return 1;
        }

        const auto* target = SSF::KernelTargetCatalog::FindById(id);
        if (target == nullptr) {
            std::cerr << "Unknown kernel target id: " << id << '\n';
            return 1;
        }

        std::cout << SSF::KernelTargetCatalog::DescribeText(*target);
        return 0;
    }

    if (command == L"--list-usermode-targets") {
        for (const auto& target : SSF::UserModeTargetCatalog::GetDefaultTargets()) {
            std::cout << target.id << " | " << target.surfaceId << " | "
                      << SSF::ToString(target.execution) << '\n';
        }
        return 0;
    }

    if (command == L"--describe-usermode-target") {
        if (argc < 3) {
            std::cerr << "--describe-usermode-target requires an id\n";
            return 1;
        }

        const std::string id = NarrowAscii(argv[2]);
        if (id.empty()) {
            std::cerr << "User-mode target ids must be ASCII\n";
            return 1;
        }

        const auto* target = SSF::UserModeTargetCatalog::FindById(id);
        if (target == nullptr) {
            std::cerr << "Unknown user-mode target id: " << id << '\n';
            return 1;
        }

        std::cout << SSF::UserModeTargetCatalog::DescribeText(*target);
        return 0;
    }

    if (command == L"--export-surface-map") {
        if (argc < 3) {
            std::cerr << "--export-surface-map requires an output path\n";
            return 1;
        }

        return ExportSurfaceMap(argv[2]);
    }

    if (command == L"--export-kernel-schemas") {
        if (argc < 3) {
            std::cerr << "--export-kernel-schemas requires an output path\n";
            return 1;
        }

        return ExportKernelSchemas(argv[2]);
    }

    if (command == L"--export-kernel-targets") {
        if (argc < 3) {
            std::cerr << "--export-kernel-targets requires an output path\n";
            return 1;
        }

        return ExportKernelTargets(argv[2]);
    }

    if (command == L"--export-engine-architecture") {
        if (argc < 3) {
            std::cerr << "--export-engine-architecture requires an output path\n";
            return 1;
        }

        return ExportEngineArchitecture(argv[2]);
    }

    if (command == L"--export-harness-adapters") {
        if (argc < 3) {
            std::cerr << "--export-harness-adapters requires an output path\n";
            return 1;
        }

        return ExportHarnessAdapters(argv[2]);
    }

    if (command == L"--export-campaign-plans") {
        if (argc < 3) {
            std::cerr << "--export-campaign-plans requires an output path\n";
            return 1;
        }

        return ExportCampaignPlans(argv[2]);
    }

    if (command == L"--export-dispatch-runtime") {
        if (argc < 4) {
            std::cerr << "--export-dispatch-runtime requires a workspace path and output path\n";
            return 1;
        }

        return ExportDispatchRuntime(argv[2], argv[3]);
    }

    if (command == L"--export-ops-pipeline") {
        if (argc < 3) {
            std::cerr << "--export-ops-pipeline requires an output path\n";
            return 1;
        }

        return ExportOpsPipeline(argv[2]);
    }

    if (command == L"--export-runner-execution") {
        if (argc < 4) {
            std::cerr << "--export-runner-execution requires a workspace path and output path\n";
            return 1;
        }

        return ExportRunnerExecution(argv[2], argv[3]);
    }

    if (command == L"--export-usermode-targets") {
        if (argc < 3) {
            std::cerr << "--export-usermode-targets requires an output path\n";
            return 1;
        }

        return ExportUserModeTargets(argv[2]);
    }

    if (command == L"--initialize-workspace") {
        if (argc < 3) {
            std::cerr << "--initialize-workspace requires a directory\n";
            return 1;
        }

        return InitializeWorkspace(argv[2]);
    }

    if (command == L"--export-kernel-seeds") {
        if (argc < 3) {
            std::cerr << "--export-kernel-seeds requires an output directory\n";
            return 1;
        }

        return ExportKernelSeeds(argv[2]);
    }

    if (command == L"--export-kernel-variants") {
        if (argc < 3) {
            std::cerr << "--export-kernel-variants requires an output directory\n";
            return 1;
        }

        return ExportKernelVariants(argv[2]);
    }

    if (command == L"--bootstrap") {
        if (argc < 3) {
            std::cerr << "--bootstrap requires an output directory\n";
            return 1;
        }

        return Bootstrap(argv[2]);
    }

    if (command == L"--run-workspace") {
        if (argc < 3) {
            std::cerr << "--run-workspace requires a workspace directory\n";
            return 1;
        }

        std::string errorMessage;
        const auto ledger = SSF::RunnerExecutionRuntime::ExecuteWorkspace(argv[2], errorMessage);
        if (!errorMessage.empty()) {
            std::cerr << errorMessage << '\n';
            return 1;
        }

        std::cout << SSF::RunnerExecutionRuntime::DescribeText(ledger);
        return 0;
    }

    if (command == L"--worker-kernel-vm" || command == L"--worker-broker" || command == L"--worker-parser") {
        if (argc < 4) {
            std::cerr << "Worker command requires a workspace directory and plan id\n";
            return 1;
        }

        const std::string planId = NarrowAscii(argv[3]);
        if (planId.empty()) {
            std::cerr << "Worker plan ids must be ASCII\n";
            return 1;
        }

        const auto workerKind = command == L"--worker-kernel-vm"
            ? SSF::WorkerCommandKind::KernelVm
            : command == L"--worker-broker"
                ? SSF::WorkerCommandKind::Broker
                : SSF::WorkerCommandKind::Parser;
        return SSF::WorkerBackendRuntime::RunWorkerCommand(workerKind, argv[2], planId);
    }

    std::cerr << "Unknown command\n";
    PrintUsage();
    return 1;
}

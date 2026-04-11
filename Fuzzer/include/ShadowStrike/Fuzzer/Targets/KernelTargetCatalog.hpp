#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

enum class KernelTransportKind {
    FilterManagerCommPort,
    CallbackReplay
};

enum class KernelIsolationMode {
    VmSnapshotOnly,
    VmSnapshotWithRebootOnCrash
};

enum class KernelCampaignType {
    StatefulSession,
    RequestReply,
    BatchIngestion,
    StateTransition
};

[[nodiscard]] std::string_view ToString(KernelTransportKind kind);
[[nodiscard]] std::string_view ToString(KernelIsolationMode mode);
[[nodiscard]] std::string_view ToString(KernelCampaignType type);

struct KernelCampaignStep {
    std::uint32_t order;
    std::string artifactId;
    std::string deliveryPhase;
    std::string objective;
    std::string expectation;
    bool resetConnectionAfter{ false };
};

struct KernelCampaign {
    std::string id;
    std::string targetId;
    std::string name;
    KernelCampaignType type;
    std::string objective;
    bool requiresFreshSession{ true };
    std::uint32_t maxArtifactsPerIteration{ 1 };
    std::vector<std::string> guardrails;
    std::vector<std::string> crashSignals;
    std::vector<std::string> telemetry;
    std::vector<KernelCampaignStep> steps;
};

struct KernelTargetDescriptor {
    std::string id;
    std::string surfaceId;
    std::string component;
    KernelTransportKind transport;
    KernelIsolationMode isolation;
    std::string snapshotProfile;
    std::uint32_t maxIterationsPerBoot;
    std::string description;
    std::vector<std::string> prerequisites;
    std::vector<std::string> guardrails;
    std::vector<KernelCampaign> campaigns;
};

class KernelTargetCatalog final {
public:
    [[nodiscard]] static const std::vector<KernelTargetDescriptor>& GetDefaultTargets();
    [[nodiscard]] static const KernelTargetDescriptor* FindById(std::string_view id);
    [[nodiscard]] static std::string DescribeText(const KernelTargetDescriptor& target);
    [[nodiscard]] static std::string RenderJson(const std::vector<KernelTargetDescriptor>& targets);
};

}  // namespace ShadowStrike::Fuzzer

#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

enum class UserModeExecutionKind {
    BrokerProcess,
    InProcessParser,
    DifferentialHarness
};

enum class UserModeCampaignType {
    SessionProtocol,
    AsyncStress,
    ParserFrontDoor,
    DifferentialParsing
};

[[nodiscard]] std::string_view ToString(UserModeExecutionKind kind);
[[nodiscard]] std::string_view ToString(UserModeCampaignType type);

struct UserModeCampaign {
    std::string id;
    std::string targetId;
    std::string name;
    UserModeCampaignType type;
    std::string harness;
    std::string objective;
    std::vector<std::string> seedSources;
    std::vector<std::string> mutationAxes;
    std::vector<std::string> invariants;
    std::vector<std::string> telemetry;
};

struct UserModeTargetDescriptor {
    std::string id;
    std::string surfaceId;
    std::string component;
    UserModeExecutionKind execution;
    std::string description;
    std::vector<std::string> prerequisites;
    std::vector<std::string> guardrails;
    std::vector<UserModeCampaign> campaigns;
};

class UserModeTargetCatalog final {
public:
    [[nodiscard]] static const std::vector<UserModeTargetDescriptor>& GetDefaultTargets();
    [[nodiscard]] static const UserModeTargetDescriptor* FindById(std::string_view id);
    [[nodiscard]] static std::string DescribeText(const UserModeTargetDescriptor& target);
    [[nodiscard]] static std::string RenderJson(const std::vector<UserModeTargetDescriptor>& targets);
};

}  // namespace ShadowStrike::Fuzzer

#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

enum class AttackSurfaceFamily {
    KernelCommPort,
    KernelCallbackReplay,
    UserModeIpc,
    Parser,
    Emulator,
    Disassembler
};

enum class TrustBoundary {
    UserToKernel,
    KernelToUser,
    LocalServiceToBroker,
    UntrustedContentToEngine
};

enum class ExecutionLane {
    InProcess,
    BrokerProcess,
    IsolatedVmKernel
};

enum class RiskTier {
    Critical,
    High,
    Medium
};

struct AttackSurfaceDescriptor {
    std::string id;
    std::string component;
    std::string entryPoint;
    std::string protocolOrFormat;
    AttackSurfaceFamily family;
    TrustBoundary boundary;
    ExecutionLane executionLane;
    RiskTier riskTier;
    bool stateful{ false };
    bool requiresVmIsolation{ false };
    std::vector<std::string> schemaSources;
    std::vector<std::string> mutationAxes;
    std::vector<std::string> invariants;
};

class AttackSurfaceRegistry final {
public:
    [[nodiscard]] static const std::vector<AttackSurfaceDescriptor>& GetDefaultRegistry() noexcept;
    [[nodiscard]] static const AttackSurfaceDescriptor* FindById(std::string_view id) noexcept;
    [[nodiscard]] static std::string RenderJson(const std::vector<AttackSurfaceDescriptor>& surfaces);
    [[nodiscard]] static std::string DescribeText(const AttackSurfaceDescriptor& surface);
};

}  // namespace ShadowStrike::Fuzzer

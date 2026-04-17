#pragma once

#include "Products/Community/PhantomEDR/IncidentResponse/IncidentTypes.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::IncidentResponse {

class ContainmentEngineImpl;

struct ContainmentParams {
    uint32_t pid = 0;
    std::wstring filePath;
    std::string ipAddress;
    std::wstring userName;
    std::wstring serviceName;
    std::string reason;
};

struct ContainmentRecord {
    std::string recordId;
    std::string incidentId;
    ContainmentAction action = ContainmentAction::IsolateNetwork;
    ContainmentParams params;
    std::chrono::system_clock::time_point executedAt{};
    std::optional<std::chrono::system_clock::time_point> rolledBackAt;
    bool success = false;
    std::string errorMessage;
};

class ContainmentEngine final {
public:
    [[nodiscard]] static ContainmentEngine& Instance();

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] bool ExecuteContainment(
        std::string_view incidentId,
        ContainmentAction action,
        const ContainmentParams& params);

    [[nodiscard]] bool RollbackContainment(
        std::string_view incidentId,
        ContainmentAction action);

    [[nodiscard]] bool IsolateNetwork(std::string_view incidentId);
    [[nodiscard]] bool RestoreNetwork(std::string_view incidentId);
    [[nodiscard]] bool TerminateProcess(uint32_t pid, bool killTree = false);
    [[nodiscard]] bool LockUserAccount(std::wstring_view userName);
    [[nodiscard]] bool UnlockUserAccount(std::wstring_view userName);
    [[nodiscard]] bool BlockIPAddress(std::string_view ipAddress);
    [[nodiscard]] bool UnblockIPAddress(std::string_view ipAddress);
    [[nodiscard]] std::vector<ContainmentRecord> GetActiveContainments() const;
    [[nodiscard]] std::vector<ContainmentRecord> GetContainmentHistory(std::string_view incidentId) const;

private:
    ContainmentEngine();
    ~ContainmentEngine();

    ContainmentEngine(const ContainmentEngine&) = delete;
    ContainmentEngine& operator=(const ContainmentEngine&) = delete;

    std::unique_ptr<ContainmentEngineImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::IncidentResponse

#pragma once

#include "Products/Community/PhantomEDR/IncidentResponse/IncidentTypes.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::IncidentResponse {

class RemediationEngineImpl;

struct RemediationParams {
    std::wstring filePath;
    std::wstring registryPath;
    std::wstring serviceName;
    std::wstring taskPath;
    std::wstring backupPath;
    std::vector<uint8_t> backupData;
    std::string reason;
};

struct RemediationRecord {
    std::string recordId;
    std::string incidentId;
    RemediationAction action = RemediationAction::QuarantineFile;
    std::string params;
    std::chrono::system_clock::time_point executedAt{};
    bool success = false;
    std::string errorMessage;
    bool rollbackAvailable = false;
};

class RemediationEngine final {
public:
    [[nodiscard]] static RemediationEngine& Instance();

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] bool ExecuteRemediation(
        std::string_view incidentId,
        RemediationAction action,
        const RemediationParams& params);

    [[nodiscard]] bool QuarantineFile(std::string_view incidentId, const std::wstring& filePath);
    [[nodiscard]] bool RestoreQuarantinedFile(std::string_view incidentId, const std::wstring& filePath);
    [[nodiscard]] bool DeleteFile(std::string_view incidentId, const std::wstring& filePath);
    [[nodiscard]] bool RollbackRegistryChanges(
        std::string_view incidentId,
        const std::wstring& registryPath,
        const std::vector<uint8_t>& backupData);
    [[nodiscard]] bool RemoveService(std::string_view incidentId, const std::wstring& serviceName);
    [[nodiscard]] bool RemoveScheduledTask(std::string_view incidentId, const std::wstring& taskPath);
    [[nodiscard]] bool RestoreFromBackup(
        std::string_view incidentId,
        const std::wstring& backupPath,
        const std::wstring& targetPath);
    [[nodiscard]] std::vector<RemediationRecord> GetRemediationHistory(std::string_view incidentId) const;

private:
    RemediationEngine();
    ~RemediationEngine();

    RemediationEngine(const RemediationEngine&) = delete;
    RemediationEngine& operator=(const RemediationEngine&) = delete;

    std::unique_ptr<RemediationEngineImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::IncidentResponse

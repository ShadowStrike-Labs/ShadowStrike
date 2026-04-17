#include "pch.h"
#include "RemediationEngine.hpp"

#include "PhantomCore/Core/Engine/QuarantineManager.hpp"
#include "PhantomCore/Core/System/ServiceManager.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/RegistryUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <ShlObj.h>
#include <combaseapi.h>
#include <comdef.h>
#include <taskschd.h>

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <format>
#include <fstream>
#include <shared_mutex>
#include <string>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "shell32.lib")

namespace ShadowStrike::Products::PhantomEDR::IncidentResponse {

namespace {

using ShadowStrike::Core::Engine::QuarantineManager;
using ShadowStrike::Core::System::ServiceManager;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Utils::FileUtils::ComputeFileSHA256;
using ShadowStrike::Utils::FileUtils::SecureEraseFile;
using ShadowStrike::Utils::HashUtils::ToHexLower;
using ShadowStrike::Utils::Logger;
using ShadowStrike::Utils::RegistryUtils::DeleteKey;
using ShadowStrike::Utils::RegistryUtils::DeleteKeyTree;
using ShadowStrike::Utils::RegistryUtils::EnableBackupPrivilege;
using ShadowStrike::Utils::RegistryUtils::EnableRestorePrivilege;
using ShadowStrike::Utils::RegistryUtils::RegistryKey;
using ShadowStrike::Utils::RegistryUtils::SplitPath;
using ShadowStrike::Utils::StringUtils::ToNarrow;
using ShadowStrike::Utils::StringUtils::ToWide;

[[nodiscard]] std::string GenerateRecordId() {
    GUID guid{};
    if (FAILED(::CoCreateGuid(&guid))) {
        return std::format("remediation-{}", static_cast<uint64_t>(::GetTickCount64()));
    }

    wchar_t buffer[64]{};
    const int chars = ::StringFromGUID2(guid, buffer, static_cast<int>(std::size(buffer)));
    if (chars <= 1) {
        return std::format("remediation-{}", static_cast<uint64_t>(::GetTickCount64()));
    }

    return ToNarrow(std::wstring_view(buffer, static_cast<size_t>(chars - 1)));
}

[[nodiscard]] int64_t ToUnixMillis(const std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

[[nodiscard]] std::chrono::system_clock::time_point FromUnixMillis(const int64_t value) {
    return std::chrono::system_clock::time_point{ std::chrono::milliseconds{ value } };
}

[[nodiscard]] std::optional<uint64_t> ParseIncidentNumericId(std::string_view incidentId) {
    if (incidentId.empty()) {
        return std::nullopt;
    }

    uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(incidentId.data(), incidentId.data() + incidentId.size(), value);
    if (ec != std::errc{} || ptr != incidentId.data() + incidentId.size()) {
        return std::nullopt;
    }

    return value;
}

[[nodiscard]] std::string SerializeParams(const RemediationParams& params) {
    return std::format(
        "{{\"filePath\":\"{}\",\"registryPath\":\"{}\",\"serviceName\":\"{}\",\"taskPath\":\"{}\",\"backupPath\":\"{}\",\"backupDataSize\":{},\"reason\":\"{}\"}}",
        ShadowStrike::Utils::StringUtils::EscapeJson(ToNarrow(params.filePath)),
        ShadowStrike::Utils::StringUtils::EscapeJson(ToNarrow(params.registryPath)),
        ShadowStrike::Utils::StringUtils::EscapeJson(ToNarrow(params.serviceName)),
        ShadowStrike::Utils::StringUtils::EscapeJson(ToNarrow(params.taskPath)),
        ShadowStrike::Utils::StringUtils::EscapeJson(ToNarrow(params.backupPath)),
        params.backupData.size(),
        ShadowStrike::Utils::StringUtils::EscapeJson(params.reason));
}

[[nodiscard]] std::filesystem::path CreateScratchRegistryPath() {
    const auto fileName = std::format("registry-{}.hiv", GenerateRecordId());
    return std::filesystem::current_path() / fileName;
}

template <typename T>
struct ComPtrGuard {
    T* ptr = nullptr;
    ~ComPtrGuard() { if (ptr != nullptr) { ptr->Release(); } }
};

struct ComScope {
    HRESULT hr = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool shouldUninitialize = SUCCEEDED(hr);
    ~ComScope() { if (shouldUninitialize) { ::CoUninitialize(); } }
    [[nodiscard]] bool IsReady() const noexcept { return SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE; }
};

[[nodiscard]] bool SaveRegistryKeyToBlob(std::wstring_view registryPath, std::vector<uint8_t>& data, std::string& error) {
    ShadowStrike::Utils::RegistryUtils::Error regError{};
    if (!EnableBackupPrivilege(&regError)) {
        error = std::format("EnableBackupPrivilege failed: {}", regError.win32);
        return false;
    }

    HKEY root = nullptr;
    std::wstring subKey;
    if (!SplitPath(registryPath, root, subKey)) {
        error = std::format("Invalid registry path {}", ToNarrow(registryPath));
        return false;
    }

    RegistryKey key;
    ShadowStrike::Utils::RegistryUtils::OpenOptions openOptions{};
    openOptions.access = KEY_READ;
    if (!key.Open(root, subKey, openOptions, &regError)) {
        error = std::format("Failed to open registry key {}: {}", ToNarrow(registryPath), regError.win32);
        return false;
    }

    const auto scratchPath = CreateScratchRegistryPath();
    if (!key.SaveToFile(scratchPath, &regError)) {
        error = std::format("Failed to backup registry key {}: {}", ToNarrow(registryPath), regError.win32);
        std::error_code ignored;
        std::filesystem::remove(scratchPath, ignored);
        return false;
    }

    std::ifstream input(scratchPath, std::ios::binary);
    if (!input) {
        error = std::format("Failed to open registry scratch file {}", scratchPath.string());
        std::error_code ignored;
        std::filesystem::remove(scratchPath, ignored);
        return false;
    }

    data.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    std::error_code ignored;
    std::filesystem::remove(scratchPath, ignored);
    return true;
}

[[nodiscard]] bool RestoreRegistryKeyFromBlob(std::wstring_view registryPath, const std::vector<uint8_t>& data, std::string& error) {
    if (data.empty()) {
        error = "Registry backup payload is empty";
        return false;
    }

    ShadowStrike::Utils::RegistryUtils::Error regError{};
    if (!EnableRestorePrivilege(&regError)) {
        error = std::format("EnableRestorePrivilege failed: {}", regError.win32);
        return false;
    }

    HKEY root = nullptr;
    std::wstring subKey;
    if (!SplitPath(registryPath, root, subKey)) {
        error = std::format("Invalid registry path {}", ToNarrow(registryPath));
        return false;
    }

    const auto scratchPath = CreateScratchRegistryPath();
    {
        std::ofstream output(scratchPath, std::ios::binary | std::ios::trunc);
        if (!output) {
            error = std::format("Failed to create registry scratch file {}", scratchPath.string());
            return false;
        }

        output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!output) {
            error = std::format("Failed to write registry scratch file {}", scratchPath.string());
            std::error_code ignored;
            std::filesystem::remove(scratchPath, ignored);
            return false;
        }
    }

    RegistryKey key;
    DWORD disposition = 0;
    ShadowStrike::Utils::RegistryUtils::OpenOptions openOptions{};
    openOptions.access = KEY_ALL_ACCESS;
    if (!key.Create(root, subKey, openOptions, &disposition, &regError)) {
        error = std::format("Failed to open registry key {} for restore: {}", ToNarrow(registryPath), regError.win32);
        std::error_code ignored;
        std::filesystem::remove(scratchPath, ignored);
        return false;
    }

    const bool restored = key.RestoreFromFile(scratchPath, REG_FORCE_RESTORE, &regError);
    std::error_code ignored;
    std::filesystem::remove(scratchPath, ignored);
    if (!restored) {
        error = std::format("Registry restore failed for {}: {}", ToNarrow(registryPath), regError.win32);
        return false;
    }

    return true;
}

[[nodiscard]] std::optional<IncidentSeverity> LookupSeverity(std::string_view incidentId) {
    const auto numericId = ParseIncidentNumericId(incidentId);
    if (!numericId.has_value()) {
        return std::nullopt;
    }

    auto result = DatabaseManager::Instance().QueryWithParams(
        "SELECT severity FROM incidents WHERE id = ? LIMIT 1",
        nullptr,
        static_cast<int64_t>(*numericId));
    if (!result.Next()) {
        return std::nullopt;
    }

    return static_cast<IncidentSeverity>(result.GetInt(0));
}

} // namespace

class RemediationEngineImpl {
public:
    std::atomic<bool> initialized{ false };
    mutable std::shared_mutex mutex;

    [[nodiscard]] bool EnsureTables() const {
        if (!DatabaseManager::Instance().IsInitialized()) {
            Logger::Error("RemediationEngine: DatabaseManager is not initialized");
            return false;
        }

        static constexpr std::string_view kCreateRemediationTable = R"SQL(
CREATE TABLE IF NOT EXISTS remediation_log (
    record_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    action INTEGER NOT NULL,
    file_path TEXT,
    registry_path TEXT,
    service_name TEXT,
    task_path TEXT,
    backup_path TEXT,
    backup_data BLOB,
    reason TEXT,
    params TEXT NOT NULL,
    executed_at INTEGER NOT NULL,
    success INTEGER NOT NULL,
    error_message TEXT,
    rollback_available INTEGER NOT NULL DEFAULT 0,
    file_hash TEXT,
    quarantine_entry_id INTEGER
))SQL";
        static constexpr std::string_view kCreateIndex =
            "CREATE INDEX IF NOT EXISTS idx_remediation_log_incident_time ON remediation_log(incident_id, executed_at DESC)";

        return DatabaseManager::Instance().Execute(kCreateRemediationTable)
            && DatabaseManager::Instance().Execute(kCreateIndex);
    }

    [[nodiscard]] bool InsertLog(
        const std::string& recordId,
        std::string_view incidentId,
        const RemediationAction action,
        const RemediationParams& params,
        const std::chrono::system_clock::time_point executedAt,
        const bool success,
        std::string_view errorMessage,
        const bool rollbackAvailable,
        std::string_view fileHash,
        const uint64_t quarantineEntryId,
        const std::vector<uint8_t>& backupData) const {
        return DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO remediation_log (record_id, incident_id, action, file_path, registry_path, service_name, task_path, backup_path, backup_data, reason, params, executed_at, success, error_message, rollback_available, file_hash, quarantine_entry_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            nullptr,
            recordId,
            std::string(incidentId),
            static_cast<int>(action),
            ToNarrow(params.filePath),
            ToNarrow(params.registryPath),
            ToNarrow(params.serviceName),
            ToNarrow(params.taskPath),
            ToNarrow(params.backupPath),
            backupData,
            params.reason,
            SerializeParams(params),
            ToUnixMillis(executedAt),
            success ? 1 : 0,
            std::string(errorMessage),
            rollbackAvailable ? 1 : 0,
            std::string(fileHash),
            static_cast<int64_t>(quarantineEntryId));
    }
};

RemediationEngine::RemediationEngine()
    : m_impl(std::make_unique<RemediationEngineImpl>()) {
}

RemediationEngine::~RemediationEngine() = default;

RemediationEngine& RemediationEngine::Instance() {
    static RemediationEngine instance;
    return instance;
}

bool RemediationEngine::Initialize() {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    if (!m_impl->EnsureTables()) {
        return false;
    }

    m_impl->initialized.store(true, std::memory_order_release);
    Logger::Info("RemediationEngine: initialized successfully");
    return true;
}

void RemediationEngine::Shutdown() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->initialized.store(false, std::memory_order_release);
    Logger::Info("RemediationEngine: shutdown complete");
}

bool RemediationEngine::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

bool RemediationEngine::ExecuteRemediation(
    std::string_view incidentId,
    const RemediationAction action,
    const RemediationParams& params) {
    if (!IsInitialized()) {
        Logger::Error("RemediationEngine: ExecuteRemediation called before initialization");
        return false;
    }

    const auto executedAt = std::chrono::system_clock::now();
    const std::string recordId = GenerateRecordId();

    bool success = false;
    bool rollbackAvailable = false;
    std::string errorMessage;
    std::string fileHash;
    uint64_t quarantineEntryId = 0;
    std::vector<uint8_t> backupData;

    switch (action) {
        case RemediationAction::QuarantineFile: {
            std::array<uint8_t, 32> hashBytes{};
            ShadowStrike::Utils::FileUtils::Error fileError{};
            if (ComputeFileSHA256(params.filePath, hashBytes, &fileError)) {
                fileHash = ToHexLower(hashBytes.data(), hashBytes.size());
            }

            auto result = QuarantineManager::Instance().QuarantineFile(
                params.filePath,
                ToWide(std::string(incidentId)),
                0);
            success = result.IsSuccess();
            quarantineEntryId = result.entryId;
            rollbackAvailable = success;
            if (!success) {
                errorMessage = ToNarrow(result.message);
            }
            break;
        }
        case RemediationAction::DeleteFile:
            success = DeleteFile(incidentId, params.filePath);
            rollbackAvailable = false;
            if (!success) {
                errorMessage = std::format("Failed to delete {}", ToNarrow(params.filePath));
            }
            break;
        case RemediationAction::RollbackRegistry:
            backupData.clear();
            SaveRegistryKeyToBlob(params.registryPath, backupData, errorMessage);
            success = RollbackRegistryChanges(incidentId, params.registryPath, params.backupData);
            rollbackAvailable = !backupData.empty();
            if (!success && errorMessage.empty()) {
                errorMessage = std::format("Failed to rollback registry {}", ToNarrow(params.registryPath));
            }
            break;
        case RemediationAction::RemoveService:
            success = RemoveService(incidentId, params.serviceName);
            rollbackAvailable = false;
            if (!success) {
                errorMessage = std::format("Failed to remove service {}", ToNarrow(params.serviceName));
            }
            break;
        case RemediationAction::RemoveScheduledTask:
            success = RemoveScheduledTask(incidentId, params.taskPath);
            rollbackAvailable = false;
            if (!success) {
                errorMessage = std::format("Failed to remove scheduled task {}", ToNarrow(params.taskPath));
            }
            break;
        case RemediationAction::RestoreBackup:
            success = RestoreFromBackup(incidentId, params.backupPath, params.filePath);
            rollbackAvailable = false;
            if (!success) {
                errorMessage = std::format(
                    "Failed to restore backup {} to {}",
                    ToNarrow(params.backupPath),
                    ToNarrow(params.filePath));
            }
            break;
    }

    if (!m_impl->InsertLog(
            recordId,
            incidentId,
            action,
            params,
            executedAt,
            success,
            errorMessage,
            rollbackAvailable,
            fileHash,
            quarantineEntryId,
            backupData)) {
        Logger::Error("RemediationEngine: failed to persist remediation audit record for incident {}", incidentId);
    }

    Logger::Info(
        "RemediationEngine: incident={} action={} success={}",
        std::string(incidentId),
        std::string(ToString(action)),
        success);
    if (!success && !errorMessage.empty()) {
        Logger::Error("RemediationEngine: incident={} action={} error={}", std::string(incidentId), std::string(ToString(action)), errorMessage);
    }

    return success;
}

bool RemediationEngine::QuarantineFile(std::string_view incidentId, const std::wstring& filePath) {
    std::array<uint8_t, 32> hashBytes{};
    ShadowStrike::Utils::FileUtils::Error fileError{};
    std::string fileHash;
    if (ComputeFileSHA256(filePath, hashBytes, &fileError)) {
        fileHash = ToHexLower(hashBytes.data(), hashBytes.size());
    }

    auto result = QuarantineManager::Instance().QuarantineFile(filePath, ToWide(std::string(incidentId)), 0);
    if (!result.IsSuccess()) {
        Logger::Error("RemediationEngine: quarantine failed for {}: {}", ToNarrow(filePath), ToNarrow(result.message));
        return false;
    }

    RemediationParams params{};
    params.filePath = filePath;
    params.reason = "File quarantined";
    if (!m_impl->InsertLog(
            GenerateRecordId(),
            incidentId,
            RemediationAction::QuarantineFile,
            params,
            std::chrono::system_clock::now(),
            true,
            {},
            true,
            fileHash,
            result.entryId,
            {})) {
        Logger::Error("RemediationEngine: failed to persist direct quarantine record");
    }

    Logger::Warn("RemediationEngine: quarantined file {} hash={}", ToNarrow(filePath), fileHash);
    return true;
}

bool RemediationEngine::RestoreQuarantinedFile(std::string_view incidentId, const std::wstring& filePath) {
    const auto entries = QuarantineManager::Instance().GetActiveEntries();
    const auto it = std::find_if(
        entries.begin(),
        entries.end(),
        [&filePath](const auto& entry) {
            return entry.originalPath == filePath;
        });
    if (it == entries.end()) {
        Logger::Warn("RemediationEngine: no active quarantine entry found for {}", ToNarrow(filePath));
        return false;
    }

    ShadowStrike::Core::Engine::RestoreRequest request{};
    request.entryId = it->entryId;
    auto result = QuarantineManager::Instance().RestoreFile(request);
    if (!result.IsSuccess()) {
        Logger::Error("RemediationEngine: restore failed for {}: {}", ToNarrow(filePath), ToNarrow(result.message));
        return false;
    }

    Logger::Info("RemediationEngine: restored quarantined file {} for incident {}", ToNarrow(filePath), std::string(incidentId));
    return true;
}

bool RemediationEngine::DeleteFile(std::string_view incidentId, const std::wstring& filePath) {
    if (filePath.empty()) {
        Logger::Error("RemediationEngine: empty file path for delete request");
        return false;
    }

    const auto severity = LookupSeverity(incidentId);
    if (severity.has_value() && *severity == IncidentSeverity::Critical) {
        ShadowStrike::Utils::FileUtils::Error fileError{};
        if (!SecureEraseFile(filePath, ShadowStrike::Utils::FileUtils::SecureEraseMode::TriplePass, &fileError)) {
            Logger::Error(
                "RemediationEngine: secure delete failed for {} win32={}",
                ToNarrow(filePath),
                fileError.win32);
            return false;
        }

        Logger::Warn("RemediationEngine: securely deleted {}", ToNarrow(filePath));
        return true;
    }

    std::wstring pathBuffer = filePath;
    pathBuffer.push_back(L'\0');

    SHFILEOPSTRUCTW operation{};
    operation.wFunc = FO_DELETE;
    operation.pFrom = pathBuffer.c_str();
    operation.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;

    const int result = ::SHFileOperationW(&operation);
    if (result != 0 || operation.fAnyOperationsAborted) {
        Logger::Error(
            "RemediationEngine: recycle-bin delete failed for {} result={} aborted={}",
            ToNarrow(filePath),
            result,
            operation.fAnyOperationsAborted);
        return false;
    }

    Logger::Warn("RemediationEngine: recycled file {}", ToNarrow(filePath));
    return true;
}

bool RemediationEngine::RollbackRegistryChanges(
    std::string_view incidentId,
    const std::wstring& registryPath,
    const std::vector<uint8_t>& backupData) {
    std::string error;
    if (!backupData.empty()) {
        if (!RestoreRegistryKeyFromBlob(registryPath, backupData, error)) {
            Logger::Error("RemediationEngine: {}", error);
            return false;
        }
        Logger::Info("RemediationEngine: restored registry key {} for incident {}", ToNarrow(registryPath), std::string(incidentId));
        return true;
    }

    HKEY root = nullptr;
    std::wstring subKey;
    if (!SplitPath(registryPath, root, subKey)) {
        Logger::Error("RemediationEngine: invalid registry path {}", ToNarrow(registryPath));
        return false;
    }

    ShadowStrike::Utils::RegistryUtils::Error regError{};
    if (!DeleteKeyTree(root, subKey, {}, &regError) && !DeleteKey(root, subKey, {}, &regError)) {
        Logger::Error(
            "RemediationEngine: failed to remove registry key {} win32={}",
            ToNarrow(registryPath),
            regError.win32);
        return false;
    }

    Logger::Warn("RemediationEngine: removed registry key {} for incident {}", ToNarrow(registryPath), std::string(incidentId));
    return true;
}

bool RemediationEngine::RemoveService(std::string_view incidentId, const std::wstring& serviceName) {
    if (!ServiceManager::Instance().StopService(serviceName, true)) {
        Logger::Warn("RemediationEngine: StopService reported failure for {}", ToNarrow(serviceName));
    }

    if (!ServiceManager::Instance().UninstallService(serviceName, true)) {
        Logger::Error("RemediationEngine: UninstallService failed for {}", ToNarrow(serviceName));
        return false;
    }

    Logger::Warn("RemediationEngine: removed service {} for incident {}", ToNarrow(serviceName), std::string(incidentId));
    return true;
}

bool RemediationEngine::RemoveScheduledTask(std::string_view incidentId, const std::wstring& taskPath) {
    if (taskPath.empty()) {
        Logger::Error("RemediationEngine: empty task path");
        return false;
    }

    ComScope comScope;
    if (!comScope.IsReady()) {
        Logger::Error("RemediationEngine: CoInitializeEx failed: 0x{:08X}", static_cast<uint32_t>(comScope.hr));
        return false;
    }

    ITaskService* service = nullptr;
    HRESULT hr = ::CoCreateInstance(
        CLSID_TaskScheduler,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        reinterpret_cast<void**>(&service));
    if (FAILED(hr) || service == nullptr) {
        Logger::Error("RemediationEngine: CoCreateInstance(TaskScheduler) failed: 0x{:08X}", static_cast<uint32_t>(hr));
        return false;
    }
    ComPtrGuard<ITaskService> serviceGuard{ service };

    hr = service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        Logger::Error("RemediationEngine: ITaskService::Connect failed: 0x{:08X}", static_cast<uint32_t>(hr));
        return false;
    }

    const size_t split = taskPath.find_last_of(L'\\');
    const std::wstring folderPath = split == std::wstring::npos || split == 0
        ? L"\\"
        : taskPath.substr(0, split);
    const std::wstring taskName = split == std::wstring::npos
        ? taskPath
        : taskPath.substr(split + 1);

    ITaskFolder* folder = nullptr;
    hr = service->GetFolder(_bstr_t(folderPath.c_str()), &folder);
    if (FAILED(hr) || folder == nullptr) {
        Logger::Error("RemediationEngine: GetFolder({}) failed: 0x{:08X}", ToNarrow(folderPath), static_cast<uint32_t>(hr));
        return false;
    }
    ComPtrGuard<ITaskFolder> folderGuard{ folder };

    hr = folder->DeleteTask(_bstr_t(taskName.c_str()), 0);
    if (FAILED(hr)) {
        Logger::Error("RemediationEngine: DeleteTask({}) failed: 0x{:08X}", ToNarrow(taskName), static_cast<uint32_t>(hr));
        return false;
    }

    Logger::Warn("RemediationEngine: removed scheduled task {} for incident {}", ToNarrow(taskPath), std::string(incidentId));
    return true;
}

bool RemediationEngine::RestoreFromBackup(
    std::string_view incidentId,
    const std::wstring& backupPath,
    const std::wstring& targetPath) {
    std::error_code createError;
    if (const auto parent = std::filesystem::path(targetPath).parent_path(); !parent.empty()) {
        std::filesystem::create_directories(parent, createError);
        if (createError) {
            Logger::Error(
                "RemediationEngine: failed to create target directory {} error={}",
                parent.string(),
                createError.value());
            return false;
        }
    }

    if (!::CopyFileW(backupPath.c_str(), targetPath.c_str(), FALSE)) {
        Logger::Error(
            "RemediationEngine: CopyFileW failed from {} to {} error={}",
            ToNarrow(backupPath),
            ToNarrow(targetPath),
            ::GetLastError());
        return false;
    }

    Logger::Info(
        "RemediationEngine: restored backup {} to {} for incident {}",
        ToNarrow(backupPath),
        ToNarrow(targetPath),
        std::string(incidentId));
    return true;
}

std::vector<RemediationRecord> RemediationEngine::GetRemediationHistory(std::string_view incidentId) const {
    if (!IsInitialized()) {
        return {};
    }

    std::vector<RemediationRecord> records;
    auto result = DatabaseManager::Instance().QueryWithParams(
        "SELECT record_id, incident_id, action, params, executed_at, success, error_message, rollback_available "
        "FROM remediation_log WHERE incident_id = ? ORDER BY executed_at DESC",
        nullptr,
        std::string(incidentId));
    while (result.Next()) {
        records.push_back(RemediationRecord{
            result.GetString(0),
            result.GetString(1),
            static_cast<RemediationAction>(result.GetInt(2)),
            result.GetString(3),
            FromUnixMillis(result.GetInt64(4)),
            result.GetInt(5) != 0,
            result.GetString(6),
            result.GetInt(7) != 0
        });
    }

    return records;
}

} // namespace ShadowStrike::Products::PhantomEDR::IncidentResponse

#include "pch.h"
#include "ContainmentEngine.hpp"

#include "PhantomCore/Config/ConfigManager.hpp"
#include "PhantomCore/Core/Engine/QuarantineManager.hpp"
#include "PhantomCore/Core/System/ServiceManager.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/NetworkUtils.hpp"
#include "PhantomCore/Utils/ProcessUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "Products/Community/PhantomEDR/Config/EDRConfigRegistration.hpp"

#include <Ws2tcpip.h>
#include <combaseapi.h>
#include <fwpmu.h>
#include <lm.h>

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <format>
#include <limits>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "rpcrt4.lib")

namespace ShadowStrike::Products::PhantomEDR::IncidentResponse {

namespace {

using ShadowStrike::Config::ConfigManager;
using ShadowStrike::Core::Engine::QuarantineManager;
using ShadowStrike::Core::System::ServiceManager;
using ShadowStrike::Core::System::ServiceState;
using ShadowStrike::Core::System::StartType;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Utils::Logger;
using ShadowStrike::Utils::NetworkUtils::ParseUrl;
using ShadowStrike::Utils::NetworkUtils::UrlComponents;
using ShadowStrike::Utils::ProcessUtils::Error;
using ShadowStrike::Utils::ProcessUtils::GetProcessName;
using ShadowStrike::Utils::ProcessUtils::GetProcessPath;
using ShadowStrike::Utils::StringUtils::ToNarrow;
using ShadowStrike::Utils::StringUtils::ToWide;

constexpr GUID kContainmentSublayerGuid{
    0x6f474a87, 0xc5f5, 0x4f20, { 0x8d, 0x8a, 0xf7, 0x23, 0x53, 0xc7, 0x1a, 0x1f }
};

constexpr wchar_t kContainmentSublayerName[] = L"ShadowStrike PhantomEDR Containment";

struct DbContainmentState {
    std::string recordId;
    std::string incidentId;
    ContainmentAction action = ContainmentAction::IsolateNetwork;
    ContainmentParams params;
    std::chrono::system_clock::time_point executedAt{};
    std::optional<std::chrono::system_clock::time_point> rolledBackAt;
    bool success = false;
    std::string errorMessage;
    std::string filterIds;
    uint64_t quarantineEntryId = 0;
    uint32_t userFlags = 0;
    int serviceStartType = -1;
    bool serviceWasRunning = false;
};

[[nodiscard]] std::string FormatWin32Error(const DWORD error) {
    if (error == ERROR_SUCCESS) {
        return {};
    }

    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = ::FormatMessageW(
        flags,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    std::wstring message;
    if (length != 0 && buffer != nullptr) {
        message.assign(buffer, length);
        while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
            message.pop_back();
        }
        ::LocalFree(buffer);
    }

    if (message.empty()) {
        return std::format("Win32 error {}", error);
    }

    return std::format("{} (error={})", ToNarrow(message), error);
}

[[nodiscard]] std::string GenerateRecordId() {
    GUID guid{};
    if (FAILED(::CoCreateGuid(&guid))) {
        return std::format("containment-{}", static_cast<uint64_t>(::GetTickCount64()));
    }

    wchar_t buffer[64]{};
    const int chars = ::StringFromGUID2(guid, buffer, static_cast<int>(std::size(buffer)));
    if (chars <= 1) {
        return std::format("containment-{}", static_cast<uint64_t>(::GetTickCount64()));
    }

    return ToNarrow(std::wstring_view(buffer, static_cast<size_t>(chars - 1)));
}

[[nodiscard]] int64_t ToUnixMillis(const std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

[[nodiscard]] std::chrono::system_clock::time_point FromUnixMillis(const int64_t value) {
    return std::chrono::system_clock::time_point{ std::chrono::milliseconds{ value } };
}

[[nodiscard]] std::string SerializeFilterIds(const std::vector<UINT64>& filterIds) {
    std::ostringstream stream;
    for (size_t i = 0; i < filterIds.size(); ++i) {
        if (i != 0) {
            stream << ',';
        }
        stream << filterIds[i];
    }
    return stream.str();
}

[[nodiscard]] std::vector<UINT64> DeserializeFilterIds(std::string_view serialized) {
    std::vector<UINT64> result;
    size_t offset = 0;
    while (offset < serialized.size()) {
        const size_t comma = serialized.find(',', offset);
        const std::string_view token = comma == std::string_view::npos
            ? serialized.substr(offset)
            : serialized.substr(offset, comma - offset);

        if (!token.empty()) {
            UINT64 value = 0;
            const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value);
            if (ec == std::errc{} && ptr == token.data() + token.size()) {
                result.push_back(value);
            }
        }

        if (comma == std::string_view::npos) {
            break;
        }

        offset = comma + 1;
    }

    return result;
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

[[nodiscard]] bool IsProcessGone(const uint32_t pid) {
    HANDLE handle = ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (handle == nullptr) {
        const DWORD error = ::GetLastError();
        return error == ERROR_INVALID_PARAMETER || error == ERROR_ACCESS_DENIED;
    }

    struct HandleGuard {
        HANDLE handle = nullptr;
        ~HandleGuard() { if (handle != nullptr) { ::CloseHandle(handle); } }
    } guard{ handle };

    return ::WaitForSingleObject(handle, 5000) == WAIT_OBJECT_0;
}

[[nodiscard]] uint16_t ResolveManagementPort() {
    if (!ConfigManager::HasInstance()) {
        return 0;
    }

    const std::string url = ConfigManager::Instance().GetValue(
        std::string(ShadowStrike::Products::PhantomEDR::Config::Keys::MgmtServerUrl),
        std::string{});
    if (url.empty()) {
        return 0;
    }

    UrlComponents components{};
    if (!ParseUrl(ToWide(url), components, nullptr)) {
        return 0;
    }

    if (components.port != 0) {
        return components.port;
    }

    if (components.scheme == L"https") {
        return 443;
    }

    if (components.scheme == L"http") {
        return 80;
    }

    return 0;
}

[[nodiscard]] FWPM_FILTER0 CreateBaseFilter(
    const std::wstring& name,
    const GUID& layerKey,
    const FWP_ACTION_TYPE actionType,
    const UINT8 weight) {
    FWPM_FILTER0 filter{};
    filter.displayData.name = const_cast<wchar_t*>(name.c_str());
    filter.subLayerKey = kContainmentSublayerGuid;
    filter.layerKey = layerKey;
    filter.action.type = actionType;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    return filter;
}

[[nodiscard]] bool QueryUserFlags(std::wstring_view userName, uint32_t& flags, std::string& error) {
    LPUSER_INFO_4 userInfo = nullptr;
    const NET_API_STATUS status = ::NetUserGetInfo(nullptr, userName.data(), 4, reinterpret_cast<LPBYTE*>(&userInfo));
    if (status != NERR_Success || userInfo == nullptr) {
        error = std::format("NetUserGetInfo failed for {}: {}", ToNarrow(userName), FormatWin32Error(status));
        if (userInfo != nullptr) {
            ::NetApiBufferFree(userInfo);
        }
        return false;
    }

    flags = userInfo->usri4_flags;
    ::NetApiBufferFree(userInfo);
    return true;
}

[[nodiscard]] bool ApplyUserFlags(std::wstring_view userName, const uint32_t flags, std::string& error) {
    USER_INFO_1008 info{};
    info.usri1008_flags = flags;
    DWORD parameterError = 0;
    const NET_API_STATUS status = ::NetUserSetInfo(
        nullptr,
        userName.data(),
        1008,
        reinterpret_cast<LPBYTE>(&info),
        &parameterError);
    if (status != NERR_Success) {
        error = std::format(
            "NetUserSetInfo failed for {} (parameter={}): {}",
            ToNarrow(userName),
            parameterError,
            FormatWin32Error(status));
        return false;
    }

    return true;
}

} // namespace

class ContainmentEngineImpl {
public:
    std::atomic<bool> initialized{ false };
    mutable std::shared_mutex mutex;
    HANDLE wfpEngineHandle = nullptr;
    uint16_t managementPort = 0;

    [[nodiscard]] bool EnsureTables() {
        auto& database = DatabaseManager::Instance();
        if (!database.IsInitialized()) {
            Logger::Error("ContainmentEngine: DatabaseManager is not initialized");
            return false;
        }

        static constexpr std::string_view kCreateContainmentTable = R"SQL(
CREATE TABLE IF NOT EXISTS containment_log (
    record_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    action INTEGER NOT NULL,
    pid INTEGER NOT NULL DEFAULT 0,
    file_path TEXT,
    ip_address TEXT,
    user_name TEXT,
    service_name TEXT,
    reason TEXT,
    executed_at INTEGER NOT NULL,
    rolled_back_at INTEGER,
    success INTEGER NOT NULL,
    error_message TEXT,
    filter_ids TEXT,
    quarantine_entry_id INTEGER,
    user_flags INTEGER,
    service_start_type INTEGER,
    service_was_running INTEGER NOT NULL DEFAULT 0
))SQL";
        static constexpr std::string_view kCreateHistoryIndex =
            "CREATE INDEX IF NOT EXISTS idx_containment_log_incident_time ON containment_log(incident_id, executed_at DESC)";
        static constexpr std::string_view kCreateActiveIndex =
            "CREATE INDEX IF NOT EXISTS idx_containment_log_active ON containment_log(incident_id, action, success, rolled_back_at)";

        return database.Execute(kCreateContainmentTable)
            && database.Execute(kCreateHistoryIndex)
            && database.Execute(kCreateActiveIndex);
    }

    [[nodiscard]] bool EnsureWfpEngineLocked(std::string& error) {
        if (wfpEngineHandle != nullptr) {
            return true;
        }

        FWPM_SESSION0 session{};
        session.displayData.name = const_cast<wchar_t*>(L"ShadowStrike PhantomEDR Containment");
        const DWORD result = ::FwpmEngineOpen0(
            nullptr,
            RPC_C_AUTHN_WINNT,
            nullptr,
            &session,
            &wfpEngineHandle);
        if (result != ERROR_SUCCESS) {
            error = std::format("FwpmEngineOpen0 failed: {}", FormatWin32Error(result));
            return false;
        }

        FWPM_SUBLAYER0 sublayer{};
        sublayer.subLayerKey = kContainmentSublayerGuid;
        sublayer.displayData.name = const_cast<wchar_t*>(kContainmentSublayerName);
        sublayer.displayData.description = const_cast<wchar_t*>(L"Persistent endpoint containment filters");
        sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        sublayer.weight = 0xFFFF;

        const DWORD sublayerResult = ::FwpmSubLayerAdd0(wfpEngineHandle, &sublayer, nullptr);
        if (sublayerResult != ERROR_SUCCESS && sublayerResult != FWP_E_ALREADY_EXISTS) {
            error = std::format("FwpmSubLayerAdd0 failed: {}", FormatWin32Error(sublayerResult));
            ::FwpmEngineClose0(wfpEngineHandle);
            wfpEngineHandle = nullptr;
            return false;
        }

        return true;
    }

    void CloseWfpEngineLocked() noexcept {
        if (wfpEngineHandle != nullptr) {
            ::FwpmEngineClose0(wfpEngineHandle);
            wfpEngineHandle = nullptr;
        }
    }

    [[nodiscard]] bool InsertContainmentRecord(
        const std::string& recordId,
        std::string_view incidentId,
        const ContainmentAction action,
        const ContainmentParams& params,
        const std::chrono::system_clock::time_point executedAt,
        const bool success,
        std::string_view errorMessage,
        std::string_view filterIds,
        const uint64_t quarantineEntryId,
        const uint32_t userFlags,
        const int serviceStartType,
        const bool serviceWasRunning) const {
        return DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO containment_log (record_id, incident_id, action, pid, file_path, ip_address, user_name, service_name, reason, executed_at, success, error_message, filter_ids, quarantine_entry_id, user_flags, service_start_type, service_was_running) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            nullptr,
            recordId,
            std::string(incidentId),
            static_cast<int>(action),
            static_cast<int64_t>(params.pid),
            ToNarrow(params.filePath),
            params.ipAddress,
            ToNarrow(params.userName),
            ToNarrow(params.serviceName),
            params.reason,
            ToUnixMillis(executedAt),
            success ? 1 : 0,
            std::string(errorMessage),
            std::string(filterIds),
            static_cast<int64_t>(quarantineEntryId),
            static_cast<int64_t>(userFlags),
            static_cast<int64_t>(serviceStartType),
            serviceWasRunning ? 1 : 0);
    }

    [[nodiscard]] bool MarkRolledBack(const std::string& recordId, const std::chrono::system_clock::time_point rolledBackAt) const {
        return DatabaseManager::Instance().ExecuteWithParams(
            "UPDATE containment_log SET rolled_back_at = ? WHERE record_id = ?",
            nullptr,
            ToUnixMillis(rolledBackAt),
            recordId);
    }

    [[nodiscard]] bool UpdateRecordMetadata(
        const std::string& recordId,
        std::string_view incidentId,
        std::string_view reason) const {
        return DatabaseManager::Instance().ExecuteWithParams(
            "UPDATE containment_log SET incident_id = ?, reason = ? WHERE record_id = ?",
            nullptr,
            std::string(incidentId),
            std::string(reason),
            recordId);
    }

    [[nodiscard]] std::optional<DbContainmentState> GetLatestActiveByIncident(
        std::string_view incidentId,
        const ContainmentAction action) const {
        auto result = DatabaseManager::Instance().QueryWithParams(
            "SELECT record_id, incident_id, action, pid, file_path, ip_address, user_name, service_name, reason, executed_at, rolled_back_at, success, error_message, filter_ids, quarantine_entry_id, user_flags, service_start_type, service_was_running "
            "FROM containment_log WHERE incident_id = ? AND action = ? AND success = 1 AND rolled_back_at IS NULL "
            "ORDER BY executed_at DESC LIMIT 1",
            nullptr,
            std::string(incidentId),
            static_cast<int>(action));

        if (!result.Next()) {
            return std::nullopt;
        }

        return MapContainmentRecord(result);
    }

    [[nodiscard]] std::optional<DbContainmentState> GetLatestActiveByUser(std::wstring_view userName) const {
        auto result = DatabaseManager::Instance().QueryWithParams(
            "SELECT record_id, incident_id, action, pid, file_path, ip_address, user_name, service_name, reason, executed_at, rolled_back_at, success, error_message, filter_ids, quarantine_entry_id, user_flags, service_start_type, service_was_running "
            "FROM containment_log WHERE user_name = ? AND action = ? AND success = 1 AND rolled_back_at IS NULL "
            "ORDER BY executed_at DESC LIMIT 1",
            nullptr,
            ToNarrow(userName),
            static_cast<int>(ContainmentAction::LockAccount));

        if (!result.Next()) {
            return std::nullopt;
        }

        return MapContainmentRecord(result);
    }

    [[nodiscard]] std::optional<DbContainmentState> GetLatestActiveByIp(std::string_view ipAddress) const {
        auto result = DatabaseManager::Instance().QueryWithParams(
            "SELECT record_id, incident_id, action, pid, file_path, ip_address, user_name, service_name, reason, executed_at, rolled_back_at, success, error_message, filter_ids, quarantine_entry_id, user_flags, service_start_type, service_was_running "
            "FROM containment_log WHERE ip_address = ? AND action = ? AND success = 1 AND rolled_back_at IS NULL "
            "ORDER BY executed_at DESC LIMIT 1",
            nullptr,
            std::string(ipAddress),
            static_cast<int>(ContainmentAction::BlockIP));

        if (!result.Next()) {
            return std::nullopt;
        }

        return MapContainmentRecord(result);
    }

    [[nodiscard]] static DbContainmentState MapContainmentRecord(ShadowStrike::Database::QueryResult& result) {
        DbContainmentState state;
        state.recordId = result.GetString(0);
        state.incidentId = result.GetString(1);
        state.action = static_cast<ContainmentAction>(result.GetInt(2));
        state.params.pid = static_cast<uint32_t>(result.GetInt64(3));
        state.params.filePath = ToWide(result.GetString(4));
        state.params.ipAddress = result.GetString(5);
        state.params.userName = ToWide(result.GetString(6));
        state.params.serviceName = ToWide(result.GetString(7));
        state.params.reason = result.GetString(8);
        state.executedAt = FromUnixMillis(result.GetInt64(9));
        if (!result.IsNull(10)) {
            state.rolledBackAt = FromUnixMillis(result.GetInt64(10));
        }
        state.success = result.GetInt(11) != 0;
        state.errorMessage = result.GetString(12);
        state.filterIds = result.GetString(13);
        state.quarantineEntryId = static_cast<uint64_t>(result.GetInt64(14));
        state.userFlags = static_cast<uint32_t>(result.GetInt64(15));
        state.serviceStartType = result.IsNull(16) ? -1 : result.GetInt(16);
        state.serviceWasRunning = result.GetInt(17) != 0;
        return state;
    }

    [[nodiscard]] std::vector<ContainmentRecord> QueryRecords(std::string_view sql, std::string_view value) const {
        std::vector<ContainmentRecord> records;
        auto result = DatabaseManager::Instance().QueryWithParams(std::string(sql), nullptr, std::string(value));
        while (result.Next()) {
            auto state = MapContainmentRecord(result);
            records.push_back(ContainmentRecord{
                state.recordId,
                state.incidentId,
                state.action,
                state.params,
                state.executedAt,
                state.rolledBackAt,
                state.success,
                state.errorMessage
            });
        }
        return records;
    }
};

ContainmentEngine::ContainmentEngine()
    : m_impl(std::make_unique<ContainmentEngineImpl>()) {
}

ContainmentEngine::~ContainmentEngine() = default;

ContainmentEngine& ContainmentEngine::Instance() {
    static ContainmentEngine instance;
    return instance;
}

bool ContainmentEngine::Initialize() {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    if (!m_impl->EnsureTables()) {
        Logger::Error("ContainmentEngine: failed to initialize containment_log schema");
        return false;
    }

    m_impl->managementPort = ResolveManagementPort();
    m_impl->initialized.store(true, std::memory_order_release);
    Logger::Info("ContainmentEngine: initialized successfully");
    return true;
}

void ContainmentEngine::Shutdown() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->CloseWfpEngineLocked();
    m_impl->initialized.store(false, std::memory_order_release);
    Logger::Info("ContainmentEngine: shutdown complete");
}

bool ContainmentEngine::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

bool ContainmentEngine::ExecuteContainment(
    std::string_view incidentId,
    const ContainmentAction action,
    const ContainmentParams& params) {
    if (!IsInitialized()) {
        Logger::Error("ContainmentEngine: ExecuteContainment called before initialization");
        return false;
    }

    const auto executedAt = std::chrono::system_clock::now();
    const std::string recordId = GenerateRecordId();

    bool success = false;
    std::string errorMessage;
    std::string filterIds;
    uint64_t quarantineEntryId = 0;
    uint32_t userFlags = 0;
    int serviceStartType = -1;
    bool serviceWasRunning = false;

    bool shouldInsertRecord = true;

    switch (action) {
        case ContainmentAction::IsolateNetwork:
            success = IsolateNetwork(incidentId);
            if (success) {
                const auto state = m_impl->GetLatestActiveByIncident(incidentId, action);
                if (state.has_value()) {
                    filterIds = state->filterIds;
                    shouldInsertRecord = false;
                }
            } else {
                errorMessage = "Network isolation failed";
            }
            break;
        case ContainmentAction::TerminateProcess:
            success = TerminateProcess(params.pid, false);
            if (!success) {
                errorMessage = std::format("Failed to terminate pid {}", params.pid);
            }
            break;
        case ContainmentAction::LockAccount: {
            success = LockUserAccount(params.userName);
            if (success) {
                const auto state = m_impl->GetLatestActiveByUser(params.userName);
                if (state.has_value()) {
                    userFlags = state->userFlags;
                    m_impl->UpdateRecordMetadata(state->recordId, incidentId, params.reason);
                    shouldInsertRecord = false;
                }
            } else {
                errorMessage = std::format("Failed to disable user {}", ToNarrow(params.userName));
            }
            break;
        }
        case ContainmentAction::QuarantineFile: {
            auto result = QuarantineManager::Instance().QuarantineFile(
                params.filePath,
                ToWide(std::string(ToString(action))),
                params.pid);
            success = result.IsSuccess();
            quarantineEntryId = result.entryId;
            if (!success) {
                errorMessage = ToNarrow(result.message);
            }
            break;
        }
        case ContainmentAction::BlockIP:
            success = BlockIPAddress(params.ipAddress);
            if (success) {
                const auto state = m_impl->GetLatestActiveByIp(params.ipAddress);
                if (state.has_value()) {
                    filterIds = state->filterIds;
                    m_impl->UpdateRecordMetadata(state->recordId, incidentId, params.reason);
                    shouldInsertRecord = false;
                }
            } else {
                errorMessage = std::format("Failed to block IP {}", params.ipAddress);
            }
            break;
        case ContainmentAction::DisableService: {
            auto serviceInfo = ServiceManager::Instance().GetServiceInfo(params.serviceName);
            if (!serviceInfo.has_value()) {
                errorMessage = std::format("Service {} not found", ToNarrow(params.serviceName));
                success = false;
                break;
            }

            serviceStartType = static_cast<int>(serviceInfo->startType);
            serviceWasRunning = serviceInfo->state == ServiceState::Running;
            if (!ServiceManager::Instance().StopService(params.serviceName, true)) {
                Logger::Warn("ContainmentEngine: failed to stop service {} before disabling", ToNarrow(params.serviceName));
            }
            success = ServiceManager::Instance().SetStartType(params.serviceName, StartType::Disabled);
            if (!success) {
                errorMessage = std::format("Failed to disable service {}", ToNarrow(params.serviceName));
            }
            break;
        }
    }

    if (shouldInsertRecord) {
        if (!m_impl->InsertContainmentRecord(
                recordId,
                incidentId,
                action,
                params,
                executedAt,
                success,
                errorMessage,
                filterIds,
                quarantineEntryId,
                userFlags,
                serviceStartType,
                serviceWasRunning)) {
            Logger::Error("ContainmentEngine: failed to persist containment audit record for incident {}", incidentId);
        }
    }

    Logger::Info(
        "ContainmentEngine: incident={} action={} success={} reason={}",
        std::string(incidentId),
        std::string(ToString(action)),
        success,
        params.reason);
    if (!success && !errorMessage.empty()) {
        Logger::Error("ContainmentEngine: incident={} action={} error={}", std::string(incidentId), std::string(ToString(action)), errorMessage);
    }

    return success;
}

bool ContainmentEngine::RollbackContainment(
    std::string_view incidentId,
    const ContainmentAction action) {
    if (!IsInitialized()) {
        Logger::Error("ContainmentEngine: RollbackContainment called before initialization");
        return false;
    }

    const auto state = m_impl->GetLatestActiveByIncident(incidentId, action);
    if (!state.has_value()) {
        Logger::Warn("ContainmentEngine: no active containment found for incident={} action={}", std::string(incidentId), std::string(ToString(action)));
        return false;
    }

    bool success = false;
    switch (action) {
        case ContainmentAction::IsolateNetwork:
            success = RestoreNetwork(incidentId);
            break;
        case ContainmentAction::TerminateProcess:
            Logger::Warn("ContainmentEngine: terminate process rollback is not supported for incident {}", std::string(incidentId));
            success = false;
            break;
        case ContainmentAction::LockAccount:
            success = UnlockUserAccount(state->params.userName);
            break;
        case ContainmentAction::QuarantineFile: {
            ShadowStrike::Core::Engine::RestoreRequest restoreRequest{};
            restoreRequest.entryId = state->quarantineEntryId;
            auto result = QuarantineManager::Instance().RestoreFile(restoreRequest);
            success = result.IsSuccess();
            if (!success) {
                Logger::Error("ContainmentEngine: failed to restore quarantined file for incident {}: {}", std::string(incidentId), ToNarrow(result.message));
            }
            break;
        }
        case ContainmentAction::BlockIP:
            success = UnblockIPAddress(state->params.ipAddress);
            break;
        case ContainmentAction::DisableService: {
            const auto originalStartType = static_cast<StartType>(state->serviceStartType);
            success = ServiceManager::Instance().SetStartType(state->params.serviceName, originalStartType);
            if (success && state->serviceWasRunning) {
                success = ServiceManager::Instance().StartService(state->params.serviceName);
            }
            break;
        }
    }

    if (success) {
        m_impl->MarkRolledBack(state->recordId, std::chrono::system_clock::now());
        Logger::Info("ContainmentEngine: rollback completed for incident={} action={}", std::string(incidentId), std::string(ToString(action)));
    }

    return success;
}

bool ContainmentEngine::IsolateNetwork(std::string_view incidentId) {
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        return false;
    }

    std::string error;
    if (!m_impl->EnsureWfpEngineLocked(error)) {
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    std::vector<UINT64> filterIds;
    auto addFilter = [&](FWPM_FILTER0& filter) -> bool {
        UINT64 filterId = 0;
        const DWORD result = ::FwpmFilterAdd0(m_impl->wfpEngineHandle, &filter, nullptr, &filterId);
        if (result != ERROR_SUCCESS) {
            error = std::format("FwpmFilterAdd0 failed: {}", FormatWin32Error(result));
            return false;
        }
        filterIds.push_back(filterId);
        return true;
    };

    DWORD result = ::FwpmTransactionBegin0(m_impl->wfpEngineHandle, 0);
    if (result != ERROR_SUCCESS) {
        Logger::Error("ContainmentEngine: FwpmTransactionBegin0 failed: {}", FormatWin32Error(result));
        return false;
    }

    const auto abortTransaction = [&]() {
        const DWORD abortResult = ::FwpmTransactionAbort0(m_impl->wfpEngineHandle);
        if (abortResult != ERROR_SUCCESS) {
            Logger::Warn("ContainmentEngine: FwpmTransactionAbort0 returned {}", abortResult);
        }
    };

    FWP_V4_ADDR_AND_MASK loopbackV4{};
    loopbackV4.addr = 0x7F000000;
    loopbackV4.mask = 0xFF000000;

    FWP_V6_ADDR_AND_MASK loopbackV6{};
    loopbackV6.addr[15] = 1;
    loopbackV6.prefixLength = 128;

    FWPM_FILTER_CONDITION0 loopbackV4Condition{};
    loopbackV4Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    loopbackV4Condition.matchType = FWP_MATCH_EQUAL;
    loopbackV4Condition.conditionValue.type = FWP_V4_ADDR_MASK;
    loopbackV4Condition.conditionValue.v4AddrMask = &loopbackV4;

    FWPM_FILTER_CONDITION0 loopbackV6Condition{};
    loopbackV6Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    loopbackV6Condition.matchType = FWP_MATCH_EQUAL;
    loopbackV6Condition.conditionValue.type = FWP_V6_ADDR_MASK;
    loopbackV6Condition.conditionValue.v6AddrMask = &loopbackV6;

    std::wstring permitV4OutName = std::format(L"PhantomEDR Loopback Outbound IPv4 {}", ToWide(incidentId));
    auto permitV4Out = CreateBaseFilter(permitV4OutName, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, 15);
    permitV4Out.filterCondition = &loopbackV4Condition;
    permitV4Out.numFilterConditions = 1;
    if (!addFilter(permitV4Out)) {
        abortTransaction();
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    std::wstring permitV4InName = std::format(L"PhantomEDR Loopback Inbound IPv4 {}", ToWide(incidentId));
    auto permitV4In = CreateBaseFilter(permitV4InName, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWP_ACTION_PERMIT, 15);
    permitV4In.filterCondition = &loopbackV4Condition;
    permitV4In.numFilterConditions = 1;
    if (!addFilter(permitV4In)) {
        abortTransaction();
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    std::wstring permitV6OutName = std::format(L"PhantomEDR Loopback Outbound IPv6 {}", ToWide(incidentId));
    auto permitV6Out = CreateBaseFilter(permitV6OutName, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_PERMIT, 15);
    permitV6Out.filterCondition = &loopbackV6Condition;
    permitV6Out.numFilterConditions = 1;
    if (!addFilter(permitV6Out)) {
        abortTransaction();
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    std::wstring permitV6InName = std::format(L"PhantomEDR Loopback Inbound IPv6 {}", ToWide(incidentId));
    auto permitV6In = CreateBaseFilter(permitV6InName, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWP_ACTION_PERMIT, 15);
    permitV6In.filterCondition = &loopbackV6Condition;
    permitV6In.numFilterConditions = 1;
    if (!addFilter(permitV6In)) {
        abortTransaction();
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    if (m_impl->managementPort != 0) {
        FWPM_FILTER_CONDITION0 remotePortCondition{};
        remotePortCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        remotePortCondition.matchType = FWP_MATCH_EQUAL;
        remotePortCondition.conditionValue.type = FWP_UINT16;
        remotePortCondition.conditionValue.uint16 = m_impl->managementPort;

        FWPM_FILTER_CONDITION0 localPortCondition{};
        localPortCondition.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
        localPortCondition.matchType = FWP_MATCH_EQUAL;
        localPortCondition.conditionValue.type = FWP_UINT16;
        localPortCondition.conditionValue.uint16 = m_impl->managementPort;

        std::wstring permitMgmtV4OutName = std::format(L"PhantomEDR Mgmt Outbound IPv4 {}", ToWide(incidentId));
        auto permitMgmtV4Out = CreateBaseFilter(permitMgmtV4OutName, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, 14);
        permitMgmtV4Out.filterCondition = &remotePortCondition;
        permitMgmtV4Out.numFilterConditions = 1;
        if (!addFilter(permitMgmtV4Out)) {
            abortTransaction();
            Logger::Error("ContainmentEngine: {}", error);
            return false;
        }

        std::wstring permitMgmtV4InName = std::format(L"PhantomEDR Mgmt Inbound IPv4 {}", ToWide(incidentId));
        auto permitMgmtV4In = CreateBaseFilter(permitMgmtV4InName, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWP_ACTION_PERMIT, 14);
        permitMgmtV4In.filterCondition = &localPortCondition;
        permitMgmtV4In.numFilterConditions = 1;
        if (!addFilter(permitMgmtV4In)) {
            abortTransaction();
            Logger::Error("ContainmentEngine: {}", error);
            return false;
        }

        std::wstring permitMgmtV6OutName = std::format(L"PhantomEDR Mgmt Outbound IPv6 {}", ToWide(incidentId));
        auto permitMgmtV6Out = CreateBaseFilter(permitMgmtV6OutName, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_PERMIT, 14);
        permitMgmtV6Out.filterCondition = &remotePortCondition;
        permitMgmtV6Out.numFilterConditions = 1;
        if (!addFilter(permitMgmtV6Out)) {
            abortTransaction();
            Logger::Error("ContainmentEngine: {}", error);
            return false;
        }

        std::wstring permitMgmtV6InName = std::format(L"PhantomEDR Mgmt Inbound IPv6 {}", ToWide(incidentId));
        auto permitMgmtV6In = CreateBaseFilter(permitMgmtV6InName, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWP_ACTION_PERMIT, 14);
        permitMgmtV6In.filterCondition = &localPortCondition;
        permitMgmtV6In.numFilterConditions = 1;
        if (!addFilter(permitMgmtV6In)) {
            abortTransaction();
            Logger::Error("ContainmentEngine: {}", error);
            return false;
        }
    }

    std::wstring blockV4OutName = std::format(L"PhantomEDR Block Outbound IPv4 {}", ToWide(incidentId));
    auto blockV4Out = CreateBaseFilter(blockV4OutName, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_BLOCK, 1);
    if (!addFilter(blockV4Out)) {
        abortTransaction();
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    std::wstring blockV4InName = std::format(L"PhantomEDR Block Inbound IPv4 {}", ToWide(incidentId));
    auto blockV4In = CreateBaseFilter(blockV4InName, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWP_ACTION_BLOCK, 1);
    if (!addFilter(blockV4In)) {
        abortTransaction();
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    std::wstring blockV6OutName = std::format(L"PhantomEDR Block Outbound IPv6 {}", ToWide(incidentId));
    auto blockV6Out = CreateBaseFilter(blockV6OutName, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_BLOCK, 1);
    if (!addFilter(blockV6Out)) {
        abortTransaction();
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    std::wstring blockV6InName = std::format(L"PhantomEDR Block Inbound IPv6 {}", ToWide(incidentId));
    auto blockV6In = CreateBaseFilter(blockV6InName, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWP_ACTION_BLOCK, 1);
    if (!addFilter(blockV6In)) {
        abortTransaction();
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    result = ::FwpmTransactionCommit0(m_impl->wfpEngineHandle);
    if (result != ERROR_SUCCESS) {
        abortTransaction();
        Logger::Error("ContainmentEngine: FwpmTransactionCommit0 failed: {}", FormatWin32Error(result));
        return false;
    }

    ContainmentParams params{};
    params.reason = "Host network isolation";
    if (!m_impl->InsertContainmentRecord(
            GenerateRecordId(),
            incidentId,
            ContainmentAction::IsolateNetwork,
            params,
            std::chrono::system_clock::now(),
            true,
            {},
            SerializeFilterIds(filterIds),
            0,
            0,
            -1,
            false)) {
        Logger::Error("ContainmentEngine: failed to persist direct network isolation record");
    }

    Logger::Warn("ContainmentEngine: host network isolation applied for incident {}", std::string(incidentId));
    return true;
}

bool ContainmentEngine::RestoreNetwork(std::string_view incidentId) {
    const auto state = m_impl->GetLatestActiveByIncident(incidentId, ContainmentAction::IsolateNetwork);
    if (!state.has_value()) {
        Logger::Warn("ContainmentEngine: no active network isolation found for incident {}", std::string(incidentId));
        return false;
    }

    std::unique_lock lock(m_impl->mutex);
    std::string error;
    if (!m_impl->EnsureWfpEngineLocked(error)) {
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    const auto filterIds = DeserializeFilterIds(state->filterIds);
    DWORD result = ::FwpmTransactionBegin0(m_impl->wfpEngineHandle, 0);
    if (result != ERROR_SUCCESS) {
        Logger::Error("ContainmentEngine: FwpmTransactionBegin0 failed during restore: {}", FormatWin32Error(result));
        return false;
    }

    bool failed = false;
    for (const auto filterId : filterIds) {
        result = ::FwpmFilterDeleteById0(m_impl->wfpEngineHandle, filterId);
        if (result != ERROR_SUCCESS && result != FWP_E_FILTER_NOT_FOUND) {
            failed = true;
            error = std::format("FwpmFilterDeleteById0 failed for {}: {}", filterId, FormatWin32Error(result));
            break;
        }
    }

    if (failed) {
        ::FwpmTransactionAbort0(m_impl->wfpEngineHandle);
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    result = ::FwpmTransactionCommit0(m_impl->wfpEngineHandle);
    if (result != ERROR_SUCCESS) {
        ::FwpmTransactionAbort0(m_impl->wfpEngineHandle);
        Logger::Error("ContainmentEngine: FwpmTransactionCommit0 failed during restore: {}", FormatWin32Error(result));
        return false;
    }

    m_impl->MarkRolledBack(state->recordId, std::chrono::system_clock::now());
    Logger::Info("ContainmentEngine: network isolation removed for incident {}", std::string(incidentId));
    return true;
}

bool ContainmentEngine::TerminateProcess(const uint32_t pid, const bool killTree) {
    if (pid == 0) {
        Logger::Error("ContainmentEngine: refusing to terminate PID 0");
        return false;
    }

    const std::string processName = GetProcessName(pid).has_value()
        ? ToNarrow(*GetProcessName(pid))
        : "<unknown>";
    const std::string processPath = GetProcessPath(pid).has_value()
        ? ToNarrow(*GetProcessPath(pid))
        : "<unknown>";

    Logger::Warn(
        "ContainmentEngine: terminating process pid={} name={} path={} tree={}",
        pid,
        processName,
        processPath,
        killTree);

    Error processError{};
    const bool terminated = killTree
        ? ShadowStrike::Utils::ProcessUtils::TerminateProcessTree(pid, 0, &processError)
        : ShadowStrike::Utils::ProcessUtils::TerminateProcess(pid, 0, &processError);

    if (!terminated) {
        Logger::Error(
            "ContainmentEngine: failed to terminate pid={} win32={} ntstatus=0x{:08X}",
            pid,
            processError.win32,
            static_cast<uint32_t>(processError.ntstatus));
        return false;
    }

    if (!IsProcessGone(pid)) {
        Logger::Error("ContainmentEngine: pid {} still appears active after termination request", pid);
        return false;
    }

    return true;
}

bool ContainmentEngine::LockUserAccount(std::wstring_view userName) {
    if (userName.empty()) {
        Logger::Error("ContainmentEngine: empty user name for lock request");
        return false;
    }

    uint32_t currentFlags = 0;
    std::string error;
    if (!QueryUserFlags(userName, currentFlags, error)) {
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    if ((currentFlags & UF_ACCOUNTDISABLE) != 0U) {
        Logger::Info("ContainmentEngine: user {} is already disabled", ToNarrow(userName));
        return true;
    }

    if (!ApplyUserFlags(userName, currentFlags | UF_ACCOUNTDISABLE, error)) {
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    ContainmentParams params{};
    params.userName = std::wstring(userName);
    params.reason = "Account lockout";
    if (!m_impl->InsertContainmentRecord(
            GenerateRecordId(),
            {},
            ContainmentAction::LockAccount,
            params,
            std::chrono::system_clock::now(),
            true,
            {},
            {},
            0,
            currentFlags,
            -1,
            false)) {
        Logger::Error("ContainmentEngine: failed to persist direct account lock record");
    }

    Logger::Warn("ContainmentEngine: user account disabled {}", ToNarrow(userName));
    return true;
}

bool ContainmentEngine::UnlockUserAccount(std::wstring_view userName) {
    const auto state = m_impl->GetLatestActiveByUser(userName);
    if (!state.has_value()) {
        Logger::Warn("ContainmentEngine: no active account lock record for {}", ToNarrow(userName));
        return false;
    }

    std::string error;
    if (!ApplyUserFlags(userName, state->userFlags, error)) {
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    m_impl->MarkRolledBack(state->recordId, std::chrono::system_clock::now());
    Logger::Info("ContainmentEngine: user account restored {}", ToNarrow(userName));
    return true;
}

bool ContainmentEngine::BlockIPAddress(std::string_view ipAddress) {
    if (ipAddress.empty()) {
        Logger::Error("ContainmentEngine: empty IP block request");
        return false;
    }

    std::unique_lock lock(m_impl->mutex);
    std::string error;
    if (!m_impl->EnsureWfpEngineLocked(error)) {
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    std::vector<UINT64> filterIds;
    auto addFilter = [&](FWPM_FILTER0& filter) -> bool {
        UINT64 filterId = 0;
        const DWORD result = ::FwpmFilterAdd0(m_impl->wfpEngineHandle, &filter, nullptr, &filterId);
        if (result != ERROR_SUCCESS) {
            error = std::format("FwpmFilterAdd0 failed: {}", FormatWin32Error(result));
            return false;
        }
        filterIds.push_back(filterId);
        return true;
    };

    DWORD result = ::FwpmTransactionBegin0(m_impl->wfpEngineHandle, 0);
    if (result != ERROR_SUCCESS) {
        Logger::Error("ContainmentEngine: FwpmTransactionBegin0 failed: {}", FormatWin32Error(result));
        return false;
    }

    const auto abortTransaction = [&]() {
        const DWORD abortResult = ::FwpmTransactionAbort0(m_impl->wfpEngineHandle);
        if (abortResult != ERROR_SUCCESS) {
            Logger::Warn("ContainmentEngine: FwpmTransactionAbort0 returned {}", abortResult);
        }
    };

    IN_ADDR ipv4{};
    IN6_ADDR ipv6{};
    if (::inet_pton(AF_INET, std::string(ipAddress).c_str(), &ipv4) == 1) {
        FWP_V4_ADDR_AND_MASK addressMask{};
        addressMask.addr = ntohl(ipv4.S_un.S_addr);
        addressMask.mask = 0xFFFFFFFF;

        FWPM_FILTER_CONDITION0 condition{};
        condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_V4_ADDR_MASK;
        condition.conditionValue.v4AddrMask = &addressMask;

        std::wstring outName = std::format(L"PhantomEDR Block IPv4 Out {}", ToWide(ipAddress));
        auto outbound = CreateBaseFilter(outName, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_BLOCK, 12);
        outbound.filterCondition = &condition;
        outbound.numFilterConditions = 1;
        if (!addFilter(outbound)) {
            abortTransaction();
            Logger::Error("ContainmentEngine: {}", error);
            return false;
        }

        std::wstring inName = std::format(L"PhantomEDR Block IPv4 In {}", ToWide(ipAddress));
        auto inbound = CreateBaseFilter(inName, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWP_ACTION_BLOCK, 12);
        inbound.filterCondition = &condition;
        inbound.numFilterConditions = 1;
        if (!addFilter(inbound)) {
            abortTransaction();
            Logger::Error("ContainmentEngine: {}", error);
            return false;
        }
    } else if (::inet_pton(AF_INET6, std::string(ipAddress).c_str(), &ipv6) == 1) {
        FWP_V6_ADDR_AND_MASK addressMask{};
        std::copy(std::begin(ipv6.u.Byte), std::end(ipv6.u.Byte), std::begin(addressMask.addr));
        addressMask.prefixLength = 128;

        FWPM_FILTER_CONDITION0 condition{};
        condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_V6_ADDR_MASK;
        condition.conditionValue.v6AddrMask = &addressMask;

        std::wstring outName = std::format(L"PhantomEDR Block IPv6 Out {}", ToWide(ipAddress));
        auto outbound = CreateBaseFilter(outName, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_BLOCK, 12);
        outbound.filterCondition = &condition;
        outbound.numFilterConditions = 1;
        if (!addFilter(outbound)) {
            abortTransaction();
            Logger::Error("ContainmentEngine: {}", error);
            return false;
        }

        std::wstring inName = std::format(L"PhantomEDR Block IPv6 In {}", ToWide(ipAddress));
        auto inbound = CreateBaseFilter(inName, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWP_ACTION_BLOCK, 12);
        inbound.filterCondition = &condition;
        inbound.numFilterConditions = 1;
        if (!addFilter(inbound)) {
            abortTransaction();
            Logger::Error("ContainmentEngine: {}", error);
            return false;
        }
    } else {
        abortTransaction();
        Logger::Error("ContainmentEngine: invalid IP address {}", std::string(ipAddress));
        return false;
    }

    result = ::FwpmTransactionCommit0(m_impl->wfpEngineHandle);
    if (result != ERROR_SUCCESS) {
        abortTransaction();
        Logger::Error("ContainmentEngine: FwpmTransactionCommit0 failed: {}", FormatWin32Error(result));
        return false;
    }

    ContainmentParams params{};
    params.ipAddress = std::string(ipAddress);
    params.reason = "IP block";
    if (!m_impl->InsertContainmentRecord(
            GenerateRecordId(),
            {},
            ContainmentAction::BlockIP,
            params,
            std::chrono::system_clock::now(),
            true,
            {},
            SerializeFilterIds(filterIds),
            0,
            0,
            -1,
            false)) {
        Logger::Error("ContainmentEngine: failed to persist direct IP block record");
    }

    Logger::Warn("ContainmentEngine: blocked IP address {}", std::string(ipAddress));
    return true;
}

bool ContainmentEngine::UnblockIPAddress(std::string_view ipAddress) {
    const auto state = m_impl->GetLatestActiveByIp(ipAddress);
    if (!state.has_value()) {
        Logger::Warn("ContainmentEngine: no active IP block record for {}", std::string(ipAddress));
        return false;
    }

    std::unique_lock lock(m_impl->mutex);
    std::string error;
    if (!m_impl->EnsureWfpEngineLocked(error)) {
        Logger::Error("ContainmentEngine: {}", error);
        return false;
    }

    DWORD result = ::FwpmTransactionBegin0(m_impl->wfpEngineHandle, 0);
    if (result != ERROR_SUCCESS) {
        Logger::Error("ContainmentEngine: FwpmTransactionBegin0 failed: {}", FormatWin32Error(result));
        return false;
    }

    const auto filterIds = DeserializeFilterIds(state->filterIds);
    for (const auto filterId : filterIds) {
        result = ::FwpmFilterDeleteById0(m_impl->wfpEngineHandle, filterId);
        if (result != ERROR_SUCCESS && result != FWP_E_FILTER_NOT_FOUND) {
            ::FwpmTransactionAbort0(m_impl->wfpEngineHandle);
            Logger::Error("ContainmentEngine: failed to remove block filter {}: {}", filterId, FormatWin32Error(result));
            return false;
        }
    }

    result = ::FwpmTransactionCommit0(m_impl->wfpEngineHandle);
    if (result != ERROR_SUCCESS) {
        ::FwpmTransactionAbort0(m_impl->wfpEngineHandle);
        Logger::Error("ContainmentEngine: FwpmTransactionCommit0 failed: {}", FormatWin32Error(result));
        return false;
    }

    m_impl->MarkRolledBack(state->recordId, std::chrono::system_clock::now());
    Logger::Info("ContainmentEngine: unblocked IP address {}", std::string(ipAddress));
    return true;
}

std::vector<ContainmentRecord> ContainmentEngine::GetActiveContainments() const {
    if (!IsInitialized()) {
        return {};
    }

    std::vector<ContainmentRecord> records;
    auto result = DatabaseManager::Instance().Query(
        "SELECT record_id, incident_id, action, pid, file_path, ip_address, user_name, service_name, reason, executed_at, rolled_back_at, success, error_message, filter_ids, quarantine_entry_id, user_flags, service_start_type, service_was_running "
        "FROM containment_log WHERE success = 1 AND rolled_back_at IS NULL ORDER BY executed_at DESC");
    while (result.Next()) {
        auto state = ContainmentEngineImpl::MapContainmentRecord(result);
        records.push_back(ContainmentRecord{
            state.recordId,
            state.incidentId,
            state.action,
            state.params,
            state.executedAt,
            state.rolledBackAt,
            state.success,
            state.errorMessage
        });
    }

    return records;
}

std::vector<ContainmentRecord> ContainmentEngine::GetContainmentHistory(std::string_view incidentId) const {
    if (!IsInitialized()) {
        return {};
    }

    return m_impl->QueryRecords(
        "SELECT record_id, incident_id, action, pid, file_path, ip_address, user_name, service_name, reason, executed_at, rolled_back_at, success, error_message, filter_ids, quarantine_entry_id, user_flags, service_start_type, service_was_running "
        "FROM containment_log WHERE incident_id = ? ORDER BY executed_at DESC",
        incidentId);
}

} // namespace ShadowStrike::Products::PhantomEDR::IncidentResponse

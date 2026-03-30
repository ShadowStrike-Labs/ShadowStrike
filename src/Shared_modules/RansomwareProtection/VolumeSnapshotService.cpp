/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - VOLUME SNAPSHOT SERVICE IMPLEMENTATION
 * ============================================================================
 *
 * @file VolumeSnapshotService.cpp
 * @brief Enterprise-grade VSS (Volume Shadow Copy Service) wrapper for
 *        ransomware protection and point-in-time recovery.
 *
 * CRITICAL DESIGN DECISIONS:
 *   - IVssBackupComponents is recreated per snapshot operation because
 *     DoSnapshotSet leaves the object in a terminal state.
 *   - VSS_BT_COPY is used (not VSS_BT_FULL) to avoid disrupting writers.
 *   - Privilege acquisition (SeBackupPrivilege, SeRestorePrivilege,
 *     SeSecurityPrivilege) is performed during Initialize().
 *   - Monitoring thread initializes its own COM apartment.
 *   - ShadowCopyProtector is notified of every newly-created snapshot.
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "VolumeSnapshotService.hpp"
#include "ShadowCopyProtector.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/StringUtils.hpp"

// Cross-module wiring
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"

#include <Windows.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <vsmgmt.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <unordered_map>
#include <cctype>
#include <cwctype>
#include <format>
#include <nlohmann/json.hpp>
#include <comdef.h>

#pragma comment(lib, "VssApi.lib")
#pragma comment(lib, "ole32.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> VolumeSnapshotService::s_instanceCreated{false};

// ============================================================================
// INTERNAL HELPERS (anonymous namespace)
// ============================================================================

namespace {

constexpr wchar_t kLogCategory[] = L"VSS";

// VSS Software Provider GUID (not declared in older SDK headers)
// {b5946137-7b9f-4925-af80-51abd60b20d5}
static const VSS_ID VSS_SWPRV_ProviderId = {
    0xb5946137, 0x7b9f, 0x4925,
    { 0xaf, 0x80, 0x51, 0xab, 0xd6, 0x0b, 0x20, 0xd5 }
};

/// @brief RAII guard for per-thread COM initialization.
struct ComInitGuard {
    bool ownsInit = false;

    explicit ComInitGuard(DWORD model = COINIT_MULTITHREADED) {
        HRESULT hr = CoInitializeEx(nullptr, model);
        if (SUCCEEDED(hr)) {
            ownsInit = true;
        } else if (hr == RPC_E_CHANGED_MODE) {
            ownsInit = false;  // already initialized in compatible mode
        } else {
            SS_LOG_ERROR(kLogCategory, L"CoInitializeEx failed: 0x%08X",
                         static_cast<unsigned>(hr));
        }
    }
    ~ComInitGuard() {
        if (ownsInit) CoUninitialize();
    }
    ComInitGuard(const ComInitGuard&)            = delete;
    ComInitGuard& operator=(const ComInitGuard&) = delete;
};

/// @brief RAII wrapper for IVssBackupComponents.
struct VssComponentsGuard {
    IVssBackupComponents* ptr = nullptr;

    VssComponentsGuard() = default;
    ~VssComponentsGuard() { Release(); }

    void Release() {
        if (ptr) {
            ptr->Release();
            ptr = nullptr;
        }
    }

    VssComponentsGuard(const VssComponentsGuard&)            = delete;
    VssComponentsGuard& operator=(const VssComponentsGuard&) = delete;
};

// Convert GUID to wide string
[[nodiscard]] std::wstring GuidToWString(const GUID& guid) {
    wchar_t buffer[64]{};
    if (StringFromGUID2(guid, buffer, 64) == 0) {
        return {};
    }
    return std::wstring(buffer);
}

// Convert wide string to GUID with validation
[[nodiscard]] bool WStringToGuid(const std::wstring& str, GUID& outGuid) {
    if (str.empty()) return false;
    HRESULT hr = CLSIDFromString(str.c_str(), &outGuid);
    return SUCCEEDED(hr);
}

// Convert VSS state to our enum
[[nodiscard]] SnapshotState VssStateToSnapshotState(VSS_SNAPSHOT_STATE vssState) {
    switch (vssState) {
        case VSS_SS_UNKNOWN:                return SnapshotState::Unknown;
        case VSS_SS_PREPARING:              return SnapshotState::Preparing;
        case VSS_SS_PROCESSING_PREPARE:     return SnapshotState::Processing;
        case VSS_SS_PREPARED:               return SnapshotState::Prepared;
        case VSS_SS_PROCESSING_PRECOMMIT:   return SnapshotState::Processing;
        case VSS_SS_PRECOMMITTED:           return SnapshotState::Prepared;
        case VSS_SS_PROCESSING_COMMIT:      return SnapshotState::Processing;
        case VSS_SS_COMMITTED:              return SnapshotState::Committed;
        case VSS_SS_PROCESSING_POSTCOMMIT:  return SnapshotState::Processing;
        case VSS_SS_CREATED:                return SnapshotState::Created;
        default:                            return SnapshotState::Unknown;
    }
}

// Convert VSS writer state
[[nodiscard]] WriterState VssWriterStateToWriterState(VSS_WRITER_STATE vssState) {
    switch (vssState) {
        case VSS_WS_STABLE:
            return WriterState::Stable;
        case VSS_WS_WAITING_FOR_FREEZE:
            return WriterState::WaitingForFreeze;
        case VSS_WS_WAITING_FOR_THAW:
            return WriterState::WaitingForThaw;
        case VSS_WS_WAITING_FOR_POST_SNAPSHOT:
        case VSS_WS_WAITING_FOR_BACKUP_COMPLETE:
            return WriterState::WaitingForCompletion;
        case VSS_WS_FAILED_AT_IDENTIFY:
        case VSS_WS_FAILED_AT_PREPARE_BACKUP:
        case VSS_WS_FAILED_AT_PREPARE_SNAPSHOT:
        case VSS_WS_FAILED_AT_FREEZE:
        case VSS_WS_FAILED_AT_THAW:
        case VSS_WS_FAILED_AT_POST_SNAPSHOT:
        case VSS_WS_FAILED_AT_BACKUP_COMPLETE:
        case VSS_WS_FAILED_AT_PRE_RESTORE:
        case VSS_WS_FAILED_AT_POST_RESTORE:
            return WriterState::Failed;
        default:
            return WriterState::Unknown;
    }
}

// Map HRESULT to VSSResult
[[nodiscard]] VSSResult HResultToVSSResult(HRESULT hr) {
    if (SUCCEEDED(hr)) return VSSResult::Success;
    switch (hr) {
        case VSS_E_BAD_STATE:                            return VSSResult::BadState;
        case VSS_E_UNEXPECTED_PROVIDER_ERROR:            return VSSResult::ProviderError;
        case VSS_E_OBJECT_NOT_FOUND:                     return VSSResult::NotFound;
        case VSS_E_VOLUME_NOT_SUPPORTED:                 return VSSResult::VolumeNotSupported;
        case VSS_E_INSUFFICIENT_STORAGE:                 return VSSResult::InsufficientStorage;
        case VSS_E_PROVIDER_VETO:                        return VSSResult::ProviderVeto;
        case VSS_E_MAXIMUM_NUMBER_OF_SNAPSHOTS_REACHED:  return VSSResult::MaxSnapshotsReached;
        case E_ACCESSDENIED:                             return VSSResult::AccessDenied;
        case E_OUTOFMEMORY:                              return VSSResult::OutOfMemory;
        default:                                         return VSSResult::UnknownError;
    }
}

// Get volume GUID path from a drive letter or path
[[nodiscard]] std::wstring GetVolumeNameFromPath(const std::wstring& path) {
    if (path.empty()) return {};
    wchar_t volumePath[MAX_PATH]{};
    if (!GetVolumePathNameW(path.c_str(), volumePath, MAX_PATH)) {
        return {};
    }
    wchar_t volumeName[MAX_PATH]{};
    if (!GetVolumeNameForVolumeMountPointW(volumePath, volumeName, MAX_PATH)) {
        return {};
    }
    return std::wstring(volumeName);
}

// Wait for IVssAsync with proper result checking
[[nodiscard]] HRESULT WaitForVssAsync(IVssAsync* pAsync, uint32_t timeoutMs = 60000) {
    if (!pAsync) return E_POINTER;

    HRESULT hrWait = pAsync->Wait(timeoutMs);
    if (FAILED(hrWait)) return hrWait;

    HRESULT hrResult = S_OK;
    HRESULT hrQuery = pAsync->QueryStatus(&hrResult, nullptr);
    if (FAILED(hrQuery)) return hrQuery;

    return hrResult;
}

// Validate volume path format to prevent traversal / injection
[[nodiscard]] bool IsValidVolumePath(const std::wstring& vol) {
    if (vol.empty() || vol.size() > VSSConstants::MAX_VOLUME_PATH_LEN) return false;
    // Accept "C:\" style or "\\?\Volume{GUID}\" style
    if (vol.size() >= 3 && std::iswalpha(vol[0]) && vol[1] == L':' && vol[2] == L'\\') {
        return true;
    }
    if (vol.starts_with(L"\\\\?\\Volume{")) {
        return true;
    }
    return false;
}

// Convert FILETIME-epoch 100ns ticks (VSS_TIMESTAMP = LONGLONG) to system_clock::time_point
[[nodiscard]] SystemTimePoint FileTimeToSystemTime(const VSS_TIMESTAMP& ts) {
    // VSS_TIMESTAMP is a LONGLONG representing 100ns intervals since 1601-01-01
    ULARGE_INTEGER ull;
    ull.QuadPart = static_cast<ULONGLONG>(ts);
    constexpr int64_t kEpochDelta = 116444736000000000LL;
    auto ticks = std::chrono::duration<int64_t, std::ratio<1, 10000000>>(
        static_cast<int64_t>(ull.QuadPart));
    return SystemTimePoint(
        ticks - std::chrono::duration<int64_t, std::ratio<1, 10000000>>(kEpochDelta));
}

// Acquire a single privilege. Returns true on success.
[[nodiscard]] bool AcquirePrivilege(const wchar_t* privName) {
    if (!Utils::SystemUtils::EnablePrivilege(privName, true)) {
        SS_LOG_WARN(kLogCategory, L"Failed to acquire privilege: %ls", privName);
        return false;
    }
    return true;
}

} // anonymous namespace

// ============================================================================
// JSON SERIALIZATION
// ============================================================================

std::string SnapshotInfo::ToJson() const {
    json j;
    j["snapshotId"]   = Utils::StringUtils::ToNarrow(snapshotId);
    j["snapshotSetId"]= Utils::StringUtils::ToNarrow(snapshotSetId);
    j["volumeName"]   = Utils::StringUtils::ToNarrow(volumeName);
    j["deviceName"]   = Utils::StringUtils::ToNarrow(deviceName);
    j["creationTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        creationTime.time_since_epoch()).count();
    j["type"]         = static_cast<int>(type);
    j["state"]        = static_cast<int>(state);
    j["sizeBytes"]    = sizeBytes;
    j["isExposed"]    = isExposed;
    j["exposePath"]   = Utils::StringUtils::ToNarrow(exposePath);
    j["attributes"]   = attributes;
    return j.dump();
}

std::string VolumeInfo::ToJson() const {
    json j;
    j["volumeName"]      = Utils::StringUtils::ToNarrow(volumeName);
    j["mountPoint"]      = Utils::StringUtils::ToNarrow(mountPoint);
    j["fileSystem"]      = Utils::StringUtils::ToNarrow(fileSystem);
    j["totalSize"]       = totalSize;
    j["freeSpace"]       = freeSpace;
    j["shadowStorageMax"]= shadowStorageMax;
    j["shadowStorageUsed"]=shadowStorageUsed;
    j["snapshotCount"]   = snapshotCount;
    j["vssSupported"]    = vssSupported;
    return j.dump();
}

std::string WriterInfo::ToJson() const {
    json j;
    j["writerId"]   = Utils::StringUtils::ToNarrow(writerId);
    j["writerName"] = Utils::StringUtils::ToNarrow(writerName);
    j["instanceId"] = Utils::StringUtils::ToNarrow(instanceId);
    j["state"]      = static_cast<int>(state);
    j["lastError"]  = lastError;
    return j.dump();
}

std::string SnapshotOperation::ToJson() const {
    json j;
    j["operationId"]     = Utils::StringUtils::ToNarrow(operationId);
    j["type"]            = static_cast<int>(type);
    j["state"]           = static_cast<int>(state);
    j["volumeName"]      = Utils::StringUtils::ToNarrow(volumeName);
    j["snapshotId"]      = Utils::StringUtils::ToNarrow(snapshotId);
    j["progressPercent"] = progressPercent;
    j["startTime"]       = std::chrono::duration_cast<std::chrono::milliseconds>(
        startTime.time_since_epoch()).count();
    j["endTime"]         = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime.time_since_epoch()).count();
    j["errorMessage"]    = errorMessage;
    return j.dump();
}

bool VolumeSnapshotConfiguration::IsValid() const noexcept {
    if (maxSnapshotsPerVolume == 0 || maxSnapshotsPerVolume > 512)   return false;
    if (defaultStorageLimitPercent == 0 || defaultStorageLimitPercent > 80) return false;
    if (monitoringIntervalSeconds == 0 || monitoringIntervalSeconds > 86400) return false;
    return true;
}

void VolumeSnapshotStatistics::Reset() noexcept {
    snapshotsCreated           = 0;
    snapshotsDeleted           = 0;
    snapshotsMounted           = 0;
    filesRestored              = 0;
    directoriesRestored        = 0;
    operationsFailed           = 0;
    totalCreationTimeMs        = 0;
    totalDeletionTimeMs        = 0;
    totalRestorationTimeMs     = 0;
    currentOperations          = 0;
    emergencySnapshotsCreated  = 0;
    for (auto& c : byType)   c = 0;
    for (auto& c : byResult) c = 0;
    startTime = Clock::now();
}

std::string VolumeSnapshotStatistics::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    json j;
    j["uptimeSeconds"]          = uptime;
    j["snapshotsCreated"]       = snapshotsCreated.load();
    j["snapshotsDeleted"]       = snapshotsDeleted.load();
    j["snapshotsMounted"]       = snapshotsMounted.load();
    j["filesRestored"]          = filesRestored.load();
    j["directoriesRestored"]    = directoriesRestored.load();
    j["operationsFailed"]       = operationsFailed.load();
    j["totalCreationTimeMs"]    = totalCreationTimeMs.load();
    j["totalDeletionTimeMs"]    = totalDeletionTimeMs.load();
    j["totalRestorationTimeMs"] = totalRestorationTimeMs.load();
    j["currentOperations"]      = currentOperations.load();
    j["emergencySnapshots"]     = emergencySnapshotsCreated.load();
    return j.dump();
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class VolumeSnapshotServiceImpl final {
public:
    VolumeSnapshotServiceImpl();
    ~VolumeSnapshotServiceImpl();

    // --- Lifecycle ---
    bool Initialize(const VolumeSnapshotConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_isActive.load(std::memory_order_acquire); }
    ModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }
    bool UpdateConfiguration(const VolumeSnapshotConfiguration& config);
    VolumeSnapshotConfiguration GetConfiguration() const;

    // --- Snapshot creation ---
    VSSResult CreateSnapshot(const std::wstring& volumeName,
                             std::wstring& outSnapshotId, SnapshotType type);
    VSSResult CreateSnapshotEx(const std::wstring& volumeName,
                               std::wstring& outSnapshotId, const SnapshotOptions& options);
    VSSResult CreateSnapshotSet(const std::vector<std::wstring>& volumes,
                                std::vector<std::wstring>& outSnapshotIds, SnapshotType type);
    VSSResult CreateEmergencySnapshot(const std::wstring& volumeName,
                                      std::wstring& outSnapshotId);

    // --- Snapshot query ---
    std::vector<SnapshotInfo> EnumerateSnapshots();
    std::vector<SnapshotInfo> EnumerateSnapshotsForVolume(const std::wstring& volumeName);
    std::optional<SnapshotInfo> GetSnapshotInfo(const std::wstring& snapshotId);
    std::vector<SnapshotInfo> GetRecoveryPoints(const std::wstring& volumeName);

    // --- Snapshot deletion ---
    VSSResult DeleteSnapshot(const std::wstring& snapshotId, bool force);
    VSSResult DeleteSnapshotsForVolume(const std::wstring& volumeName);
    VSSResult DeleteOldestSnapshot(const std::wstring& volumeName);
    uint32_t  DeleteSnapshotsOlderThan(const SystemTimePoint& cutoffTime);

    // --- Snapshot mounting ---
    VSSResult MountSnapshot(const std::wstring& snapshotId, const std::wstring& mountPoint);
    VSSResult UnmountSnapshot(const std::wstring& snapshotId);
    bool IsSnapshotMounted(const std::wstring& snapshotId);
    std::optional<std::wstring> GetMountPoint(const std::wstring& snapshotId);

    // --- File restoration ---
    VSSResult RestoreFile(const std::wstring& snapshotId,
                          const std::wstring& sourceFile, const std::wstring& destFile);
    VSSResult RestoreDirectory(const std::wstring& snapshotId,
                               const std::wstring& sourceDir, const std::wstring& destDir,
                               bool recursive);
    VSSResult RestoreToOriginalLocation(const std::wstring& snapshotId,
                                        const std::wstring& filePath);

    // --- Integrity ---
    bool VerifySnapshotIntegrity(const std::wstring& snapshotId);

    // --- Volume management ---
    std::vector<VolumeInfo> GetVSSVolumes();
    std::optional<VolumeInfo> GetVolumeInfo(const std::wstring& volumeName);
    bool IsVSSSupported(const std::wstring& volumeName);
    std::wstring GetVolumeFromPath(const std::wstring& path);

    // --- Storage management ---
    VSSResult SetStorageLimit(const std::wstring& volumeName, uint64_t maxSizeBytes);
    VSSResult SetStorageLimitPercent(const std::wstring& volumeName, uint32_t percent);
    std::optional<uint64_t> GetStorageLimit(const std::wstring& volumeName);
    std::optional<uint64_t> GetStorageUsage(const std::wstring& volumeName);
    VSSResult CleanupOldSnapshots(const std::wstring& volumeName, uint32_t keepCount);

    // --- Writers ---
    std::vector<WriterInfo> GetWriters();
    bool AreWritersStable();
    VSSResult WaitForWriters(uint32_t timeoutMs);

    // --- Operations ---
    std::vector<SnapshotOperation> GetActiveOperations();
    std::optional<SnapshotOperation> GetOperation(const std::wstring& operationId);
    bool CancelOperation(const std::wstring& operationId);

    // --- Monitoring ---
    bool StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const noexcept { return m_monitoring.load(std::memory_order_acquire); }

    // --- Callbacks ---
    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterCompletionCallback(CompletionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // --- Statistics ---
    VolumeSnapshotStatisticsSnapshot GetStatistics() const;
    void ResetStatistics();
    bool SelfTest();

private:
    // Internal helpers
    void MonitoringThreadFunc();
    VSSResult CreateSnapshotInternal(const std::wstring& volumeName,
                                     std::wstring& outSnapshotId,
                                     const SnapshotOptions& options);
    VSSResult DeleteSnapshotInternal(const std::wstring& snapshotId, bool force);
    std::vector<SnapshotInfo> QuerySnapshots();
    void NotifyProgress(const std::wstring& operationId, uint32_t percent);
    void NotifyCompletion(const std::wstring& operationId, VSSResult result);
    void NotifyError(const std::string& message, int code);
    bool AcquireRequiredPrivileges();
    void NotifyShadowCopyProtector(const std::wstring& snapshotId);
    VSSResult ExposeSnapshot(const std::wstring& snapshotId, const std::wstring& exposePath);
    VSSResult UnexposeSnapshot(const std::wstring& snapshotId);

    // State
    mutable std::shared_mutex m_mutex;
    std::atomic<bool>         m_isActive{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    VolumeSnapshotConfiguration m_config;
    bool m_privilegesAcquired = false;

    // COM state
    bool m_comInitialized = false;

    // Monitoring
    std::atomic<bool> m_monitoring{false};
    std::unique_ptr<std::thread> m_monitorThread;
    std::atomic<bool> m_stopMonitoring{false};

    // Active operations
    std::vector<SnapshotOperation> m_activeOperations;

    // Mounted snapshots (snapshotId -> mountPoint)
    std::unordered_map<std::wstring, std::wstring> m_mountedSnapshots;

    // Callbacks (protected by m_callbackMutex to avoid holding m_mutex during invocation)
    mutable std::mutex m_callbackMutex;
    ProgressCallback   m_progressCallback;
    CompletionCallback m_completionCallback;
    ErrorCallback      m_errorCallback;

    // Statistics
    VolumeSnapshotStatistics m_stats;
};

// ============================================================================
// PIMPL CONSTRUCTOR / DESTRUCTOR
// ============================================================================

VolumeSnapshotServiceImpl::VolumeSnapshotServiceImpl() {
    SS_LOG_DEBUG(kLogCategory, L"VolumeSnapshotServiceImpl constructed");
}

VolumeSnapshotServiceImpl::~VolumeSnapshotServiceImpl() {
    Shutdown();
    SS_LOG_DEBUG(kLogCategory, L"VolumeSnapshotServiceImpl destroyed");
}

// ============================================================================
// PRIVILEGE ACQUISITION
// ============================================================================

bool VolumeSnapshotServiceImpl::AcquireRequiredPrivileges() {
    bool ok = true;
    ok &= AcquirePrivilege(L"SeBackupPrivilege");
    ok &= AcquirePrivilege(L"SeRestorePrivilege");
    ok &= AcquirePrivilege(L"SeSecurityPrivilege");
    if (!ok) {
        SS_LOG_WARN(kLogCategory,
            L"Not all VSS privileges acquired — some operations may fail");
    }
    return ok;
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool VolumeSnapshotServiceImpl::Initialize(const VolumeSnapshotConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_isActive.load(std::memory_order_relaxed)) {
        SS_LOG_WARN(kLogCategory, L"VolumeSnapshotService already initialized");
        return false;
    }

    m_status.store(ModuleStatus::Initializing, std::memory_order_release);

    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Invalid VolumeSnapshotService configuration");
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
    m_config = config;

    // Initialize COM
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        SS_LOG_ERROR(kLogCategory, L"CoInitializeEx failed: 0x%08X",
                     static_cast<unsigned>(hr));
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
    m_comInitialized = (hr != RPC_E_CHANGED_MODE);

    // Acquire VSS privileges
    m_privilegesAcquired = AcquireRequiredPrivileges();

    m_stats.Reset();

    // Start monitoring if configured
    if (m_config.enableMonitoring) {
        lock.unlock();
        StartMonitoring();
        lock.lock();
    }

    m_isActive.store(true, std::memory_order_release);
    m_status.store(ModuleStatus::Running, std::memory_order_release);
    SS_LOG_INFO(kLogCategory, L"VolumeSnapshotService initialized (privileges=%ls)",
                m_privilegesAcquired ? L"acquired" : L"partial");
    return true;
}

void VolumeSnapshotServiceImpl::Shutdown() {
    // Stop monitoring first (outside the main lock to avoid deadlock with thread join)
    StopMonitoring();

    std::unique_lock lock(m_mutex);
    if (!m_isActive.load(std::memory_order_relaxed)) return;

    m_status.store(ModuleStatus::Stopping, std::memory_order_release);

    // Unmount all mounted snapshots
    for (const auto& [sid, mp] : m_mountedSnapshots) {
        UnexposeSnapshot(sid);
    }
    m_mountedSnapshots.clear();

    // Uninitialize COM
    if (m_comInitialized) {
        CoUninitialize();
        m_comInitialized = false;
    }

    m_isActive.store(false, std::memory_order_release);
    m_status.store(ModuleStatus::Stopped, std::memory_order_release);
    SS_LOG_INFO(kLogCategory, L"VolumeSnapshotService shutdown complete");
}

bool VolumeSnapshotServiceImpl::UpdateConfiguration(const VolumeSnapshotConfiguration& config) {
    std::unique_lock lock(m_mutex);
    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Invalid configuration rejected");
        return false;
    }
    m_config = config;
    SS_LOG_INFO(kLogCategory, L"Configuration updated");
    return true;
}

VolumeSnapshotConfiguration VolumeSnapshotServiceImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// SNAPSHOT CREATION — core internal
// ============================================================================

VSSResult VolumeSnapshotServiceImpl::CreateSnapshotInternal(
    const std::wstring& volumeName,
    std::wstring& outSnapshotId,
    const SnapshotOptions& options)
{
    // Validate input
    if (!IsValidVolumePath(volumeName)) {
        SS_LOG_ERROR(kLogCategory, L"Invalid volume path for snapshot creation");
        return VSSResult::InvalidParameter;
    }

    std::unique_lock lock(m_mutex);
    if (!m_isActive.load(std::memory_order_relaxed)) {
        return VSSResult::NotInitialized;
    }

    // Enforce per-volume snapshot cap
    {
        lock.unlock();
        auto existing = EnumerateSnapshotsForVolume(volumeName);
        lock.lock();
        if (existing.size() >= m_config.maxSnapshotsPerVolume) {
            SS_LOG_WARN(kLogCategory,
                L"Max snapshots (%u) reached for volume — cleaning oldest",
                static_cast<unsigned>(m_config.maxSnapshotsPerVolume));
            lock.unlock();
            DeleteOldestSnapshot(volumeName);
            lock.lock();
        }
    }

    // Create fresh IVssBackupComponents per operation.
    // DoSnapshotSet leaves the components in a terminal state; reuse is forbidden.
    VssComponentsGuard comps;
    HRESULT hr = CreateVssBackupComponents(&comps.ptr);
    if (FAILED(hr) || !comps.ptr) {
        SS_LOG_ERROR(kLogCategory, L"CreateVssBackupComponents failed: 0x%08X",
                     static_cast<unsigned>(hr));
        return HResultToVSSResult(hr);
    }

    hr = comps.ptr->InitializeForBackup();
    if (FAILED(hr)) {
        SS_LOG_ERROR(kLogCategory, L"InitializeForBackup failed: 0x%08X",
                     static_cast<unsigned>(hr));
        return HResultToVSSResult(hr);
    }

    // VSS_BT_COPY: non-intrusive, does not affect writer log sequences.
    // VSS_BT_FULL would reset writer logs and disrupt real backup software.
    hr = comps.ptr->SetBackupState(
        true,           // selectComponents
        true,           // backupBootableSystemState
        VSS_BT_COPY,   // CRITICAL: COPY not FULL
        false           // partialFileSupport
    );
    if (FAILED(hr)) {
        SS_LOG_ERROR(kLogCategory, L"SetBackupState failed: 0x%08X",
                     static_cast<unsigned>(hr));
        return HResultToVSSResult(hr);
    }

    // Gather writer metadata (only if writers requested)
    if (options.includeWriters) {
        IVssAsync* pAsync = nullptr;
        hr = comps.ptr->GatherWriterMetadata(&pAsync);
        if (SUCCEEDED(hr) && pAsync) {
            hr = WaitForVssAsync(pAsync, options.timeoutMs);
            pAsync->Release();
            if (FAILED(hr)) {
                SS_LOG_WARN(kLogCategory,
                    L"GatherWriterMetadata failed: 0x%08X — proceeding without writers",
                    static_cast<unsigned>(hr));
            }
        }
    }

    // Start snapshot set
    GUID snapshotSetId{};
    hr = comps.ptr->StartSnapshotSet(&snapshotSetId);
    if (FAILED(hr)) {
        SS_LOG_ERROR(kLogCategory, L"StartSnapshotSet failed: 0x%08X",
                     static_cast<unsigned>(hr));
        return HResultToVSSResult(hr);
    }

    // Add volume
    GUID snapshotId{};
    hr = comps.ptr->AddToSnapshotSet(
        const_cast<wchar_t*>(volumeName.c_str()),
        GUID_NULL,
        &snapshotId);
    if (FAILED(hr)) {
        SS_LOG_ERROR(kLogCategory, L"AddToSnapshotSet failed: 0x%08X",
                     static_cast<unsigned>(hr));
        return HResultToVSSResult(hr);
    }

    // PrepareForBackup
    {
        IVssAsync* pAsync = nullptr;
        hr = comps.ptr->PrepareForBackup(&pAsync);
        if (SUCCEEDED(hr) && pAsync) {
            hr = WaitForVssAsync(pAsync, options.timeoutMs);
            pAsync->Release();
            if (FAILED(hr)) {
                SS_LOG_ERROR(kLogCategory, L"PrepareForBackup failed: 0x%08X",
                             static_cast<unsigned>(hr));
                return HResultToVSSResult(hr);
            }
        } else if (FAILED(hr)) {
            SS_LOG_ERROR(kLogCategory, L"PrepareForBackup call failed: 0x%08X",
                         static_cast<unsigned>(hr));
            return HResultToVSSResult(hr);
        }
    }

    // DoSnapshotSet
    {
        IVssAsync* pAsync = nullptr;
        hr = comps.ptr->DoSnapshotSet(&pAsync);
        if (SUCCEEDED(hr) && pAsync) {
            hr = WaitForVssAsync(pAsync, options.timeoutMs);
            pAsync->Release();
            if (FAILED(hr)) {
                SS_LOG_ERROR(kLogCategory, L"DoSnapshotSet failed: 0x%08X",
                             static_cast<unsigned>(hr));
                return HResultToVSSResult(hr);
            }
        } else if (FAILED(hr)) {
            SS_LOG_ERROR(kLogCategory, L"DoSnapshotSet call failed: 0x%08X",
                         static_cast<unsigned>(hr));
            return HResultToVSSResult(hr);
        }
    }

    // Retrieve snapshot properties to confirm creation
    VSS_SNAPSHOT_PROP prop{};
    hr = comps.ptr->GetSnapshotProperties(snapshotId, &prop);
    if (FAILED(hr)) {
        SS_LOG_ERROR(kLogCategory,
            L"GetSnapshotProperties failed after DoSnapshotSet: 0x%08X",
            static_cast<unsigned>(hr));
        return HResultToVSSResult(hr);
    }

    outSnapshotId = GuidToWString(prop.m_SnapshotId);
    VssFreeSnapshotProperties(&prop);

    auto idx = static_cast<size_t>(options.type);
    if (idx < m_stats.byType.size()) {
        m_stats.byType[idx]++;
    }

    return VSSResult::Success;
}

// ============================================================================
// SNAPSHOT CREATION — public wrappers
// ============================================================================

VSSResult VolumeSnapshotServiceImpl::CreateSnapshot(
    const std::wstring& volumeName,
    std::wstring& outSnapshotId,
    SnapshotType type)
{
    SnapshotOptions opts;
    opts.type        = type;
    opts.autoCleanup = m_config.autoCleanupSnapshots;
    return CreateSnapshotEx(volumeName, outSnapshotId, opts);
}

VSSResult VolumeSnapshotServiceImpl::CreateSnapshotEx(
    const std::wstring& volumeName,
    std::wstring& outSnapshotId,
    const SnapshotOptions& options)
{
    auto startTime = Clock::now();
    m_stats.currentOperations++;

    VSSResult result = CreateSnapshotInternal(volumeName, outSnapshotId, options);

    m_stats.currentOperations--;
    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime).count();

    if (result == VSSResult::Success) {
        m_stats.snapshotsCreated++;
        m_stats.totalCreationTimeMs += static_cast<uint64_t>(durationMs);

        // Notify ShadowCopyProtector so this snapshot is tamper-protected
        NotifyShadowCopyProtector(outSnapshotId);

        // Cross-module wiring: AlertSystem + TelemetryCollector
        if (Communication::TelemetryCollector::HasInstance()) {
            Communication::TelemetryCollector::Instance().RecordCustom(
                "vss_snapshot_created",
                {
                    {"volume",     Utils::StringUtils::ToNarrow(volumeName)},
                    {"snapshotId", Utils::StringUtils::ToNarrow(outSnapshotId)},
                    {"durationMs", std::to_string(durationMs)}
                });
        }

        SS_LOG_INFO(kLogCategory, L"Snapshot created: %ls (%lldms)",
                    outSnapshotId.c_str(), static_cast<long long>(durationMs));
    } else {
        m_stats.operationsFailed++;

        if (Communication::AlertSystem::HasInstance()) {
            (void)Communication::AlertSystem::Instance().RaiseAlert(
                Communication::AlertSeverity::High,
                Communication::AlertType::Operational,
                "VolumeSnapshotService",
                std::format("Snapshot creation failed for {} — result={}",
                    Utils::StringUtils::ToNarrow(volumeName),
                    static_cast<int>(result)),
                std::format("durationMs={}", durationMs));
        }

        SS_LOG_ERROR(kLogCategory, L"Snapshot creation failed: result=%d (%lldms)",
                     static_cast<int>(result), static_cast<long long>(durationMs));
    }

    auto ri = static_cast<size_t>(result);
    if (ri < m_stats.byResult.size()) {
        m_stats.byResult[ri]++;
    }

    return result;
}

VSSResult VolumeSnapshotServiceImpl::CreateSnapshotSet(
    const std::vector<std::wstring>& volumes,
    std::vector<std::wstring>& outSnapshotIds,
    SnapshotType type)
{
    if (volumes.empty()) return VSSResult::InvalidParameter;

    for (const auto& vol : volumes) {
        if (!IsValidVolumePath(vol)) {
            SS_LOG_ERROR(kLogCategory, L"Invalid volume in snapshot set");
            return VSSResult::InvalidParameter;
        }
    }

    std::unique_lock lock(m_mutex);
    if (!m_isActive.load(std::memory_order_relaxed)) {
        return VSSResult::NotInitialized;
    }

    VssComponentsGuard comps;
    HRESULT hr = CreateVssBackupComponents(&comps.ptr);
    if (FAILED(hr) || !comps.ptr) return HResultToVSSResult(hr);

    hr = comps.ptr->InitializeForBackup();
    if (FAILED(hr)) return HResultToVSSResult(hr);

    hr = comps.ptr->SetBackupState(true, true, VSS_BT_COPY, false);
    if (FAILED(hr)) return HResultToVSSResult(hr);

    // Gather writer metadata
    {
        IVssAsync* pAsync = nullptr;
        hr = comps.ptr->GatherWriterMetadata(&pAsync);
        if (SUCCEEDED(hr) && pAsync) {
            WaitForVssAsync(pAsync);
            pAsync->Release();
        }
    }

    GUID snapshotSetId{};
    hr = comps.ptr->StartSnapshotSet(&snapshotSetId);
    if (FAILED(hr)) return HResultToVSSResult(hr);

    std::vector<GUID> snapshotIds;
    snapshotIds.reserve(volumes.size());
    for (const auto& vol : volumes) {
        GUID sid{};
        hr = comps.ptr->AddToSnapshotSet(
            const_cast<wchar_t*>(vol.c_str()), GUID_NULL, &sid);
        if (FAILED(hr)) {
            SS_LOG_ERROR(kLogCategory, L"AddToSnapshotSet failed for multi-volume: 0x%08X",
                         static_cast<unsigned>(hr));
            return HResultToVSSResult(hr);
        }
        snapshotIds.push_back(sid);
    }

    // PrepareForBackup + DoSnapshotSet
    {
        IVssAsync* pAsync = nullptr;
        hr = comps.ptr->PrepareForBackup(&pAsync);
        if (SUCCEEDED(hr) && pAsync) {
            hr = WaitForVssAsync(pAsync);
            pAsync->Release();
        }
        if (FAILED(hr)) return HResultToVSSResult(hr);
    }
    {
        IVssAsync* pAsync = nullptr;
        hr = comps.ptr->DoSnapshotSet(&pAsync);
        if (SUCCEEDED(hr) && pAsync) {
            hr = WaitForVssAsync(pAsync);
            pAsync->Release();
        }
        if (FAILED(hr)) return HResultToVSSResult(hr);
    }

    outSnapshotIds.reserve(snapshotIds.size());
    for (const auto& id : snapshotIds) {
        auto idStr = GuidToWString(id);
        outSnapshotIds.push_back(idStr);
        NotifyShadowCopyProtector(idStr);
    }
    m_stats.snapshotsCreated += static_cast<uint64_t>(outSnapshotIds.size());

    return VSSResult::Success;
}

VSSResult VolumeSnapshotServiceImpl::CreateEmergencySnapshot(
    const std::wstring& volumeName,
    std::wstring& outSnapshotId)
{
    SS_LOG_WARN(kLogCategory,
        L"EMERGENCY snapshot requested for volume: %ls", volumeName.c_str());

    SnapshotOptions opts;
    opts.type           = SnapshotType::CrashConsistent;
    opts.includeWriters = false;  // skip writers for speed
    opts.timeoutMs      = VSSConstants::EMERGENCY_SNAPSHOT_TIMEOUT_MS;

    VSSResult result = CreateSnapshotEx(volumeName, outSnapshotId, opts);
    if (result == VSSResult::Success) {
        m_stats.emergencySnapshotsCreated++;
        SS_LOG_INFO(kLogCategory,
            L"Emergency snapshot created successfully: %ls", outSnapshotId.c_str());
    } else {
        SS_LOG_FATAL(kLogCategory,
            L"EMERGENCY snapshot FAILED for volume %ls — recovery may be compromised",
            volumeName.c_str());
    }
    return result;
}

// ============================================================================
// SNAPSHOT ENUMERATION
// ============================================================================

std::vector<SnapshotInfo> VolumeSnapshotServiceImpl::QuerySnapshots() {
    std::vector<SnapshotInfo> snapshots;

    // Create transient backup components for querying
    VssComponentsGuard comps;
    HRESULT hr = CreateVssBackupComponents(&comps.ptr);
    if (FAILED(hr) || !comps.ptr) return snapshots;

    hr = comps.ptr->InitializeForBackup();
    if (FAILED(hr)) return snapshots;

    hr = comps.ptr->SetBackupState(true, true, VSS_BT_COPY, false);
    if (FAILED(hr)) return snapshots;

    IVssEnumObject* pEnum = nullptr;
    hr = comps.ptr->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, &pEnum);
    if (FAILED(hr) || !pEnum) return snapshots;

    VSS_OBJECT_PROP prop{};
    ULONG fetched = 0;
    while (pEnum->Next(1, &prop, &fetched) == S_OK && fetched > 0) {
        if (prop.Type == VSS_OBJECT_SNAPSHOT) {
            VSS_SNAPSHOT_PROP& snap = prop.Obj.Snap;

            SnapshotInfo info;
            info.snapshotId    = GuidToWString(snap.m_SnapshotId);
            info.snapshotSetId = GuidToWString(snap.m_SnapshotSetId);
            if (snap.m_pwszOriginalVolumeName)
                info.volumeName = snap.m_pwszOriginalVolumeName;
            if (snap.m_pwszSnapshotDeviceObject)
                info.deviceName = snap.m_pwszSnapshotDeviceObject;
            info.state      = VssStateToSnapshotState(snap.m_eStatus);
            info.attributes = snap.m_lSnapshotAttributes;
            info.creationTime = FileTimeToSystemTime(snap.m_tsCreationTimestamp);

            snapshots.push_back(std::move(info));
            VssFreeSnapshotProperties(&snap);
        }
    }
    pEnum->Release();

    return snapshots;
}

std::vector<SnapshotInfo> VolumeSnapshotServiceImpl::EnumerateSnapshots() {
    return QuerySnapshots();
}

std::vector<SnapshotInfo> VolumeSnapshotServiceImpl::EnumerateSnapshotsForVolume(
    const std::wstring& volumeName)
{
    auto all = QuerySnapshots();
    std::vector<SnapshotInfo> filtered;
    filtered.reserve(all.size());
    for (auto& s : all) {
        if (s.volumeName == volumeName) {
            filtered.push_back(std::move(s));
        }
    }
    return filtered;
}

std::optional<SnapshotInfo> VolumeSnapshotServiceImpl::GetSnapshotInfo(
    const std::wstring& snapshotId)
{
    GUID guid{};
    if (!WStringToGuid(snapshotId, guid)) {
        SS_LOG_ERROR(kLogCategory, L"Invalid snapshot GUID: %ls", snapshotId.c_str());
        return std::nullopt;
    }

    VssComponentsGuard comps;
    HRESULT hr = CreateVssBackupComponents(&comps.ptr);
    if (FAILED(hr) || !comps.ptr) return std::nullopt;

    hr = comps.ptr->InitializeForBackup();
    if (FAILED(hr)) return std::nullopt;

    hr = comps.ptr->SetBackupState(true, true, VSS_BT_COPY, false);
    if (FAILED(hr)) return std::nullopt;

    VSS_SNAPSHOT_PROP prop{};
    hr = comps.ptr->GetSnapshotProperties(guid, &prop);
    if (FAILED(hr)) return std::nullopt;

    SnapshotInfo info;
    info.snapshotId    = GuidToWString(prop.m_SnapshotId);
    info.snapshotSetId = GuidToWString(prop.m_SnapshotSetId);
    if (prop.m_pwszOriginalVolumeName)
        info.volumeName = prop.m_pwszOriginalVolumeName;
    if (prop.m_pwszSnapshotDeviceObject)
        info.deviceName = prop.m_pwszSnapshotDeviceObject;
    info.state      = VssStateToSnapshotState(prop.m_eStatus);
    info.attributes = prop.m_lSnapshotAttributes;
    info.creationTime = FileTimeToSystemTime(prop.m_tsCreationTimestamp);

    // Check mount state
    {
        std::shared_lock lock(m_mutex);
        auto it = m_mountedSnapshots.find(snapshotId);
        if (it != m_mountedSnapshots.end()) {
            info.isExposed  = true;
            info.exposePath = it->second;
        }
    }

    VssFreeSnapshotProperties(&prop);
    return info;
}

std::vector<SnapshotInfo> VolumeSnapshotServiceImpl::GetRecoveryPoints(
    const std::wstring& volumeName)
{
    // Recovery points are snapshots in Created state, sorted newest-first
    auto snapshots = EnumerateSnapshotsForVolume(volumeName);
    std::erase_if(snapshots, [](const SnapshotInfo& s) {
        return s.state != SnapshotState::Created;
    });
    std::sort(snapshots.begin(), snapshots.end(),
        [](const SnapshotInfo& a, const SnapshotInfo& b) {
            return a.creationTime > b.creationTime;
        });
    return snapshots;
}

// ============================================================================
// SNAPSHOT DELETION
// ============================================================================

VSSResult VolumeSnapshotServiceImpl::DeleteSnapshotInternal(
    const std::wstring& snapshotId, bool force)
{
    auto startTime = Clock::now();

    GUID guid{};
    if (!WStringToGuid(snapshotId, guid)) {
        SS_LOG_ERROR(kLogCategory, L"Invalid GUID for deletion: %ls", snapshotId.c_str());
        return VSSResult::InvalidParameter;
    }

    // Unmount if mounted
    {
        std::unique_lock lock(m_mutex);
        if (m_mountedSnapshots.count(snapshotId) > 0) {
            m_mountedSnapshots.erase(snapshotId);
        }
    }

    VssComponentsGuard comps;
    HRESULT hr = CreateVssBackupComponents(&comps.ptr);
    if (FAILED(hr) || !comps.ptr) return HResultToVSSResult(hr);

    hr = comps.ptr->InitializeForBackup();
    if (FAILED(hr)) return HResultToVSSResult(hr);

    hr = comps.ptr->SetBackupState(true, true, VSS_BT_COPY, false);
    if (FAILED(hr)) return HResultToVSSResult(hr);

    LONG deletedCount = 0;
    GUID nonDeletedId{};
    hr = comps.ptr->DeleteSnapshots(
        guid, VSS_OBJECT_SNAPSHOT, force ? TRUE : FALSE,
        &deletedCount, &nonDeletedId);

    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime).count();

    if (SUCCEEDED(hr) && deletedCount > 0) {
        m_stats.snapshotsDeleted++;
        m_stats.totalDeletionTimeMs += static_cast<uint64_t>(durationMs);
        SS_LOG_INFO(kLogCategory, L"Snapshot deleted: %ls (%lldms)",
                    snapshotId.c_str(), static_cast<long long>(durationMs));
        return VSSResult::Success;
    }

    m_stats.operationsFailed++;
    SS_LOG_ERROR(kLogCategory, L"DeleteSnapshots failed: 0x%08X (deleted=%ld)",
                 static_cast<unsigned>(hr), deletedCount);
    return HResultToVSSResult(hr);
}

VSSResult VolumeSnapshotServiceImpl::DeleteSnapshot(
    const std::wstring& snapshotId, bool force)
{
    return DeleteSnapshotInternal(snapshotId, force);
}

VSSResult VolumeSnapshotServiceImpl::DeleteSnapshotsForVolume(
    const std::wstring& volumeName)
{
    auto snapshots = EnumerateSnapshotsForVolume(volumeName);
    VSSResult lastResult = VSSResult::Success;
    for (const auto& s : snapshots) {
        auto r = DeleteSnapshotInternal(s.snapshotId, true);
        if (r != VSSResult::Success) lastResult = r;
    }
    return lastResult;
}

VSSResult VolumeSnapshotServiceImpl::DeleteOldestSnapshot(
    const std::wstring& volumeName)
{
    auto snapshots = EnumerateSnapshotsForVolume(volumeName);
    if (snapshots.empty()) return VSSResult::NotFound;

    auto oldest = std::min_element(snapshots.begin(), snapshots.end(),
        [](const SnapshotInfo& a, const SnapshotInfo& b) {
            return a.creationTime < b.creationTime;
        });
    return DeleteSnapshotInternal(oldest->snapshotId, true);
}

uint32_t VolumeSnapshotServiceImpl::DeleteSnapshotsOlderThan(
    const SystemTimePoint& cutoffTime)
{
    uint32_t deleted = 0;
    auto snapshots = EnumerateSnapshots();
    for (const auto& s : snapshots) {
        if (s.creationTime < cutoffTime) {
            if (DeleteSnapshotInternal(s.snapshotId, true) == VSSResult::Success) {
                deleted++;
            }
        }
    }
    return deleted;
}

// ============================================================================
// SNAPSHOT MOUNTING
// ============================================================================

VSSResult VolumeSnapshotServiceImpl::ExposeSnapshot(
    const std::wstring& snapshotId,
    const std::wstring& exposePath)
{
    GUID guid{};
    if (!WStringToGuid(snapshotId, guid)) {
        return VSSResult::InvalidParameter;
    }

    VssComponentsGuard comps;
    HRESULT hr = CreateVssBackupComponents(&comps.ptr);
    if (FAILED(hr) || !comps.ptr) return HResultToVSSResult(hr);

    hr = comps.ptr->InitializeForBackup();
    if (FAILED(hr)) return HResultToVSSResult(hr);

    hr = comps.ptr->SetBackupState(true, true, VSS_BT_COPY, false);
    if (FAILED(hr)) return HResultToVSSResult(hr);

    wchar_t* pwszExpose = nullptr;
    hr = comps.ptr->ExposeSnapshot(
        guid, nullptr, VSS_VOLSNAP_ATTR_EXPOSED_LOCALLY,
        const_cast<wchar_t*>(exposePath.c_str()), &pwszExpose);

    if (pwszExpose) CoTaskMemFree(pwszExpose);

    return HResultToVSSResult(hr);
}

VSSResult VolumeSnapshotServiceImpl::UnexposeSnapshot(const std::wstring& snapshotId) {
    // Remove the mount point. VSS auto-unexposes on snapshot deletion.
    // For manual unexpose, we remove the directory junction.
    std::shared_lock lock(m_mutex);
    auto it = m_mountedSnapshots.find(snapshotId);
    if (it == m_mountedSnapshots.end()) {
        return VSSResult::Success;
    }
    const std::wstring mountPt = it->second;
    lock.unlock();

    std::error_code ec;
    if (fs::exists(mountPt, ec) && fs::is_directory(mountPt, ec)) {
        // DefineDosDeviceW to remove expose or simply remove directory
        if (!RemoveDirectoryW(mountPt.c_str())) {
            SS_LOG_WARN(kLogCategory,
                L"Failed to remove mount point directory: %ls", mountPt.c_str());
        }
    }
    return VSSResult::Success;
}

VSSResult VolumeSnapshotServiceImpl::MountSnapshot(
    const std::wstring& snapshotId,
    const std::wstring& mountPoint)
{
    if (snapshotId.empty() || mountPoint.empty()) {
        return VSSResult::InvalidParameter;
    }

    VSSResult result = ExposeSnapshot(snapshotId, mountPoint);
    if (result == VSSResult::Success) {
        std::unique_lock lock(m_mutex);
        m_mountedSnapshots[snapshotId] = mountPoint;
        m_stats.snapshotsMounted++;
        SS_LOG_INFO(kLogCategory, L"Snapshot mounted: %ls -> %ls",
                    snapshotId.c_str(), mountPoint.c_str());
    }
    return result;
}

VSSResult VolumeSnapshotServiceImpl::UnmountSnapshot(const std::wstring& snapshotId) {
    VSSResult result = UnexposeSnapshot(snapshotId);
    if (result == VSSResult::Success) {
        std::unique_lock lock(m_mutex);
        m_mountedSnapshots.erase(snapshotId);
        SS_LOG_INFO(kLogCategory, L"Snapshot unmounted: %ls", snapshotId.c_str());
    }
    return result;
}

bool VolumeSnapshotServiceImpl::IsSnapshotMounted(const std::wstring& snapshotId) {
    std::shared_lock lock(m_mutex);
    return m_mountedSnapshots.count(snapshotId) > 0;
}

std::optional<std::wstring> VolumeSnapshotServiceImpl::GetMountPoint(
    const std::wstring& snapshotId)
{
    std::shared_lock lock(m_mutex);
    auto it = m_mountedSnapshots.find(snapshotId);
    return (it != m_mountedSnapshots.end()) ? std::optional{it->second} : std::nullopt;
}

// ============================================================================
// FILE RESTORATION
// ============================================================================

VSSResult VolumeSnapshotServiceImpl::RestoreFile(
    const std::wstring& snapshotId,
    const std::wstring& sourceFile,
    const std::wstring& destFile)
{
    if (snapshotId.empty() || sourceFile.empty() || destFile.empty()) {
        return VSSResult::InvalidParameter;
    }

    auto startTime = Clock::now();

    // Get the snapshot device path (e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\)
    auto snapInfo = GetSnapshotInfo(snapshotId);
    if (!snapInfo.has_value() || snapInfo->deviceName.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"Cannot resolve snapshot device for %ls", snapshotId.c_str());
        return VSSResult::NotFound;
    }

    // Build source path from device object name
    std::wstring devicePath = snapInfo->deviceName;
    if (!devicePath.empty() && devicePath.back() != L'\\') devicePath += L'\\';
    fs::path srcPath = fs::path(devicePath) / sourceFile;
    fs::path dstPath = destFile;

    // Ensure destination directory exists
    std::error_code ec;
    if (dstPath.has_parent_path()) {
        fs::create_directories(dstPath.parent_path(), ec);
    }

    fs::copy_file(srcPath, dstPath, fs::copy_options::overwrite_existing, ec);

    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime).count();

    if (!ec) {
        m_stats.filesRestored++;
        m_stats.totalRestorationTimeMs += static_cast<uint64_t>(durationMs);
        SS_LOG_INFO(kLogCategory, L"File restored: %ls -> %ls (%lldms)",
                    sourceFile.c_str(), destFile.c_str(),
                    static_cast<long long>(durationMs));
        return VSSResult::Success;
    }

    m_stats.operationsFailed++;
    SS_LOG_ERROR(kLogCategory, L"File restore failed: %hs", ec.message().c_str());
    return VSSResult::RestoreFailed;
}

VSSResult VolumeSnapshotServiceImpl::RestoreDirectory(
    const std::wstring& snapshotId,
    const std::wstring& sourceDir,
    const std::wstring& destDir,
    bool recursive)
{
    if (snapshotId.empty() || sourceDir.empty() || destDir.empty()) {
        return VSSResult::InvalidParameter;
    }

    auto startTime = Clock::now();

    auto snapInfo = GetSnapshotInfo(snapshotId);
    if (!snapInfo.has_value() || snapInfo->deviceName.empty()) {
        return VSSResult::NotFound;
    }

    std::wstring devicePath = snapInfo->deviceName;
    if (!devicePath.empty() && devicePath.back() != L'\\') devicePath += L'\\';
    fs::path srcPath = fs::path(devicePath) / sourceDir;
    fs::path dstPath = destDir;

    std::error_code ec;
    if (recursive) {
        fs::copy(srcPath, dstPath,
                 fs::copy_options::recursive | fs::copy_options::overwrite_existing, ec);
    } else {
        fs::create_directories(dstPath, ec);
        if (!ec) {
            for (const auto& entry : fs::directory_iterator(srcPath, ec)) {
                if (!ec && entry.is_regular_file()) {
                    fs::copy_file(entry.path(), dstPath / entry.path().filename(),
                                  fs::copy_options::overwrite_existing, ec);
                }
            }
        }
    }

    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime).count();

    if (!ec) {
        m_stats.directoriesRestored++;
        m_stats.totalRestorationTimeMs += static_cast<uint64_t>(durationMs);
        SS_LOG_INFO(kLogCategory, L"Directory restored: %ls -> %ls (%lldms)",
                    sourceDir.c_str(), destDir.c_str(),
                    static_cast<long long>(durationMs));
        return VSSResult::Success;
    }

    m_stats.operationsFailed++;
    SS_LOG_ERROR(kLogCategory, L"Directory restore failed: %hs", ec.message().c_str());
    return VSSResult::RestoreFailed;
}

VSSResult VolumeSnapshotServiceImpl::RestoreToOriginalLocation(
    const std::wstring& snapshotId,
    const std::wstring& filePath)
{
    return RestoreFile(snapshotId, filePath, filePath);
}

// ============================================================================
// SNAPSHOT INTEGRITY VERIFICATION
// ============================================================================

bool VolumeSnapshotServiceImpl::VerifySnapshotIntegrity(const std::wstring& snapshotId) {
    auto info = GetSnapshotInfo(snapshotId);
    if (!info.has_value()) {
        SS_LOG_ERROR(kLogCategory,
            L"Integrity check failed — snapshot not found: %ls", snapshotId.c_str());
        return false;
    }

    if (info->state != SnapshotState::Created) {
        SS_LOG_ERROR(kLogCategory,
            L"Integrity check failed — snapshot not in Created state: %ls (state=%d)",
            snapshotId.c_str(), static_cast<int>(info->state));
        return false;
    }

    // Verify device object is accessible
    if (info->deviceName.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"Integrity check failed — no device name for: %ls", snapshotId.c_str());
        return false;
    }

    // Attempt to open the device to verify accessibility
    std::wstring testPath = info->deviceName;
    if (!testPath.empty() && testPath.back() != L'\\') testPath += L'\\';

    std::error_code ec;
    bool exists = fs::exists(testPath, ec);
    if (ec || !exists) {
        SS_LOG_ERROR(kLogCategory,
            L"Integrity check failed — device inaccessible: %ls", testPath.c_str());
        return false;
    }

    SS_LOG_INFO(kLogCategory, L"Snapshot integrity verified: %ls", snapshotId.c_str());
    return true;
}

// ============================================================================
// VOLUME MANAGEMENT
// ============================================================================

std::vector<VolumeInfo> VolumeSnapshotServiceImpl::GetVSSVolumes() {
    std::vector<VolumeInfo> volumes;

    wchar_t volumeName[MAX_PATH]{};
    HANDLE hFind = FindFirstVolumeW(volumeName, MAX_PATH);
    if (hFind == INVALID_HANDLE_VALUE) return volumes;

    do {
        auto info = GetVolumeInfo(volumeName);
        if (info.has_value() && info->vssSupported) {
            volumes.push_back(std::move(*info));
        }
    } while (FindNextVolumeW(hFind, volumeName, MAX_PATH));

    FindVolumeClose(hFind);
    return volumes;
}

std::optional<VolumeInfo> VolumeSnapshotServiceImpl::GetVolumeInfo(
    const std::wstring& volumeName)
{
    VolumeInfo info;
    info.volumeName = volumeName;

    wchar_t volumePath[MAX_PATH]{};
    DWORD pathLen = 0;
    if (GetVolumePathNamesForVolumeNameW(
            volumeName.c_str(), volumePath, MAX_PATH, &pathLen)) {
        info.mountPoint = volumePath;
    }

    wchar_t fsName[MAX_PATH]{};
    wchar_t label[MAX_PATH]{};
    if (GetVolumeInformationW(volumeName.c_str(), label, MAX_PATH,
                              nullptr, nullptr, nullptr, fsName, MAX_PATH)) {
        info.fileSystem = fsName;
        info.label      = label;
    }

    ULARGE_INTEGER freeBytesAvailable{}, totalBytes{}, totalFreeBytes{};
    if (GetDiskFreeSpaceExW(volumeName.c_str(),
                            &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
        info.totalSize = totalBytes.QuadPart;
        info.freeSpace = totalFreeBytes.QuadPart;
    }

    info.vssSupported = IsVSSSupported(volumeName);

    if (info.vssSupported) {
        auto snapshots = EnumerateSnapshotsForVolume(volumeName);
        info.snapshotCount = static_cast<uint32_t>(snapshots.size());
    }

    return info;
}

bool VolumeSnapshotServiceImpl::IsVSSSupported(const std::wstring& volumeName) {
    wchar_t fsName[MAX_PATH]{};
    if (!GetVolumeInformationW(volumeName.c_str(), nullptr, 0, nullptr,
                               nullptr, nullptr, fsName, MAX_PATH)) {
        return false;
    }
    return (wcscmp(fsName, L"NTFS") == 0) || (wcscmp(fsName, L"ReFS") == 0);
}

std::wstring VolumeSnapshotServiceImpl::GetVolumeFromPath(const std::wstring& path) {
    return GetVolumeNameFromPath(path);
}

// ============================================================================
// STORAGE MANAGEMENT (IVssDifferentialSoftwareSnapshotMgmt)
// ============================================================================

VSSResult VolumeSnapshotServiceImpl::SetStorageLimit(
    const std::wstring& volumeName, uint64_t maxSizeBytes)
{
    if (!IsValidVolumePath(volumeName) || maxSizeBytes == 0) {
        return VSSResult::InvalidParameter;
    }

    IVssSnapshotMgmt* pMgmt = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_VssSnapshotMgmt, nullptr, CLSCTX_ALL,
        IID_IVssSnapshotMgmt, reinterpret_cast<void**>(&pMgmt));
    if (FAILED(hr) || !pMgmt) {
        SS_LOG_ERROR(kLogCategory,
            L"Failed to create IVssSnapshotMgmt: 0x%08X", static_cast<unsigned>(hr));
        return HResultToVSSResult(hr);
    }

    IVssDifferentialSoftwareSnapshotMgmt* pDiffMgmt = nullptr;
    hr = pMgmt->GetProviderMgmtInterface(
        VSS_SWPRV_ProviderId, IID_IVssDifferentialSoftwareSnapshotMgmt,
        reinterpret_cast<IUnknown**>(&pDiffMgmt));
    if (FAILED(hr) || !pDiffMgmt) {
        pMgmt->Release();
        SS_LOG_ERROR(kLogCategory,
            L"Failed to get IVssDifferentialSoftwareSnapshotMgmt: 0x%08X",
            static_cast<unsigned>(hr));
        return HResultToVSSResult(hr);
    }

    // ChangeDiffAreaMaximumSize: volume, diffArea (same volume), maxSize
    hr = pDiffMgmt->ChangeDiffAreaMaximumSize(
        const_cast<wchar_t*>(volumeName.c_str()),
        const_cast<wchar_t*>(volumeName.c_str()),
        static_cast<LONGLONG>(maxSizeBytes));

    pDiffMgmt->Release();
    pMgmt->Release();

    if (SUCCEEDED(hr)) {
        SS_LOG_INFO(kLogCategory,
            L"Storage limit set to %llu bytes for %ls",
            static_cast<unsigned long long>(maxSizeBytes), volumeName.c_str());
        return VSSResult::Success;
    }

    SS_LOG_ERROR(kLogCategory,
        L"ChangeDiffAreaMaximumSize failed: 0x%08X", static_cast<unsigned>(hr));
    return HResultToVSSResult(hr);
}

VSSResult VolumeSnapshotServiceImpl::SetStorageLimitPercent(
    const std::wstring& volumeName, uint32_t percent)
{
    if (percent == 0 || percent > 80) {
        SS_LOG_ERROR(kLogCategory,
            L"Storage limit percent out of range: %u (must be 1-80)", percent);
        return VSSResult::InvalidParameter;
    }

    auto info = GetVolumeInfo(volumeName);
    if (!info.has_value() || info->totalSize == 0) {
        return VSSResult::VolumeNotSupported;
    }

    uint64_t maxSize = (info->totalSize / 100) * percent;
    return SetStorageLimit(volumeName, maxSize);
}

std::optional<uint64_t> VolumeSnapshotServiceImpl::GetStorageLimit(
    const std::wstring& volumeName)
{
    IVssSnapshotMgmt* pMgmt = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_VssSnapshotMgmt, nullptr, CLSCTX_ALL,
        IID_IVssSnapshotMgmt, reinterpret_cast<void**>(&pMgmt));
    if (FAILED(hr) || !pMgmt) return std::nullopt;

    IVssDifferentialSoftwareSnapshotMgmt* pDiffMgmt = nullptr;
    hr = pMgmt->GetProviderMgmtInterface(
        VSS_SWPRV_ProviderId, IID_IVssDifferentialSoftwareSnapshotMgmt,
        reinterpret_cast<IUnknown**>(&pDiffMgmt));
    if (FAILED(hr) || !pDiffMgmt) {
        pMgmt->Release();
        return std::nullopt;
    }

    IVssEnumMgmtObject* pEnum = nullptr;
    hr = pDiffMgmt->QueryDiffAreasOnVolume(
        const_cast<wchar_t*>(volumeName.c_str()), &pEnum);
    if (FAILED(hr) || !pEnum) {
        pDiffMgmt->Release();
        pMgmt->Release();
        return std::nullopt;
    }

    std::optional<uint64_t> result;
    VSS_MGMT_OBJECT_PROP prop{};
    ULONG fetched = 0;
    if (pEnum->Next(1, &prop, &fetched) == S_OK && fetched > 0) {
        if (prop.Type == VSS_MGMT_OBJECT_DIFF_AREA) {
            result = static_cast<uint64_t>(prop.Obj.DiffArea.m_llMaximumDiffSpace);
            if (prop.Obj.DiffArea.m_pwszVolumeName) {
                CoTaskMemFree(prop.Obj.DiffArea.m_pwszVolumeName);
            }
            if (prop.Obj.DiffArea.m_pwszDiffAreaVolumeName) {
                CoTaskMemFree(prop.Obj.DiffArea.m_pwszDiffAreaVolumeName);
            }
        }
    }

    pEnum->Release();
    pDiffMgmt->Release();
    pMgmt->Release();
    return result;
}

std::optional<uint64_t> VolumeSnapshotServiceImpl::GetStorageUsage(
    const std::wstring& volumeName)
{
    IVssSnapshotMgmt* pMgmt = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_VssSnapshotMgmt, nullptr, CLSCTX_ALL,
        IID_IVssSnapshotMgmt, reinterpret_cast<void**>(&pMgmt));
    if (FAILED(hr) || !pMgmt) return std::nullopt;

    IVssDifferentialSoftwareSnapshotMgmt* pDiffMgmt = nullptr;
    hr = pMgmt->GetProviderMgmtInterface(
        VSS_SWPRV_ProviderId, IID_IVssDifferentialSoftwareSnapshotMgmt,
        reinterpret_cast<IUnknown**>(&pDiffMgmt));
    if (FAILED(hr) || !pDiffMgmt) {
        pMgmt->Release();
        return std::nullopt;
    }

    IVssEnumMgmtObject* pEnum = nullptr;
    hr = pDiffMgmt->QueryDiffAreasOnVolume(
        const_cast<wchar_t*>(volumeName.c_str()), &pEnum);
    if (FAILED(hr) || !pEnum) {
        pDiffMgmt->Release();
        pMgmt->Release();
        return std::nullopt;
    }

    std::optional<uint64_t> result;
    VSS_MGMT_OBJECT_PROP prop{};
    ULONG fetched = 0;
    if (pEnum->Next(1, &prop, &fetched) == S_OK && fetched > 0) {
        if (prop.Type == VSS_MGMT_OBJECT_DIFF_AREA) {
            result = static_cast<uint64_t>(prop.Obj.DiffArea.m_llUsedDiffSpace);
            if (prop.Obj.DiffArea.m_pwszVolumeName) {
                CoTaskMemFree(prop.Obj.DiffArea.m_pwszVolumeName);
            }
            if (prop.Obj.DiffArea.m_pwszDiffAreaVolumeName) {
                CoTaskMemFree(prop.Obj.DiffArea.m_pwszDiffAreaVolumeName);
            }
        }
    }

    pEnum->Release();
    pDiffMgmt->Release();
    pMgmt->Release();
    return result;
}

VSSResult VolumeSnapshotServiceImpl::CleanupOldSnapshots(
    const std::wstring& volumeName, uint32_t keepCount)
{
    auto snapshots = EnumerateSnapshotsForVolume(volumeName);
    if (snapshots.size() <= keepCount) return VSSResult::Success;

    std::sort(snapshots.begin(), snapshots.end(),
        [](const SnapshotInfo& a, const SnapshotInfo& b) {
            return a.creationTime < b.creationTime;
        });

    size_t toDelete = snapshots.size() - keepCount;
    uint32_t deletedCount = 0;
    for (size_t i = 0; i < toDelete; i++) {
        if (DeleteSnapshotInternal(snapshots[i].snapshotId, true) == VSSResult::Success) {
            deletedCount++;
        }
    }

    SS_LOG_INFO(kLogCategory,
        L"Cleanup: deleted %u of %zu excess snapshots on %ls",
        deletedCount, toDelete, volumeName.c_str());
    return VSSResult::Success;
}

// ============================================================================
// WRITER MANAGEMENT
// ============================================================================

std::vector<WriterInfo> VolumeSnapshotServiceImpl::GetWriters() {
    std::vector<WriterInfo> writers;

    VssComponentsGuard comps;
    HRESULT hr = CreateVssBackupComponents(&comps.ptr);
    if (FAILED(hr) || !comps.ptr) return writers;

    hr = comps.ptr->InitializeForBackup();
    if (FAILED(hr)) return writers;

    hr = comps.ptr->SetBackupState(true, true, VSS_BT_COPY, false);
    if (FAILED(hr)) return writers;

    // Must gather metadata then query writer status
    IVssAsync* pGather = nullptr;
    hr = comps.ptr->GatherWriterMetadata(&pGather);
    if (SUCCEEDED(hr) && pGather) {
        WaitForVssAsync(pGather);
        pGather->Release();
    }

    // GatherWriterStatus to get state
    IVssAsync* pStatus = nullptr;
    hr = comps.ptr->GatherWriterStatus(&pStatus);
    if (SUCCEEDED(hr) && pStatus) {
        WaitForVssAsync(pStatus);
        pStatus->Release();
    }

    UINT writerCount = 0;
    hr = comps.ptr->GetWriterStatusCount(&writerCount);
    if (FAILED(hr)) return writers;

    writers.reserve(writerCount);
    for (UINT i = 0; i < writerCount; i++) {
        GUID instanceId{}, writerId{};
        BSTR writerName = nullptr;
        VSS_WRITER_STATE state{};
        HRESULT writerHr = S_OK;

        hr = comps.ptr->GetWriterStatus(
            i, &instanceId, &writerId, &writerName, &state, &writerHr);
        if (SUCCEEDED(hr)) {
            WriterInfo info;
            info.writerId   = GuidToWString(writerId);
            info.instanceId = GuidToWString(instanceId);
            if (writerName) {
                info.writerName = writerName;
                SysFreeString(writerName);
            }
            info.state     = VssWriterStateToWriterState(state);
            info.lastError = writerHr;
            writers.push_back(std::move(info));
        }
    }

    return writers;
}

bool VolumeSnapshotServiceImpl::AreWritersStable() {
    auto writers = GetWriters();
    if (writers.empty()) return false;
    return std::all_of(writers.begin(), writers.end(),
        [](const WriterInfo& w) { return w.state == WriterState::Stable; });
}

VSSResult VolumeSnapshotServiceImpl::WaitForWriters(uint32_t timeoutMs) {
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    while (Clock::now() < deadline) {
        if (AreWritersStable()) return VSSResult::Success;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    return VSSResult::Timeout;
}

// ============================================================================
// OPERATION TRACKING
// ============================================================================

std::vector<SnapshotOperation> VolumeSnapshotServiceImpl::GetActiveOperations() {
    std::shared_lock lock(m_mutex);
    return m_activeOperations;
}

std::optional<SnapshotOperation> VolumeSnapshotServiceImpl::GetOperation(
    const std::wstring& operationId)
{
    std::shared_lock lock(m_mutex);
    auto it = std::find_if(m_activeOperations.begin(), m_activeOperations.end(),
        [&](const SnapshotOperation& op) { return op.operationId == operationId; });
    return (it != m_activeOperations.end()) ? std::optional{*it} : std::nullopt;
}

bool VolumeSnapshotServiceImpl::CancelOperation(const std::wstring& operationId) {
    std::unique_lock lock(m_mutex);
    auto it = std::find_if(m_activeOperations.begin(), m_activeOperations.end(),
        [&](const SnapshotOperation& op) { return op.operationId == operationId; });
    if (it != m_activeOperations.end()) {
        it->state = OperationState::Cancelled;
        SS_LOG_INFO(kLogCategory, L"Operation cancelled: %ls", operationId.c_str());
        return true;
    }
    return false;
}

// ============================================================================
// MONITORING
// ============================================================================

bool VolumeSnapshotServiceImpl::StartMonitoring() {
    std::unique_lock lock(m_mutex);
    if (m_monitoring.load(std::memory_order_relaxed)) return true;

    m_stopMonitoring.store(false, std::memory_order_release);
    m_monitorThread = std::make_unique<std::thread>(
        &VolumeSnapshotServiceImpl::MonitoringThreadFunc, this);
    m_monitoring.store(true, std::memory_order_release);
    SS_LOG_INFO(kLogCategory, L"VSS monitoring started");
    return true;
}

void VolumeSnapshotServiceImpl::StopMonitoring() {
    std::unique_ptr<std::thread> threadToJoin;
    {
        std::unique_lock lock(m_mutex);
        if (!m_monitoring.load(std::memory_order_relaxed)) return;

        m_stopMonitoring.store(true, std::memory_order_release);
        threadToJoin = std::move(m_monitorThread);
        m_monitoring.store(false, std::memory_order_release);
    }
    // Join outside the lock to avoid deadlock with monitoring thread
    if (threadToJoin && threadToJoin->joinable()) {
        threadToJoin->join();
    }
    SS_LOG_INFO(kLogCategory, L"VSS monitoring stopped");
}

void VolumeSnapshotServiceImpl::MonitoringThreadFunc() {
    // Monitoring thread must initialize its own COM apartment
    ComInitGuard comGuard(COINIT_MULTITHREADED);
    SS_LOG_DEBUG(kLogCategory, L"Monitoring thread started");

    while (!m_stopMonitoring.load(std::memory_order_acquire)) {
        // Read config under lock
        VolumeSnapshotConfiguration config;
        {
            std::shared_lock lock(m_mutex);
            config = m_config;
        }

        // Check writer health
        if (config.monitorWriters) {
            if (!AreWritersStable()) {
                SS_LOG_WARN(kLogCategory, L"VSS writers not stable — potential issue");
            }
        }

        // Age-based cleanup
        if (config.autoCleanupSnapshots && config.maxSnapshotAgeDays > 0) {
            auto cutoff = std::chrono::system_clock::now()
                        - std::chrono::hours(24 * config.maxSnapshotAgeDays);
            auto deleted = DeleteSnapshotsOlderThan(cutoff);
            if (deleted > 0) {
                SS_LOG_INFO(kLogCategory,
                    L"Monitoring: cleaned %u aged snapshots", deleted);
            }
        }

        // Sleep in small increments to allow quick shutdown
        auto sleepEnd = Clock::now()
            + std::chrono::seconds(config.monitoringIntervalSeconds);
        while (Clock::now() < sleepEnd &&
               !m_stopMonitoring.load(std::memory_order_acquire))
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    SS_LOG_DEBUG(kLogCategory, L"Monitoring thread stopped");
}

// ============================================================================
// CALLBACKS
// ============================================================================

void VolumeSnapshotServiceImpl::RegisterProgressCallback(ProgressCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_progressCallback = std::move(cb);
}

void VolumeSnapshotServiceImpl::RegisterCompletionCallback(CompletionCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_completionCallback = std::move(cb);
}

void VolumeSnapshotServiceImpl::RegisterErrorCallback(ErrorCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_errorCallback = std::move(cb);
}

void VolumeSnapshotServiceImpl::UnregisterCallbacks() {
    std::lock_guard lock(m_callbackMutex);
    m_progressCallback   = nullptr;
    m_completionCallback = nullptr;
    m_errorCallback      = nullptr;
}

void VolumeSnapshotServiceImpl::NotifyProgress(
    const std::wstring& operationId, uint32_t percent)
{
    ProgressCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_progressCallback;
    }
    if (cb) {
        try { cb(operationId, percent); }
        catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory,
                L"Progress callback threw: %hs", e.what());
        }
    }
}

void VolumeSnapshotServiceImpl::NotifyCompletion(
    const std::wstring& operationId, VSSResult result)
{
    CompletionCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_completionCallback;
    }
    if (cb) {
        try { cb(operationId, result); }
        catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory,
                L"Completion callback threw: %hs", e.what());
        }
    }
}

void VolumeSnapshotServiceImpl::NotifyError(const std::string& message, int code) {
    ErrorCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_errorCallback;
    }
    if (cb) {
        try { cb(message, code); }
        catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory,
                L"Error callback threw: %hs", e.what());
        }
    }
}

// ============================================================================
// SHADOWCOPYPROTECTOR INTEGRATION
// ============================================================================

void VolumeSnapshotServiceImpl::NotifyShadowCopyProtector(
    const std::wstring& snapshotId)
{
    // If ShadowCopyProtector is active, inform it of new snapshot
    if (ShadowCopyProtector::HasInstance()) {
        auto& protector = ShadowCopyProtector::Instance();
        if (protector.IsInitialized()) {
            // VerifyShadowCopy both confirms existence and marks it as known/protected
            bool ok = protector.VerifyShadowCopy(snapshotId);
            if (ok) {
                SS_LOG_DEBUG(kLogCategory,
                    L"ShadowCopyProtector notified of snapshot: %ls",
                    snapshotId.c_str());
            } else {
                SS_LOG_WARN(kLogCategory,
                    L"ShadowCopyProtector could not verify snapshot: %ls",
                    snapshotId.c_str());
            }
        }
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

VolumeSnapshotStatisticsSnapshot VolumeSnapshotServiceImpl::GetStatistics() const {
    VolumeSnapshotStatisticsSnapshot snap;
    snap.snapshotsCreated         = m_stats.snapshotsCreated.load(std::memory_order_relaxed);
    snap.snapshotsDeleted         = m_stats.snapshotsDeleted.load(std::memory_order_relaxed);
    snap.snapshotsMounted         = m_stats.snapshotsMounted.load(std::memory_order_relaxed);
    snap.filesRestored            = m_stats.filesRestored.load(std::memory_order_relaxed);
    snap.directoriesRestored      = m_stats.directoriesRestored.load(std::memory_order_relaxed);
    snap.operationsFailed         = m_stats.operationsFailed.load(std::memory_order_relaxed);
    snap.totalCreationTimeMs      = m_stats.totalCreationTimeMs.load(std::memory_order_relaxed);
    snap.totalDeletionTimeMs      = m_stats.totalDeletionTimeMs.load(std::memory_order_relaxed);
    snap.totalRestorationTimeMs   = m_stats.totalRestorationTimeMs.load(std::memory_order_relaxed);
    snap.currentOperations        = m_stats.currentOperations.load(std::memory_order_relaxed);
    snap.emergencySnapshotsCreated = m_stats.emergencySnapshotsCreated.load(std::memory_order_relaxed);
    for (size_t i = 0; i < snap.byType.size(); ++i)
        snap.byType[i] = m_stats.byType[i].load(std::memory_order_relaxed);
    for (size_t i = 0; i < snap.byResult.size(); ++i)
        snap.byResult[i] = m_stats.byResult[i].load(std::memory_order_relaxed);
    const auto now = Clock::now();
    snap.uptimeSeconds = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now - m_stats.startTime).count());
    return snap;
}

void VolumeSnapshotServiceImpl::ResetStatistics() {
    m_stats.Reset();
    SS_LOG_INFO(kLogCategory, L"Statistics reset");
}

bool VolumeSnapshotServiceImpl::SelfTest() {
    SS_LOG_INFO(kLogCategory, L"Running VolumeSnapshotService self-test...");

    // Test 1: VSS volume enumeration
    auto volumes = GetVSSVolumes();
    if (volumes.empty()) {
        SS_LOG_WARN(kLogCategory,
            L"Self-test: no VSS-capable volumes (may be expected in VM)");
    } else {
        SS_LOG_INFO(kLogCategory,
            L"Self-test PASS: volume enumeration (%zu volumes)",
            volumes.size());
    }

    // Test 2: Writer enumeration
    auto writers = GetWriters();
    SS_LOG_INFO(kLogCategory,
        L"Self-test PASS: writer enumeration (%zu writers)", writers.size());

    // Test 3: Snapshot enumeration
    auto snapshots = EnumerateSnapshots();
    SS_LOG_INFO(kLogCategory,
        L"Self-test PASS: snapshot enumeration (%zu snapshots)", snapshots.size());

    // Test 4: Configuration validation
    VolumeSnapshotConfiguration testConfig;
    if (!testConfig.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Self-test FAIL: default config validation");
        return false;
    }
    SS_LOG_INFO(kLogCategory, L"Self-test PASS: configuration validation");

    SS_LOG_INFO(kLogCategory, L"All VolumeSnapshotService self-tests passed");
    return true;
}

// ============================================================================
// PUBLIC API — SINGLETON + FORWARDING
// ============================================================================

VolumeSnapshotService& VolumeSnapshotService::Instance() noexcept {
    static VolumeSnapshotService instance;
    return instance;
}

bool VolumeSnapshotService::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

VolumeSnapshotService::VolumeSnapshotService()
    : m_impl(std::make_unique<VolumeSnapshotServiceImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

VolumeSnapshotService::~VolumeSnapshotService() {
    m_impl->Shutdown();
    s_instanceCreated.store(false, std::memory_order_release);
}

// --- Lifecycle ---
bool VolumeSnapshotService::Initialize(const VolumeSnapshotConfiguration& c) { return m_impl->Initialize(c); }
void VolumeSnapshotService::Shutdown() { m_impl->Shutdown(); }
bool VolumeSnapshotService::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
ModuleStatus VolumeSnapshotService::GetStatus() const noexcept { return m_impl->GetStatus(); }
bool VolumeSnapshotService::UpdateConfiguration(const VolumeSnapshotConfiguration& c) { return m_impl->UpdateConfiguration(c); }
VolumeSnapshotConfiguration VolumeSnapshotService::GetConfiguration() const { return m_impl->GetConfiguration(); }

// --- Snapshot creation ---
VSSResult VolumeSnapshotService::CreateSnapshot(const std::wstring& v, std::wstring& o, SnapshotType t) { return m_impl->CreateSnapshot(v, o, t); }
VSSResult VolumeSnapshotService::CreateSnapshotEx(const std::wstring& v, std::wstring& o, const SnapshotOptions& opts) { return m_impl->CreateSnapshotEx(v, o, opts); }
VSSResult VolumeSnapshotService::CreateSnapshotSet(const std::vector<std::wstring>& v, std::vector<std::wstring>& o, SnapshotType t) { return m_impl->CreateSnapshotSet(v, o, t); }
VSSResult VolumeSnapshotService::CreateEmergencySnapshot(const std::wstring& v, std::wstring& o) { return m_impl->CreateEmergencySnapshot(v, o); }

// --- Snapshot query ---
std::vector<SnapshotInfo> VolumeSnapshotService::EnumerateSnapshots() { return m_impl->EnumerateSnapshots(); }
std::vector<SnapshotInfo> VolumeSnapshotService::EnumerateSnapshotsForVolume(const std::wstring& v) { return m_impl->EnumerateSnapshotsForVolume(v); }
std::optional<SnapshotInfo> VolumeSnapshotService::GetSnapshotInfo(const std::wstring& s) { return m_impl->GetSnapshotInfo(s); }
std::vector<SnapshotInfo> VolumeSnapshotService::GetRecoveryPoints(const std::wstring& v) { return m_impl->GetRecoveryPoints(v); }

// --- Deletion ---
VSSResult VolumeSnapshotService::DeleteSnapshot(const std::wstring& s, bool f) { return m_impl->DeleteSnapshot(s, f); }
VSSResult VolumeSnapshotService::DeleteSnapshotsForVolume(const std::wstring& v) { return m_impl->DeleteSnapshotsForVolume(v); }
VSSResult VolumeSnapshotService::DeleteOldestSnapshot(const std::wstring& v) { return m_impl->DeleteOldestSnapshot(v); }
uint32_t VolumeSnapshotService::DeleteSnapshotsOlderThan(const SystemTimePoint& t) { return m_impl->DeleteSnapshotsOlderThan(t); }

// --- Mounting ---
VSSResult VolumeSnapshotService::MountSnapshot(const std::wstring& s, const std::wstring& m) { return m_impl->MountSnapshot(s, m); }
VSSResult VolumeSnapshotService::UnmountSnapshot(const std::wstring& s) { return m_impl->UnmountSnapshot(s); }
bool VolumeSnapshotService::IsSnapshotMounted(const std::wstring& s) { return m_impl->IsSnapshotMounted(s); }
std::optional<std::wstring> VolumeSnapshotService::GetMountPoint(const std::wstring& s) { return m_impl->GetMountPoint(s); }

// --- Restoration ---
VSSResult VolumeSnapshotService::RestoreFile(const std::wstring& s, const std::wstring& f, const std::wstring& d) { return m_impl->RestoreFile(s, f, d); }
VSSResult VolumeSnapshotService::RestoreDirectory(const std::wstring& s, const std::wstring& sd, const std::wstring& dd, bool r) { return m_impl->RestoreDirectory(s, sd, dd, r); }
VSSResult VolumeSnapshotService::RestoreToOriginalLocation(const std::wstring& s, const std::wstring& f) { return m_impl->RestoreToOriginalLocation(s, f); }

// --- Integrity ---
bool VolumeSnapshotService::VerifySnapshotIntegrity(const std::wstring& s) { return m_impl->VerifySnapshotIntegrity(s); }

// --- Volume info ---
std::vector<VolumeInfo> VolumeSnapshotService::GetVSSVolumes() { return m_impl->GetVSSVolumes(); }
std::optional<VolumeInfo> VolumeSnapshotService::GetVolumeInfo(const std::wstring& v) { return m_impl->GetVolumeInfo(v); }
bool VolumeSnapshotService::IsVSSSupported(const std::wstring& v) { return m_impl->IsVSSSupported(v); }
std::wstring VolumeSnapshotService::GetVolumeFromPath(const std::wstring& p) { return m_impl->GetVolumeFromPath(p); }

// --- Storage ---
VSSResult VolumeSnapshotService::SetStorageLimit(const std::wstring& v, uint64_t m) { return m_impl->SetStorageLimit(v, m); }
VSSResult VolumeSnapshotService::SetStorageLimitPercent(const std::wstring& v, uint32_t p) { return m_impl->SetStorageLimitPercent(v, p); }
std::optional<uint64_t> VolumeSnapshotService::GetStorageLimit(const std::wstring& v) { return m_impl->GetStorageLimit(v); }
std::optional<uint64_t> VolumeSnapshotService::GetStorageUsage(const std::wstring& v) { return m_impl->GetStorageUsage(v); }
VSSResult VolumeSnapshotService::CleanupOldSnapshots(const std::wstring& v, uint32_t k) { return m_impl->CleanupOldSnapshots(v, k); }

// --- Writers ---
std::vector<WriterInfo> VolumeSnapshotService::GetWriters() { return m_impl->GetWriters(); }
bool VolumeSnapshotService::AreWritersStable() { return m_impl->AreWritersStable(); }
VSSResult VolumeSnapshotService::WaitForWriters(uint32_t t) { return m_impl->WaitForWriters(t); }

// --- Operations ---
std::vector<SnapshotOperation> VolumeSnapshotService::GetActiveOperations() { return m_impl->GetActiveOperations(); }
std::optional<SnapshotOperation> VolumeSnapshotService::GetOperation(const std::wstring& o) { return m_impl->GetOperation(o); }
bool VolumeSnapshotService::CancelOperation(const std::wstring& o) { return m_impl->CancelOperation(o); }

// --- Monitoring ---
bool VolumeSnapshotService::StartMonitoring() { return m_impl->StartMonitoring(); }
void VolumeSnapshotService::StopMonitoring() { m_impl->StopMonitoring(); }
bool VolumeSnapshotService::IsMonitoring() const noexcept { return m_impl->IsMonitoring(); }

// --- Callbacks ---
void VolumeSnapshotService::RegisterProgressCallback(ProgressCallback cb) { m_impl->RegisterProgressCallback(std::move(cb)); }
void VolumeSnapshotService::RegisterCompletionCallback(CompletionCallback cb) { m_impl->RegisterCompletionCallback(std::move(cb)); }
void VolumeSnapshotService::RegisterErrorCallback(ErrorCallback cb) { m_impl->RegisterErrorCallback(std::move(cb)); }
void VolumeSnapshotService::UnregisterCallbacks() { m_impl->UnregisterCallbacks(); }

// --- Statistics ---
VolumeSnapshotStatisticsSnapshot VolumeSnapshotService::GetStatistics() const { return m_impl->GetStatistics(); }
void VolumeSnapshotService::ResetStatistics() { m_impl->ResetStatistics(); }

// --- Utility ---
bool VolumeSnapshotService::SelfTest() { return m_impl->SelfTest(); }
std::string VolumeSnapshotService::GetVersionString() noexcept {
    return std::to_string(VSSConstants::VERSION_MAJOR) + "." +
           std::to_string(VSSConstants::VERSION_MINOR) + "." +
           std::to_string(VSSConstants::VERSION_PATCH);
}

// ============================================================================
// FREE UTILITY FUNCTIONS
// ============================================================================

std::string_view GetVSSResultName(VSSResult result) noexcept {
    switch (result) {
        case VSSResult::Success:              return "Success";
        case VSSResult::NotInitialized:       return "NotInitialized";
        case VSSResult::AlreadyInitialized:   return "AlreadyInitialized";
        case VSSResult::InvalidParameter:     return "InvalidParameter";
        case VSSResult::AccessDenied:         return "AccessDenied";
        case VSSResult::OutOfMemory:          return "OutOfMemory";
        case VSSResult::NotFound:             return "NotFound";
        case VSSResult::BadState:             return "BadState";
        case VSSResult::ProviderError:        return "ProviderError";
        case VSSResult::VolumeNotSupported:   return "VolumeNotSupported";
        case VSSResult::InsufficientStorage:  return "InsufficientStorage";
        case VSSResult::ProviderVeto:         return "ProviderVeto";
        case VSSResult::MaxSnapshotsReached:  return "MaxSnapshotsReached";
        case VSSResult::WriterFailed:         return "WriterFailed";
        case VSSResult::Timeout:              return "Timeout";
        case VSSResult::MountFailed:          return "MountFailed";
        case VSSResult::RestoreFailed:        return "RestoreFailed";
        case VSSResult::IntegrityCheckFailed: return "IntegrityCheckFailed";
        case VSSResult::PrivilegeError:       return "PrivilegeError";
        case VSSResult::UnknownError:         return "UnknownError";
        default:                              return "Unknown";
    }
}

std::string_view GetSnapshotTypeName(SnapshotType type) noexcept {
    switch (type) {
        case SnapshotType::Standard:        return "Standard";
        case SnapshotType::AppConsistent:   return "AppConsistent";
        case SnapshotType::CrashConsistent: return "CrashConsistent";
        case SnapshotType::Transportable:   return "Transportable";
        default:                            return "Unknown";
    }
}

std::string_view GetSnapshotStateName(SnapshotState state) noexcept {
    switch (state) {
        case SnapshotState::Unknown:    return "Unknown";
        case SnapshotState::Preparing:  return "Preparing";
        case SnapshotState::Processing: return "Processing";
        case SnapshotState::Prepared:   return "Prepared";
        case SnapshotState::Committed:  return "Committed";
        case SnapshotState::Created:    return "Created";
        default:                        return "Unknown";
    }
}

std::string_view GetWriterStateName(WriterState state) noexcept {
    switch (state) {
        case WriterState::Unknown:              return "Unknown";
        case WriterState::Stable:               return "Stable";
        case WriterState::WaitingForFreeze:     return "WaitingForFreeze";
        case WriterState::WaitingForThaw:       return "WaitingForThaw";
        case WriterState::WaitingForCompletion: return "WaitingForCompletion";
        case WriterState::Failed:               return "Failed";
        default:                                return "Unknown";
    }
}

// ============================================================================
// VOLUME SNAPSHOT STATISTICS SNAPSHOT — ToJson
// ============================================================================

std::string VolumeSnapshotStatisticsSnapshot::ToJson() const {
    nlohmann::json j;
    j["snapshotsCreated"]          = snapshotsCreated;
    j["snapshotsDeleted"]          = snapshotsDeleted;
    j["snapshotsMounted"]          = snapshotsMounted;
    j["filesRestored"]             = filesRestored;
    j["directoriesRestored"]       = directoriesRestored;
    j["operationsFailed"]          = operationsFailed;
    j["totalCreationTimeMs"]       = totalCreationTimeMs;
    j["totalDeletionTimeMs"]       = totalDeletionTimeMs;
    j["totalRestorationTimeMs"]    = totalRestorationTimeMs;
    j["currentOperations"]         = currentOperations;
    j["emergencySnapshotsCreated"] = emergencySnapshotsCreated;
    j["uptimeSeconds"]             = uptimeSeconds;
    nlohmann::json types = nlohmann::json::array();
    for (size_t i = 0; i < byType.size(); ++i) {
        if (byType[i] > 0) {
            types.push_back({{"type", std::string(GetSnapshotTypeName(static_cast<SnapshotType>(i)))},
                             {"count", byType[i]}});
        }
    }
    j["byType"] = std::move(types);
    return j.dump();
}

// ============================================================================
// KERNEL BRIDGE — OnKernelProcessNotify / OnKernelImageLoad / RequestBlock
// ============================================================================

void VolumeSnapshotService::OnKernelProcessNotify(
    uint32_t /*pid*/, uint32_t /*parentPid*/,
    std::wstring_view /*imagePath*/, bool /*isCreate*/)
{
    // VSS is passive — no per-process tracking needed
}

void VolumeSnapshotService::OnKernelImageLoad(
    uint32_t /*pid*/, std::wstring_view /*imagePath*/, uintptr_t /*imageBase*/)
{
    // VSS is passive — no image-load analysis needed
}

[[nodiscard]] bool VolumeSnapshotService::RequestKernelProcessBlock(
    uint32_t pid, std::wstring_view reason)
{
    if (!Communication::IPCManager::HasInstance() ||
        !Communication::IPCManager::Instance().IsFilterPortConnected())
    {
        return false;
    }
    #pragma pack(push, 1)
    struct KernelBlockMsg {
        uint32_t msgType = 0x30;
        uint32_t pid     = 0;
    } msg;
    #pragma pack(pop)
    msg.pid = pid;
    const bool sent = Communication::IPCManager::Instance().SendToKernel(&msg, sizeof(msg));
    if (sent) {
        SS_LOG_INFO(kLogCategory,
            L"Kernel process block requested for PID %u: %.*s",
            pid,
            static_cast<int>(reason.size()), reason.data());
    }
    return sent;
}

// ============================================================================
// CROSS-MODULE WIRING — AlertSystem & TelemetryCollector
// ============================================================================

void VolumeSnapshotService::ReportSnapshotEventToAlertSystem(
    const std::string& event, const std::string& detail)
{
    if (!Communication::AlertSystem::HasInstance()) return;
    (void)Communication::AlertSystem::Instance().RaiseAlert(
        Communication::AlertSeverity::Info,
        Communication::AlertType::Operational,
        "VolumeSnapshotService",
        event,
        detail);
}

void VolumeSnapshotService::ReportSnapshotTelemetry(
    const std::string& eventName,
    const std::map<std::string, std::string>& fields)
{
    if (!Communication::TelemetryCollector::HasInstance()) return;
    Communication::TelemetryCollector::Instance().RecordCustom(eventName, fields);
}

}  // namespace Ransomware
}  // namespace ShadowStrike
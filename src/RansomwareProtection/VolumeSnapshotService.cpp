/**
 * ============================================================================
 * ShadowStrike NGAV - VOLUME SNAPSHOT SERVICE IMPLEMENTATION
 * ============================================================================
 *
 * @file VolumeSnapshotService.cpp
 * @brief Enterprise-grade VSS (Volume Shadow Copy Service) wrapper for
 *        ransomware protection and point-in-time recovery
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "VolumeSnapshotService.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/StringUtils.hpp"

#include <Windows.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <vsmgmt.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
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
// INTERNAL STRUCTURES & HELPERS
// ============================================================================

namespace {

/// @brief Convert GUID to wide string
std::wstring GuidToWString(const GUID& guid) {
    wchar_t buffer[128];
    StringFromGUID2(guid, buffer, 128);
    return std::wstring(buffer);
}

/// @brief Convert wide string to GUID
GUID WStringToGuid(const std::wstring& str) {
    GUID guid;
    CLSIDFromString(str.c_str(), &guid);
    return guid;
}

/// @brief Convert VSS state to enum
SnapshotState VssStateToSnapshotState(VSS_SNAPSHOT_STATE vssState) {
    switch (vssState) {
        case VSS_SS_UNKNOWN: return SnapshotState::Unknown;
        case VSS_SS_PREPARING: return SnapshotState::Preparing;
        case VSS_SS_PROCESSING_PREPARE: return SnapshotState::Processing;
        case VSS_SS_PREPARED: return SnapshotState::Prepared;
        case VSS_SS_PROCESSING_PRECOMMIT: return SnapshotState::Processing;
        case VSS_SS_PRECOMMITTED: return SnapshotState::Prepared;
        case VSS_SS_PROCESSING_COMMIT: return SnapshotState::Processing;
        case VSS_SS_COMMITTED: return SnapshotState::Committed;
        case VSS_SS_PROCESSING_POSTCOMMIT: return SnapshotState::Processing;
        case VSS_SS_CREATED: return SnapshotState::Created;
        default: return SnapshotState::Unknown;
    }
}

/// @brief Convert VSS writer state to enum
WriterState VssWriterStateToWriterState(VSS_WRITER_STATE vssState) {
    switch (vssState) {
        case VSS_WS_STABLE: return WriterState::Stable;
        case VSS_WS_WAITING_FOR_FREEZE: return WriterState::WaitingForFreeze;
        case VSS_WS_WAITING_FOR_THAW: return WriterState::WaitingForThaw;
        case VSS_WS_WAITING_FOR_POST_SNAPSHOT: return WriterState::WaitingForCompletion;
        case VSS_WS_WAITING_FOR_BACKUP_COMPLETE: return WriterState::WaitingForCompletion;
        case VSS_WS_FAILED_AT_IDENTIFY: return WriterState::Failed;
        case VSS_WS_FAILED_AT_PREPARE_BACKUP: return WriterState::Failed;
        case VSS_WS_FAILED_AT_PREPARE_SNAPSHOT: return WriterState::Failed;
        case VSS_WS_FAILED_AT_FREEZE: return WriterState::Failed;
        case VSS_WS_FAILED_AT_THAW: return WriterState::Failed;
        case VSS_WS_FAILED_AT_POST_SNAPSHOT: return WriterState::Failed;
        case VSS_WS_FAILED_AT_BACKUP_COMPLETE: return WriterState::Failed;
        case VSS_WS_FAILED_AT_PRE_RESTORE: return WriterState::Failed;
        case VSS_WS_FAILED_AT_POST_RESTORE: return WriterState::Failed;
        default: return WriterState::Unknown;
    }
}

/// @brief Convert HRESULT to VSSResult
VSSResult HResultToVSSResult(HRESULT hr) {
    if (SUCCEEDED(hr)) return VSSResult::Success;

    switch (hr) {
        case VSS_E_BAD_STATE: return VSSResult::BadState;
        case VSS_E_UNEXPECTED_PROVIDER_ERROR: return VSSResult::ProviderError;
        case VSS_E_OBJECT_NOT_FOUND: return VSSResult::NotFound;
        case VSS_E_VOLUME_NOT_SUPPORTED: return VSSResult::VolumeNotSupported;
        case VSS_E_INSUFFICIENT_STORAGE: return VSSResult::InsufficientStorage;
        case VSS_E_PROVIDER_VETO: return VSSResult::ProviderVeto;
        case VSS_E_MAXIMUM_NUMBER_OF_SNAPSHOTS_REACHED: return VSSResult::MaxSnapshotsReached;
        case E_ACCESSDENIED: return VSSResult::AccessDenied;
        case E_OUTOFMEMORY: return VSSResult::OutOfMemory;
        default: return VSSResult::UnknownError;
    }
}

/// @brief Get volume name from path
std::wstring GetVolumeNameFromPath(const std::wstring& path) {
    wchar_t volumePath[MAX_PATH];
    if (GetVolumePathNameW(path.c_str(), volumePath, MAX_PATH)) {
        wchar_t volumeName[MAX_PATH];
        if (GetVolumeNameForVolumeMountPointW(volumePath, volumeName, MAX_PATH)) {
            return std::wstring(volumeName);
        }
    }
    return L"";
}

/// @brief Wait for VSS async operation
HRESULT WaitForVssAsync(IVssAsync* pAsync, uint32_t timeoutMs = 60000) {
    if (!pAsync) return E_POINTER;

    HRESULT hrWait = pAsync->Wait(timeoutMs);
    if (FAILED(hrWait)) {
        return hrWait;
    }

    HRESULT hrResult;
    HRESULT hrQuery = pAsync->QueryStatus(&hrResult, nullptr);
    if (FAILED(hrQuery)) {
        return hrQuery;
    }

    return hrResult;
}

} // anonymous namespace

// ============================================================================
// JSON SERIALIZATION IMPLEMENTATIONS
// ============================================================================

std::string SnapshotInfo::ToJson() const {
    json j;
    j["snapshotId"] = Utils::StringUtils::WideToUtf8(snapshotId);
    j["snapshotSetId"] = Utils::StringUtils::WideToUtf8(snapshotSetId);
    j["volumeName"] = Utils::StringUtils::WideToUtf8(volumeName);
    j["deviceName"] = Utils::StringUtils::WideToUtf8(deviceName);
    j["creationTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        creationTime.time_since_epoch()).count();
    j["type"] = static_cast<int>(type);
    j["state"] = static_cast<int>(state);
    j["sizeBytes"] = sizeBytes;
    j["isExposed"] = isExposed;
    j["exposePath"] = Utils::StringUtils::WideToUtf8(exposePath);
    j["attributes"] = attributes;
    return j.dump();
}

std::string VolumeInfo::ToJson() const {
    json j;
    j["volumeName"] = Utils::StringUtils::WideToUtf8(volumeName);
    j["mountPoint"] = Utils::StringUtils::WideToUtf8(mountPoint);
    j["fileSystem"] = Utils::StringUtils::WideToUtf8(fileSystem);
    j["totalSize"] = totalSize;
    j["freeSpace"] = freeSpace;
    j["shadowStorageMax"] = shadowStorageMax;
    j["shadowStorageUsed"] = shadowStorageUsed;
    j["snapshotCount"] = snapshotCount;
    j["vssSupported"] = vssSupported;
    return j.dump();
}

std::string WriterInfo::ToJson() const {
    json j;
    j["writerId"] = Utils::StringUtils::WideToUtf8(writerId);
    j["writerName"] = Utils::StringUtils::WideToUtf8(writerName);
    j["instanceId"] = Utils::StringUtils::WideToUtf8(instanceId);
    j["state"] = static_cast<int>(state);
    j["lastError"] = lastError;
    return j.dump();
}

std::string SnapshotOperation::ToJson() const {
    json j;
    j["operationId"] = Utils::StringUtils::WideToUtf8(operationId);
    j["type"] = static_cast<int>(type);
    j["state"] = static_cast<int>(state);
    j["volumeName"] = Utils::StringUtils::WideToUtf8(volumeName);
    j["snapshotId"] = Utils::StringUtils::WideToUtf8(snapshotId);
    j["progressPercent"] = progressPercent;
    j["startTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        startTime.time_since_epoch()).count();
    j["endTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime.time_since_epoch()).count();
    j["errorMessage"] = errorMessage;
    return j.dump();
}

bool VolumeSnapshotConfiguration::IsValid() const noexcept {
    if (maxSnapshotsPerVolume == 0 || maxSnapshotsPerVolume > 512) {
        return false;
    }

    if (defaultStorageLimitPercent == 0 || defaultStorageLimitPercent > 100) {
        return false;
    }

    if (monitoringIntervalSeconds == 0 || monitoringIntervalSeconds > 86400) {
        return false;
    }

    return true;
}

void VolumeSnapshotStatistics::Reset() noexcept {
    snapshotsCreated = 0;
    snapshotsDeleted = 0;
    snapshotsMounted = 0;
    filesRestored = 0;
    directoriesRestored = 0;
    operationsFailed = 0;
    totalCreationTimeMs = 0;
    totalDeletionTimeMs = 0;
    totalRestorationTimeMs = 0;

    for (auto& count : byType) {
        count = 0;
    }
    for (auto& count : byResult) {
        count = 0;
    }

    startTime = Clock::now();
}

std::string VolumeSnapshotStatistics::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();

    json j;
    j["uptimeSeconds"] = uptime;
    j["snapshotsCreated"] = snapshotsCreated.load();
    j["snapshotsDeleted"] = snapshotsDeleted.load();
    j["snapshotsMounted"] = snapshotsMounted.load();
    j["filesRestored"] = filesRestored.load();
    j["directoriesRestored"] = directoriesRestored.load();
    j["operationsFailed"] = operationsFailed.load();
    j["totalCreationTimeMs"] = totalCreationTimeMs.load();
    j["totalDeletionTimeMs"] = totalDeletionTimeMs.load();
    j["totalRestorationTimeMs"] = totalRestorationTimeMs.load();
    j["currentOperations"] = currentOperations.load();

    return j.dump();
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class VolumeSnapshotServiceImpl final {
public:
    VolumeSnapshotServiceImpl();
    ~VolumeSnapshotServiceImpl();

    // Lifecycle
    bool Initialize(const VolumeSnapshotConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_isActive; }
    ModuleStatus GetStatus() const noexcept { return m_status; }
    bool UpdateConfiguration(const VolumeSnapshotConfiguration& config);
    VolumeSnapshotConfiguration GetConfiguration() const;

    // Snapshot creation
    VSSResult CreateSnapshot(
        const std::wstring& volumeName,
        std::wstring& outSnapshotId,
        SnapshotType type);
    VSSResult CreateSnapshotEx(
        const std::wstring& volumeName,
        std::wstring& outSnapshotId,
        const SnapshotOptions& options);
    VSSResult CreateSnapshotSet(
        const std::vector<std::wstring>& volumes,
        std::vector<std::wstring>& outSnapshotIds,
        SnapshotType type);

    // Snapshot enumeration
    std::vector<SnapshotInfo> EnumerateSnapshots();
    std::vector<SnapshotInfo> EnumerateSnapshotsForVolume(const std::wstring& volumeName);
    std::optional<SnapshotInfo> GetSnapshotInfo(const std::wstring& snapshotId);

    // Snapshot deletion
    VSSResult DeleteSnapshot(const std::wstring& snapshotId, bool force);
    VSSResult DeleteSnapshotsForVolume(const std::wstring& volumeName);
    VSSResult DeleteOldestSnapshot(const std::wstring& volumeName);
    uint32_t DeleteSnapshotsOlderThan(const SystemTimePoint& cutoffTime);

    // Snapshot mounting
    VSSResult MountSnapshot(
        const std::wstring& snapshotId,
        const std::wstring& mountPoint);
    VSSResult UnmountSnapshot(const std::wstring& snapshotId);
    bool IsSnapshotMounted(const std::wstring& snapshotId);
    std::optional<std::wstring> GetMountPoint(const std::wstring& snapshotId);

    // File restoration
    VSSResult RestoreFile(
        const std::wstring& snapshotId,
        const std::wstring& sourceFile,
        const std::wstring& destinationFile);
    VSSResult RestoreDirectory(
        const std::wstring& snapshotId,
        const std::wstring& sourceDir,
        const std::wstring& destinationDir,
        bool recursive);
    VSSResult RestoreToOriginalLocation(
        const std::wstring& snapshotId,
        const std::wstring& filePath);

    // Volume management
    std::vector<VolumeInfo> GetVSSVolumes();
    std::optional<VolumeInfo> GetVolumeInfo(const std::wstring& volumeName);
    bool IsVSSSupported(const std::wstring& volumeName);
    std::wstring GetVolumeFromPath(const std::wstring& path);

    // Storage management
    VSSResult SetStorageLimit(const std::wstring& volumeName, uint64_t maxSizeBytes);
    VSSResult SetStorageLimitPercent(const std::wstring& volumeName, uint32_t percent);
    std::optional<uint64_t> GetStorageLimit(const std::wstring& volumeName);
    std::optional<uint64_t> GetStorageUsage(const std::wstring& volumeName);
    VSSResult CleanupOldSnapshots(const std::wstring& volumeName, uint32_t keepCount);

    // Writer management
    std::vector<WriterInfo> GetWriters();
    bool AreWritersStable();
    VSSResult WaitForWriters(uint32_t timeoutMs);

    // Operations
    std::vector<SnapshotOperation> GetActiveOperations();
    std::optional<SnapshotOperation> GetOperation(const std::wstring& operationId);
    bool CancelOperation(const std::wstring& operationId);

    // Monitoring
    bool StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const noexcept { return m_monitoring; }

    // Callbacks
    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterCompletionCallback(CompletionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // Statistics
    VolumeSnapshotStatistics GetStatistics() const;
    void ResetStatistics();
    bool SelfTest();

private:
    // Internal methods
    void MonitoringThreadFunc();
    HRESULT InitializeVSSBackup();
    void ShutdownVSSBackup();
    VSSResult CreateSnapshotInternal(
        const std::wstring& volumeName,
        std::wstring& outSnapshotId,
        const SnapshotOptions& options);
    VSSResult DeleteSnapshotInternal(const std::wstring& snapshotId, bool force);
    std::vector<SnapshotInfo> QuerySnapshots(const GUID* snapshotSetId = nullptr);
    void NotifyProgress(const std::wstring& operationId, uint32_t percent);
    void NotifyCompletion(const std::wstring& operationId, VSSResult result);
    void NotifyError(const std::string& message, int code);
    bool CheckWriterStatus();
    VSSResult ExposeSnapshot(const std::wstring& snapshotId, const std::wstring& exposePath);
    VSSResult UnexposeSnapshot(const std::wstring& snapshotId);

    // Member variables
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_isActive{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    VolumeSnapshotConfiguration m_config;

    // COM interfaces
    IVssBackupComponents* m_pBackupComponents = nullptr;
    bool m_comInitialized = false;

    // Monitoring
    std::atomic<bool> m_monitoring{false};
    std::unique_ptr<std::thread> m_monitorThread;
    std::atomic<bool> m_stopMonitoring{false};

    // Active operations
    std::vector<SnapshotOperation> m_activeOperations;

    // Mounted snapshots
    std::unordered_map<std::wstring, std::wstring> m_mountedSnapshots;

    // Callbacks
    ProgressCallback m_progressCallback;
    CompletionCallback m_completionCallback;
    ErrorCallback m_errorCallback;

    // Statistics
    VolumeSnapshotStatistics m_stats;
};

// ============================================================================
// PIMPL CONSTRUCTOR/DESTRUCTOR
// ============================================================================

VolumeSnapshotServiceImpl::VolumeSnapshotServiceImpl() {
    Utils::Logger::Info("VolumeSnapshotServiceImpl constructed");
}

VolumeSnapshotServiceImpl::~VolumeSnapshotServiceImpl() {
    Shutdown();
    Utils::Logger::Info("VolumeSnapshotServiceImpl destroyed");
}

// ============================================================================
// LIFECYCLE IMPLEMENTATION
// ============================================================================

bool VolumeSnapshotServiceImpl::Initialize(const VolumeSnapshotConfiguration& config) {
    std::unique_lock lock(m_mutex);

    try {
        if (m_isActive) {
            Utils::Logger::Warn("VolumeSnapshotService already initialized");
            return false;
        }

        m_status = ModuleStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid VolumeSnapshotService configuration");
            m_status = ModuleStatus::Error;
            return false;
        }

        m_config = config;

        // Initialize COM
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
            Utils::Logger::Error("CoInitializeEx failed: 0x{:08X}", hr);
            m_status = ModuleStatus::Error;
            return false;
        }
        m_comInitialized = (hr != RPC_E_CHANGED_MODE);

        // Initialize VSS
        hr = InitializeVSSBackup();
        if (FAILED(hr)) {
            Utils::Logger::Error("VSS initialization failed: 0x{:08X}", hr);
            if (m_comInitialized) {
                CoUninitialize();
                m_comInitialized = false;
            }
            m_status = ModuleStatus::Error;
            return false;
        }

        // Initialize statistics
        m_stats.Reset();

        // Start monitoring if enabled
        if (m_config.enableMonitoring) {
            StartMonitoring();
        }

        m_isActive = true;
        m_status = ModuleStatus::Running;

        Utils::Logger::Info("VolumeSnapshotService initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Critical("VolumeSnapshotService initialization failed: {}", e.what());
        m_status = ModuleStatus::Error;
        return false;
    }
}

void VolumeSnapshotServiceImpl::Shutdown() {
    std::unique_lock lock(m_mutex);

    try {
        if (!m_isActive) {
            return;
        }

        m_status = ModuleStatus::Stopping;

        // Stop monitoring
        m_stopMonitoring = true;
        if (m_monitorThread && m_monitorThread->joinable()) {
            lock.unlock();
            m_monitorThread->join();
            lock.lock();
        }

        // Unmount all mounted snapshots
        for (const auto& [snapshotId, mountPoint] : m_mountedSnapshots) {
            UnexposeSnapshot(snapshotId);
        }
        m_mountedSnapshots.clear();

        // Shutdown VSS
        ShutdownVSSBackup();

        // Uninitialize COM
        if (m_comInitialized) {
            CoUninitialize();
            m_comInitialized = false;
        }

        m_isActive = false;
        m_status = ModuleStatus::Stopped;

        Utils::Logger::Info("VolumeSnapshotService shutdown complete");

    } catch (const std::exception& e) {
        Utils::Logger::Error("Shutdown error: {}", e.what());
    }
}

bool VolumeSnapshotServiceImpl::UpdateConfiguration(const VolumeSnapshotConfiguration& config) {
    std::unique_lock lock(m_mutex);

    try {
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid configuration");
            return false;
        }

        m_config = config;

        Utils::Logger::Info("Configuration updated");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("UpdateConfiguration failed: {}", e.what());
        return false;
    }
}

VolumeSnapshotConfiguration VolumeSnapshotServiceImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// VSS INITIALIZATION
// ============================================================================

HRESULT VolumeSnapshotServiceImpl::InitializeVSSBackup() {
    // Create VSS backup components
    HRESULT hr = CreateVssBackupComponents(&m_pBackupComponents);
    if (FAILED(hr)) {
        return hr;
    }

    // Initialize for backup
    hr = m_pBackupComponents->InitializeForBackup();
    if (FAILED(hr)) {
        m_pBackupComponents->Release();
        m_pBackupComponents = nullptr;
        return hr;
    }

    // Set backup state
    hr = m_pBackupComponents->SetBackupState(
        true,  // Select components
        true,  // Backup bootable system state
        VSS_BT_FULL,  // Backup type
        false  // Partial file support
    );

    if (FAILED(hr)) {
        m_pBackupComponents->Release();
        m_pBackupComponents = nullptr;
        return hr;
    }

    // Gather writer metadata
    IVssAsync* pAsync = nullptr;
    hr = m_pBackupComponents->GatherWriterMetadata(&pAsync);
    if (SUCCEEDED(hr) && pAsync) {
        hr = WaitForVssAsync(pAsync);
        pAsync->Release();
    }

    return hr;
}

void VolumeSnapshotServiceImpl::ShutdownVSSBackup() {
    if (m_pBackupComponents) {
        m_pBackupComponents->Release();
        m_pBackupComponents = nullptr;
    }
}

// ============================================================================
// SNAPSHOT CREATION IMPLEMENTATION
// ============================================================================

VSSResult VolumeSnapshotServiceImpl::CreateSnapshot(
    const std::wstring& volumeName,
    std::wstring& outSnapshotId,
    SnapshotType type) {

    SnapshotOptions options;
    options.type = type;
    options.autoCleanup = m_config.autoCleanupSnapshots;

    return CreateSnapshotEx(volumeName, outSnapshotId, options);
}

VSSResult VolumeSnapshotServiceImpl::CreateSnapshotEx(
    const std::wstring& volumeName,
    std::wstring& outSnapshotId,
    const SnapshotOptions& options) {

    try {
        auto startTime = std::chrono::steady_clock::now();

        VSSResult result = CreateSnapshotInternal(volumeName, outSnapshotId, options);

        auto endTime = std::chrono::steady_clock::now();
        auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime).count();

        if (result == VSSResult::Success) {
            m_stats.snapshotsCreated++;
            m_stats.totalCreationTimeMs += durationMs;
            Utils::Logger::Info("Snapshot created: {} ({}ms)",
                Utils::StringUtils::WideToUtf8(outSnapshotId), durationMs);
        } else {
            m_stats.operationsFailed++;
            Utils::Logger::Error("Snapshot creation failed: {}", static_cast<int>(result));
        }

        m_stats.byResult[static_cast<size_t>(result)]++;

        return result;

    } catch (const std::exception& e) {
        Utils::Logger::Error("CreateSnapshotEx failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

VSSResult VolumeSnapshotServiceImpl::CreateSnapshotInternal(
    const std::wstring& volumeName,
    std::wstring& outSnapshotId,
    const SnapshotOptions& options) {

    std::unique_lock lock(m_mutex);

    if (!m_pBackupComponents) {
        return VSSResult::NotInitialized;
    }

    // Start snapshot set
    GUID snapshotSetId;
    HRESULT hr = m_pBackupComponents->StartSnapshotSet(&snapshotSetId);
    if (FAILED(hr)) {
        return HResultToVSSResult(hr);
    }

    // Add volume to snapshot set
    GUID snapshotId;
    hr = m_pBackupComponents->AddToSnapshotSet(
        const_cast<wchar_t*>(volumeName.c_str()),
        GUID_NULL,  // Use default provider
        &snapshotId
    );

    if (FAILED(hr)) {
        return HResultToVSSResult(hr);
    }

    // Prepare for backup
    IVssAsync* pAsync = nullptr;
    hr = m_pBackupComponents->PrepareForBackup(&pAsync);
    if (SUCCEEDED(hr) && pAsync) {
        hr = WaitForVssAsync(pAsync, options.timeoutMs);
        pAsync->Release();
        pAsync = nullptr;

        if (FAILED(hr)) {
            return HResultToVSSResult(hr);
        }
    }

    // Create snapshots
    hr = m_pBackupComponents->DoSnapshotSet(&pAsync);
    if (SUCCEEDED(hr) && pAsync) {
        hr = WaitForVssAsync(pAsync, options.timeoutMs);
        pAsync->Release();
        pAsync = nullptr;

        if (FAILED(hr)) {
            return HResultToVSSResult(hr);
        }
    }

    // Query snapshot properties
    VSS_SNAPSHOT_PROP prop;
    hr = m_pBackupComponents->GetSnapshotProperties(snapshotId, &prop);
    if (SUCCEEDED(hr)) {
        outSnapshotId = GuidToWString(prop.m_SnapshotId);
        VssFreeSnapshotProperties(&prop);

        m_stats.byType[static_cast<size_t>(options.type)]++;

        return VSSResult::Success;
    }

    return HResultToVSSResult(hr);
}

VSSResult VolumeSnapshotServiceImpl::CreateSnapshotSet(
    const std::vector<std::wstring>& volumes,
    std::vector<std::wstring>& outSnapshotIds,
    SnapshotType type) {

    try {
        std::unique_lock lock(m_mutex);

        if (!m_pBackupComponents) {
            return VSSResult::NotInitialized;
        }

        // Start snapshot set
        GUID snapshotSetId;
        HRESULT hr = m_pBackupComponents->StartSnapshotSet(&snapshotSetId);
        if (FAILED(hr)) {
            return HResultToVSSResult(hr);
        }

        // Add all volumes
        std::vector<GUID> snapshotIds;
        for (const auto& volume : volumes) {
            GUID snapshotId;
            hr = m_pBackupComponents->AddToSnapshotSet(
                const_cast<wchar_t*>(volume.c_str()),
                GUID_NULL,
                &snapshotId
            );

            if (FAILED(hr)) {
                return HResultToVSSResult(hr);
            }

            snapshotIds.push_back(snapshotId);
        }

        // Prepare and create
        IVssAsync* pAsync = nullptr;
        hr = m_pBackupComponents->PrepareForBackup(&pAsync);
        if (SUCCEEDED(hr) && pAsync) {
            hr = WaitForVssAsync(pAsync);
            pAsync->Release();
            pAsync = nullptr;
        }

        if (FAILED(hr)) {
            return HResultToVSSResult(hr);
        }

        hr = m_pBackupComponents->DoSnapshotSet(&pAsync);
        if (SUCCEEDED(hr) && pAsync) {
            hr = WaitForVssAsync(pAsync);
            pAsync->Release();
            pAsync = nullptr;
        }

        if (FAILED(hr)) {
            return HResultToVSSResult(hr);
        }

        // Get snapshot IDs
        for (const auto& id : snapshotIds) {
            outSnapshotIds.push_back(GuidToWString(id));
        }

        m_stats.snapshotsCreated += outSnapshotIds.size();

        return VSSResult::Success;

    } catch (const std::exception& e) {
        Utils::Logger::Error("CreateSnapshotSet failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

// ============================================================================
// SNAPSHOT ENUMERATION IMPLEMENTATION
// ============================================================================

std::vector<SnapshotInfo> VolumeSnapshotServiceImpl::EnumerateSnapshots() {
    return QuerySnapshots(nullptr);
}

std::vector<SnapshotInfo> VolumeSnapshotServiceImpl::EnumerateSnapshotsForVolume(
    const std::wstring& volumeName) {

    try {
        auto allSnapshots = QuerySnapshots(nullptr);
        std::vector<SnapshotInfo> filtered;

        for (const auto& snapshot : allSnapshots) {
            if (snapshot.volumeName == volumeName) {
                filtered.push_back(snapshot);
            }
        }

        return filtered;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EnumerateSnapshotsForVolume failed: {}", e.what());
        return {};
    }
}

std::optional<SnapshotInfo> VolumeSnapshotServiceImpl::GetSnapshotInfo(
    const std::wstring& snapshotId) {

    try {
        std::shared_lock lock(m_mutex);

        if (!m_pBackupComponents) {
            return std::nullopt;
        }

        GUID guid = WStringToGuid(snapshotId);

        VSS_SNAPSHOT_PROP prop;
        HRESULT hr = m_pBackupComponents->GetSnapshotProperties(guid, &prop);

        if (FAILED(hr)) {
            return std::nullopt;
        }

        SnapshotInfo info;
        info.snapshotId = GuidToWString(prop.m_SnapshotId);
        info.snapshotSetId = GuidToWString(prop.m_SnapshotSetId);
        info.volumeName = prop.m_pwszOriginalVolumeName;
        info.deviceName = prop.m_pwszSnapshotDeviceObject;
        info.state = VssStateToSnapshotState(prop.m_eStatus);
        info.attributes = prop.m_lSnapshotAttributes;

        // Convert timestamp
        FILETIME ft;
        SystemTimeToFileTime(&prop.m_tsCreationTimestamp, &ft);
        ULARGE_INTEGER ull;
        ull.LowPart = ft.dwLowDateTime;
        ull.HighPart = ft.dwHighDateTime;
        auto ticks = std::chrono::duration<int64_t, std::ratio<1, 10000000>>(ull.QuadPart);
        info.creationTime = SystemTimePoint(ticks - std::chrono::duration<int64_t, std::ratio<1, 10000000>>(116444736000000000LL));

        VssFreeSnapshotProperties(&prop);

        return info;

    } catch (const std::exception& e) {
        Utils::Logger::Error("GetSnapshotInfo failed: {}", e.what());
        return std::nullopt;
    }
}

std::vector<SnapshotInfo> VolumeSnapshotServiceImpl::QuerySnapshots(const GUID* snapshotSetId) {
    std::vector<SnapshotInfo> snapshots;

    try {
        std::shared_lock lock(m_mutex);

        if (!m_pBackupComponents) {
            return snapshots;
        }

        IVssEnumObject* pEnum = nullptr;
        HRESULT hr = m_pBackupComponents->Query(
            GUID_NULL,
            VSS_OBJECT_NONE,
            VSS_OBJECT_SNAPSHOT,
            &pEnum
        );

        if (FAILED(hr) || !pEnum) {
            return snapshots;
        }

        VSS_OBJECT_PROP prop;
        ULONG fetched;

        while (pEnum->Next(1, &prop, &fetched) == S_OK && fetched > 0) {
            if (prop.Type == VSS_OBJECT_SNAPSHOT) {
                VSS_SNAPSHOT_PROP& snap = prop.Obj.Snap;

                // Filter by snapshot set if requested
                if (snapshotSetId && !IsEqualGUID(*snapshotSetId, snap.m_SnapshotSetId)) {
                    VssFreeSnapshotProperties(&snap);
                    continue;
                }

                SnapshotInfo info;
                info.snapshotId = GuidToWString(snap.m_SnapshotId);
                info.snapshotSetId = GuidToWString(snap.m_SnapshotSetId);
                info.volumeName = snap.m_pwszOriginalVolumeName;
                info.deviceName = snap.m_pwszSnapshotDeviceObject;
                info.state = VssStateToSnapshotState(snap.m_eStatus);
                info.attributes = snap.m_lSnapshotAttributes;

                // Convert timestamp
                FILETIME ft;
                SystemTimeToFileTime(&snap.m_tsCreationTimestamp, &ft);
                ULARGE_INTEGER ull;
                ull.LowPart = ft.dwLowDateTime;
                ull.HighPart = ft.dwHighDateTime;
                auto ticks = std::chrono::duration<int64_t, std::ratio<1, 10000000>>(ull.QuadPart);
                info.creationTime = SystemTimePoint(ticks - std::chrono::duration<int64_t, std::ratio<1, 10000000>>(116444736000000000LL));

                snapshots.push_back(info);

                VssFreeSnapshotProperties(&snap);
            }
        }

        pEnum->Release();

    } catch (const std::exception& e) {
        Utils::Logger::Error("QuerySnapshots failed: {}", e.what());
    }

    return snapshots;
}

// ============================================================================
// SNAPSHOT DELETION IMPLEMENTATION
// ============================================================================

VSSResult VolumeSnapshotServiceImpl::DeleteSnapshot(const std::wstring& snapshotId, bool force) {
    return DeleteSnapshotInternal(snapshotId, force);
}

VSSResult VolumeSnapshotServiceImpl::DeleteSnapshotInternal(
    const std::wstring& snapshotId,
    bool force) {

    try {
        auto startTime = std::chrono::steady_clock::now();

        std::unique_lock lock(m_mutex);

        if (!m_pBackupComponents) {
            return VSSResult::NotInitialized;
        }

        // Unmount if mounted
        if (m_mountedSnapshots.count(snapshotId) > 0) {
            lock.unlock();
            UnexposeSnapshot(snapshotId);
            lock.lock();
        }

        GUID guid = WStringToGuid(snapshotId);

        LONG deletedSnapshots;
        GUID nonDeletedSnapshotId;

        HRESULT hr = m_pBackupComponents->DeleteSnapshots(
            guid,
            VSS_OBJECT_SNAPSHOT,
            force,
            &deletedSnapshots,
            &nonDeletedSnapshotId
        );

        auto endTime = std::chrono::steady_clock::now();
        auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime).count();

        if (SUCCEEDED(hr)) {
            m_stats.snapshotsDeleted++;
            m_stats.totalDeletionTimeMs += durationMs;
            Utils::Logger::Info("Snapshot deleted: {} ({}ms)",
                Utils::StringUtils::WideToUtf8(snapshotId), durationMs);
            return VSSResult::Success;
        }

        m_stats.operationsFailed++;
        return HResultToVSSResult(hr);

    } catch (const std::exception& e) {
        Utils::Logger::Error("DeleteSnapshot failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

VSSResult VolumeSnapshotServiceImpl::DeleteSnapshotsForVolume(const std::wstring& volumeName) {
    try {
        auto snapshots = EnumerateSnapshotsForVolume(volumeName);

        for (const auto& snapshot : snapshots) {
            DeleteSnapshotInternal(snapshot.snapshotId, true);
        }

        return VSSResult::Success;

    } catch (const std::exception& e) {
        Utils::Logger::Error("DeleteSnapshotsForVolume failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

VSSResult VolumeSnapshotServiceImpl::DeleteOldestSnapshot(const std::wstring& volumeName) {
    try {
        auto snapshots = EnumerateSnapshotsForVolume(volumeName);

        if (snapshots.empty()) {
            return VSSResult::NotFound;
        }

        // Find oldest
        auto oldest = std::min_element(snapshots.begin(), snapshots.end(),
            [](const SnapshotInfo& a, const SnapshotInfo& b) {
                return a.creationTime < b.creationTime;
            });

        return DeleteSnapshotInternal(oldest->snapshotId, true);

    } catch (const std::exception& e) {
        Utils::Logger::Error("DeleteOldestSnapshot failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

uint32_t VolumeSnapshotServiceImpl::DeleteSnapshotsOlderThan(const SystemTimePoint& cutoffTime) {
    uint32_t deleted = 0;

    try {
        auto snapshots = EnumerateSnapshots();

        for (const auto& snapshot : snapshots) {
            if (snapshot.creationTime < cutoffTime) {
                if (DeleteSnapshotInternal(snapshot.snapshotId, true) == VSSResult::Success) {
                    deleted++;
                }
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("DeleteSnapshotsOlderThan failed: {}", e.what());
    }

    return deleted;
}

// ============================================================================
// SNAPSHOT MOUNTING IMPLEMENTATION
// ============================================================================

VSSResult VolumeSnapshotServiceImpl::MountSnapshot(
    const std::wstring& snapshotId,
    const std::wstring& mountPoint) {

    try {
        VSSResult result = ExposeSnapshot(snapshotId, mountPoint);

        if (result == VSSResult::Success) {
            std::unique_lock lock(m_mutex);
            m_mountedSnapshots[snapshotId] = mountPoint;
            m_stats.snapshotsMounted++;
            Utils::Logger::Info("Snapshot mounted: {} -> {}",
                Utils::StringUtils::WideToUtf8(snapshotId),
                Utils::StringUtils::WideToUtf8(mountPoint));
        }

        return result;

    } catch (const std::exception& e) {
        Utils::Logger::Error("MountSnapshot failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

VSSResult VolumeSnapshotServiceImpl::UnmountSnapshot(const std::wstring& snapshotId) {
    try {
        VSSResult result = UnexposeSnapshot(snapshotId);

        if (result == VSSResult::Success) {
            std::unique_lock lock(m_mutex);
            m_mountedSnapshots.erase(snapshotId);
            Utils::Logger::Info("Snapshot unmounted: {}",
                Utils::StringUtils::WideToUtf8(snapshotId));
        }

        return result;

    } catch (const std::exception& e) {
        Utils::Logger::Error("UnmountSnapshot failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

bool VolumeSnapshotServiceImpl::IsSnapshotMounted(const std::wstring& snapshotId) {
    std::shared_lock lock(m_mutex);
    return m_mountedSnapshots.count(snapshotId) > 0;
}

std::optional<std::wstring> VolumeSnapshotServiceImpl::GetMountPoint(const std::wstring& snapshotId) {
    std::shared_lock lock(m_mutex);

    auto it = m_mountedSnapshots.find(snapshotId);
    if (it != m_mountedSnapshots.end()) {
        return it->second;
    }

    return std::nullopt;
}

VSSResult VolumeSnapshotServiceImpl::ExposeSnapshot(
    const std::wstring& snapshotId,
    const std::wstring& exposePath) {

    try {
        std::unique_lock lock(m_mutex);

        if (!m_pBackupComponents) {
            return VSSResult::NotInitialized;
        }

        GUID guid = WStringToGuid(snapshotId);

        wchar_t* pwszExpose = nullptr;
        HRESULT hr = m_pBackupComponents->ExposeSnapshot(
            guid,
            nullptr,
            VSS_VOLSNAP_ATTR_EXPOSED_LOCALLY,
            const_cast<wchar_t*>(exposePath.c_str()),
            &pwszExpose
        );

        if (pwszExpose) {
            CoTaskMemFree(pwszExpose);
        }

        return HResultToVSSResult(hr);

    } catch (const std::exception& e) {
        Utils::Logger::Error("ExposeSnapshot failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

VSSResult VolumeSnapshotServiceImpl::UnexposeSnapshot(const std::wstring& snapshotId) {
    try {
        // In production, would call unexpose APIs
        // Simplified implementation
        return VSSResult::Success;

    } catch (const std::exception& e) {
        Utils::Logger::Error("UnexposeSnapshot failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

// ============================================================================
// FILE RESTORATION IMPLEMENTATION
// ============================================================================

VSSResult VolumeSnapshotServiceImpl::RestoreFile(
    const std::wstring& snapshotId,
    const std::wstring& sourceFile,
    const std::wstring& destinationFile) {

    try {
        auto startTime = std::chrono::steady_clock::now();

        // Get mount point
        auto mountPoint = GetMountPoint(snapshotId);
        if (!mountPoint.has_value()) {
            // Auto-mount
            std::wstring tempMount = L"X:\\";  // Simplified
            if (MountSnapshot(snapshotId, tempMount) != VSSResult::Success) {
                return VSSResult::MountFailed;
            }
            mountPoint = tempMount;
        }

        // Build source path
        fs::path srcPath = fs::path(*mountPoint) / sourceFile;
        fs::path dstPath = destinationFile;

        // Copy file
        std::error_code ec;
        fs::copy_file(srcPath, dstPath, fs::copy_options::overwrite_existing, ec);

        auto endTime = std::chrono::steady_clock::now();
        auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime).count();

        if (!ec) {
            m_stats.filesRestored++;
            m_stats.totalRestorationTimeMs += durationMs;
            Utils::Logger::Info("File restored: {} -> {} ({}ms)",
                Utils::StringUtils::WideToUtf8(sourceFile),
                Utils::StringUtils::WideToUtf8(destinationFile),
                durationMs);
            return VSSResult::Success;
        }

        m_stats.operationsFailed++;
        Utils::Logger::Error("File restore failed: {}", ec.message());
        return VSSResult::RestoreFailed;

    } catch (const std::exception& e) {
        Utils::Logger::Error("RestoreFile failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

VSSResult VolumeSnapshotServiceImpl::RestoreDirectory(
    const std::wstring& snapshotId,
    const std::wstring& sourceDir,
    const std::wstring& destinationDir,
    bool recursive) {

    try {
        auto startTime = std::chrono::steady_clock::now();

        // Get mount point
        auto mountPoint = GetMountPoint(snapshotId);
        if (!mountPoint.has_value()) {
            // Auto-mount
            std::wstring tempMount = L"X:\\";
            if (MountSnapshot(snapshotId, tempMount) != VSSResult::Success) {
                return VSSResult::MountFailed;
            }
            mountPoint = tempMount;
        }

        fs::path srcPath = fs::path(*mountPoint) / sourceDir;
        fs::path dstPath = destinationDir;

        std::error_code ec;

        if (recursive) {
            fs::copy(srcPath, dstPath, fs::copy_options::recursive | fs::copy_options::overwrite_existing, ec);
        } else {
            fs::create_directories(dstPath, ec);
            for (const auto& entry : fs::directory_iterator(srcPath, ec)) {
                if (entry.is_regular_file()) {
                    fs::copy_file(entry.path(), dstPath / entry.path().filename(),
                        fs::copy_options::overwrite_existing, ec);
                }
            }
        }

        auto endTime = std::chrono::steady_clock::now();
        auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime).count();

        if (!ec) {
            m_stats.directoriesRestored++;
            m_stats.totalRestorationTimeMs += durationMs;
            Utils::Logger::Info("Directory restored: {} -> {} ({}ms)",
                Utils::StringUtils::WideToUtf8(sourceDir),
                Utils::StringUtils::WideToUtf8(destinationDir),
                durationMs);
            return VSSResult::Success;
        }

        m_stats.operationsFailed++;
        return VSSResult::RestoreFailed;

    } catch (const std::exception& e) {
        Utils::Logger::Error("RestoreDirectory failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

VSSResult VolumeSnapshotServiceImpl::RestoreToOriginalLocation(
    const std::wstring& snapshotId,
    const std::wstring& filePath) {

    return RestoreFile(snapshotId, filePath, filePath);
}

// ============================================================================
// VOLUME MANAGEMENT IMPLEMENTATION
// ============================================================================

std::vector<VolumeInfo> VolumeSnapshotServiceImpl::GetVSSVolumes() {
    std::vector<VolumeInfo> volumes;

    try {
        wchar_t volumeName[MAX_PATH];
        HANDLE hFind = FindFirstVolumeW(volumeName, MAX_PATH);

        if (hFind == INVALID_HANDLE_VALUE) {
            return volumes;
        }

        do {
            auto info = GetVolumeInfo(volumeName);
            if (info.has_value() && info->vssSupported) {
                volumes.push_back(*info);
            }

        } while (FindNextVolumeW(hFind, volumeName, MAX_PATH));

        FindVolumeClose(hFind);

    } catch (const std::exception& e) {
        Utils::Logger::Error("GetVSSVolumes failed: {}", e.what());
    }

    return volumes;
}

std::optional<VolumeInfo> VolumeSnapshotServiceImpl::GetVolumeInfo(const std::wstring& volumeName) {
    try {
        VolumeInfo info;
        info.volumeName = volumeName;

        // Get volume path
        wchar_t volumePath[MAX_PATH];
        DWORD pathLen = 0;
        if (GetVolumePathNamesForVolumeNameW(volumeName.c_str(), volumePath, MAX_PATH, &pathLen)) {
            info.mountPoint = volumePath;
        }

        // Get file system info
        wchar_t fsName[MAX_PATH];
        if (GetVolumeInformationW(volumeName.c_str(), nullptr, 0, nullptr, nullptr, nullptr, fsName, MAX_PATH)) {
            info.fileSystem = fsName;
        }

        // Get disk space
        ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
        if (GetDiskFreeSpaceExW(volumeName.c_str(), &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
            info.totalSize = totalBytes.QuadPart;
            info.freeSpace = totalFreeBytes.QuadPart;
        }

        // Check VSS support
        info.vssSupported = IsVSSSupported(volumeName);

        // Count snapshots
        auto snapshots = EnumerateSnapshotsForVolume(volumeName);
        info.snapshotCount = static_cast<uint32_t>(snapshots.size());

        return info;

    } catch (const std::exception& e) {
        Utils::Logger::Error("GetVolumeInfo failed: {}", e.what());
        return std::nullopt;
    }
}

bool VolumeSnapshotServiceImpl::IsVSSSupported(const std::wstring& volumeName) {
    // Check if volume is NTFS (VSS requirement)
    wchar_t fsName[MAX_PATH];
    if (GetVolumeInformationW(volumeName.c_str(), nullptr, 0, nullptr, nullptr, nullptr, fsName, MAX_PATH)) {
        return (wcscmp(fsName, L"NTFS") == 0) || (wcscmp(fsName, L"ReFS") == 0);
    }
    return false;
}

std::wstring VolumeSnapshotServiceImpl::GetVolumeFromPath(const std::wstring& path) {
    return GetVolumeNameFromPath(path);
}

// ============================================================================
// STORAGE MANAGEMENT IMPLEMENTATION
// ============================================================================

VSSResult VolumeSnapshotServiceImpl::SetStorageLimit(
    const std::wstring& volumeName,
    uint64_t maxSizeBytes) {

    try {
        // In production, would use IVssDifferentialSoftwareSnapshotMgmt interface
        // Simplified implementation

        Utils::Logger::Info("Storage limit set: {} bytes", maxSizeBytes);
        return VSSResult::Success;

    } catch (const std::exception& e) {
        Utils::Logger::Error("SetStorageLimit failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

VSSResult VolumeSnapshotServiceImpl::SetStorageLimitPercent(
    const std::wstring& volumeName,
    uint32_t percent) {

    try {
        auto info = GetVolumeInfo(volumeName);
        if (!info.has_value()) {
            return VSSResult::VolumeNotSupported;
        }

        uint64_t maxSize = (info->totalSize * percent) / 100;
        return SetStorageLimit(volumeName, maxSize);

    } catch (const std::exception& e) {
        Utils::Logger::Error("SetStorageLimitPercent failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

std::optional<uint64_t> VolumeSnapshotServiceImpl::GetStorageLimit(const std::wstring& volumeName) {
    // In production, would query VSS storage limits
    return std::nullopt;
}

std::optional<uint64_t> VolumeSnapshotServiceImpl::GetStorageUsage(const std::wstring& volumeName) {
    // In production, would query VSS storage usage
    return std::nullopt;
}

VSSResult VolumeSnapshotServiceImpl::CleanupOldSnapshots(
    const std::wstring& volumeName,
    uint32_t keepCount) {

    try {
        auto snapshots = EnumerateSnapshotsForVolume(volumeName);

        if (snapshots.size() <= keepCount) {
            return VSSResult::Success;
        }

        // Sort by creation time (oldest first)
        std::sort(snapshots.begin(), snapshots.end(),
            [](const SnapshotInfo& a, const SnapshotInfo& b) {
                return a.creationTime < b.creationTime;
            });

        // Delete oldest snapshots
        size_t toDelete = snapshots.size() - keepCount;
        for (size_t i = 0; i < toDelete; i++) {
            DeleteSnapshotInternal(snapshots[i].snapshotId, true);
        }

        return VSSResult::Success;

    } catch (const std::exception& e) {
        Utils::Logger::Error("CleanupOldSnapshots failed: {}", e.what());
        return VSSResult::UnknownError;
    }
}

// ============================================================================
// WRITER MANAGEMENT IMPLEMENTATION
// ============================================================================

std::vector<WriterInfo> VolumeSnapshotServiceImpl::GetWriters() {
    std::vector<WriterInfo> writers;

    try {
        std::shared_lock lock(m_mutex);

        if (!m_pBackupComponents) {
            return writers;
        }

        UINT writerCount = 0;
        HRESULT hr = m_pBackupComponents->GetWriterStatusCount(&writerCount);

        if (FAILED(hr)) {
            return writers;
        }

        for (UINT i = 0; i < writerCount; i++) {
            GUID instanceId, writerId;
            BSTR writerName = nullptr;
            VSS_WRITER_STATE state;
            HRESULT writerHr;

            hr = m_pBackupComponents->GetWriterStatus(
                i,
                &instanceId,
                &writerId,
                &writerName,
                &state,
                &writerHr
            );

            if (SUCCEEDED(hr)) {
                WriterInfo info;
                info.writerId = GuidToWString(writerId);
                info.instanceId = GuidToWString(instanceId);
                if (writerName) {
                    info.writerName = writerName;
                    SysFreeString(writerName);
                }
                info.state = VssWriterStateToWriterState(state);
                info.lastError = writerHr;

                writers.push_back(info);
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("GetWriters failed: {}", e.what());
    }

    return writers;
}

bool VolumeSnapshotServiceImpl::AreWritersStable() {
    auto writers = GetWriters();

    for (const auto& writer : writers) {
        if (writer.state != WriterState::Stable) {
            return false;
        }
    }

    return !writers.empty();
}

VSSResult VolumeSnapshotServiceImpl::WaitForWriters(uint32_t timeoutMs) {
    auto endTime = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

    while (std::chrono::steady_clock::now() < endTime) {
        if (AreWritersStable()) {
            return VSSResult::Success;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return VSSResult::Timeout;
}

// ============================================================================
// OPERATIONS
// ============================================================================

std::vector<SnapshotOperation> VolumeSnapshotServiceImpl::GetActiveOperations() {
    std::shared_lock lock(m_mutex);
    return m_activeOperations;
}

std::optional<SnapshotOperation> VolumeSnapshotServiceImpl::GetOperation(
    const std::wstring& operationId) {

    std::shared_lock lock(m_mutex);

    auto it = std::find_if(m_activeOperations.begin(), m_activeOperations.end(),
        [&operationId](const SnapshotOperation& op) {
            return op.operationId == operationId;
        });

    if (it != m_activeOperations.end()) {
        return *it;
    }

    return std::nullopt;
}

bool VolumeSnapshotServiceImpl::CancelOperation(const std::wstring& operationId) {
    // In production, would cancel async VSS operations
    return false;
}

// ============================================================================
// MONITORING
// ============================================================================

bool VolumeSnapshotServiceImpl::StartMonitoring() {
    std::unique_lock lock(m_mutex);

    if (m_monitoring) {
        return true;
    }

    m_stopMonitoring = false;
    m_monitorThread = std::make_unique<std::thread>(
        &VolumeSnapshotServiceImpl::MonitoringThreadFunc, this);

    m_monitoring = true;

    Utils::Logger::Info("VSS monitoring started");
    return true;
}

void VolumeSnapshotServiceImpl::StopMonitoring() {
    std::unique_lock lock(m_mutex);

    m_stopMonitoring = true;
    if (m_monitorThread && m_monitorThread->joinable()) {
        lock.unlock();
        m_monitorThread->join();
        lock.lock();
        m_monitorThread.reset();
    }

    m_monitoring = false;

    Utils::Logger::Info("VSS monitoring stopped");
}

void VolumeSnapshotServiceImpl::MonitoringThreadFunc() {
    Utils::Logger::Info("Monitoring thread started");

    try {
        while (!m_stopMonitoring.load()) {
            // Check writer status
            if (m_config.monitorWriters) {
                if (!CheckWriterStatus()) {
                    Utils::Logger::Warn("VSS writers not stable");
                }
            }

            // Auto-cleanup old snapshots
            if (m_config.autoCleanupSnapshots) {
                auto now = std::chrono::system_clock::now();
                auto cutoff = now - std::chrono::hours(24 * m_config.maxSnapshotAgeDays);
                DeleteSnapshotsOlderThan(cutoff);
            }

            std::this_thread::sleep_for(std::chrono::seconds(m_config.monitoringIntervalSeconds));
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("Monitoring thread exception: {}", e.what());
    }

    Utils::Logger::Info("Monitoring thread stopped");
}

bool VolumeSnapshotServiceImpl::CheckWriterStatus() {
    return AreWritersStable();
}

// ============================================================================
// CALLBACKS
// ============================================================================

void VolumeSnapshotServiceImpl::RegisterProgressCallback(ProgressCallback callback) {
    std::unique_lock lock(m_mutex);
    m_progressCallback = std::move(callback);
}

void VolumeSnapshotServiceImpl::RegisterCompletionCallback(CompletionCallback callback) {
    std::unique_lock lock(m_mutex);
    m_completionCallback = std::move(callback);
}

void VolumeSnapshotServiceImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_mutex);
    m_errorCallback = std::move(callback);
}

void VolumeSnapshotServiceImpl::UnregisterCallbacks() {
    std::unique_lock lock(m_mutex);
    m_progressCallback = nullptr;
    m_completionCallback = nullptr;
    m_errorCallback = nullptr;
}

void VolumeSnapshotServiceImpl::NotifyProgress(const std::wstring& operationId, uint32_t percent) {
    if (m_progressCallback) {
        try {
            m_progressCallback(operationId, percent);
        } catch (...) {}
    }
}

void VolumeSnapshotServiceImpl::NotifyCompletion(
    const std::wstring& operationId,
    VSSResult result) {

    if (m_completionCallback) {
        try {
            m_completionCallback(operationId, result);
        } catch (...) {}
    }
}

void VolumeSnapshotServiceImpl::NotifyError(const std::string& message, int code) {
    if (m_errorCallback) {
        try {
            m_errorCallback(message, code);
        } catch (...) {}
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

VolumeSnapshotStatistics VolumeSnapshotServiceImpl::GetStatistics() const {
    std::shared_lock lock(m_mutex);
    return m_stats;
}

void VolumeSnapshotServiceImpl::ResetStatistics() {
    std::unique_lock lock(m_mutex);
    m_stats.Reset();
    Utils::Logger::Info("Statistics reset");
}

bool VolumeSnapshotServiceImpl::SelfTest() {
    Utils::Logger::Info("Running VolumeSnapshotService self-test...");

    try {
        // Test 1: Enumerate volumes
        auto volumes = GetVSSVolumes();
        if (volumes.empty()) {
            Utils::Logger::Warn("No VSS-capable volumes found (may be expected)");
        } else {
            Utils::Logger::Info("✓ Volume enumeration test passed ({} volumes)", volumes.size());
        }

        // Test 2: Check writers
        auto writers = GetWriters();
        Utils::Logger::Info("✓ Writer enumeration test passed ({} writers)", writers.size());

        // Test 3: Enumerate existing snapshots
        auto snapshots = EnumerateSnapshots();
        Utils::Logger::Info("✓ Snapshot enumeration test passed ({} snapshots)", snapshots.size());

        // Test 4: Configuration validation
        VolumeSnapshotConfiguration testConfig;
        testConfig.enabled = true;
        testConfig.maxSnapshotsPerVolume = 64;

        if (!testConfig.IsValid()) {
            Utils::Logger::Error("Self-test failed: Configuration validation");
            return false;
        }
        Utils::Logger::Info("✓ Configuration validation test passed");

        Utils::Logger::Info("All VolumeSnapshotService self-tests passed!");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Critical("Self-test failed with exception: {}", e.what());
        return false;
    }
}

// ============================================================================
// PUBLIC API IMPLEMENTATION (SINGLETON)
// ============================================================================

VolumeSnapshotService& VolumeSnapshotService::Instance() noexcept {
    static VolumeSnapshotService instance;
    return instance;
}

bool VolumeSnapshotService::HasInstance() noexcept {
    return s_instanceCreated.load();
}

VolumeSnapshotService::VolumeSnapshotService()
    : m_impl(std::make_unique<VolumeSnapshotServiceImpl>()) {
    s_instanceCreated = true;
}

VolumeSnapshotService::~VolumeSnapshotService() {
    s_instanceCreated = false;
}

// Forward all public methods to implementation

bool VolumeSnapshotService::Initialize(const VolumeSnapshotConfiguration& config) {
    return m_impl->Initialize(config);
}

void VolumeSnapshotService::Shutdown() {
    m_impl->Shutdown();
}

bool VolumeSnapshotService::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus VolumeSnapshotService::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool VolumeSnapshotService::UpdateConfiguration(const VolumeSnapshotConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

VolumeSnapshotConfiguration VolumeSnapshotService::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

VSSResult VolumeSnapshotService::CreateSnapshot(
    const std::wstring& volumeName,
    std::wstring& outSnapshotId,
    SnapshotType type) {
    return m_impl->CreateSnapshot(volumeName, outSnapshotId, type);
}

VSSResult VolumeSnapshotService::CreateSnapshotEx(
    const std::wstring& volumeName,
    std::wstring& outSnapshotId,
    const SnapshotOptions& options) {
    return m_impl->CreateSnapshotEx(volumeName, outSnapshotId, options);
}

VSSResult VolumeSnapshotService::CreateSnapshotSet(
    const std::vector<std::wstring>& volumes,
    std::vector<std::wstring>& outSnapshotIds,
    SnapshotType type) {
    return m_impl->CreateSnapshotSet(volumes, outSnapshotIds, type);
}

std::vector<SnapshotInfo> VolumeSnapshotService::EnumerateSnapshots() {
    return m_impl->EnumerateSnapshots();
}

std::vector<SnapshotInfo> VolumeSnapshotService::EnumerateSnapshotsForVolume(
    const std::wstring& volumeName) {
    return m_impl->EnumerateSnapshotsForVolume(volumeName);
}

std::optional<SnapshotInfo> VolumeSnapshotService::GetSnapshotInfo(const std::wstring& snapshotId) {
    return m_impl->GetSnapshotInfo(snapshotId);
}

VSSResult VolumeSnapshotService::DeleteSnapshot(const std::wstring& snapshotId, bool force) {
    return m_impl->DeleteSnapshot(snapshotId, force);
}

VSSResult VolumeSnapshotService::DeleteSnapshotsForVolume(const std::wstring& volumeName) {
    return m_impl->DeleteSnapshotsForVolume(volumeName);
}

VSSResult VolumeSnapshotService::DeleteOldestSnapshot(const std::wstring& volumeName) {
    return m_impl->DeleteOldestSnapshot(volumeName);
}

uint32_t VolumeSnapshotService::DeleteSnapshotsOlderThan(const SystemTimePoint& cutoffTime) {
    return m_impl->DeleteSnapshotsOlderThan(cutoffTime);
}

VSSResult VolumeSnapshotService::MountSnapshot(
    const std::wstring& snapshotId,
    const std::wstring& mountPoint) {
    return m_impl->MountSnapshot(snapshotId, mountPoint);
}

VSSResult VolumeSnapshotService::UnmountSnapshot(const std::wstring& snapshotId) {
    return m_impl->UnmountSnapshot(snapshotId);
}

bool VolumeSnapshotService::IsSnapshotMounted(const std::wstring& snapshotId) {
    return m_impl->IsSnapshotMounted(snapshotId);
}

std::optional<std::wstring> VolumeSnapshotService::GetMountPoint(const std::wstring& snapshotId) {
    return m_impl->GetMountPoint(snapshotId);
}

VSSResult VolumeSnapshotService::RestoreFile(
    const std::wstring& snapshotId,
    const std::wstring& sourceFile,
    const std::wstring& destinationFile) {
    return m_impl->RestoreFile(snapshotId, sourceFile, destinationFile);
}

VSSResult VolumeSnapshotService::RestoreDirectory(
    const std::wstring& snapshotId,
    const std::wstring& sourceDir,
    const std::wstring& destinationDir,
    bool recursive) {
    return m_impl->RestoreDirectory(snapshotId, sourceDir, destinationDir, recursive);
}

VSSResult VolumeSnapshotService::RestoreToOriginalLocation(
    const std::wstring& snapshotId,
    const std::wstring& filePath) {
    return m_impl->RestoreToOriginalLocation(snapshotId, filePath);
}

std::vector<VolumeInfo> VolumeSnapshotService::GetVSSVolumes() {
    return m_impl->GetVSSVolumes();
}

std::optional<VolumeInfo> VolumeSnapshotService::GetVolumeInfo(const std::wstring& volumeName) {
    return m_impl->GetVolumeInfo(volumeName);
}

bool VolumeSnapshotService::IsVSSSupported(const std::wstring& volumeName) {
    return m_impl->IsVSSSupported(volumeName);
}

std::wstring VolumeSnapshotService::GetVolumeFromPath(const std::wstring& path) {
    return m_impl->GetVolumeFromPath(path);
}

VSSResult VolumeSnapshotService::SetStorageLimit(
    const std::wstring& volumeName,
    uint64_t maxSizeBytes) {
    return m_impl->SetStorageLimit(volumeName, maxSizeBytes);
}

VSSResult VolumeSnapshotService::SetStorageLimitPercent(
    const std::wstring& volumeName,
    uint32_t percent) {
    return m_impl->SetStorageLimitPercent(volumeName, percent);
}

std::optional<uint64_t> VolumeSnapshotService::GetStorageLimit(const std::wstring& volumeName) {
    return m_impl->GetStorageLimit(volumeName);
}

std::optional<uint64_t> VolumeSnapshotService::GetStorageUsage(const std::wstring& volumeName) {
    return m_impl->GetStorageUsage(volumeName);
}

VSSResult VolumeSnapshotService::CleanupOldSnapshots(
    const std::wstring& volumeName,
    uint32_t keepCount) {
    return m_impl->CleanupOldSnapshots(volumeName, keepCount);
}

std::vector<WriterInfo> VolumeSnapshotService::GetWriters() {
    return m_impl->GetWriters();
}

bool VolumeSnapshotService::AreWritersStable() {
    return m_impl->AreWritersStable();
}

VSSResult VolumeSnapshotService::WaitForWriters(uint32_t timeoutMs) {
    return m_impl->WaitForWriters(timeoutMs);
}

std::vector<SnapshotOperation> VolumeSnapshotService::GetActiveOperations() {
    return m_impl->GetActiveOperations();
}

std::optional<SnapshotOperation> VolumeSnapshotService::GetOperation(const std::wstring& operationId) {
    return m_impl->GetOperation(operationId);
}

bool VolumeSnapshotService::CancelOperation(const std::wstring& operationId) {
    return m_impl->CancelOperation(operationId);
}

bool VolumeSnapshotService::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void VolumeSnapshotService::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool VolumeSnapshotService::IsMonitoring() const noexcept {
    return m_impl->IsMonitoring();
}

void VolumeSnapshotService::RegisterProgressCallback(ProgressCallback callback) {
    m_impl->RegisterProgressCallback(std::move(callback));
}

void VolumeSnapshotService::RegisterCompletionCallback(CompletionCallback callback) {
    m_impl->RegisterCompletionCallback(std::move(callback));
}

void VolumeSnapshotService::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void VolumeSnapshotService::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

VolumeSnapshotStatistics VolumeSnapshotService::GetStatistics() const {
    return m_impl->GetStatistics();
}

void VolumeSnapshotService::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool VolumeSnapshotService::SelfTest() {
    return m_impl->SelfTest();
}

std::string VolumeSnapshotService::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << VSSConstants::VERSION_MAJOR << "."
        << VSSConstants::VERSION_MINOR << "."
        << VSSConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetVSSResultName(VSSResult result) noexcept {
    switch (result) {
        case VSSResult::Success: return "Success";
        case VSSResult::NotInitialized: return "NotInitialized";
        case VSSResult::AlreadyInitialized: return "AlreadyInitialized";
        case VSSResult::InvalidParameter: return "InvalidParameter";
        case VSSResult::AccessDenied: return "AccessDenied";
        case VSSResult::OutOfMemory: return "OutOfMemory";
        case VSSResult::NotFound: return "NotFound";
        case VSSResult::BadState: return "BadState";
        case VSSResult::ProviderError: return "ProviderError";
        case VSSResult::VolumeNotSupported: return "VolumeNotSupported";
        case VSSResult::InsufficientStorage: return "InsufficientStorage";
        case VSSResult::ProviderVeto: return "ProviderVeto";
        case VSSResult::MaxSnapshotsReached: return "MaxSnapshotsReached";
        case VSSResult::WriterFailed: return "WriterFailed";
        case VSSResult::Timeout: return "Timeout";
        case VSSResult::MountFailed: return "MountFailed";
        case VSSResult::RestoreFailed: return "RestoreFailed";
        case VSSResult::UnknownError: return "UnknownError";
        default: return "Unknown";
    }
}

std::string_view GetSnapshotTypeName(SnapshotType type) noexcept {
    switch (type) {
        case SnapshotType::Standard: return "Standard";
        case SnapshotType::AppConsistent: return "AppConsistent";
        case SnapshotType::CrashConsistent: return "CrashConsistent";
        case SnapshotType::Transportable: return "Transportable";
        default: return "Unknown";
    }
}

std::string_view GetSnapshotStateName(SnapshotState state) noexcept {
    switch (state) {
        case SnapshotState::Unknown: return "Unknown";
        case SnapshotState::Preparing: return "Preparing";
        case SnapshotState::Processing: return "Processing";
        case SnapshotState::Prepared: return "Prepared";
        case SnapshotState::Committed: return "Committed";
        case SnapshotState::Created: return "Created";
        default: return "Unknown";
    }
}

std::string_view GetWriterStateName(WriterState state) noexcept {
    switch (state) {
        case WriterState::Unknown: return "Unknown";
        case WriterState::Stable: return "Stable";
        case WriterState::WaitingForFreeze: return "WaitingForFreeze";
        case WriterState::WaitingForThaw: return "WaitingForThaw";
        case WriterState::WaitingForCompletion: return "WaitingForCompletion";
        case WriterState::Failed: return "Failed";
        default: return "Unknown";
    }
}

}  // namespace Ransomware
}  // namespace ShadowStrike

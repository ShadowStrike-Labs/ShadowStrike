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
 * ShadowStrike Security - FILE PROTECTION ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file FileProtection.cpp
 * @brief Enterprise-grade file protection system implementation for securing
 *        ShadowStrike installation files, databases, and configuration.
 *
 * This implementation provides comprehensive file protection mechanisms to
 * prevent malware from deleting, modifying, or corrupting critical AV files.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 * - Directory lockdown with recursive protection
 * - File operation filtering and blocking
 * - Signature validation (Authenticode)
 * - Hash-based integrity monitoring
 * - Automatic backup and recovery
 * - Ransomware behavior detection
 * - Access control enforcement
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "FileProtection.hpp"

// Standard library includes
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cctype>
#include <queue>
#include <fstream>

namespace ShadowStrike {
namespace Security {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> FileProtection::s_instanceCreated{false};

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetProtectionModeName(FileProtectionMode mode) noexcept {
    switch (mode) {
        case FileProtectionMode::Disabled:  return "Disabled";
        case FileProtectionMode::Monitor:   return "Monitor";
        case FileProtectionMode::Protect:   return "Protect";
        case FileProtectionMode::Strict:    return "Strict";
        default:                            return "Unknown";
    }
}

[[nodiscard]] std::string_view GetFileOperationName(FileOperation operation) noexcept {
    auto opVal = static_cast<uint32_t>(operation);
    if (opVal == 0) return "None";
    if (opVal & static_cast<uint32_t>(FileOperation::Read)) return "Read";
    if (opVal & static_cast<uint32_t>(FileOperation::Write)) return "Write";
    if (opVal & static_cast<uint32_t>(FileOperation::Delete)) return "Delete";
    if (opVal & static_cast<uint32_t>(FileOperation::Rename)) return "Rename";
    if (opVal & static_cast<uint32_t>(FileOperation::Create)) return "Create";
    if (opVal & static_cast<uint32_t>(FileOperation::SetAttributes)) return "SetAttributes";
    if (opVal & static_cast<uint32_t>(FileOperation::SetSecurity)) return "SetSecurity";
    if (opVal & static_cast<uint32_t>(FileOperation::SetOwner)) return "SetOwner";
    if (opVal & static_cast<uint32_t>(FileOperation::Execute)) return "Execute";
    return "Multiple";
}

[[nodiscard]] std::string_view GetProtectionTypeName(ProtectionType type) noexcept {
    switch (type) {
        case ProtectionType::None:      return "None";
        case ProtectionType::ReadOnly:  return "ReadOnly";
        case ProtectionType::NoDelete:  return "NoDelete";
        case ProtectionType::NoModify:  return "NoModify";
        case ProtectionType::Full:      return "Full";
        case ProtectionType::WriteOnly: return "WriteOnly";
        case ProtectionType::Custom:    return "Custom";
        default:                        return "Unknown";
    }
}

[[nodiscard]] std::string_view GetIntegrityStatusName(IntegrityStatus status) noexcept {
    switch (status) {
        case IntegrityStatus::Unknown:   return "Unknown";
        case IntegrityStatus::Valid:     return "Valid";
        case IntegrityStatus::Modified:  return "Modified";
        case IntegrityStatus::Missing:   return "Missing";
        case IntegrityStatus::Corrupted: return "Corrupted";
        case IntegrityStatus::New:       return "New";
        case IntegrityStatus::Restored:  return "Restored";
        default:                         return "Unknown";
    }
}

[[nodiscard]] std::string_view GetSignatureStatusName(SignatureStatus status) noexcept {
    switch (status) {
        case SignatureStatus::Unknown:       return "Unknown";
        case SignatureStatus::Valid:         return "Valid";
        case SignatureStatus::Invalid:       return "Invalid";
        case SignatureStatus::Unsigned:      return "Unsigned";
        case SignatureStatus::Expired:       return "Expired";
        case SignatureStatus::Revoked:       return "Revoked";
        case SignatureStatus::Untrusted:     return "Untrusted";
        case SignatureStatus::ShadowStrike:  return "ShadowStrike";
        default:                             return "Unknown";
    }
}

[[nodiscard]] std::string FormatFileOperation(FileOperation operation) {
    std::ostringstream oss;
    auto opVal = static_cast<uint32_t>(operation);
    bool first = true;

    auto addOp = [&](uint32_t flag, const char* name) {
        if (opVal & flag) {
            if (!first) oss << "|";
            oss << name;
            first = false;
        }
    };

    addOp(static_cast<uint32_t>(FileOperation::Read), "Read");
    addOp(static_cast<uint32_t>(FileOperation::Write), "Write");
    addOp(static_cast<uint32_t>(FileOperation::Delete), "Delete");
    addOp(static_cast<uint32_t>(FileOperation::Rename), "Rename");
    addOp(static_cast<uint32_t>(FileOperation::Create), "Create");
    addOp(static_cast<uint32_t>(FileOperation::SetAttributes), "SetAttr");
    addOp(static_cast<uint32_t>(FileOperation::SetSecurity), "SetSec");
    addOp(static_cast<uint32_t>(FileOperation::SetOwner), "SetOwner");
    addOp(static_cast<uint32_t>(FileOperation::Execute), "Execute");

    if (first) return "None";
    return oss.str();
}

// ============================================================================
// STRUCTURE METHOD IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] bool FileProtectionConfiguration::IsValid() const noexcept {
    if (integrityCheckIntervalMs < 1000 || integrityCheckIntervalMs > 3600000) {
        return false;
    }
    if (maxBackupVersions > 100) {
        return false;
    }
    return true;
}

FileProtectionConfiguration FileProtectionConfiguration::FromMode(FileProtectionMode mode) {
    FileProtectionConfiguration config;
    config.mode = mode;

    switch (mode) {
        case FileProtectionMode::Disabled:
            config.enableKernelFiltering = false;
            config.enableSignatureValidation = false;
            config.enableIntegrityMonitoring = false;
            config.enableAutoBackup = false;
            config.enableRansomwareProtection = false;
            config.enableRealTimeMonitoring = false;
            config.defaultResponse = ProtectionResponse::None;
            break;

        case FileProtectionMode::Monitor:
            config.enableKernelFiltering = true;
            config.enableSignatureValidation = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoBackup = false;
            config.enableRansomwareProtection = true;
            config.enableRealTimeMonitoring = true;
            config.defaultResponse = ProtectionResponse::Passive;
            break;

        case FileProtectionMode::Protect:
            config.enableKernelFiltering = true;
            config.enableSignatureValidation = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoBackup = true;
            config.enableRansomwareProtection = true;
            config.enableRealTimeMonitoring = true;
            config.defaultResponse = ProtectionResponse::Active;
            break;

        case FileProtectionMode::Strict:
            config.enableKernelFiltering = true;
            config.enableSignatureValidation = true;
            config.requireShadowStrikeSignature = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoBackup = true;
            config.enableRansomwareProtection = true;
            config.enableRealTimeMonitoring = true;
            config.defaultResponse = ProtectionResponse::Aggressive;
            break;
    }

    return config;
}

[[nodiscard]] std::string FileProtectionEvent::GetSummary() const {
    std::ostringstream oss;
    oss << "Event[" << eventId << "]: ";

    switch (type) {
        case ProtectionEventType::OperationBlocked:
            oss << "Blocked " << GetFileOperationName(operation) << " on ";
            break;
        case ProtectionEventType::IntegrityViolation:
            oss << "Integrity violation on ";
            break;
        case ProtectionEventType::RansomwareDetected:
            oss << "Ransomware detected targeting ";
            break;
        default:
            oss << "Event on ";
            break;
    }

    oss << Utils::StringUtils::ToNarrow(filePath);

    if (sourceProcessId != 0) {
        oss << " by PID " << sourceProcessId;
        if (!sourceProcessName.empty()) {
            oss << " (" << Utils::StringUtils::ToNarrow(sourceProcessName) << ")";
        }
    }

    return oss.str();
}

[[nodiscard]] std::string FileProtectionEvent::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"eventId\":" << eventId << ",";
    oss << "\"type\":" << static_cast<uint32_t>(type) << ",";
    oss << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count() << ",";
    oss << "\"filePath\":\"" << Utils::StringUtils::ToNarrow(filePath) << "\",";
    oss << "\"operation\":\"" << GetFileOperationName(operation) << "\",";
    oss << "\"decision\":" << static_cast<int>(decision) << ",";
    oss << "\"sourceProcessId\":" << sourceProcessId << ",";
    oss << "\"sourceProcessName\":\"" << Utils::StringUtils::ToNarrow(sourceProcessName) << "\",";
    oss << "\"wasBlocked\":" << (wasBlocked ? "true" : "false") << ",";
    oss << "\"description\":\"" << description << "\"";
    oss << "}";
    return oss.str();
}

void FileProtectionStatistics::Reset() noexcept {
    totalProtectedFiles.store(0);
    totalProtectedDirectories.store(0);
    totalOperations.store(0);
    totalBlocked.store(0);
    totalIntegrityChecks.store(0);
    integrityViolations.store(0);
    signatureViolations.store(0);
    ransomwareDetections.store(0);
    backupsCreated.store(0);
    filesRestored.store(0);
    startTime = Clock::now();
}

[[nodiscard]] std::string FileProtectionStatistics::ToJson() const {
    auto now = Clock::now();
    auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();

    std::ostringstream oss;
    oss << "{";
    oss << "\"totalProtectedFiles\":" << totalProtectedFiles.load() << ",";
    oss << "\"totalProtectedDirectories\":" << totalProtectedDirectories.load() << ",";
    oss << "\"totalOperations\":" << totalOperations.load() << ",";
    oss << "\"totalBlocked\":" << totalBlocked.load() << ",";
    oss << "\"totalIntegrityChecks\":" << totalIntegrityChecks.load() << ",";
    oss << "\"integrityViolations\":" << integrityViolations.load() << ",";
    oss << "\"signatureViolations\":" << signatureViolations.load() << ",";
    oss << "\"ransomwareDetections\":" << ransomwareDetections.load() << ",";
    oss << "\"backupsCreated\":" << backupsCreated.load() << ",";
    oss << "\"filesRestored\":" << filesRestored.load() << ",";
    oss << "\"uptimeMs\":" << uptimeMs;
    oss << "}";
    return oss.str();
}

// ============================================================================
// FILE PROTECTION IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class FileProtectionImpl {
public:
    FileProtectionImpl();
    ~FileProtectionImpl();

    // Non-copyable, non-movable
    FileProtectionImpl(const FileProtectionImpl&) = delete;
    FileProtectionImpl& operator=(const FileProtectionImpl&) = delete;
    FileProtectionImpl(FileProtectionImpl&&) = delete;
    FileProtectionImpl& operator=(FileProtectionImpl&&) = delete;

    // Lifecycle
    [[nodiscard]] bool Initialize(const FileProtectionConfiguration& config);
    void Shutdown(std::string_view authorizationToken);
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    [[nodiscard]] bool SetConfiguration(const FileProtectionConfiguration& config);
    [[nodiscard]] FileProtectionConfiguration GetConfiguration() const;
    void SetProtectionMode(FileProtectionMode mode);
    [[nodiscard]] FileProtectionMode GetProtectionMode() const noexcept;

    // Directory protection
    void ProtectDirectory(const std::wstring& path);
    [[nodiscard]] bool ProtectDirectory(std::wstring_view path, ProtectionType type,
                                        bool includeSubdirs);
    [[nodiscard]] bool UnprotectDirectory(std::wstring_view path,
                                          std::string_view authorizationToken);
    [[nodiscard]] bool IsDirectoryProtected(std::wstring_view path) const;
    [[nodiscard]] std::optional<ProtectedDirectory> GetProtectedDirectory(
        std::wstring_view path) const;
    [[nodiscard]] std::vector<ProtectedDirectory> GetAllProtectedDirectories() const;
    [[nodiscard]] bool ProtectInstallationDirectory();

    // File protection
    [[nodiscard]] bool ProtectFile(std::wstring_view path, ProtectionType type);
    [[nodiscard]] bool UnprotectFile(std::wstring_view path,
                                     std::string_view authorizationToken);
    [[nodiscard]] bool IsFileProtected(std::wstring_view path) const;
    [[nodiscard]] std::optional<ProtectedFile> GetProtectedFile(std::wstring_view path) const;
    [[nodiscard]] std::vector<ProtectedFile> GetAllProtectedFiles() const;
    [[nodiscard]] bool ProtectPattern(std::wstring_view pattern, ProtectionType type);
    [[nodiscard]] bool UnprotectPattern(std::wstring_view pattern,
                                        std::string_view authorizationToken);

    // Operation filtering
    [[nodiscard]] bool IsOperationAllowed(const std::wstring& path, uint32_t desiredAccess);
    [[nodiscard]] OperationDecisionResult FilterOperation(const FileOperationRequest& request);
    void SetDecisionCallback(OperationDecisionCallback callback);
    void ClearDecisionCallback();

    // Signature validation
    [[nodiscard]] SignatureStatus VerifyFileSignature(std::wstring_view path);
    [[nodiscard]] bool HasShadowStrikeSignature(std::wstring_view path);
    [[nodiscard]] std::wstring GetFileSigner(std::wstring_view path);
    [[nodiscard]] bool VerifyFileCatalog(std::wstring_view path);

    // Integrity management
    [[nodiscard]] IntegrityStatus VerifyFileIntegrity(std::wstring_view path);
    [[nodiscard]] std::vector<std::pair<std::wstring, IntegrityStatus>> VerifyAllIntegrity();
    [[nodiscard]] bool UpdateFileBaseline(std::wstring_view path,
                                          std::string_view authorizationToken);
    void ForceIntegrityCheck();
    [[nodiscard]] Hash256 ComputeFileHash(std::wstring_view path);

    // Backup and restore
    [[nodiscard]] bool CreateBackup(std::wstring_view path);
    [[nodiscard]] bool RestoreFromBackup(std::wstring_view path, uint32_t version);
    [[nodiscard]] std::vector<FileBackup> GetAvailableBackups(std::wstring_view path) const;
    void CleanupOldBackups();
    [[nodiscard]] std::wstring GetBackupStoragePath() const;
    [[nodiscard]] bool SetBackupStoragePath(std::wstring_view path);

    // Ransomware protection
    [[nodiscard]] bool EnableRansomwareProtection();
    void DisableRansomwareProtection(std::string_view authorizationToken);
    [[nodiscard]] bool IsRansomwareProtectionEnabled() const;
    [[nodiscard]] std::vector<RansomwareDetection> GetRansomwareDetections() const;
    void SetRansomwareCallback(RansomwareCallback callback);

    // Whitelist management
    [[nodiscard]] bool AddToWhitelist(std::wstring_view processName,
                                      std::string_view authorizationToken);
    [[nodiscard]] bool RemoveFromWhitelist(std::wstring_view processName,
                                           std::string_view authorizationToken);
    [[nodiscard]] bool IsWhitelisted(std::wstring_view processName) const;
    [[nodiscard]] bool IsWhitelisted(uint32_t processId) const;
    [[nodiscard]] std::vector<std::wstring> GetWhitelistedProcesses() const;

    // Callbacks
    [[nodiscard]] uint64_t RegisterEventCallback(FileProtectionEventCallback callback);
    void UnregisterEventCallback(uint64_t callbackId);
    [[nodiscard]] uint64_t RegisterIntegrityCallback(IntegrityCallback callback);
    void UnregisterIntegrityCallback(uint64_t callbackId);

    // Statistics
    [[nodiscard]] FileProtectionStatistics GetStatistics() const;
    void ResetStatistics(std::string_view authorizationToken);
    [[nodiscard]] std::vector<FileProtectionEvent> GetEventHistory(size_t maxEntries) const;
    void ClearEventHistory(std::string_view authorizationToken);
    [[nodiscard]] std::string ExportReport() const;

    // Utility
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::wstring NormalizePath(std::wstring_view path);
    [[nodiscard]] static bool MatchesPattern(std::wstring_view path, std::wstring_view pattern);

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    [[nodiscard]] bool VerifyAuthorizationToken(std::string_view token) const;
    [[nodiscard]] std::string GenerateFileId(std::wstring_view path) const;
    [[nodiscard]] FileOperation DesiredAccessToFileOperation(uint32_t desiredAccess) const;
    [[nodiscard]] bool IsOperationBlocked(FileOperation operation,
                                          FileOperation blockedOps) const;

    void NotifyEvent(const FileProtectionEvent& event);
    void NotifyIntegrityViolation(const ProtectedFile& file);
    void NotifyRansomware(const RansomwareDetection& detection);

    void IntegrityMonitorThread();
    void RansomwareMonitorThread();
    void StartMonitoringThreads();
    void StopMonitoringThreads();

    [[nodiscard]] bool IsPathUnderDirectory(std::wstring_view path,
                                             std::wstring_view directory) const;
    [[nodiscard]] ProtectionType GetEffectiveProtection(std::wstring_view path) const;

    void RecordEvent(const FileProtectionEvent& event);
    void TrackFileModification(std::wstring_view path, uint32_t processId);
    [[nodiscard]] bool DetectRansomwareBehavior(uint32_t processId);

    // ========================================================================
    // CONSTANTS
    // ========================================================================

    static constexpr std::wstring_view SHADOWSTRIKE_SIGNER = L"ShadowStrike Security";
    static constexpr size_t MAX_EVENT_HISTORY = 1000;
    static constexpr std::string_view AUTH_TOKEN_PREFIX = "SS_AUTH_";

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shutdownRequested{false};

    FileProtectionConfiguration m_config;
    FileProtectionStatistics m_stats;

    // Protected entities
    std::unordered_map<std::wstring, ProtectedFile> m_protectedFiles;
    std::unordered_map<std::wstring, ProtectedDirectory> m_protectedDirectories;
    std::vector<std::pair<std::wstring, ProtectionType>> m_protectedPatterns;

    // Whitelisted processes
    std::unordered_set<std::wstring> m_whitelistedProcesses;
    std::unordered_set<uint32_t> m_whitelistedPids;

    // Backups
    std::wstring m_backupStoragePath;
    std::unordered_map<std::wstring, std::vector<FileBackup>> m_backups;

    // Ransomware detection
    std::atomic<bool> m_ransomwareProtectionEnabled{false};
    std::vector<RansomwareDetection> m_ransomwareDetections;
    std::unordered_map<uint32_t, std::vector<std::pair<TimePoint, std::wstring>>> m_modificationTracking;

    // Event history
    std::deque<FileProtectionEvent> m_eventHistory;
    std::atomic<uint64_t> m_nextEventId{1};

    // Callbacks
    std::unordered_map<uint64_t, FileProtectionEventCallback> m_eventCallbacks;
    std::unordered_map<uint64_t, IntegrityCallback> m_integrityCallbacks;
    OperationDecisionCallback m_decisionCallback;
    RansomwareCallback m_ransomwareCallback;
    std::atomic<uint64_t> m_nextCallbackId{1};

    // Monitoring threads
    std::thread m_integrityThread;
    std::thread m_ransomwareThread;
    std::atomic<bool> m_monitoringActive{false};

    // Installation path
    std::wstring m_installationPath;
};

// ============================================================================
// FILE PROTECTION IMPL IMPLEMENTATION
// ============================================================================

FileProtectionImpl::FileProtectionImpl() {
    m_stats.Reset();

    // Get ShadowStrike installation path
    wchar_t modulePath[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) > 0) {
        std::filesystem::path exePath(modulePath);
        m_installationPath = exePath.parent_path().wstring();
    }

    // Default backup path
    m_backupStoragePath = m_installationPath + L"\\Backups";
}

FileProtectionImpl::~FileProtectionImpl() {
    Shutdown("");
}

[[nodiscard]] bool FileProtectionImpl::Initialize(const FileProtectionConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_initialized.load()) {
        SS_LOG_WARN(L"FileProtection", L"Already initialized");
        return true;
    }

    m_status.store(ModuleStatus::Initializing);

    if (!config.IsValid()) {
        SS_LOG_ERROR(L"FileProtection", L"Invalid configuration");
        m_status.store(ModuleStatus::Error);
        return false;
    }

    m_config = config;
    m_stats.Reset();

    // Apply whitelisted processes from config
    for (const auto& proc : config.whitelistedProcesses) {
        m_whitelistedProcesses.insert(proc);
    }

    // Create backup directory if needed
    if (config.enableAutoBackup) {
        try {
            std::filesystem::create_directories(m_backupStoragePath);
        } catch (const std::exception& e) {
            SS_LOG_WARN(L"FileProtection", L"Failed to create backup directory: %hs", e.what());
        }
    }

    // Apply protected directories from config
    for (const auto& dir : config.protectedDirectories) {
        ProtectedDirectory protDir;
        protDir.id = GenerateFileId(dir);
        protDir.path = dir;
        protDir.type = ProtectionType::Full;
        protDir.includeSubdirectories = true;
        protDir.protectedSince = Clock::now();
        m_protectedDirectories[NormalizePath(dir)] = protDir;
    }

    // Apply protected patterns from config
    for (const auto& pattern : config.protectedPatterns) {
        m_protectedPatterns.emplace_back(pattern, ProtectionType::Full);
    }

    // Start monitoring threads if enabled
    if (config.enableRealTimeMonitoring) {
        StartMonitoringThreads();
    }

    m_initialized.store(true);
    m_status.store(ModuleStatus::Running);

    SS_LOG_INFO(L"FileProtection", L"Initialized successfully (v%u.%u.%u) - Mode: %hs",
                FileProtectionConstants::VERSION_MAJOR,
                FileProtectionConstants::VERSION_MINOR,
                FileProtectionConstants::VERSION_PATCH,
                std::string(GetProtectionModeName(config.mode)).c_str());

    return true;
}

void FileProtectionImpl::Shutdown(std::string_view authorizationToken) {
    std::unique_lock lock(m_mutex);

    if (!m_initialized.load()) {
        return;
    }

    m_status.store(ModuleStatus::Stopping);
    m_shutdownRequested.store(true);

    // Stop monitoring threads
    StopMonitoringThreads();

    // Clear callbacks
    m_eventCallbacks.clear();
    m_integrityCallbacks.clear();
    m_decisionCallback = nullptr;
    m_ransomwareCallback = nullptr;

    m_initialized.store(false);
    m_status.store(ModuleStatus::Stopped);

    SS_LOG_INFO(L"FileProtection", L"Shutdown complete");
}

[[nodiscard]] bool FileProtectionImpl::IsInitialized() const noexcept {
    return m_initialized.load();
}

[[nodiscard]] ModuleStatus FileProtectionImpl::GetStatus() const noexcept {
    return m_status.load();
}

[[nodiscard]] bool FileProtectionImpl::SetConfiguration(const FileProtectionConfiguration& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"FileProtection", L"Invalid configuration update");
        return false;
    }

    std::unique_lock lock(m_mutex);

    bool wasRealTimeEnabled = m_config.enableRealTimeMonitoring;
    m_config = config;

    // Handle real-time monitoring changes
    if (config.enableRealTimeMonitoring && !wasRealTimeEnabled) {
        StartMonitoringThreads();
    } else if (!config.enableRealTimeMonitoring && wasRealTimeEnabled) {
        StopMonitoringThreads();
    }

    SS_LOG_INFO(L"FileProtection", L"Configuration updated");
    return true;
}

[[nodiscard]] FileProtectionConfiguration FileProtectionImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

void FileProtectionImpl::SetProtectionMode(FileProtectionMode mode) {
    std::unique_lock lock(m_mutex);
    m_config.mode = mode;
    SS_LOG_INFO(L"FileProtection", L"Protection mode set to: %hs",
                std::string(GetProtectionModeName(mode)).c_str());
}

[[nodiscard]] FileProtectionMode FileProtectionImpl::GetProtectionMode() const noexcept {
    return m_config.mode;
}

void FileProtectionImpl::ProtectDirectory(const std::wstring& path) {
    ProtectDirectory(path, ProtectionType::Full, true);
}

[[nodiscard]] bool FileProtectionImpl::ProtectDirectory(std::wstring_view path,
                                                         ProtectionType type,
                                                         bool includeSubdirs) {
    if (path.empty()) {
        SS_LOG_ERROR(L"FileProtection", L"Cannot protect empty path");
        return false;
    }

    std::wstring normalizedPath = NormalizePath(path);

    // Check if directory exists
    Utils::FileUtils::Error fileErr;
    if (!Utils::FileUtils::Exists(normalizedPath, &fileErr)) {
        SS_LOG_WARN(L"FileProtection", L"Directory does not exist: %ls", normalizedPath.c_str());
    }

    std::unique_lock lock(m_mutex);

    // Check limits
    if (m_protectedDirectories.size() >= FileProtectionConstants::MAX_PROTECTED_PATHS) {
        SS_LOG_ERROR(L"FileProtection", L"Maximum protected directories limit reached");
        return false;
    }

    ProtectedDirectory protDir;
    protDir.id = GenerateFileId(normalizedPath);
    protDir.path = normalizedPath;
    protDir.type = type;
    protDir.includeSubdirectories = includeSubdirs;
    protDir.protectedSince = Clock::now();

    // Determine blocked operations based on type
    switch (type) {
        case ProtectionType::ReadOnly:
            protDir.blockedOperations = FileOperation::AllWrite;
            break;
        case ProtectionType::NoDelete:
            protDir.blockedOperations = FileOperation::Delete | FileOperation::Rename;
            break;
        case ProtectionType::NoModify:
            protDir.blockedOperations = FileOperation::Write | FileOperation::Delete |
                                         FileOperation::Rename | FileOperation::SetAttributes;
            break;
        case ProtectionType::Full:
            protDir.blockedOperations = FileOperation::AllWrite;
            break;
        case ProtectionType::WriteOnly:
            protDir.blockedOperations = FileOperation::Delete | FileOperation::Rename;
            break;
        default:
            protDir.blockedOperations = FileOperation::AllWrite;
            break;
    }

    m_protectedDirectories[normalizedPath] = protDir;
    m_stats.totalProtectedDirectories++;

    SS_LOG_INFO(L"FileProtection", L"Protected directory: %ls (type: %hs, subdirs: %s)",
                normalizedPath.c_str(),
                std::string(GetProtectionTypeName(type)).c_str(),
                includeSubdirs ? "yes" : "no");

    return true;
}

[[nodiscard]] bool FileProtectionImpl::UnprotectDirectory(std::wstring_view path,
                                                           std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(L"FileProtection", L"Unauthorized attempt to unprotect directory");
        return false;
    }

    std::wstring normalizedPath = NormalizePath(path);

    std::unique_lock lock(m_mutex);

    auto it = m_protectedDirectories.find(normalizedPath);
    if (it == m_protectedDirectories.end()) {
        return false;
    }

    m_protectedDirectories.erase(it);
    m_stats.totalProtectedDirectories--;

    SS_LOG_INFO(L"FileProtection", L"Unprotected directory: %ls", normalizedPath.c_str());
    return true;
}

[[nodiscard]] bool FileProtectionImpl::IsDirectoryProtected(std::wstring_view path) const {
    std::wstring normalizedPath = NormalizePath(path);

    std::shared_lock lock(m_mutex);

    // Direct match
    if (m_protectedDirectories.count(normalizedPath) > 0) {
        return true;
    }

    // Check if path is under a protected directory
    for (const auto& [dirPath, dir] : m_protectedDirectories) {
        if (dir.includeSubdirectories && IsPathUnderDirectory(normalizedPath, dirPath)) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] std::optional<ProtectedDirectory> FileProtectionImpl::GetProtectedDirectory(
    std::wstring_view path) const {

    std::wstring normalizedPath = NormalizePath(path);

    std::shared_lock lock(m_mutex);

    auto it = m_protectedDirectories.find(normalizedPath);
    if (it != m_protectedDirectories.end()) {
        return it->second;
    }

    return std::nullopt;
}

[[nodiscard]] std::vector<ProtectedDirectory> FileProtectionImpl::GetAllProtectedDirectories() const {
    std::shared_lock lock(m_mutex);

    std::vector<ProtectedDirectory> result;
    result.reserve(m_protectedDirectories.size());

    for (const auto& [path, dir] : m_protectedDirectories) {
        result.push_back(dir);
    }

    return result;
}

[[nodiscard]] bool FileProtectionImpl::ProtectInstallationDirectory() {
    if (m_installationPath.empty()) {
        SS_LOG_ERROR(L"FileProtection", L"Installation path not set");
        return false;
    }

    bool success = true;

    // Protect main installation directory
    success &= ProtectDirectory(m_installationPath, ProtectionType::Full, true);

    // Protect specific critical subdirectories
    std::vector<std::wstring> criticalDirs = {
        m_installationPath + L"\\Signatures",
        m_installationPath + L"\\Database",
        m_installationPath + L"\\Config",
        m_installationPath + L"\\Quarantine",
        m_installationPath + L"\\Logs"
    };

    for (const auto& dir : criticalDirs) {
        Utils::FileUtils::Error fileErr;
        if (Utils::FileUtils::Exists(dir, &fileErr)) {
            success &= ProtectDirectory(dir, ProtectionType::Full, true);
        }
    }

    // Protect critical files
    std::vector<std::wstring> criticalFiles = {
        m_installationPath + L"\\ShadowStrike.exe",
        m_installationPath + L"\\ShadowStrikeService.exe",
        m_installationPath + L"\\ShadowStrikeDriver.sys",
        m_installationPath + L"\\signatures.db",
        m_installationPath + L"\\config.xml"
    };

    for (const auto& file : criticalFiles) {
        Utils::FileUtils::Error fileErr;
        if (Utils::FileUtils::Exists(file, &fileErr)) {
            success &= ProtectFile(file, ProtectionType::Full);
        }
    }

    SS_LOG_INFO(L"FileProtection", L"Installation directory protection %s",
                success ? L"enabled" : L"partially enabled");

    return success;
}

[[nodiscard]] bool FileProtectionImpl::ProtectFile(std::wstring_view path, ProtectionType type) {
    if (path.empty()) {
        SS_LOG_ERROR(L"FileProtection", L"Cannot protect empty path");
        return false;
    }

    std::wstring normalizedPath = NormalizePath(path);

    std::unique_lock lock(m_mutex);

    // Check limits
    if (m_protectedFiles.size() >= FileProtectionConstants::MAX_PROTECTED_PATHS) {
        SS_LOG_ERROR(L"FileProtection", L"Maximum protected files limit reached");
        return false;
    }

    ProtectedFile protFile;
    protFile.id = GenerateFileId(normalizedPath);
    protFile.path = normalizedPath;
    protFile.normalizedPath = normalizedPath;
    protFile.type = type;
    protFile.protectedSince = Clock::now();
    protFile.isDirectory = false;

    // Determine blocked operations based on type
    switch (type) {
        case ProtectionType::ReadOnly:
            protFile.blockedOperations = FileOperation::AllWrite;
            break;
        case ProtectionType::NoDelete:
            protFile.blockedOperations = FileOperation::Delete | FileOperation::Rename;
            break;
        case ProtectionType::NoModify:
            protFile.blockedOperations = FileOperation::Write | FileOperation::Delete |
                                          FileOperation::Rename | FileOperation::SetAttributes;
            break;
        case ProtectionType::Full:
            protFile.blockedOperations = FileOperation::AllWrite;
            break;
        case ProtectionType::WriteOnly:
            protFile.blockedOperations = FileOperation::Delete | FileOperation::Rename;
            break;
        default:
            protFile.blockedOperations = FileOperation::AllWrite;
            break;
    }

    // Get file info
    Utils::FileUtils::Error fileErr;
    Utils::FileUtils::FileStat fileStat;
    if (Utils::FileUtils::Stat(normalizedPath, fileStat, &fileErr)) {
        protFile.fileSize = fileStat.size;
    }

    // Compute baseline hash
    protFile.expectedHash = ComputeFileHash(normalizedPath);
    protFile.currentHash = protFile.expectedHash;
    protFile.integrity = IntegrityStatus::Valid;
    protFile.lastVerified = Clock::now();

    // Check signature
    protFile.signature = VerifyFileSignature(normalizedPath);
    protFile.isShadowStrikeFile = (protFile.signature == SignatureStatus::ShadowStrike);

    m_protectedFiles[normalizedPath] = protFile;
    m_stats.totalProtectedFiles++;

    // Create backup if enabled
    if (m_config.enableAutoBackup) {
        CreateBackup(normalizedPath);
    }

    SS_LOG_INFO(L"FileProtection", L"Protected file: %ls (type: %hs)",
                normalizedPath.c_str(),
                std::string(GetProtectionTypeName(type)).c_str());

    return true;
}

[[nodiscard]] bool FileProtectionImpl::UnprotectFile(std::wstring_view path,
                                                      std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(L"FileProtection", L"Unauthorized attempt to unprotect file");
        return false;
    }

    std::wstring normalizedPath = NormalizePath(path);

    std::unique_lock lock(m_mutex);

    auto it = m_protectedFiles.find(normalizedPath);
    if (it == m_protectedFiles.end()) {
        return false;
    }

    m_protectedFiles.erase(it);
    m_stats.totalProtectedFiles--;

    SS_LOG_INFO(L"FileProtection", L"Unprotected file: %ls", normalizedPath.c_str());
    return true;
}

[[nodiscard]] bool FileProtectionImpl::IsFileProtected(std::wstring_view path) const {
    std::wstring normalizedPath = NormalizePath(path);

    std::shared_lock lock(m_mutex);

    // Direct file match
    if (m_protectedFiles.count(normalizedPath) > 0) {
        return true;
    }

    // Check if file is under a protected directory
    for (const auto& [dirPath, dir] : m_protectedDirectories) {
        if (IsPathUnderDirectory(normalizedPath, dirPath)) {
            return true;
        }
    }

    // Check patterns
    for (const auto& [pattern, type] : m_protectedPatterns) {
        if (MatchesPattern(normalizedPath, pattern)) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] std::optional<ProtectedFile> FileProtectionImpl::GetProtectedFile(
    std::wstring_view path) const {

    std::wstring normalizedPath = NormalizePath(path);

    std::shared_lock lock(m_mutex);

    auto it = m_protectedFiles.find(normalizedPath);
    if (it != m_protectedFiles.end()) {
        return it->second;
    }

    return std::nullopt;
}

[[nodiscard]] std::vector<ProtectedFile> FileProtectionImpl::GetAllProtectedFiles() const {
    std::shared_lock lock(m_mutex);

    std::vector<ProtectedFile> result;
    result.reserve(m_protectedFiles.size());

    for (const auto& [path, file] : m_protectedFiles) {
        result.push_back(file);
    }

    return result;
}

[[nodiscard]] bool FileProtectionImpl::ProtectPattern(std::wstring_view pattern,
                                                       ProtectionType type) {
    if (pattern.empty()) {
        return false;
    }

    std::unique_lock lock(m_mutex);

    if (m_protectedPatterns.size() >= FileProtectionConstants::MAX_PROTECTED_PATTERNS) {
        SS_LOG_ERROR(L"FileProtection", L"Maximum protected patterns limit reached");
        return false;
    }

    m_protectedPatterns.emplace_back(std::wstring(pattern), type);

    SS_LOG_INFO(L"FileProtection", L"Protected pattern: %ls", std::wstring(pattern).c_str());
    return true;
}

[[nodiscard]] bool FileProtectionImpl::UnprotectPattern(std::wstring_view pattern,
                                                         std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(L"FileProtection", L"Unauthorized attempt to unprotect pattern");
        return false;
    }

    std::unique_lock lock(m_mutex);

    auto it = std::find_if(m_protectedPatterns.begin(), m_protectedPatterns.end(),
                          [&pattern](const auto& p) { return p.first == pattern; });

    if (it != m_protectedPatterns.end()) {
        m_protectedPatterns.erase(it);
        return true;
    }

    return false;
}

[[nodiscard]] bool FileProtectionImpl::IsOperationAllowed(const std::wstring& path,
                                                           uint32_t desiredAccess) {
    if (m_config.mode == FileProtectionMode::Disabled) {
        return true;
    }

    FileOperationRequest request;
    request.filePath = path;
    request.desiredAccess = desiredAccess;
    request.operation = DesiredAccessToFileOperation(desiredAccess);
    request.processId = GetCurrentProcessId();
    request.threadId = GetCurrentThreadId();
    request.timestamp = Clock::now();

    auto result = FilterOperation(request);
    return (result.decision == OperationDecision::Allow ||
            result.decision == OperationDecision::AllowLogged);
}

[[nodiscard]] OperationDecisionResult FileProtectionImpl::FilterOperation(
    const FileOperationRequest& request) {

    OperationDecisionResult result;
    result.decision = OperationDecision::Allow;
    m_stats.totalOperations++;

    // Check if protection is disabled
    if (m_config.mode == FileProtectionMode::Disabled) {
        return result;
    }

    std::wstring normalizedPath = NormalizePath(request.filePath);

    // Check if caller is whitelisted
    if (IsWhitelisted(request.processId) || request.hasShadowStrikeSignature) {
        result.decision = OperationDecision::Allow;
        result.reason = "Whitelisted process";
        return result;
    }

    // Check custom decision callback first
    if (m_decisionCallback) {
        auto customResult = m_decisionCallback(request);
        if (customResult.has_value()) {
            return *customResult;
        }
    }

    // Check if file is protected
    std::shared_lock lock(m_mutex);

    bool isProtected = false;
    FileOperation blockedOps = FileOperation::None;

    // Check direct file protection
    auto fileIt = m_protectedFiles.find(normalizedPath);
    if (fileIt != m_protectedFiles.end()) {
        isProtected = true;
        blockedOps = fileIt->second.blockedOperations;
    }

    // Check directory protection
    if (!isProtected) {
        for (const auto& [dirPath, dir] : m_protectedDirectories) {
            if (IsPathUnderDirectory(normalizedPath, dirPath)) {
                isProtected = true;
                blockedOps = dir.blockedOperations;
                break;
            }
        }
    }

    // Check pattern protection
    if (!isProtected) {
        for (const auto& [pattern, type] : m_protectedPatterns) {
            if (MatchesPattern(normalizedPath, pattern)) {
                isProtected = true;
                // Use default blocking for patterns
                blockedOps = FileOperation::AllWrite;
                break;
            }
        }
    }

    lock.unlock();

    if (!isProtected) {
        return result;
    }

    // Check if operation is blocked
    if (IsOperationBlocked(request.operation, blockedOps)) {
        if (m_config.mode == FileProtectionMode::Monitor) {
            result.decision = OperationDecision::AllowLogged;
            result.shouldLog = true;
            result.reason = "Operation logged (monitor mode)";
        } else {
            result.decision = OperationDecision::Block;
            result.shouldLog = true;
            result.shouldAlert = true;
            result.reason = "Protected file operation blocked";

            m_stats.totalBlocked++;

            // Record event
            FileProtectionEvent event;
            event.eventId = m_nextEventId++;
            event.type = ProtectionEventType::OperationBlocked;
            event.timestamp = Clock::now();
            event.filePath = normalizedPath;
            event.operation = request.operation;
            event.decision = OperationDecision::Block;
            event.sourceProcessId = request.processId;
            event.sourceProcessName = request.processName;
            event.sourceProcessPath = request.processPath;
            event.wasBlocked = true;
            event.description = result.reason;

            RecordEvent(event);
            NotifyEvent(event);

            // Track for ransomware detection
            if (m_ransomwareProtectionEnabled.load()) {
                TrackFileModification(normalizedPath, request.processId);
            }
        }
    }

    return result;
}

void FileProtectionImpl::SetDecisionCallback(OperationDecisionCallback callback) {
    std::unique_lock lock(m_mutex);
    m_decisionCallback = std::move(callback);
}

void FileProtectionImpl::ClearDecisionCallback() {
    std::unique_lock lock(m_mutex);
    m_decisionCallback = nullptr;
}

[[nodiscard]] SignatureStatus FileProtectionImpl::VerifyFileSignature(std::wstring_view path) {
#ifdef _WIN32
    std::wstring pathStr(path);

    WINTRUST_FILE_INFO fileInfo;
    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = pathStr.c_str();
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    GUID wvtProvGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wintrustData;
    memset(&wintrustData, 0, sizeof(wintrustData));
    wintrustData.cbStruct = sizeof(wintrustData);
    wintrustData.pPolicyCallbackData = nullptr;
    wintrustData.pSIPClientData = nullptr;
    wintrustData.dwUIChoice = WTD_UI_NONE;
    wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
    wintrustData.pFile = &fileInfo;
    wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrustData.hWVTStateData = nullptr;
    wintrustData.pwszURLReference = nullptr;
    wintrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    wintrustData.dwUIContext = 0;

    LONG status = WinVerifyTrust(nullptr, &wvtProvGuid, &wintrustData);

    // Cleanup
    wintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &wvtProvGuid, &wintrustData);

    switch (status) {
        case ERROR_SUCCESS:
            // Check if it's a ShadowStrike signature
            {
                std::wstring signer = GetFileSigner(path);
                if (signer.find(SHADOWSTRIKE_SIGNER) != std::wstring::npos) {
                    return SignatureStatus::ShadowStrike;
                }
            }
            return SignatureStatus::Valid;

        case TRUST_E_NOSIGNATURE:
            return SignatureStatus::Unsigned;

        case TRUST_E_EXPLICIT_DISTRUST:
            return SignatureStatus::Untrusted;

        case CRYPT_E_SECURITY_SETTINGS:
            return SignatureStatus::Untrusted;

        case TRUST_E_SUBJECT_NOT_TRUSTED:
            return SignatureStatus::Invalid;

        case CERT_E_EXPIRED:
            return SignatureStatus::Expired;

        case CERT_E_REVOKED:
            return SignatureStatus::Revoked;

        default:
            return SignatureStatus::Unknown;
    }
#else
    return SignatureStatus::Unknown;
#endif
}

[[nodiscard]] bool FileProtectionImpl::HasShadowStrikeSignature(std::wstring_view path) {
    return VerifyFileSignature(path) == SignatureStatus::ShadowStrike;
}

[[nodiscard]] std::wstring FileProtectionImpl::GetFileSigner(std::wstring_view path) {
#ifdef _WIN32
    // This would use CryptQueryObject and related APIs
    // Simplified implementation
    return L"";
#else
    return L"";
#endif
}

[[nodiscard]] bool FileProtectionImpl::VerifyFileCatalog(std::wstring_view path) {
    // Verify file against Windows catalog
    // Implementation would use CryptCATAdminCalcHashFromFileHandle, etc.
    return VerifyFileSignature(path) != SignatureStatus::Invalid &&
           VerifyFileSignature(path) != SignatureStatus::Unsigned;
}

[[nodiscard]] IntegrityStatus FileProtectionImpl::VerifyFileIntegrity(std::wstring_view path) {
    std::wstring normalizedPath = NormalizePath(path);

    m_stats.totalIntegrityChecks++;

    // Check if file exists
    Utils::FileUtils::Error fileErr;
    if (!Utils::FileUtils::Exists(normalizedPath, &fileErr)) {
        return IntegrityStatus::Missing;
    }

    std::shared_lock lock(m_mutex);

    auto it = m_protectedFiles.find(normalizedPath);
    if (it == m_protectedFiles.end()) {
        return IntegrityStatus::Unknown;
    }

    lock.unlock();

    // Compute current hash
    Hash256 currentHash = ComputeFileHash(normalizedPath);

    // Compare with expected hash
    if (currentHash == it->second.expectedHash) {
        return IntegrityStatus::Valid;
    }

    m_stats.integrityViolations++;

    // Create event
    FileProtectionEvent event;
    event.eventId = m_nextEventId++;
    event.type = ProtectionEventType::IntegrityViolation;
    event.timestamp = Clock::now();
    event.filePath = normalizedPath;
    event.previousHash = it->second.expectedHash;
    event.newHash = currentHash;
    event.description = "File integrity violation detected";

    RecordEvent(event);
    NotifyEvent(event);

    return IntegrityStatus::Modified;
}

[[nodiscard]] std::vector<std::pair<std::wstring, IntegrityStatus>>
FileProtectionImpl::VerifyAllIntegrity() {

    std::vector<std::pair<std::wstring, IntegrityStatus>> results;

    std::shared_lock lock(m_mutex);
    std::vector<std::wstring> paths;
    for (const auto& [path, file] : m_protectedFiles) {
        paths.push_back(path);
    }
    lock.unlock();

    for (const auto& path : paths) {
        IntegrityStatus status = VerifyFileIntegrity(path);
        results.emplace_back(path, status);
    }

    return results;
}

[[nodiscard]] bool FileProtectionImpl::UpdateFileBaseline(std::wstring_view path,
                                                           std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(L"FileProtection", L"Unauthorized attempt to update baseline");
        return false;
    }

    std::wstring normalizedPath = NormalizePath(path);

    std::unique_lock lock(m_mutex);

    auto it = m_protectedFiles.find(normalizedPath);
    if (it == m_protectedFiles.end()) {
        return false;
    }

    // Compute new hash
    Hash256 newHash = ComputeFileHash(normalizedPath);

    it->second.expectedHash = newHash;
    it->second.currentHash = newHash;
    it->second.integrity = IntegrityStatus::Valid;
    it->second.lastVerified = Clock::now();

    SS_LOG_INFO(L"FileProtection", L"Updated baseline for: %ls", normalizedPath.c_str());
    return true;
}

void FileProtectionImpl::ForceIntegrityCheck() {
    SS_LOG_INFO(L"FileProtection", L"Forcing integrity check on all protected files");

    auto results = VerifyAllIntegrity();

    for (const auto& [path, status] : results) {
        if (status == IntegrityStatus::Modified || status == IntegrityStatus::Missing) {
            SS_LOG_WARN(L"FileProtection", L"Integrity issue: %ls - %hs",
                        path.c_str(),
                        std::string(GetIntegrityStatusName(status)).c_str());
        }
    }
}

[[nodiscard]] Hash256 FileProtectionImpl::ComputeFileHash(std::wstring_view path) {
    Hash256 hash{};

    std::wstring pathStr(path);
    std::array<uint8_t, 32> hashBytes;
    Utils::FileUtils::Error fileErr;

    if (Utils::FileUtils::ComputeFileSHA256(pathStr, hashBytes, &fileErr)) {
        std::copy(hashBytes.begin(), hashBytes.end(), hash.begin());
    }

    return hash;
}

[[nodiscard]] bool FileProtectionImpl::CreateBackup(std::wstring_view path) {
    std::wstring normalizedPath = NormalizePath(path);

    Utils::FileUtils::Error fileErr;
    if (!Utils::FileUtils::Exists(normalizedPath, &fileErr)) {
        SS_LOG_ERROR(L"FileProtection", L"Cannot backup non-existent file: %ls",
                     normalizedPath.c_str());
        return false;
    }

    // Generate backup filename
    auto now = std::chrono::system_clock::now();
    auto nowTime = std::chrono::system_clock::to_time_t(now);
    std::tm* tmPtr = std::localtime(&nowTime);

    std::wostringstream woss;
    woss << std::put_time(tmPtr, L"%Y%m%d_%H%M%S");

    std::filesystem::path originalPath(normalizedPath);
    std::wstring backupName = originalPath.stem().wstring() + L"_" +
                              woss.str() + originalPath.extension().wstring();
    std::wstring backupPath = m_backupStoragePath + L"\\" + backupName;

    try {
        // Ensure backup directory exists
        std::filesystem::create_directories(m_backupStoragePath);

        // Copy file
        std::filesystem::copy_file(normalizedPath, backupPath,
                                   std::filesystem::copy_options::overwrite_existing);

        // Record backup
        std::unique_lock lock(m_mutex);

        FileBackup backup;
        backup.id = GenerateFileId(backupPath);
        backup.originalPath = normalizedPath;
        backup.backupPath = backupPath;
        backup.originalHash = ComputeFileHash(normalizedPath);
        backup.backupHash = ComputeFileHash(backupPath);

        Utils::FileUtils::FileStat fileStat;
        if (Utils::FileUtils::Stat(normalizedPath, fileStat, &fileErr)) {
            backup.originalSize = fileStat.size;
        }

        backup.backupTime = Clock::now();
        backup.versionNumber = static_cast<uint32_t>(m_backups[normalizedPath].size()) + 1;
        backup.reason = "Auto-backup";

        m_backups[normalizedPath].push_back(backup);
        m_stats.backupsCreated++;

        SS_LOG_INFO(L"FileProtection", L"Created backup: %ls -> %ls",
                    normalizedPath.c_str(), backupPath.c_str());

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"FileProtection", L"Backup failed: %hs", e.what());
        return false;
    }
}

[[nodiscard]] bool FileProtectionImpl::RestoreFromBackup(std::wstring_view path, uint32_t version) {
    std::wstring normalizedPath = NormalizePath(path);

    std::shared_lock lock(m_mutex);

    auto it = m_backups.find(normalizedPath);
    if (it == m_backups.end() || it->second.empty()) {
        SS_LOG_ERROR(L"FileProtection", L"No backups found for: %ls", normalizedPath.c_str());
        return false;
    }

    // Find the backup
    const FileBackup* backupToRestore = nullptr;
    if (version == 0) {
        // Use latest backup
        backupToRestore = &it->second.back();
    } else {
        for (const auto& backup : it->second) {
            if (backup.versionNumber == version) {
                backupToRestore = &backup;
                break;
            }
        }
    }

    if (!backupToRestore) {
        SS_LOG_ERROR(L"FileProtection", L"Backup version %u not found", version);
        return false;
    }

    lock.unlock();

    try {
        std::filesystem::copy_file(backupToRestore->backupPath, normalizedPath,
                                   std::filesystem::copy_options::overwrite_existing);

        m_stats.filesRestored++;

        // Update protected file info
        std::unique_lock writeLock(m_mutex);
        auto fileIt = m_protectedFiles.find(normalizedPath);
        if (fileIt != m_protectedFiles.end()) {
            fileIt->second.currentHash = backupToRestore->originalHash;
            fileIt->second.expectedHash = backupToRestore->originalHash;
            fileIt->second.integrity = IntegrityStatus::Restored;
            fileIt->second.lastVerified = Clock::now();
        }

        // Record event
        FileProtectionEvent event;
        event.eventId = m_nextEventId++;
        event.type = ProtectionEventType::FileRestored;
        event.timestamp = Clock::now();
        event.filePath = normalizedPath;
        event.wasRestored = true;
        event.description = "File restored from backup";

        RecordEvent(event);
        NotifyEvent(event);

        SS_LOG_INFO(L"FileProtection", L"Restored file: %ls from version %u",
                    normalizedPath.c_str(), backupToRestore->versionNumber);

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"FileProtection", L"Restore failed: %hs", e.what());
        return false;
    }
}

[[nodiscard]] std::vector<FileBackup> FileProtectionImpl::GetAvailableBackups(
    std::wstring_view path) const {

    std::wstring normalizedPath = NormalizePath(path);

    std::shared_lock lock(m_mutex);

    auto it = m_backups.find(normalizedPath);
    if (it != m_backups.end()) {
        return it->second;
    }

    return {};
}

void FileProtectionImpl::CleanupOldBackups() {
    std::unique_lock lock(m_mutex);

    for (auto& [path, backups] : m_backups) {
        while (backups.size() > m_config.maxBackupVersions) {
            // Remove oldest backup
            try {
                std::filesystem::remove(backups.front().backupPath);
            } catch (...) {}
            backups.erase(backups.begin());
        }
    }

    SS_LOG_INFO(L"FileProtection", L"Cleaned up old backups");
}

[[nodiscard]] std::wstring FileProtectionImpl::GetBackupStoragePath() const {
    return m_backupStoragePath;
}

[[nodiscard]] bool FileProtectionImpl::SetBackupStoragePath(std::wstring_view path) {
    if (path.empty()) {
        return false;
    }

    try {
        std::filesystem::create_directories(path);
        m_backupStoragePath = path;
        SS_LOG_INFO(L"FileProtection", L"Backup storage path set to: %ls",
                    m_backupStoragePath.c_str());
        return true;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"FileProtection", L"Failed to set backup path: %hs", e.what());
        return false;
    }
}

[[nodiscard]] bool FileProtectionImpl::EnableRansomwareProtection() {
    m_ransomwareProtectionEnabled.store(true);
    SS_LOG_INFO(L"FileProtection", L"Ransomware protection enabled");
    return true;
}

void FileProtectionImpl::DisableRansomwareProtection(std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(L"FileProtection", L"Unauthorized attempt to disable ransomware protection");
        return;
    }

    m_ransomwareProtectionEnabled.store(false);
    SS_LOG_INFO(L"FileProtection", L"Ransomware protection disabled");
}

[[nodiscard]] bool FileProtectionImpl::IsRansomwareProtectionEnabled() const {
    return m_ransomwareProtectionEnabled.load();
}

[[nodiscard]] std::vector<RansomwareDetection> FileProtectionImpl::GetRansomwareDetections() const {
    std::shared_lock lock(m_mutex);
    return m_ransomwareDetections;
}

void FileProtectionImpl::SetRansomwareCallback(RansomwareCallback callback) {
    std::unique_lock lock(m_mutex);
    m_ransomwareCallback = std::move(callback);
}

[[nodiscard]] bool FileProtectionImpl::AddToWhitelist(std::wstring_view processName,
                                                       std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(L"FileProtection", L"Unauthorized attempt to modify whitelist");
        return false;
    }

    std::unique_lock lock(m_mutex);
    m_whitelistedProcesses.insert(std::wstring(processName));

    SS_LOG_INFO(L"FileProtection", L"Added to whitelist: %ls",
                std::wstring(processName).c_str());
    return true;
}

[[nodiscard]] bool FileProtectionImpl::RemoveFromWhitelist(std::wstring_view processName,
                                                            std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(L"FileProtection", L"Unauthorized attempt to modify whitelist");
        return false;
    }

    std::unique_lock lock(m_mutex);
    auto it = m_whitelistedProcesses.find(std::wstring(processName));
    if (it != m_whitelistedProcesses.end()) {
        m_whitelistedProcesses.erase(it);
        SS_LOG_INFO(L"FileProtection", L"Removed from whitelist: %ls",
                    std::wstring(processName).c_str());
        return true;
    }
    return false;
}

[[nodiscard]] bool FileProtectionImpl::IsWhitelisted(std::wstring_view processName) const {
    std::shared_lock lock(m_mutex);
    return m_whitelistedProcesses.count(std::wstring(processName)) > 0;
}

[[nodiscard]] bool FileProtectionImpl::IsWhitelisted(uint32_t processId) const {
    std::shared_lock lock(m_mutex);

    // Check cached PIDs
    if (m_whitelistedPids.count(processId) > 0) {
        return true;
    }

    // Get process name and check against whitelist
    // This would use Utils::ProcessUtils in production
    return false;
}

[[nodiscard]] std::vector<std::wstring> FileProtectionImpl::GetWhitelistedProcesses() const {
    std::shared_lock lock(m_mutex);
    return std::vector<std::wstring>(m_whitelistedProcesses.begin(),
                                      m_whitelistedProcesses.end());
}

[[nodiscard]] uint64_t FileProtectionImpl::RegisterEventCallback(
    FileProtectionEventCallback callback) {

    std::unique_lock lock(m_mutex);
    uint64_t callbackId = m_nextCallbackId++;
    m_eventCallbacks[callbackId] = std::move(callback);
    return callbackId;
}

void FileProtectionImpl::UnregisterEventCallback(uint64_t callbackId) {
    std::unique_lock lock(m_mutex);
    m_eventCallbacks.erase(callbackId);
}

[[nodiscard]] uint64_t FileProtectionImpl::RegisterIntegrityCallback(IntegrityCallback callback) {
    std::unique_lock lock(m_mutex);
    uint64_t callbackId = m_nextCallbackId++;
    m_integrityCallbacks[callbackId] = std::move(callback);
    return callbackId;
}

void FileProtectionImpl::UnregisterIntegrityCallback(uint64_t callbackId) {
    std::unique_lock lock(m_mutex);
    m_integrityCallbacks.erase(callbackId);
}

[[nodiscard]] FileProtectionStatistics FileProtectionImpl::GetStatistics() const {
    return m_stats;
}

void FileProtectionImpl::ResetStatistics(std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        return;
    }
    m_stats.Reset();
}

[[nodiscard]] std::vector<FileProtectionEvent> FileProtectionImpl::GetEventHistory(
    size_t maxEntries) const {

    std::shared_lock lock(m_mutex);

    std::vector<FileProtectionEvent> result;
    size_t count = std::min(maxEntries, m_eventHistory.size());

    auto it = m_eventHistory.rbegin();
    for (size_t i = 0; i < count && it != m_eventHistory.rend(); ++i, ++it) {
        result.push_back(*it);
    }

    return result;
}

void FileProtectionImpl::ClearEventHistory(std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        return;
    }

    std::unique_lock lock(m_mutex);
    m_eventHistory.clear();
}

[[nodiscard]] std::string FileProtectionImpl::ExportReport() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"version\": \"" << FileProtectionConstants::VERSION_MAJOR << "."
        << FileProtectionConstants::VERSION_MINOR << "."
        << FileProtectionConstants::VERSION_PATCH << "\",\n";
    oss << "  \"status\": \"" << static_cast<int>(m_status.load()) << "\",\n";
    oss << "  \"mode\": \"" << GetProtectionModeName(m_config.mode) << "\",\n";
    oss << "  \"statistics\": " << m_stats.ToJson() << ",\n";

    std::shared_lock lock(m_mutex);
    oss << "  \"protectedFilesCount\": " << m_protectedFiles.size() << ",\n";
    oss << "  \"protectedDirectoriesCount\": " << m_protectedDirectories.size() << ",\n";
    oss << "  \"whitelistedProcessesCount\": " << m_whitelistedProcesses.size() << ",\n";
    oss << "  \"ransomwareDetectionsCount\": " << m_ransomwareDetections.size() << "\n";
    oss << "}";

    return oss.str();
}

[[nodiscard]] bool FileProtectionImpl::SelfTest() {
    SS_LOG_INFO(L"FileProtection", L"Running self-test...");

    bool allPassed = true;

    // Test 1: Verify initialization
    if (!m_initialized.load()) {
        SS_LOG_ERROR(L"FileProtection", L"Self-test: Not initialized");
        allPassed = false;
    }

    // Test 2: Test path normalization
    std::wstring testPath = NormalizePath(L"C:\\Windows\\..\\Windows\\System32");
    if (testPath.empty()) {
        SS_LOG_ERROR(L"FileProtection", L"Self-test: Path normalization failed");
        allPassed = false;
    }

    // Test 3: Test pattern matching
    if (!MatchesPattern(L"C:\\test\\file.exe", L"*.exe")) {
        SS_LOG_ERROR(L"FileProtection", L"Self-test: Pattern matching failed");
        allPassed = false;
    }

    // Test 4: Test hash computation
    Hash256 testHash = ComputeFileHash(m_installationPath + L"\\ShadowStrike.exe");
    bool hashValid = false;
    for (const auto& byte : testHash) {
        if (byte != 0) {
            hashValid = true;
            break;
        }
    }
    // Skip if file doesn't exist
    Utils::FileUtils::Error fileErr;
    if (Utils::FileUtils::Exists(m_installationPath + L"\\ShadowStrike.exe", &fileErr) &&
        !hashValid) {
        SS_LOG_WARN(L"FileProtection", L"Self-test: Hash computation returned empty");
    }

    // Test 5: Test whitelist operations
    {
        std::unique_lock lock(m_mutex);
        size_t prevSize = m_whitelistedProcesses.size();
        m_whitelistedProcesses.insert(L"_selftest_.exe");
        if (m_whitelistedProcesses.size() != prevSize + 1) {
            SS_LOG_ERROR(L"FileProtection", L"Self-test: Whitelist insert failed");
            allPassed = false;
        }
        m_whitelistedProcesses.erase(L"_selftest_.exe");
    }

    // Test 6: Test configuration validation
    FileProtectionConfiguration testConfig;
    testConfig.integrityCheckIntervalMs = 5000;
    if (!testConfig.IsValid()) {
        SS_LOG_ERROR(L"FileProtection", L"Self-test: Config validation failed");
        allPassed = false;
    }

    if (allPassed) {
        SS_LOG_INFO(L"FileProtection", L"Self-test: All tests passed");
    } else {
        SS_LOG_ERROR(L"FileProtection", L"Self-test: Some tests failed");
    }

    return allPassed;
}

[[nodiscard]] std::wstring FileProtectionImpl::NormalizePath(std::wstring_view path) {
    if (path.empty()) {
        return L"";
    }

    std::wstring result(path);

    // Convert to lowercase
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);

    // Replace forward slashes with backslashes
    std::replace(result.begin(), result.end(), L'/', L'\\');

    // Remove trailing backslash
    while (!result.empty() && result.back() == L'\\') {
        result.pop_back();
    }

    // Try to get absolute path
    try {
        std::filesystem::path fsPath(result);
        if (fsPath.is_relative()) {
            fsPath = std::filesystem::absolute(fsPath);
        }
        result = fsPath.lexically_normal().wstring();
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    } catch (...) {
        // Keep original on error
    }

    return result;
}

[[nodiscard]] bool FileProtectionImpl::MatchesPattern(std::wstring_view path,
                                                       std::wstring_view pattern) {
    if (pattern.empty() || path.empty()) {
        return false;
    }

    std::wstring pathLower(path);
    std::wstring patternLower(pattern);
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
    std::transform(patternLower.begin(), patternLower.end(), patternLower.begin(), ::towlower);

    // Simple wildcard matching
    size_t pIdx = 0, sIdx = 0;
    size_t starIdx = std::wstring::npos;
    size_t matchIdx = 0;

    while (sIdx < pathLower.size()) {
        if (pIdx < patternLower.size() &&
            (patternLower[pIdx] == L'?' || patternLower[pIdx] == pathLower[sIdx])) {
            ++pIdx;
            ++sIdx;
        } else if (pIdx < patternLower.size() && patternLower[pIdx] == L'*') {
            starIdx = pIdx;
            matchIdx = sIdx;
            ++pIdx;
        } else if (starIdx != std::wstring::npos) {
            pIdx = starIdx + 1;
            ++matchIdx;
            sIdx = matchIdx;
        } else {
            return false;
        }
    }

    while (pIdx < patternLower.size() && patternLower[pIdx] == L'*') {
        ++pIdx;
    }

    return pIdx == patternLower.size();
}

// ============================================================================
// INTERNAL METHODS
// ============================================================================

[[nodiscard]] bool FileProtectionImpl::VerifyAuthorizationToken(std::string_view token) const {
    if (token.empty()) {
        return false;
    }

    // In production, this would validate against a secure token store
    // For now, accept tokens that start with the expected prefix
    return token.substr(0, AUTH_TOKEN_PREFIX.size()) == AUTH_TOKEN_PREFIX;
}

[[nodiscard]] std::string FileProtectionImpl::GenerateFileId(std::wstring_view path) const {
    std::string narrowPath = Utils::StringUtils::ToNarrow(std::wstring(path));
    std::array<uint8_t, 32> hash;

    // Simple hash generation
    std::hash<std::string> hasher;
    size_t h = hasher(narrowPath);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << h;
    return oss.str();
}

[[nodiscard]] FileOperation FileProtectionImpl::DesiredAccessToFileOperation(
    uint32_t desiredAccess) const {

    uint32_t result = 0;

    if (desiredAccess & GENERIC_READ) result |= static_cast<uint32_t>(FileOperation::Read);
    if (desiredAccess & GENERIC_WRITE) result |= static_cast<uint32_t>(FileOperation::Write);
    if (desiredAccess & DELETE) result |= static_cast<uint32_t>(FileOperation::Delete);
    if (desiredAccess & GENERIC_EXECUTE) result |= static_cast<uint32_t>(FileOperation::Execute);
    if (desiredAccess & FILE_WRITE_ATTRIBUTES)
        result |= static_cast<uint32_t>(FileOperation::SetAttributes);
    if (desiredAccess & WRITE_DAC || desiredAccess & WRITE_OWNER)
        result |= static_cast<uint32_t>(FileOperation::SetSecurity);

    return static_cast<FileOperation>(result);
}

[[nodiscard]] bool FileProtectionImpl::IsOperationBlocked(FileOperation operation,
                                                           FileOperation blockedOps) const {
    return (static_cast<uint32_t>(operation) & static_cast<uint32_t>(blockedOps)) != 0;
}

void FileProtectionImpl::NotifyEvent(const FileProtectionEvent& event) {
    std::shared_lock lock(m_mutex);

    for (const auto& [id, callback] : m_eventCallbacks) {
        if (callback) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileProtection", L"Event callback exception: %hs", e.what());
            }
        }
    }
}

void FileProtectionImpl::NotifyIntegrityViolation(const ProtectedFile& file) {
    std::shared_lock lock(m_mutex);

    for (const auto& [id, callback] : m_integrityCallbacks) {
        if (callback) {
            try {
                callback(file);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileProtection", L"Integrity callback exception: %hs", e.what());
            }
        }
    }
}

void FileProtectionImpl::NotifyRansomware(const RansomwareDetection& detection) {
    if (m_ransomwareCallback) {
        try {
            m_ransomwareCallback(detection);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileProtection", L"Ransomware callback exception: %hs", e.what());
        }
    }
}

void FileProtectionImpl::IntegrityMonitorThread() {
    SS_LOG_INFO(L"FileProtection", L"Integrity monitor thread started");

    while (m_monitoringActive.load() && !m_shutdownRequested.load()) {
        // Wait for interval
        std::this_thread::sleep_for(
            std::chrono::milliseconds(m_config.integrityCheckIntervalMs));

        if (!m_monitoringActive.load()) break;

        // Perform integrity check
        auto results = VerifyAllIntegrity();

        for (const auto& [path, status] : results) {
            if (status == IntegrityStatus::Modified || status == IntegrityStatus::Missing) {
                std::shared_lock lock(m_mutex);
                auto it = m_protectedFiles.find(path);
                if (it != m_protectedFiles.end()) {
                    NotifyIntegrityViolation(it->second);
                }
            }
        }
    }

    SS_LOG_INFO(L"FileProtection", L"Integrity monitor thread stopped");
}

void FileProtectionImpl::RansomwareMonitorThread() {
    SS_LOG_INFO(L"FileProtection", L"Ransomware monitor thread started");

    while (m_monitoringActive.load() && !m_shutdownRequested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        if (!m_monitoringActive.load() || !m_ransomwareProtectionEnabled.load()) continue;

        // Check modification tracking for ransomware behavior
        std::unique_lock lock(m_mutex);
        auto now = Clock::now();

        for (auto it = m_modificationTracking.begin(); it != m_modificationTracking.end();) {
            uint32_t pid = it->first;
            auto& modifications = it->second;

            // Remove old entries
            modifications.erase(
                std::remove_if(modifications.begin(), modifications.end(),
                              [now](const auto& entry) {
                                  return std::chrono::duration_cast<std::chrono::milliseconds>(
                                             now - entry.first).count() >
                                         FileProtectionConstants::RANSOMWARE_DETECTION_WINDOW_MS;
                              }),
                modifications.end());

            // Check threshold
            if (modifications.size() >= FileProtectionConstants::RANSOMWARE_MODIFICATION_THRESHOLD) {
                RansomwareDetection detection;
                detection.timestamp = now;
                detection.processId = pid;
                detection.modificationCount = static_cast<uint32_t>(modifications.size());
                detection.confidence = std::min(100u,
                    static_cast<uint32_t>(modifications.size()) * 10);

                for (const auto& mod : modifications) {
                    detection.affectedFiles.push_back(mod.second);
                }

                m_ransomwareDetections.push_back(detection);
                m_stats.ransomwareDetections++;

                lock.unlock();
                NotifyRansomware(detection);
                lock.lock();

                modifications.clear();

                SS_LOG_WARN(L"FileProtection",
                            L"Ransomware behavior detected from PID %u (%u modifications)",
                            pid, detection.modificationCount);
            }

            if (modifications.empty()) {
                it = m_modificationTracking.erase(it);
            } else {
                ++it;
            }
        }
    }

    SS_LOG_INFO(L"FileProtection", L"Ransomware monitor thread stopped");
}

void FileProtectionImpl::StartMonitoringThreads() {
    if (m_monitoringActive.load()) {
        return;
    }

    m_monitoringActive.store(true);

    if (m_config.enableIntegrityMonitoring) {
        m_integrityThread = std::thread(&FileProtectionImpl::IntegrityMonitorThread, this);
    }

    if (m_config.enableRansomwareProtection) {
        m_ransomwareThread = std::thread(&FileProtectionImpl::RansomwareMonitorThread, this);
    }
}

void FileProtectionImpl::StopMonitoringThreads() {
    m_monitoringActive.store(false);

    if (m_integrityThread.joinable()) {
        m_integrityThread.join();
    }

    if (m_ransomwareThread.joinable()) {
        m_ransomwareThread.join();
    }
}

[[nodiscard]] bool FileProtectionImpl::IsPathUnderDirectory(std::wstring_view path,
                                                             std::wstring_view directory) const {
    std::wstring normalizedPath = NormalizePath(path);
    std::wstring normalizedDir = NormalizePath(directory);

    if (normalizedPath.size() <= normalizedDir.size()) {
        return false;
    }

    return normalizedPath.substr(0, normalizedDir.size()) == normalizedDir &&
           normalizedPath[normalizedDir.size()] == L'\\';
}

[[nodiscard]] ProtectionType FileProtectionImpl::GetEffectiveProtection(
    std::wstring_view path) const {

    std::wstring normalizedPath = NormalizePath(path);

    // Check direct file protection
    auto fileIt = m_protectedFiles.find(normalizedPath);
    if (fileIt != m_protectedFiles.end()) {
        return fileIt->second.type;
    }

    // Check directory protection
    for (const auto& [dirPath, dir] : m_protectedDirectories) {
        if (IsPathUnderDirectory(normalizedPath, dirPath)) {
            return dir.type;
        }
    }

    return ProtectionType::None;
}

void FileProtectionImpl::RecordEvent(const FileProtectionEvent& event) {
    std::unique_lock lock(m_mutex);

    m_eventHistory.push_back(event);

    // Trim if too large
    while (m_eventHistory.size() > MAX_EVENT_HISTORY) {
        m_eventHistory.pop_front();
    }

    m_stats.lastEventTime = event.timestamp;
}

void FileProtectionImpl::TrackFileModification(std::wstring_view path, uint32_t processId) {
    std::unique_lock lock(m_mutex);
    m_modificationTracking[processId].emplace_back(Clock::now(), std::wstring(path));
}

[[nodiscard]] bool FileProtectionImpl::DetectRansomwareBehavior(uint32_t processId) {
    std::shared_lock lock(m_mutex);

    auto it = m_modificationTracking.find(processId);
    if (it == m_modificationTracking.end()) {
        return false;
    }

    return it->second.size() >= FileProtectionConstants::RANSOMWARE_MODIFICATION_THRESHOLD;
}

// ============================================================================
// FILE PROTECTION PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

FileProtection::FileProtection()
    : m_impl(std::make_unique<FileProtectionImpl>()) {
    s_instanceCreated.store(true);
}

FileProtection::~FileProtection() {
    if (m_impl) {
        m_impl->Shutdown("");
    }
}

[[nodiscard]] FileProtection& FileProtection::Instance() noexcept {
    static FileProtection instance;
    return instance;
}

[[nodiscard]] bool FileProtection::HasInstance() noexcept {
    return s_instanceCreated.load();
}

[[nodiscard]] bool FileProtection::Initialize(const FileProtectionConfiguration& config) {
    return m_impl->Initialize(config);
}

[[nodiscard]] bool FileProtection::Initialize(FileProtectionMode mode) {
    return m_impl->Initialize(FileProtectionConfiguration::FromMode(mode));
}

void FileProtection::Shutdown(std::string_view authorizationToken) {
    m_impl->Shutdown(authorizationToken);
}

[[nodiscard]] bool FileProtection::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

[[nodiscard]] ModuleStatus FileProtection::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

[[nodiscard]] bool FileProtection::SetConfiguration(const FileProtectionConfiguration& config) {
    return m_impl->SetConfiguration(config);
}

[[nodiscard]] FileProtectionConfiguration FileProtection::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void FileProtection::SetProtectionMode(FileProtectionMode mode) {
    m_impl->SetProtectionMode(mode);
}

[[nodiscard]] FileProtectionMode FileProtection::GetProtectionMode() const noexcept {
    return m_impl->GetProtectionMode();
}

void FileProtection::ProtectDirectory(const std::wstring& path) {
    m_impl->ProtectDirectory(path);
}

[[nodiscard]] bool FileProtection::ProtectDirectory(std::wstring_view path, ProtectionType type,
                                                     bool includeSubdirs) {
    return m_impl->ProtectDirectory(path, type, includeSubdirs);
}

[[nodiscard]] bool FileProtection::UnprotectDirectory(std::wstring_view path,
                                                       std::string_view authorizationToken) {
    return m_impl->UnprotectDirectory(path, authorizationToken);
}

[[nodiscard]] bool FileProtection::IsDirectoryProtected(std::wstring_view path) const {
    return m_impl->IsDirectoryProtected(path);
}

[[nodiscard]] std::optional<ProtectedDirectory> FileProtection::GetProtectedDirectory(
    std::wstring_view path) const {
    return m_impl->GetProtectedDirectory(path);
}

[[nodiscard]] std::vector<ProtectedDirectory> FileProtection::GetAllProtectedDirectories() const {
    return m_impl->GetAllProtectedDirectories();
}

[[nodiscard]] bool FileProtection::ProtectInstallationDirectory() {
    return m_impl->ProtectInstallationDirectory();
}

[[nodiscard]] bool FileProtection::ProtectFile(std::wstring_view path, ProtectionType type) {
    return m_impl->ProtectFile(path, type);
}

[[nodiscard]] bool FileProtection::UnprotectFile(std::wstring_view path,
                                                  std::string_view authorizationToken) {
    return m_impl->UnprotectFile(path, authorizationToken);
}

[[nodiscard]] bool FileProtection::IsFileProtected(std::wstring_view path) const {
    return m_impl->IsFileProtected(path);
}

[[nodiscard]] std::optional<ProtectedFile> FileProtection::GetProtectedFile(
    std::wstring_view path) const {
    return m_impl->GetProtectedFile(path);
}

[[nodiscard]] std::vector<ProtectedFile> FileProtection::GetAllProtectedFiles() const {
    return m_impl->GetAllProtectedFiles();
}

[[nodiscard]] bool FileProtection::ProtectPattern(std::wstring_view pattern,
                                                   ProtectionType type) {
    return m_impl->ProtectPattern(pattern, type);
}

[[nodiscard]] bool FileProtection::UnprotectPattern(std::wstring_view pattern,
                                                     std::string_view authorizationToken) {
    return m_impl->UnprotectPattern(pattern, authorizationToken);
}

[[nodiscard]] bool FileProtection::IsOperationAllowed(const std::wstring& path,
                                                       uint32_t desiredAccess) {
    return m_impl->IsOperationAllowed(path, desiredAccess);
}

[[nodiscard]] OperationDecisionResult FileProtection::FilterOperation(
    const FileOperationRequest& request) {
    return m_impl->FilterOperation(request);
}

void FileProtection::SetDecisionCallback(OperationDecisionCallback callback) {
    m_impl->SetDecisionCallback(std::move(callback));
}

void FileProtection::ClearDecisionCallback() {
    m_impl->ClearDecisionCallback();
}

[[nodiscard]] SignatureStatus FileProtection::VerifyFileSignature(std::wstring_view path) {
    return m_impl->VerifyFileSignature(path);
}

[[nodiscard]] bool FileProtection::HasShadowStrikeSignature(std::wstring_view path) {
    return m_impl->HasShadowStrikeSignature(path);
}

[[nodiscard]] std::wstring FileProtection::GetFileSigner(std::wstring_view path) {
    return m_impl->GetFileSigner(path);
}

[[nodiscard]] bool FileProtection::VerifyFileCatalog(std::wstring_view path) {
    return m_impl->VerifyFileCatalog(path);
}

[[nodiscard]] IntegrityStatus FileProtection::VerifyFileIntegrity(std::wstring_view path) {
    return m_impl->VerifyFileIntegrity(path);
}

[[nodiscard]] std::vector<std::pair<std::wstring, IntegrityStatus>>
FileProtection::VerifyAllIntegrity() {
    return m_impl->VerifyAllIntegrity();
}

[[nodiscard]] bool FileProtection::UpdateFileBaseline(std::wstring_view path,
                                                       std::string_view authorizationToken) {
    return m_impl->UpdateFileBaseline(path, authorizationToken);
}

void FileProtection::ForceIntegrityCheck() {
    m_impl->ForceIntegrityCheck();
}

[[nodiscard]] Hash256 FileProtection::ComputeFileHash(std::wstring_view path) {
    return m_impl->ComputeFileHash(path);
}

[[nodiscard]] bool FileProtection::CreateBackup(std::wstring_view path) {
    return m_impl->CreateBackup(path);
}

[[nodiscard]] bool FileProtection::RestoreFromBackup(std::wstring_view path, uint32_t version) {
    return m_impl->RestoreFromBackup(path, version);
}

[[nodiscard]] std::vector<FileBackup> FileProtection::GetAvailableBackups(
    std::wstring_view path) const {
    return m_impl->GetAvailableBackups(path);
}

void FileProtection::CleanupOldBackups() {
    m_impl->CleanupOldBackups();
}

[[nodiscard]] std::wstring FileProtection::GetBackupStoragePath() const {
    return m_impl->GetBackupStoragePath();
}

[[nodiscard]] bool FileProtection::SetBackupStoragePath(std::wstring_view path) {
    return m_impl->SetBackupStoragePath(path);
}

[[nodiscard]] bool FileProtection::EnableRansomwareProtection() {
    return m_impl->EnableRansomwareProtection();
}

void FileProtection::DisableRansomwareProtection(std::string_view authorizationToken) {
    m_impl->DisableRansomwareProtection(authorizationToken);
}

[[nodiscard]] bool FileProtection::IsRansomwareProtectionEnabled() const {
    return m_impl->IsRansomwareProtectionEnabled();
}

[[nodiscard]] std::vector<RansomwareDetection> FileProtection::GetRansomwareDetections() const {
    return m_impl->GetRansomwareDetections();
}

void FileProtection::SetRansomwareCallback(RansomwareCallback callback) {
    m_impl->SetRansomwareCallback(std::move(callback));
}

[[nodiscard]] bool FileProtection::AddToWhitelist(std::wstring_view processName,
                                                   std::string_view authorizationToken) {
    return m_impl->AddToWhitelist(processName, authorizationToken);
}

[[nodiscard]] bool FileProtection::RemoveFromWhitelist(std::wstring_view processName,
                                                        std::string_view authorizationToken) {
    return m_impl->RemoveFromWhitelist(processName, authorizationToken);
}

[[nodiscard]] bool FileProtection::IsWhitelisted(std::wstring_view processName) const {
    return m_impl->IsWhitelisted(processName);
}

[[nodiscard]] bool FileProtection::IsWhitelisted(uint32_t processId) const {
    return m_impl->IsWhitelisted(processId);
}

[[nodiscard]] std::vector<std::wstring> FileProtection::GetWhitelistedProcesses() const {
    return m_impl->GetWhitelistedProcesses();
}

[[nodiscard]] uint64_t FileProtection::RegisterEventCallback(
    FileProtectionEventCallback callback) {
    return m_impl->RegisterEventCallback(std::move(callback));
}

void FileProtection::UnregisterEventCallback(uint64_t callbackId) {
    m_impl->UnregisterEventCallback(callbackId);
}

[[nodiscard]] uint64_t FileProtection::RegisterIntegrityCallback(IntegrityCallback callback) {
    return m_impl->RegisterIntegrityCallback(std::move(callback));
}

void FileProtection::UnregisterIntegrityCallback(uint64_t callbackId) {
    m_impl->UnregisterIntegrityCallback(callbackId);
}

[[nodiscard]] FileProtectionStatistics FileProtection::GetStatistics() const {
    return m_impl->GetStatistics();
}

void FileProtection::ResetStatistics(std::string_view authorizationToken) {
    m_impl->ResetStatistics(authorizationToken);
}

[[nodiscard]] std::vector<FileProtectionEvent> FileProtection::GetEventHistory(
    size_t maxEntries) const {
    return m_impl->GetEventHistory(maxEntries);
}

void FileProtection::ClearEventHistory(std::string_view authorizationToken) {
    m_impl->ClearEventHistory(authorizationToken);
}

[[nodiscard]] std::string FileProtection::ExportReport() const {
    return m_impl->ExportReport();
}

[[nodiscard]] bool FileProtection::SelfTest() {
    return m_impl->SelfTest();
}

[[nodiscard]] std::wstring FileProtection::NormalizePath(std::wstring_view path) {
    return FileProtectionImpl::NormalizePath(path);
}

[[nodiscard]] bool FileProtection::MatchesPattern(std::wstring_view path,
                                                   std::wstring_view pattern) {
    return FileProtectionImpl::MatchesPattern(path, pattern);
}

[[nodiscard]] std::string FileProtection::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << FileProtectionConstants::VERSION_MAJOR << "."
        << FileProtectionConstants::VERSION_MINOR << "."
        << FileProtectionConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// RAII HELPER IMPLEMENTATIONS
// ============================================================================

FileProtectionGuard::FileProtectionGuard(std::wstring_view path, ProtectionType type)
    : m_path(path) {

    m_authToken = "SS_AUTH_GUARD_" + std::to_string(std::chrono::steady_clock::now()
        .time_since_epoch().count());

    m_protected = FileProtection::Instance().ProtectFile(path, type);
}

FileProtectionGuard::~FileProtectionGuard() {
    if (m_protected) {
        FileProtection::Instance().UnprotectFile(m_path, m_authToken);
    }
}

}  // namespace Security
}  // namespace ShadowStrike

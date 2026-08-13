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

#include "pch.h"
#include "FileProtection.hpp"
#include "SelfDefense.hpp"   // SelfDefenseConstants::CRITICAL_INSTALLED_FILES
#include "../Utils/PE_sig_verf.hpp"
#include "../Communication/IPCManager.hpp"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// Standard library includes
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cctype>
#include <queue>
#include <fstream>
#include <random>

namespace ShadowStrike {
namespace Security {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> FileProtection::s_instanceCreated{false};

// ============================================================================
// JSON ESCAPING HELPER (HIGH-01: prevent log injection via crafted paths)
// ============================================================================

static std::string JsonEscape(std::string_view input) {
    std::string result;
    result.reserve(input.size() + 16);
    for (char c : input) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b";  break;
            case '\f': result += "\\f";  break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    result += buf;
                } else {
                    result += c;
                }
                break;
        }
    }
    return result;
}

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

[[nodiscard]] std::string_view GetIntegrityStatusName(FileIntegrityStatus status) noexcept {
    switch (status) {
        case FileIntegrityStatus::Unknown:   return "Unknown";
        case FileIntegrityStatus::Valid:     return "Valid";
        case FileIntegrityStatus::Modified:  return "Modified";
        case FileIntegrityStatus::Missing:   return "Missing";
        case FileIntegrityStatus::Corrupted: return "Corrupted";
        case FileIntegrityStatus::New:       return "New";
        case FileIntegrityStatus::Restored:  return "Restored";
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
            config.defaultResponse = FileProtectionResponse::None;
            break;

        case FileProtectionMode::Monitor:
            config.enableKernelFiltering = true;
            config.enableSignatureValidation = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoBackup = false;
            config.enableRansomwareProtection = true;
            config.enableRealTimeMonitoring = true;
            config.defaultResponse = FileProtectionResponse::Passive;
            break;

        case FileProtectionMode::Protect:
            config.enableKernelFiltering = true;
            config.enableSignatureValidation = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoBackup = true;
            config.enableRansomwareProtection = true;
            config.enableRealTimeMonitoring = true;
            config.defaultResponse = FileProtectionResponse::Active;
            break;

        case FileProtectionMode::Strict:
            config.enableKernelFiltering = true;
            config.enableSignatureValidation = true;
            config.requireShadowStrikeSignature = true;
            config.enableIntegrityMonitoring = true;
            config.enableAutoBackup = true;
            config.enableRansomwareProtection = true;
            config.enableRealTimeMonitoring = true;
            config.defaultResponse = FileProtectionResponse::Aggressive;
            break;
    }

    return config;
}

[[nodiscard]] std::string FileProtectionEvent::GetSummary() const {
    std::ostringstream oss;
    oss << "Event[" << eventId << "]: ";

    switch (type) {
        case FileProtectionEventType::OperationBlocked:
            oss << "Blocked " << GetFileOperationName(operation) << " on ";
            break;
        case FileProtectionEventType::IntegrityViolation:
            oss << "Integrity violation on ";
            break;
        case FileProtectionEventType::RansomwareDetected:
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
    oss << "\"filePath\":\"" << JsonEscape(Utils::StringUtils::ToNarrow(filePath)) << "\",";
    oss << "\"operation\":\"" << GetFileOperationName(operation) << "\",";
    oss << "\"decision\":" << static_cast<int>(decision) << ",";
    oss << "\"sourceProcessId\":" << sourceProcessId << ",";
    oss << "\"sourceProcessName\":\"" << JsonEscape(Utils::StringUtils::ToNarrow(sourceProcessName)) << "\",";
    oss << "\"wasBlocked\":" << (wasBlocked ? "true" : "false") << ",";
    oss << "\"description\":\"" << JsonEscape(description) << "\"";
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string FileProtectionStatistics::ToJson() const {
    auto now = Clock::now();
    auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();

    std::ostringstream oss;
    oss << "{";
    oss << "\"totalProtectedFiles\":" << totalProtectedFiles << ",";
    oss << "\"totalProtectedDirectories\":" << totalProtectedDirectories << ",";
    oss << "\"totalOperations\":" << totalOperations << ",";
    oss << "\"totalBlocked\":" << totalBlocked << ",";
    oss << "\"totalIntegrityChecks\":" << totalIntegrityChecks << ",";
    oss << "\"integrityViolations\":" << integrityViolations << ",";
    oss << "\"signatureViolations\":" << signatureViolations << ",";
    oss << "\"ransomwareDetections\":" << ransomwareDetections << ",";
    oss << "\"backupsCreated\":" << backupsCreated << ",";
    oss << "\"filesRestored\":" << filesRestored << ",";
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
    [[nodiscard]] FileOperationDecisionResult FilterOperation(const FileOperationRequest& request);
    void SetDecisionCallback(FileOperationDecisionCallback callback);
    void ClearDecisionCallback();

    // Signature validation
    [[nodiscard]] SignatureStatus VerifyFileSignature(std::wstring_view path) const;
    [[nodiscard]] bool HasShadowStrikeSignature(std::wstring_view path);
    [[nodiscard]] std::wstring GetFileSigner(std::wstring_view path) const;
    [[nodiscard]] bool VerifyFileCatalog(std::wstring_view path);

    // Integrity management
    [[nodiscard]] FileIntegrityStatus VerifyFileIntegrity(std::wstring_view path);
    [[nodiscard]] std::vector<std::pair<std::wstring, FileIntegrityStatus>> VerifyAllIntegrity();
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
    [[nodiscard]] uint64_t RegisterIntegrityCallback(FileIntegrityCallback callback);
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

    // Kernel bridge + auth (called by public FileProtection facade)
    [[nodiscard]] std::string GenerateAuthorizationToken() const;
    void SyncProtectedPathsToKernel();
    void OnKernelBlockEventInternal(const void* data, uint32_t size);

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

    // CRIT-02 FIX: HMAC-based authorization — prefix is validated against
    // a per-session secret generated at initialization time.
    static constexpr size_t AUTH_TOKEN_SIZE = 64;

    // MED-01 FIX: Cap tracked PIDs for ransomware detection to prevent DoS.
    static constexpr size_t MAX_TRACKED_PIDS = 4096;
    static constexpr size_t MAX_MODS_PER_PID = 200;

    // ========================================================================
    // INTERNAL ATOMIC STATISTICS (non-copyable, stays inside PIMPL)
    // ========================================================================

    struct InternalStats {
        std::atomic<uint64_t> totalProtectedFiles{0};
        std::atomic<uint64_t> totalProtectedDirectories{0};
        std::atomic<uint64_t> totalOperations{0};
        std::atomic<uint64_t> totalBlocked{0};
        std::atomic<uint64_t> totalIntegrityChecks{0};
        std::atomic<uint64_t> integrityViolations{0};
        std::atomic<uint64_t> signatureViolations{0};
        std::atomic<uint64_t> ransomwareDetections{0};
        std::atomic<uint64_t> backupsCreated{0};
        std::atomic<uint64_t> filesRestored{0};
        TimePoint startTime = Clock::now();
        std::atomic<uint64_t> lastEventTimeNs{0};

        void Reset() noexcept {
            totalProtectedFiles.store(0, std::memory_order_relaxed);
            totalProtectedDirectories.store(0, std::memory_order_relaxed);
            totalOperations.store(0, std::memory_order_relaxed);
            totalBlocked.store(0, std::memory_order_relaxed);
            totalIntegrityChecks.store(0, std::memory_order_relaxed);
            integrityViolations.store(0, std::memory_order_relaxed);
            signatureViolations.store(0, std::memory_order_relaxed);
            ransomwareDetections.store(0, std::memory_order_relaxed);
            backupsCreated.store(0, std::memory_order_relaxed);
            filesRestored.store(0, std::memory_order_relaxed);
            startTime = Clock::now();
            lastEventTimeNs.store(0, std::memory_order_relaxed);
        }

        [[nodiscard]] FileProtectionStatistics Snapshot() const noexcept {
            FileProtectionStatistics s;
            s.totalProtectedFiles      = totalProtectedFiles.load(std::memory_order_relaxed);
            s.totalProtectedDirectories = totalProtectedDirectories.load(std::memory_order_relaxed);
            s.totalOperations          = totalOperations.load(std::memory_order_relaxed);
            s.totalBlocked             = totalBlocked.load(std::memory_order_relaxed);
            s.totalIntegrityChecks     = totalIntegrityChecks.load(std::memory_order_relaxed);
            s.integrityViolations      = integrityViolations.load(std::memory_order_relaxed);
            s.signatureViolations      = signatureViolations.load(std::memory_order_relaxed);
            s.ransomwareDetections     = ransomwareDetections.load(std::memory_order_relaxed);
            s.backupsCreated           = backupsCreated.load(std::memory_order_relaxed);
            s.filesRestored            = filesRestored.load(std::memory_order_relaxed);
            s.startTime                = startTime;
            auto ns = lastEventTimeNs.load(std::memory_order_relaxed);
            if (ns > 0) {
                s.lastEventTime = TimePoint(std::chrono::nanoseconds(ns));
            }
            return s;
        }
    };

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shutdownRequested{false};

    FileProtectionConfiguration m_config;
    InternalStats m_stats;

    // CRIT-02 FIX: Per-session authorization secret (generated once at init)
    std::string m_authSecret;

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
    std::unordered_map<uint64_t, FileIntegrityCallback> m_integrityCallbacks;
    FileOperationDecisionCallback m_decisionCallback;
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

    // Per-session HMAC secret for authorization tokens. Use BCryptGenRandom
    // (CNG kernel-level CSPRNG) — mt19937 seeded from a single std::random_device
    // call yields a 32-bit seed that an attacker with code access can brute-force,
    // defeating the entire authorization-token scheme.
    {
        m_authSecret.assign(AUTH_TOKEN_SIZE, '\0');
        NTSTATUS rngStatus = BCryptGenRandom(
            nullptr,
            reinterpret_cast<PUCHAR>(m_authSecret.data()),
            static_cast<ULONG>(AUTH_TOKEN_SIZE),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(rngStatus)) {
            SS_LOG_ERROR(L"FileProtection",
                         L"BCryptGenRandom failed for auth secret: 0x%08lx", rngStatus);
            SecureZeroMemory(m_authSecret.data(), m_authSecret.size());
            m_authSecret.clear();
            m_status.store(ModuleStatus::Error);
            return false;
        }
    }

    // Apply whitelisted processes from config (lower-cased for canonical
    // comparison with the lookup paths in FilterOperation / IsWhitelisted).
    for (const auto& proc : config.whitelistedProcesses) {
        std::wstring lower(proc);
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        m_whitelistedProcesses.insert(std::move(lower));
    }

    // Create backup directory if needed
    if (config.enableAutoBackup) {
        try {
            std::filesystem::create_directories(m_backupStoragePath);
        } catch (const std::exception& e) {
            SS_LOG_WARN(L"FileProtection", L"Failed to create backup directory: %hs", e.what());
        }

        // HIGH-03 FIX: Auto-protect the backup directory
        if (!m_backupStoragePath.empty()) {
            ProtectedDirectory backupDir;
            backupDir.id = GenerateFileId(m_backupStoragePath);
            backupDir.path = m_backupStoragePath;
            backupDir.type = ProtectionType::Full;
            backupDir.includeSubdirectories = true;
            backupDir.protectedSince = Clock::now();
            m_protectedDirectories[NormalizePath(m_backupStoragePath)] = backupDir;
            m_stats.totalProtectedDirectories.fetch_add(1, std::memory_order_relaxed);
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

    // WIRE-02: Sync protected paths to kernel driver after initialization
    // Release lock first — kernel bridge may block on filter port I/O
    lock.unlock();
    SyncProtectedPathsToKernel();

    // WIRE-03: Register handler for kernel-side file protection block events
    try {
        auto& ipc = Communication::IPCManager::Instance();
        ipc.RegisterGenericHandler(
            [this](SHADOWSTRIKE_MESSAGE_TYPE msgType, const void* data, size_t size) {
                if (msgType == FilterMessageType_SelfProtectAlert) {
                    OnKernelBlockEventInternal(data, static_cast<uint32_t>(size));
                }
            });
        SS_LOG_DEBUG(L"FileProtection", L"Registered kernel SelfProtect alert handler");
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"FileProtection", L"Failed to register kernel event handler: %hs (kernel may not be loaded)", e.what());
    }

    return true;
}

void FileProtectionImpl::Shutdown(std::string_view authorizationToken) {
    // Require valid token for non-destructor callers
    if (!authorizationToken.empty() && !VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(L"FileProtection", L"Unauthorized shutdown attempt blocked");
        return;
    }

    // Atomically mark as uninitialized; only one caller proceeds
    bool wasInitialized = m_initialized.exchange(false);
    if (!wasInitialized) {
        return;
    }

    m_status.store(ModuleStatus::Stopping);
    m_shutdownRequested.store(true);

    // FIX: Unregister kernel event handler BEFORE stopping threads.
    // The lambda captured `this`; if IPCManager dispatches after destruction,
    // we get use-after-free.
    try {
        if (Communication::IPCManager::HasInstance()) {
            Communication::IPCManager::Instance().RegisterGenericHandler(nullptr);
        }
    } catch (...) {
        // IPCManager may already be torn down during process exit
    }

    // Stop monitoring threads BEFORE taking the lock.
    // Threads acquire shared_lock internally; joining under our unique_lock
    // would deadlock.
    StopMonitoringThreads();

    // Now safe to take exclusive lock for state cleanup
    {
        std::unique_lock lock(m_mutex);
        m_eventCallbacks.clear();
        m_integrityCallbacks.clear();
        m_decisionCallback = nullptr;
        m_ransomwareCallback = nullptr;
    }

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

    bool needStartMonitoring = false;
    bool needStopMonitoring = false;

    {
        std::unique_lock lock(m_mutex);
        bool wasRealTimeEnabled = m_config.enableRealTimeMonitoring;
        m_config = config;

        // Sync whitelisted processes, protected directories, and protected
        // patterns from the new configuration into the live in-memory state.
        // Previously this method only stored the config struct, so policy
        // changes from runtime callers were silently ignored by the filter.
        for (const auto& proc : config.whitelistedProcesses) {
            std::wstring lower(proc);
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            m_whitelistedProcesses.insert(std::move(lower));
        }

        for (const auto& dir : config.protectedDirectories) {
            auto key = NormalizePath(dir);
            if (key.empty() ||
                m_protectedDirectories.size() >= FileProtectionConstants::MAX_PROTECTED_PATHS) {
                continue;
            }
            if (m_protectedDirectories.count(key) > 0) {
                continue;
            }
            ProtectedDirectory protDir;
            protDir.id = GenerateFileId(key);
            protDir.path = key;
            protDir.type = ProtectionType::Full;
            protDir.includeSubdirectories = true;
            protDir.protectedSince = Clock::now();
            protDir.blockedOperations = FileOperation::AllWrite;
            m_protectedDirectories.emplace(std::move(key), std::move(protDir));
            m_stats.totalProtectedDirectories.fetch_add(1, std::memory_order_relaxed);
        }

        for (const auto& pattern : config.protectedPatterns) {
            if (pattern.empty() ||
                m_protectedPatterns.size() >= FileProtectionConstants::MAX_PROTECTED_PATTERNS) {
                continue;
            }
            auto exists = std::any_of(m_protectedPatterns.begin(), m_protectedPatterns.end(),
                                      [&pattern](const auto& p) { return p.first == pattern; });
            if (!exists) {
                m_protectedPatterns.emplace_back(pattern, ProtectionType::Full);
            }
        }

        if (config.enableRealTimeMonitoring && !wasRealTimeEnabled) {
            needStartMonitoring = true;
        } else if (!config.enableRealTimeMonitoring && wasRealTimeEnabled) {
            needStopMonitoring = true;
        }
    }

    // Thread join/launch outside lock to avoid deadlock — monitoring threads
    // acquire shared_lock internally.
    if (needStopMonitoring) {
        StopMonitoringThreads();
    } else if (needStartMonitoring) {
        StartMonitoringThreads();
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
    std::shared_lock lock(m_mutex);
    return m_config.mode;
}

void FileProtectionImpl::ProtectDirectory(const std::wstring& path) {
    if (!ProtectDirectory(path, ProtectionType::Full, true)) {
        SS_LOG_WARN(L"FileProtection", L"ProtectDirectory default request failed: %ls", path.c_str());
    }
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
    m_stats.totalProtectedDirectories.fetch_add(1, std::memory_order_relaxed);

    SS_LOG_INFO(L"FileProtection", L"Protected directory: %ls (type: %hs, subdirs: %hs)",
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
    m_stats.totalProtectedDirectories.fetch_sub(1, std::memory_order_relaxed);

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

    // Protect critical files. Shared with TamperProtection through
    // SelfDefenseConstants, because the two hand-written copies had drifted: of the
    // five names previously listed here, only ShadowStrikePhantomService.exe is a file
    // the installer ships. ShadowStrikeDriver.sys, signatures.db, config.xml and
    // ShadowStrike.exe do not exist under those names, so this protected one file out
    // of five while reporting success.
    std::vector<std::wstring> criticalFiles;
    criticalFiles.reserve(SelfDefenseConstants::CRITICAL_INSTALLED_FILES.size());
    for (const auto& rel : SelfDefenseConstants::CRITICAL_INSTALLED_FILES) {
        criticalFiles.emplace_back(m_installationPath + L"\\" + std::wstring(rel));
    }

    for (const auto& file : criticalFiles) {
        Utils::FileUtils::Error fileErr;
        if (Utils::FileUtils::Exists(file, &fileErr)) {
            success &= ProtectFile(file, ProtectionType::Full);
        }
    }

    SS_LOG_INFO(L"FileProtection", L"Installation directory protection %ls",
                success ? L"enabled" : L"partially enabled");

    return success;
}

[[nodiscard]] bool FileProtectionImpl::ProtectFile(std::wstring_view path, ProtectionType type) {
    if (path.empty()) {
        SS_LOG_ERROR(L"FileProtection", L"Cannot protect empty path");
        return false;
    }

    std::wstring normalizedPath = NormalizePath(path);

    // CRIT-03 FIX: Perform ALL I/O (hashing, signature, stat) OUTSIDE the lock.
    // Only map insertion happens under the exclusive lock.
    Utils::FileUtils::Error fileErr;
    Utils::FileUtils::FileStat fileStat;
    uint64_t fileSize = 0;
    if (Utils::FileUtils::Stat(normalizedPath, fileStat, &fileErr)) {
        fileSize = fileStat.size;
    }

    Hash256 hash = ComputeFileHash(normalizedPath);
    SignatureStatus sig = VerifyFileSignature(normalizedPath);

    // Now take the lock for map operations only
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

    protFile.fileSize = fileSize;
    protFile.expectedHash = hash;
    protFile.currentHash = hash;
    protFile.integrity = FileIntegrityStatus::Valid;
    protFile.lastVerified = Clock::now();
    protFile.signature = sig;
    protFile.isShadowStrikeFile = (sig == SignatureStatus::ShadowStrike);

    m_protectedFiles[normalizedPath] = protFile;
    m_stats.totalProtectedFiles.fetch_add(1, std::memory_order_relaxed);

    lock.unlock();

    // Create backup if enabled (I/O — do outside lock)
    if (m_config.enableAutoBackup && !CreateBackup(normalizedPath)) {
        SS_LOG_WARN(L"FileProtection", L"Automatic backup failed for protected file: %ls", normalizedPath.c_str());
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
    m_stats.totalProtectedFiles.fetch_sub(1, std::memory_order_relaxed);

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
    FileOperationRequest request;
    request.filePath = path;
    request.desiredAccess = desiredAccess;
    request.operation = DesiredAccessToFileOperation(desiredAccess);
    request.processId = GetCurrentProcessId();
    request.threadId = GetCurrentThreadId();
    request.timestamp = Clock::now();

    auto result = FilterOperation(request);
    return (result.decision == FileOperationDecision::Allow ||
            result.decision == FileOperationDecision::AllowLogged);
}

[[nodiscard]] FileOperationDecisionResult FileProtectionImpl::FilterOperation(
    const FileOperationRequest& request) {

    FileOperationDecisionResult result;
    result.decision = FileOperationDecision::Allow;
    m_stats.totalOperations.fetch_add(1, std::memory_order_relaxed);

    std::wstring normalizedPath = NormalizePath(request.filePath);

    // Snapshot all shared state under a single lock acquisition to avoid
    // multiple lock cycles and data-race on m_config / m_decisionCallback.
    FileProtectionMode currentMode;
    FileOperationDecisionCallback callbackCopy;
    bool isWhitelisted = false;
    bool isProtected = false;
    FileOperation blockedOps = FileOperation::None;

    {
        std::shared_lock lock(m_mutex);

        currentMode = m_config.mode;
        if (currentMode == FileProtectionMode::Disabled) {
            return result;
        }

        // Whitelist check — inline to avoid recursive lock.
        // SECURITY: `request.hasShadowStrikeSignature` is caller-asserted and
        // therefore untrusted (an external caller can simply set the flag to
        // bypass protection). We rely exclusively on the in-process whitelist
        // (pids/names) and the kernel-driver signature check (IsWhitelisted(pid)).
        if (m_whitelistedPids.count(request.processId) > 0) {
            isWhitelisted = true;
        } else if (!request.processName.empty()) {
            std::wstring nameLower(request.processName);
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
            if (m_whitelistedProcesses.count(nameLower) > 0) {
                isWhitelisted = true;
            }
        }

        if (isWhitelisted) {
            result.reason = "Whitelisted process";
            return result;
        }

        // Snapshot callback
        callbackCopy = m_decisionCallback;

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
                    blockedOps = FileOperation::AllWrite;
                    break;
                }
            }
        }
    } // shared_lock released

    // Custom decision callback invoked outside lock to avoid holding lock
    // during potentially long user callback.
    if (callbackCopy) {
        try {
            auto customResult = callbackCopy(request);
            if (customResult.has_value()) {
                return *customResult;
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileProtection",
                         L"Decision callback threw exception: %hs", e.what());
        }
    }

    if (!isProtected) {
        return result;
    }

    // Check if operation is blocked
    if (IsOperationBlocked(request.operation, blockedOps)) {
        if (currentMode == FileProtectionMode::Monitor) {
            result.decision = FileOperationDecision::AllowLogged;
            result.shouldLog = true;
            result.reason = "Operation logged (monitor mode)";
        } else {
            result.decision = FileOperationDecision::Block;
            result.shouldLog = true;
            result.shouldAlert = true;
            result.reason = "Protected file operation blocked";

            m_stats.totalBlocked.fetch_add(1, std::memory_order_relaxed);

            // Record event
            FileProtectionEvent event;
            event.eventId = m_nextEventId++;
            event.type = FileProtectionEventType::OperationBlocked;
            event.timestamp = Clock::now();
            event.filePath = normalizedPath;
            event.operation = request.operation;
            event.decision = FileOperationDecision::Block;
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

void FileProtectionImpl::SetDecisionCallback(FileOperationDecisionCallback callback) {
    std::unique_lock lock(m_mutex);
    m_decisionCallback = std::move(callback);
}

void FileProtectionImpl::ClearDecisionCallback() {
    std::unique_lock lock(m_mutex);
    m_decisionCallback = nullptr;
}

[[nodiscard]] SignatureStatus FileProtectionImpl::VerifyFileSignature(std::wstring_view path) const {
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

[[nodiscard]] std::wstring FileProtectionImpl::GetFileSigner(std::wstring_view path) const {
#ifdef _WIN32
    Utils::pe_sig_utils::PEFileSignatureVerifier verifier;
    Utils::pe_sig_utils::SignatureInfo sigInfo;
    Utils::pe_sig_utils::Error sigErr;

    if (verifier.VerifyPESignature(path, sigInfo, &sigErr) && sigInfo.isSigned) {
        return sigInfo.signerName;
    }

    // If embedded signature verification failed, try catalog-based lookup
    if (verifier.VerifyEmbeddedSignature(path, sigInfo, &sigErr) && sigInfo.isSigned) {
        return sigInfo.signerName;
    }

    SS_LOG_DEBUG(L"FileProtection", L"No signer found for: %ls (error: %ls)",
                 std::wstring(path).c_str(), sigErr.message.c_str());
    return L"";
#else
    return L"";
#endif
}

[[nodiscard]] bool FileProtectionImpl::VerifyFileCatalog(std::wstring_view path) {
#ifdef _WIN32
    Utils::pe_sig_utils::PEFileSignatureVerifier verifier;
    Utils::pe_sig_utils::SignatureInfo sigInfo;
    Utils::pe_sig_utils::Error sigErr;

    // First try direct embedded signature
    if (verifier.VerifyPESignature(path, sigInfo, &sigErr)) {
        return sigInfo.isSigned && sigInfo.isVerified && sigInfo.isChainTrusted;
    }

    // Fall back to embedded-only check (catalog-backed files)
    if (verifier.VerifyEmbeddedSignature(path, sigInfo, &sigErr)) {
        return sigInfo.isSigned && sigInfo.isVerified;
    }

    return false;
#else
    return false;
#endif
}

[[nodiscard]] FileIntegrityStatus FileProtectionImpl::VerifyFileIntegrity(std::wstring_view path) {
    std::wstring normalizedPath = NormalizePath(path);

    m_stats.totalIntegrityChecks.fetch_add(1, std::memory_order_relaxed);

    // Check if file exists
    Utils::FileUtils::Error fileErr;
    if (!Utils::FileUtils::Exists(normalizedPath, &fileErr)) {
        return FileIntegrityStatus::Missing;
    }

    // Copy expected hash under lock; iterator is invalid after unlock
    Hash256 expectedHash{};
    bool found = false;
    {
        std::shared_lock lock(m_mutex);
        auto it = m_protectedFiles.find(normalizedPath);
        if (it != m_protectedFiles.end()) {
            expectedHash = it->second.expectedHash;
            found = true;
        }
    }

    if (!found) {
        return FileIntegrityStatus::Unknown;
    }

    // Compute current hash (I/O-heavy — done outside lock)
    Hash256 currentHash = ComputeFileHash(normalizedPath);

    if (currentHash == expectedHash) {
        return FileIntegrityStatus::Valid;
    }

    m_stats.integrityViolations.fetch_add(1, std::memory_order_relaxed);

    // Create and record event
    FileProtectionEvent event;
    event.eventId = m_nextEventId++;
    event.type = FileProtectionEventType::IntegrityViolation;
    event.timestamp = Clock::now();
    event.filePath = normalizedPath;
    event.previousHash = expectedHash;
    event.newHash = currentHash;
    event.description = "File integrity violation detected";

    RecordEvent(event);
    NotifyEvent(event);

    // Notify integrity callbacks with current file state
    {
        std::shared_lock lock(m_mutex);
        auto it = m_protectedFiles.find(normalizedPath);
        if (it != m_protectedFiles.end()) {
            NotifyIntegrityViolation(it->second);
        }
    }

    return FileIntegrityStatus::Modified;
}

[[nodiscard]] std::vector<std::pair<std::wstring, FileIntegrityStatus>>
FileProtectionImpl::VerifyAllIntegrity() {

    std::vector<std::pair<std::wstring, FileIntegrityStatus>> results;

    std::shared_lock lock(m_mutex);
    std::vector<std::wstring> paths;
    for (const auto& [path, file] : m_protectedFiles) {
        paths.push_back(path);
    }
    lock.unlock();

    for (const auto& path : paths) {
        FileIntegrityStatus status = VerifyFileIntegrity(path);
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

    // MED-04 FIX: Do hashing outside the lock. Same issue as CRIT-03.
    Hash256 newHash = ComputeFileHash(normalizedPath);

    std::unique_lock lock(m_mutex);

    auto it = m_protectedFiles.find(normalizedPath);
    if (it == m_protectedFiles.end()) {
        return false;
    }

    it->second.expectedHash = newHash;
    it->second.currentHash = newHash;
    it->second.integrity = FileIntegrityStatus::Valid;
    it->second.lastVerified = Clock::now();

    SS_LOG_INFO(L"FileProtection", L"Updated baseline for: %ls", normalizedPath.c_str());
    return true;
}

void FileProtectionImpl::ForceIntegrityCheck() {
    SS_LOG_INFO(L"FileProtection", L"Forcing integrity check on all protected files");

    auto results = VerifyAllIntegrity();

    for (const auto& [path, status] : results) {
        if (status == FileIntegrityStatus::Modified || status == FileIntegrityStatus::Missing) {
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

    // Snapshot the backup storage path under a shared_lock — SetBackupStoragePath
    // may run concurrently. Holding the path by value lets the I/O below run
    // unsynchronized with respect to that mutator.
    std::wstring storageRoot;
    {
        std::shared_lock lock(m_mutex);
        storageRoot = m_backupStoragePath;
    }
    if (storageRoot.empty()) {
        SS_LOG_ERROR(L"FileProtection", L"Backup storage path is not configured");
        return false;
    }

    // Generate backup filename
    auto now = std::chrono::system_clock::now();
    auto nowTime = std::chrono::system_clock::to_time_t(now);
    std::tm tmBuf{};
    localtime_s(&tmBuf, &nowTime);

    std::wostringstream woss;
    woss << std::put_time(&tmBuf, L"%Y%m%d_%H%M%S");

    std::filesystem::path originalPath(normalizedPath);
    std::wstring backupName = originalPath.stem().wstring() + L"_" +
                              woss.str() + originalPath.extension().wstring();
    std::wstring backupPath = storageRoot + L"\\" + backupName;

    try {
        // Ensure backup directory exists
        std::filesystem::create_directories(storageRoot);

        // Copy file (I/O — done before taking the lock)
        std::filesystem::copy_file(normalizedPath, backupPath,
                                   std::filesystem::copy_options::overwrite_existing);

        // Hashing is I/O-heavy; compute before taking the exclusive map lock.
        Hash256 originalHash = ComputeFileHash(normalizedPath);
        Hash256 backupHash = ComputeFileHash(backupPath);

        uint64_t originalSize = 0;
        Utils::FileUtils::FileStat fileStat;
        if (Utils::FileUtils::Stat(normalizedPath, fileStat, &fileErr)) {
            originalSize = fileStat.size;
        }

        // Record backup
        std::unique_lock lock(m_mutex);

        FileBackup backup;
        backup.id = GenerateFileId(backupPath);
        backup.originalPath = normalizedPath;
        backup.backupPath = backupPath;
        backup.originalHash = originalHash;
        backup.backupHash = backupHash;
        backup.originalSize = originalSize;
        backup.backupTime = Clock::now();
        backup.versionNumber = static_cast<uint32_t>(m_backups[normalizedPath].size()) + 1;
        backup.reason = "Auto-backup";

        m_backups[normalizedPath].push_back(backup);
        m_stats.backupsCreated.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"FileProtection", L"Created backup: %ls -> %ls",
                    normalizedPath.c_str(), backupPath.c_str());

        return true;

    } catch (const std::filesystem::filesystem_error& e) {
        SS_LOG_ERROR(L"FileProtection", L"Backup filesystem error: %hs", e.what());
        return false;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"FileProtection", L"Backup failed: %hs", e.what());
        return false;
    }
}

[[nodiscard]] bool FileProtectionImpl::RestoreFromBackup(std::wstring_view path, uint32_t version) {
    std::wstring normalizedPath = NormalizePath(path);

    // Copy the chosen backup struct out by value before releasing the lock —
    // a const pointer into the vector becomes dangling the moment we drop
    // the lock, because a concurrent CreateBackup() push_back can reallocate.
    FileBackup backupCopy;
    {
        std::shared_lock lock(m_mutex);
        auto it = m_backups.find(normalizedPath);
        if (it == m_backups.end() || it->second.empty()) {
            SS_LOG_ERROR(L"FileProtection", L"No backups found for: %ls", normalizedPath.c_str());
            return false;
        }

        const FileBackup* backupToRestore = nullptr;
        if (version == 0) {
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

        backupCopy = *backupToRestore;
    }

    try {
        std::filesystem::copy_file(backupCopy.backupPath, normalizedPath,
                                   std::filesystem::copy_options::overwrite_existing);

        m_stats.filesRestored.fetch_add(1, std::memory_order_relaxed);

        // Update protected file info
        std::unique_lock writeLock(m_mutex);
        auto fileIt = m_protectedFiles.find(normalizedPath);
        if (fileIt != m_protectedFiles.end()) {
            fileIt->second.currentHash = backupCopy.originalHash;
            fileIt->second.expectedHash = backupCopy.originalHash;
            fileIt->second.integrity = FileIntegrityStatus::Restored;
            fileIt->second.lastVerified = Clock::now();
        }
        writeLock.unlock();

        // Record event
        FileProtectionEvent event;
        event.eventId = m_nextEventId.fetch_add(1);
        event.type = FileProtectionEventType::FileRestored;
        event.timestamp = Clock::now();
        event.filePath = normalizedPath;
        event.wasRestored = true;
        event.description = "File restored from backup";

        RecordEvent(event);
        NotifyEvent(event);

        SS_LOG_INFO(L"FileProtection", L"Restored file: %ls from version %u",
                    normalizedPath.c_str(), backupCopy.versionNumber);

        return true;

    } catch (const std::filesystem::filesystem_error& e) {
        SS_LOG_ERROR(L"FileProtection", L"Restore filesystem error: %hs", e.what());
        return false;
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
            } catch (const std::exception& e) {
                SS_LOG_WARN(L"FileProtection",
                            L"Failed to remove old backup '%ls': %hs",
                            backups.front().backupPath.c_str(), e.what());
            }
            backups.erase(backups.begin());
        }
    }

    SS_LOG_DEBUG(L"FileProtection", L"Cleaned up old backups");
}

[[nodiscard]] std::wstring FileProtectionImpl::GetBackupStoragePath() const {
    std::shared_lock lock(m_mutex);
    return m_backupStoragePath;
}

[[nodiscard]] bool FileProtectionImpl::SetBackupStoragePath(std::wstring_view path) {
    if (path.empty()) {
        return false;
    }

    try {
        std::filesystem::create_directories(path);

        std::unique_lock lock(m_mutex);

        // HIGH-03 FIX: Remove protection from old backup dir, add to new one
        if (!m_backupStoragePath.empty()) {
            m_protectedDirectories.erase(NormalizePath(m_backupStoragePath));
        }

        m_backupStoragePath = path;

        ProtectedDirectory backupDir;
        backupDir.id = GenerateFileId(m_backupStoragePath);
        backupDir.path = std::wstring(m_backupStoragePath);
        backupDir.type = ProtectionType::Full;
        backupDir.includeSubdirectories = true;
        backupDir.protectedSince = Clock::now();
        m_protectedDirectories[NormalizePath(m_backupStoragePath)] = backupDir;

        SS_LOG_INFO(L"FileProtection", L"Backup storage path set to: %ls (auto-protected)",
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
    if (processName.empty()) {
        return false;
    }

    // Whitelist lookups in IsWhitelisted(uint32_t) lower-case the resolved
    // process name before comparing; store the canonical lowercase form here
    // so name-based whitelisting actually matches at policy-decision time.
    std::wstring nameLower(processName);
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

    std::unique_lock lock(m_mutex);
    m_whitelistedProcesses.insert(nameLower);

    SS_LOG_INFO(L"FileProtection", L"Added to whitelist: %ls", nameLower.c_str());
    return true;
}

[[nodiscard]] bool FileProtectionImpl::RemoveFromWhitelist(std::wstring_view processName,
                                                            std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(L"FileProtection", L"Unauthorized attempt to modify whitelist");
        return false;
    }
    if (processName.empty()) {
        return false;
    }

    std::wstring nameLower(processName);
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

    std::unique_lock lock(m_mutex);
    auto it = m_whitelistedProcesses.find(nameLower);
    if (it != m_whitelistedProcesses.end()) {
        m_whitelistedProcesses.erase(it);
        SS_LOG_INFO(L"FileProtection", L"Removed from whitelist: %ls", nameLower.c_str());
        return true;
    }
    return false;
}

[[nodiscard]] bool FileProtectionImpl::IsWhitelisted(std::wstring_view processName) const {
    std::wstring nameLower(processName);
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
    std::shared_lock lock(m_mutex);
    return m_whitelistedProcesses.count(nameLower) > 0;
}

[[nodiscard]] bool FileProtectionImpl::IsWhitelisted(uint32_t processId) const {
    std::shared_lock lock(m_mutex);

    // Check cached PIDs
    if (m_whitelistedPids.count(processId) > 0) {
        return true;
    }

    // Resolve process name and check against name whitelist
    auto nameOpt = Utils::ProcessUtils::GetProcessName(
        static_cast<Utils::ProcessUtils::ProcessId>(processId));
    if (!nameOpt.has_value()) {
        return false;
    }

    std::wstring nameLower = *nameOpt;
    std::transform(nameLower.begin(), nameLower.end(),
                   nameLower.begin(), ::towlower);
    if (m_whitelistedProcesses.count(nameLower) == 0) {
        return false;
    }

    // HIGH-02 FIX: Validate process image signature to prevent name-spoofing bypass.
    // An attacker can trivially rename a malicious executable to match a whitelisted name.
    auto pathOpt = Utils::ProcessUtils::GetProcessPath(
        static_cast<Utils::ProcessUtils::ProcessId>(processId));
    if (!pathOpt.has_value()) {
        SS_LOG_WARN(L"FileProtection", L"Whitelist check for PID %u: cannot resolve image path, denying", processId);
        return false;
    }

    SignatureStatus sig = VerifyFileSignature(*pathOpt);
    if (sig != SignatureStatus::Valid && sig != SignatureStatus::ShadowStrike) {
        SS_LOG_WARN(L"FileProtection", L"Whitelist bypass attempt: PID %u name '%ls' is unsigned/untrusted",
                    processId, nameLower.c_str());
        return false;
    }

    return true;
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

[[nodiscard]] uint64_t FileProtectionImpl::RegisterIntegrityCallback(FileIntegrityCallback callback) {
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
    return m_stats.Snapshot();
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

    std::shared_lock lock(m_mutex);
    oss << "  \"mode\": \"" << GetProtectionModeName(m_config.mode) << "\",\n";
    oss << "  \"statistics\": " << m_stats.Snapshot().ToJson() << ",\n";
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
    //
    // Hash the running module, which is guaranteed to exist. This used to hash
    // m_installationPath + "\\ShadowStrike.exe" - a file this product does not
    // install - and then suppressed the failure with an Exists() check, so the test
    // passed without ever computing a hash. A self-test that cannot fail is worse
    // than no self-test, because it reports coverage that is not there.
    WCHAR selfTestModule[MAX_PATH] = {};
    if (::GetModuleFileNameW(nullptr, selfTestModule, MAX_PATH) == 0) {
        SS_LOG_WARN(L"FileProtection",
                    L"Self-test: cannot determine the running module path, so hash "
                    L"computation was not exercised");
    } else {
        const std::wstring selfPath(selfTestModule);
        Hash256 testHash = ComputeFileHash(selfPath);
        bool hashValid = false;
        for (const auto& byte : testHash) {
            if (byte != 0) {
                hashValid = true;
                break;
            }
        }
        if (!hashValid) {
            SS_LOG_ERROR(L"FileProtection",
                         L"Self-test: hash computation returned all zeroes for %ls, "
                         L"which exists - file integrity hashing is not working",
                         selfPath.c_str());
            allPassed = false;
        }
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

    // Validate path length
    if (path.size() > FileProtectionConstants::MAX_PATH_LENGTH) {
        SS_LOG_WARN(L"FileProtection", L"Path exceeds maximum length (%zu)", path.size());
        return L"";
    }

    std::wstring result(path);

    // Strip NTFS Alternate Data Streams to prevent protection bypass via
    // paths like "file.exe:evil_stream". The search must skip:
    //   - the drive-letter colon at index 1 (e.g. "C:")
    //   - the long-path/device prefixes "\\?\" and "\\.\" which embed "C:"
    //   - UNC prefixes "\\server\share" which contain no colon
    size_t adsSearchStart = 0;
    if (result.size() >= 2 && result[1] == L':') {
        adsSearchStart = 2;
    } else if (result.size() >= 4 &&
               result[0] == L'\\' && result[1] == L'\\' &&
               (result[2] == L'?' || result[2] == L'.') &&
               result[3] == L'\\') {
        // Skip the "\\?\" or "\\.\" prefix and the drive-letter colon that
        // follows (e.g. "\\?\C:\..." → start search after the second backslash).
        if (result.size() >= 6 && result[5] == L':') {
            adsSearchStart = 6;
        } else {
            adsSearchStart = 4;
        }
    }
    auto adsPos = result.find(L':', adsSearchStart);
    if (adsPos != std::wstring::npos) {
        result.erase(adsPos);
    }

    // Convert to lowercase for case-insensitive matching
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);

    // Replace forward slashes with backslashes
    std::replace(result.begin(), result.end(), L'/', L'\\');

    // Remove trailing backslash but preserve drive root (e.g. "C:\")
    while (result.size() > 3 && result.back() == L'\\') {
        result.pop_back();
    }

    // Resolve relative segments (.., .) via filesystem
    try {
        std::filesystem::path fsPath(result);
        if (fsPath.is_relative()) {
            fsPath = std::filesystem::absolute(fsPath);
        }
        result = fsPath.lexically_normal().wstring();
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);

        // lexically_normal may re-add trailing separator
        while (result.size() > 3 && result.back() == L'\\') {
            result.pop_back();
        }
    } catch (const std::filesystem::filesystem_error& e) {
        // MED-03 FIX: Catch specific exception. Swallowing catch(...) hides logic bugs.
        SS_LOG_DEBUG(L"FileProtection", L"Path normalization fallback for '%ls': %hs",
                     result.c_str(), e.what());
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

    // Snapshot the per-session secret under shared_lock so a concurrent
    // re-Initialize() cannot mutate it mid-read.
    std::string secret;
    {
        std::shared_lock lock(m_mutex);
        if (m_authSecret.empty()) {
            return false;
        }
        secret = m_authSecret;
    }

    // HMAC-SHA256 verification using Windows CNG (BCrypt).
    // Token format: hex(HMAC-SHA256(secret, nonce)) + ":" + nonce

    auto colonPos = token.find(':');
    if (colonPos == std::string_view::npos || colonPos == 0) {
        return false;
    }

    std::string_view macHex = token.substr(0, colonPos);
    std::string_view nonce = token.substr(colonPos + 1);

    if (nonce.empty() || macHex.size() != 64) { // SHA-256 = 32 bytes = 64 hex chars
        return false;
    }

    // Compute expected HMAC via Windows CNG
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                                   BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        SS_LOG_ERROR(L"FileProtection", L"BCryptOpenAlgorithmProvider failed: 0x%08lx", status);
        SecureZeroMemory(secret.data(), secret.size());
        return false;
    }

    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                               reinterpret_cast<PUCHAR>(secret.data()),
                               static_cast<ULONG>(secret.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroMemory(secret.data(), secret.size());
        return false;
    }

    status = BCryptHashData(hHash,
                             reinterpret_cast<PUCHAR>(const_cast<char*>(nonce.data())),
                             static_cast<ULONG>(nonce.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroMemory(secret.data(), secret.size());
        return false;
    }

    UCHAR computed[32]{};
    status = BCryptFinishHash(hHash, computed, sizeof(computed), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    SecureZeroMemory(secret.data(), secret.size());

    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }

    // Convert computed hash to hex string
    char computedHex[65]{};
    for (int i = 0; i < 32; ++i) {
        snprintf(computedHex + i * 2, 3, "%02x", computed[i]);
    }

    // Constant-time comparison to prevent timing side-channel attacks.
    // Compare raw bytes via XOR accumulation.
    unsigned int diff = 0;
    for (size_t i = 0; i < 64; ++i) {
        diff |= static_cast<unsigned char>(computedHex[i]) ^ static_cast<unsigned char>(macHex[i]);
    }

    // Scrub sensitive material before returning
    SecureZeroMemory(computed, sizeof(computed));
    SecureZeroMemory(computedHex, sizeof(computedHex));

    return diff == 0;
}

[[nodiscard]] std::string FileProtectionImpl::GenerateAuthorizationToken() const {
    // Snapshot the per-session secret under shared_lock.
    std::string secret;
    {
        std::shared_lock lock(m_mutex);
        if (m_authSecret.empty()) {
            return {};
        }
        secret = m_authSecret;
    }

    // Cryptographically-secure random nonce (16 bytes -> 32 hex chars).
    uint8_t nonceBytes[16]{};
    NTSTATUS rngStatus = BCryptGenRandom(
        nullptr, nonceBytes, sizeof(nonceBytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(rngStatus)) {
        SS_LOG_ERROR(L"FileProtection", L"BCryptGenRandom (nonce) failed: 0x%08lx", rngStatus);
        SecureZeroMemory(secret.data(), secret.size());
        return {};
    }

    char nonce[33]{};
    for (size_t i = 0; i < sizeof(nonceBytes); ++i) {
        snprintf(nonce + i * 2, 3, "%02x", nonceBytes[i]);
    }

    // Compute HMAC-SHA256(secret, nonce) via Windows CNG
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                                   BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        SecureZeroMemory(secret.data(), secret.size());
        return {};
    }

    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                               reinterpret_cast<PUCHAR>(secret.data()),
                               static_cast<ULONG>(secret.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroMemory(secret.data(), secret.size());
        return {};
    }

    auto nonceLen = static_cast<ULONG>(strlen(nonce));
    status = BCryptHashData(hHash, reinterpret_cast<PUCHAR>(nonce), nonceLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroMemory(secret.data(), secret.size());
        return {};
    }

    UCHAR computed[32]{};
    status = BCryptFinishHash(hHash, computed, sizeof(computed), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    SecureZeroMemory(secret.data(), secret.size());

    if (!BCRYPT_SUCCESS(status)) return {};

    // Format: hex(hmac) + ":" + nonce
    char macHex[65]{};
    for (int i = 0; i < 32; ++i) {
        snprintf(macHex + i * 2, 3, "%02x", computed[i]);
    }
    SecureZeroMemory(computed, sizeof(computed));

    std::string result = std::string(macHex) + ":" + nonce;
    SecureZeroMemory(macHex, sizeof(macHex));
    return result;
}

[[nodiscard]] std::string FileProtectionImpl::GenerateFileId(std::wstring_view path) const {
    std::string narrowPath = Utils::StringUtils::ToNarrow(std::wstring(path));

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
    if (desiredAccess & WRITE_DAC)
        result |= static_cast<uint32_t>(FileOperation::SetSecurity);
    if (desiredAccess & WRITE_OWNER)
        result |= static_cast<uint32_t>(FileOperation::SetOwner);

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
    RansomwareCallback callbackCopy;
    {
        std::shared_lock lock(m_mutex);
        callbackCopy = m_ransomwareCallback;
    }

    if (callbackCopy) {
        try {
            callbackCopy(detection);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileProtection", L"Ransomware callback exception: %hs", e.what());
        }
    }
}

void FileProtectionImpl::IntegrityMonitorThread() {
    SS_LOG_INFO(L"FileProtection", L"Integrity monitor thread started");

    while (m_monitoringActive.load() && !m_shutdownRequested.load()) {
        // Read interval under lock to avoid data race on m_config
        uint32_t intervalMs;
        {
            std::shared_lock lock(m_mutex);
            intervalMs = m_config.integrityCheckIntervalMs;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));

        if (!m_monitoringActive.load() || m_shutdownRequested.load()) break;

        // VerifyAllIntegrity -> VerifyFileIntegrity already records events
        // and calls NotifyIntegrityViolation, so no extra notification needed.
        const auto integrityResults = VerifyAllIntegrity();
        SS_LOG_DEBUG(L"FileProtection", L"Integrity monitor checked %zu protected files", integrityResults.size());
    }

    SS_LOG_INFO(L"FileProtection", L"Integrity monitor thread stopped");
}

void FileProtectionImpl::RansomwareMonitorThread() {
    SS_LOG_INFO(L"FileProtection", L"Ransomware monitor thread started");

    while (m_monitoringActive.load() && !m_shutdownRequested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        if (!m_monitoringActive.load() || !m_ransomwareProtectionEnabled.load()) continue;

        // Collect detections under lock, then notify outside lock
        std::vector<RansomwareDetection> pendingDetections;

        {
            std::unique_lock lock(m_mutex);
            auto now = Clock::now();

            for (auto it = m_modificationTracking.begin();
                 it != m_modificationTracking.end();) {

                uint32_t pid = it->first;
                auto& modifications = it->second;

                // Remove old entries outside detection window
                modifications.erase(
                    std::remove_if(modifications.begin(), modifications.end(),
                                  [now](const auto& entry) {
                                      return std::chrono::duration_cast<Milliseconds>(
                                                 now - entry.first).count() >
                                             static_cast<int64_t>(
                                                 FileProtectionConstants::RANSOMWARE_DETECTION_WINDOW_MS);
                                  }),
                    modifications.end());

                // Check threshold
                if (modifications.size() >=
                    FileProtectionConstants::RANSOMWARE_MODIFICATION_THRESHOLD) {

                    RansomwareDetection detection;
                    detection.timestamp = now;
                    detection.processId = pid;
                    detection.modificationCount =
                        static_cast<uint32_t>(modifications.size());
                    detection.confidence = std::min(
                        100u, static_cast<uint32_t>(modifications.size()) * 10);

                    for (const auto& mod : modifications) {
                        detection.affectedFiles.push_back(mod.second);
                    }

                    m_ransomwareDetections.push_back(detection);
                    m_stats.ransomwareDetections.fetch_add(1, std::memory_order_relaxed);
                    pendingDetections.push_back(std::move(detection));

                    modifications.clear();

                    SS_LOG_WARN(L"FileProtection",
                                L"Ransomware behavior detected from PID %u (%u mods)",
                                pid, pendingDetections.back().modificationCount);
                }

                if (modifications.empty()) {
                    it = m_modificationTracking.erase(it);
                } else {
                    ++it;
                }
            }
        } // lock released

        // Notify callbacks outside lock to avoid deadlock
        for (const auto& det : pendingDetections) {
            NotifyRansomware(det);
        }
    }

    SS_LOG_INFO(L"FileProtection", L"Ransomware monitor thread stopped");
}

void FileProtectionImpl::StartMonitoringThreads() {
    // MED-02 FIX: Use atomic exchange to prevent double-start race condition.
    // Two threads calling StartMonitoringThreads() concurrently could both pass
    // the load() check and spawn duplicate monitoring threads.
    bool expected = false;
    if (!m_monitoringActive.compare_exchange_strong(expected, true)) {
        return;  // Another thread already started monitoring
    }

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

    if (normalizedDir.empty() || normalizedPath.size() <= normalizedDir.size()) {
        return false;
    }

    if (normalizedPath.compare(0, normalizedDir.size(), normalizedDir) != 0) {
        return false;
    }

    // Accept matches where the directory either already ends in a separator
    // (e.g. the drive root "c:\") or is followed by a separator in the path.
    // Without this branch, files directly under a root-protected directory
    // would be reported as not-under it.
    if (normalizedDir.back() == L'\\') {
        return true;
    }
    return normalizedPath[normalizedDir.size()] == L'\\';
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

    auto ns = event.timestamp.time_since_epoch().count();
    m_stats.lastEventTimeNs.store(static_cast<uint64_t>(ns), std::memory_order_relaxed);
}

void FileProtectionImpl::TrackFileModification(std::wstring_view path, uint32_t processId) {
    std::unique_lock lock(m_mutex);

    // MED-01 FIX: Cap tracked PIDs to prevent unbounded memory growth (DoS vector).
    // Attacker could spawn thousands of PIDs to exhaust agent memory.
    if (m_modificationTracking.size() >= MAX_TRACKED_PIDS &&
        m_modificationTracking.find(processId) == m_modificationTracking.end()) {
        // Evict the entry with the oldest last-access time.
        // If all entries have empty vectors, just evict the first one.
        auto oldest = m_modificationTracking.begin();
        bool foundNonEmpty = false;
        for (auto it = m_modificationTracking.begin(); it != m_modificationTracking.end(); ++it) {
            if (it->second.empty()) continue;
            if (!foundNonEmpty || it->second.back().first < oldest->second.back().first) {
                oldest = it;
                foundNonEmpty = true;
            }
        }
        m_modificationTracking.erase(oldest);
    }

    auto& entries = m_modificationTracking[processId];

    // Cap per-PID entries too
    if (entries.size() >= MAX_MODS_PER_PID) {
        entries.erase(entries.begin());
    }

    entries.emplace_back(Clock::now(), std::wstring(path));
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
// KERNEL BRIDGE IMPLEMENTATION (WIRE-01, WIRE-03)
// ============================================================================

void FileProtectionImpl::SyncProtectedPathsToKernel() {
    // WIRE-01: Serialize all user-mode protected paths and push to kernel driver
    // via IPCManager so FpCheckAccess() in PreCreate.c can enforce them.
    try {
        // Gather paths under shared lock
        std::vector<std::wstring> paths;
        {
            std::shared_lock lock(m_mutex);
            paths.reserve(m_protectedFiles.size() + m_protectedDirectories.size());
            for (const auto& [p, _] : m_protectedFiles) {
                paths.push_back(p);
            }
            for (const auto& [p, _] : m_protectedDirectories) {
                paths.push_back(p);
            }
        }

        if (paths.empty()) {
            SS_LOG_DEBUG(L"FileProtection", L"No paths to sync to kernel");
            return;
        }

        // Build the payload: uint32_t count, then count null-terminated wide strings
        uint32_t count = static_cast<uint32_t>(std::min<size_t>(paths.size(), 4096));
        std::vector<uint8_t> payload;
        payload.resize(sizeof(uint32_t));
        std::memcpy(payload.data(), &count, sizeof(count));

        for (uint32_t i = 0; i < count; ++i) {
            const auto& p = paths[i];
            size_t byteLen = (p.size() + 1) * sizeof(wchar_t);
            size_t offset = payload.size();
            payload.resize(offset + byteLen);
            std::memcpy(payload.data() + offset, p.c_str(), byteLen);
        }

        // Build SHADOWSTRIKE_MESSAGE_HEADER + payload
        size_t totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + payload.size();

        // Guard against payload exceeding UINT32_MAX (message header fields are 32-bit)
        if (totalSize > static_cast<size_t>(UINT32_MAX)) {
            SS_LOG_ERROR(L"FileProtection", L"Kernel sync payload too large (%zu bytes)", totalSize);
            return;
        }

        std::vector<uint8_t> message(totalSize, 0);

        auto* header = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(message.data());
        header->Magic       = SHADOWSTRIKE_MESSAGE_MAGIC;
        header->Version     = SHADOWSTRIKE_PROTOCOL_VERSION;
        header->MessageType = static_cast<UINT16>(FilterMessageType_UpdatePolicy);
        header->MessageId   = m_nextEventId.fetch_add(1);
        header->TotalSize   = static_cast<UINT32>(totalSize);
        header->DataSize    = static_cast<UINT32>(payload.size());

        LARGE_INTEGER ts;
        QueryPerformanceCounter(&ts);
        header->Timestamp = ts.QuadPart;
        header->Flags     = 0;

        std::memcpy(message.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
                     payload.data(), payload.size());

        // Send via IPCManager
        auto& ipc = Communication::IPCManager::Instance();
        bool sent = ipc.SendToKernel(message.data(), message.size());

        if (sent) {
            SS_LOG_INFO(L"FileProtection", L"Synced %u protected paths to kernel driver", count);
        } else {
            SS_LOG_WARN(L"FileProtection", L"Failed to sync paths to kernel (driver may not be loaded)");
        }
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"FileProtection", L"Kernel path sync exception: %hs", e.what());
    }
}

void FileProtectionImpl::OnKernelBlockEventInternal(const void* data, uint32_t size) {
    // WIRE-03: Handle block events received from the kernel driver.
    // The kernel sends self-protect alerts when FpCheckAccess() blocks an operation.
    // Format: { uint32_t processId, uint32_t operation, uint16_t pathLen, wchar_t path[] }
    static constexpr uint32_t kMinEventSize = sizeof(uint32_t) * 2 + sizeof(uint16_t); // 10 bytes
    if (!data || size < kMinEventSize) {
        SS_LOG_WARN(L"FileProtection", L"Invalid kernel block event (size=%u, min=%u)", size, kMinEventSize);
        return;
    }

    // Parse kernel alert: { uint32_t processId, uint32_t operation, uint16_t pathLen, wchar_t path[] }
    auto ptr = static_cast<const uint8_t*>(data);
    uint32_t processId = 0;
    uint32_t operation = 0;
    uint16_t pathLen = 0;

    std::memcpy(&processId, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    std::memcpy(&operation, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    std::memcpy(&pathLen, ptr, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    size_t consumed = sizeof(uint32_t) * 2 + sizeof(uint16_t);
    size_t pathBytes = static_cast<size_t>(pathLen) * sizeof(wchar_t);

    if (consumed + pathBytes > size) {
        SS_LOG_WARN(L"FileProtection", L"Kernel block event truncated (pathLen=%u)", pathLen);
        return;
    }

    std::wstring filePath(reinterpret_cast<const wchar_t*>(ptr), pathLen);

    // Record the event
    FileProtectionEvent event;
    event.eventId = m_nextEventId.fetch_add(1);
    event.type = FileProtectionEventType::OperationBlocked;
    event.timestamp = Clock::now();
    event.filePath = filePath;
    event.operation = static_cast<FileOperation>(operation);
    event.sourceProcessId = processId;
    event.decision = FileOperationDecision::Block;
    event.wasBlocked = true;
    event.description = "Blocked by kernel file protection driver";

    auto nameOpt = Utils::ProcessUtils::GetProcessName(
        static_cast<Utils::ProcessUtils::ProcessId>(processId));
    if (nameOpt.has_value()) {
        event.sourceProcessName = *nameOpt;
    }

    m_stats.totalBlocked.fetch_add(1, std::memory_order_relaxed);
    m_stats.totalOperations.fetch_add(1, std::memory_order_relaxed);

    RecordEvent(event);
    NotifyEvent(event);

    SS_LOG_INFO(L"FileProtection", L"Kernel blocked PID %u from %ls on '%ls'",
                processId,
                GetFileOperationName(static_cast<FileOperation>(operation)).data(),
                filePath.c_str());
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

[[nodiscard]] FileOperationDecisionResult FileProtection::FilterOperation(
    const FileOperationRequest& request) {
    return m_impl->FilterOperation(request);
}

void FileProtection::SetDecisionCallback(FileOperationDecisionCallback callback) {
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

[[nodiscard]] FileIntegrityStatus FileProtection::VerifyFileIntegrity(std::wstring_view path) {
    return m_impl->VerifyFileIntegrity(path);
}

[[nodiscard]] std::vector<std::pair<std::wstring, FileIntegrityStatus>>
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

[[nodiscard]] uint64_t FileProtection::RegisterIntegrityCallback(FileIntegrityCallback callback) {
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

[[nodiscard]] std::string FileProtection::GenerateAuthorizationToken() const {
    return m_impl->GenerateAuthorizationToken();
}

void FileProtection::SyncProtectedPathsToKernel() {
    m_impl->SyncProtectedPathsToKernel();
}

void FileProtection::OnKernelBlockEvent(const void* data, uint32_t size) {
    m_impl->OnKernelBlockEventInternal(data, size);
}

// ============================================================================
// RAII HELPER IMPLEMENTATIONS
// ============================================================================

FileProtectionGuard::FileProtectionGuard(std::wstring_view path, ProtectionType type)
    : m_path(path) {

    // HIGH-04 FIX: Use HMAC-based authorization token instead of predictable
    // steady_clock timestamp. The old token was trivially forgeable.
    m_authToken = FileProtection::Instance().GenerateAuthorizationToken();
    m_protected = FileProtection::Instance().ProtectFile(path, type);
}

FileProtectionGuard::~FileProtectionGuard() {
    if (m_protected) {
        if (!FileProtection::Instance().UnprotectFile(m_path, m_authToken)) {
            SS_LOG_WARN(L"FileProtection", L"FileProtectionGuard cleanup failed for: %ls", m_path.c_str());
        }
    }
}

}  // namespace Security
}  // namespace ShadowStrike

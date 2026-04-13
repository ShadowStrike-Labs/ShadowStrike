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
#include "pch.h"
/**
 * ============================================================================
 * ShadowStrike NGAV - RESTORE MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file RestoreManager.cpp
 * @brief Implementation of the RestoreManager class using PIMPL pattern.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "RestoreManager.hpp"
#include "BackupManager.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/JsonUtils.hpp"

#include <rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <algorithm>
#include <future>
#include <random>
#include <deque>
#include <condition_variable>
#include <stack>

namespace ShadowStrike {
namespace Backup {

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================

std::atomic<bool> RestoreManager::s_instanceCreated{false};

// ============================================================================
// HELPERS
// ============================================================================

namespace {

    constexpr size_t kMaxPathComponent = 255;
    constexpr size_t kMaxRestoreErrors = 10000;
    constexpr size_t kMaxRollbackJournalEntries = 500000;
    constexpr std::chrono::seconds kShutdownTimeout{30};

    [[nodiscard]] std::string GenerateId() {
        UUID uuid{};
        if (UuidCreate(&uuid) != RPC_S_OK) {
            SS_LOG_ERROR(L"RestoreManager", L"UuidCreate failed, generating fallback ID");
            std::random_device rd;
            std::mt19937_64 gen(rd());
            std::uniform_int_distribution<uint64_t> dis;
            std::ostringstream oss;
            oss << std::hex << std::setfill('0')
                << std::setw(8) << (dis(gen) & 0xFFFFFFFF) << "-"
                << std::setw(4) << (dis(gen) & 0xFFFF) << "-"
                << std::setw(4) << (dis(gen) & 0xFFFF) << "-"
                << std::setw(4) << (dis(gen) & 0xFFFF) << "-"
                << std::setw(12) << (dis(gen) & 0xFFFFFFFFFFFF);
            return oss.str();
        }
        RPC_CSTR szUuid = nullptr;
        if (UuidToStringA(&uuid, &szUuid) != RPC_S_OK || !szUuid) {
            SS_LOG_ERROR(L"RestoreManager", L"UuidToStringA failed");
            return {};
        }
        std::string s(reinterpret_cast<const char*>(szUuid));
        RpcStringFreeA(&szUuid);
        return s;
    }

    // Path traversal & symlink attack mitigation.
    // Returns true if the path is safe (no traversal above root, no reparse points in chain).
    [[nodiscard]] bool IsPathSafe(const fs::path& target, const fs::path& allowedRoot) noexcept {
        try {
            // Normalize both paths to canonical form for comparison
            fs::path normalTarget = fs::weakly_canonical(target);
            fs::path normalRoot = fs::weakly_canonical(allowedRoot);

            // Check that target is under the allowed root
            auto [rootEnd, targetPos] = std::mismatch(
                normalRoot.begin(), normalRoot.end(),
                normalTarget.begin(), normalTarget.end());

            if (rootEnd != normalRoot.end()) {
                return false;  // target is not under allowedRoot
            }

            // Check individual path components for ".." that survived normalization
            for (const auto& component : normalTarget) {
                std::wstring name = component.wstring();
                if (name == L".." || name.find(L'\0') != std::wstring::npos) {
                    return false;
                }
                if (name.length() > kMaxPathComponent) {
                    return false;
                }
            }

            // Check for reparse points (symlinks/junctions) in the existing portion of the path
            fs::path existing = normalTarget;
            while (!existing.empty() && existing != existing.root_path()) {
                std::error_code ec;
                if (fs::exists(existing, ec) && !ec) {
                    if (fs::is_symlink(existing, ec) && !ec) {
                        return false;  // Symlink in path — potential attack vector
                    }
                    break;  // Found the deepest existing component
                }
                existing = existing.parent_path();
            }

            return true;
        } catch (...) {
            return false;
        }
    }

    // Validate backupId contains only safe characters (UUID format)
    [[nodiscard]] bool IsValidBackupId(const std::string& id) noexcept {
        if (id.empty() || id.size() > 64) return false;
        for (char c : id) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F') || c == '-')) {
                return false;
            }
        }
        return true;
    }

    // Enumerate files in a backup data directory
    [[nodiscard]] std::vector<fs::path> EnumerateBackupFiles(
        const fs::path& backupDataDir) noexcept
    {
        std::vector<fs::path> files;
        try {
            if (!fs::exists(backupDataDir) || !fs::is_directory(backupDataDir)) {
                return files;
            }
            for (const auto& entry : fs::directory_iterator(backupDataDir)) {
                if (entry.is_regular_file()) {
                    files.push_back(entry.path());
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"RestoreManager", L"Failed to enumerate backup directory: %hs", e.what());
        }
        return files;
    }

    // Compute SHA-256 for a file, returns hex-lowercase string or empty on failure
    [[nodiscard]] std::string ComputeFileHash(const fs::path& filePath) {
        std::vector<uint8_t> digest;
        Utils::HashUtils::Error err;
        if (!Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::SHA256,
                filePath.wstring(), digest, &err)) {
            return {};
        }
        return Utils::HashUtils::ToHexLower(digest);
    }

    // Resolve a "keep both" rename: appends (1), (2), etc.
    [[nodiscard]] fs::path GenerateKeepBothPath(const fs::path& target) {
        fs::path stem = target.stem();
        fs::path ext = target.extension();
        fs::path parent = target.parent_path();
        for (int i = 1; i < 10000; ++i) {
            fs::path candidate = parent / (stem.wstring() + L" (" + std::to_wstring(i) + L")" + ext.wstring());
            std::error_code ec;
            if (!fs::exists(candidate, ec)) {
                return candidate;
            }
        }
        return {};  // Exhausted — extremely unlikely
    }

}  // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class RestoreManagerImpl {
public:
    RestoreManagerImpl() = default;

    ~RestoreManagerImpl() {
        ShutdownInternal();
    }

    // State
    std::atomic<RestoreModuleStatus> m_status{RestoreModuleStatus::Uninitialized};
    RestoreStatistics m_stats;

    // Active Operations
    std::unordered_map<std::string, RestoreProgress> m_activeRestores;
    std::unordered_map<std::string, RestoreResult> m_results;

    // Per-restore cancel flags (avoids global m_stopRequested killing all restores)
    std::unordered_map<std::string, std::shared_ptr<std::atomic<bool>>> m_cancelFlags;

    // Rollback Journals: restoreID -> stack of operations to undo
    struct FileOperation {
        enum Type { Created, Overwritten, Renamed };
        Type type = Created;
        fs::path path;
        fs::path backupCopyPath;  // Pre-overwrite backup stored here
    };
    std::unordered_map<std::string, std::deque<FileOperation>> m_rollbackJournals;

    // Synchronization
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_callbackMutex;

    // Threading control for pauses
    std::condition_variable_any m_cv;

    // Tracked worker threads (no detached threads — safe lifetime)
    std::unordered_map<std::string, std::thread> m_workerThreads;

    // Callbacks — snapshot copies for invocation outside locks
    std::vector<RestoreProgressCallback> m_progressCallbacks;
    std::vector<RestoreCompletionCallback> m_completionCallbacks;
    std::vector<RestoreConflictCallback> m_conflictCallbacks;
    std::vector<RestoreFileCallback> m_fileCallbacks;
    std::vector<RestoreErrorCallback> m_errorCallbacks;

    // Global shutdown flag
    std::atomic<bool> m_shutdownRequested{false};

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    bool Initialize() {
        std::unique_lock lock(m_mutex);
        if (m_status == RestoreModuleStatus::Ready ||
            m_status == RestoreModuleStatus::Restoring) {
            return true;
        }
        if (m_status != RestoreModuleStatus::Uninitialized &&
            m_status != RestoreModuleStatus::Stopped &&
            m_status != RestoreModuleStatus::Error) {
            return false;
        }

        m_status = RestoreModuleStatus::Initializing;
        m_shutdownRequested = false;
        m_stats.Reset();
        m_status = RestoreModuleStatus::Ready;

        SS_LOG_INFO(L"RestoreManager", L"Initialized v%hs", RestoreManager::GetVersionString().c_str());
        return true;
    }

    void ShutdownInternal() {
        {
            std::unique_lock lock(m_mutex);
            if (m_status == RestoreModuleStatus::Stopped ||
                m_status == RestoreModuleStatus::Uninitialized) {
                return;
            }
            m_status = RestoreModuleStatus::Stopping;
            m_shutdownRequested = true;

            // Signal all per-restore cancellation
            for (auto& [id, flag] : m_cancelFlags) {
                flag->store(true);
            }
            m_cv.notify_all();
        }

        // Join all worker threads outside the lock to avoid deadlock
        JoinAllWorkers();

        {
            std::unique_lock lock(m_mutex);
            m_activeRestores.clear();
            m_cancelFlags.clear();
            m_status = RestoreModuleStatus::Stopped;
        }

        SS_LOG_INFO(L"RestoreManager", L"Shutdown complete");
    }

    void JoinAllWorkers() {
        // Collect threads to join outside the mutex
        std::vector<std::thread> threadsToJoin;
        {
            std::unique_lock lock(m_mutex);
            for (auto& [id, t] : m_workerThreads) {
                if (t.joinable()) {
                    threadsToJoin.push_back(std::move(t));
                }
            }
            m_workerThreads.clear();
        }
        for (auto& t : threadsToJoin) {
            t.join();
        }
    }

    // ========================================================================
    // INPUT VALIDATION
    // ========================================================================

    [[nodiscard]] bool ValidateRestoreInputs(
        const std::string& backupId,
        const std::vector<RestoreTarget>& targets,
        const RestoreOptions& options)
    {
        if (!IsValidBackupId(backupId)) {
            NotifyError("Invalid backup ID format — potential path injection", 100);
            return false;
        }
        if (targets.empty()) {
            NotifyError("No restore targets provided", 101);
            return false;
        }
        if (!options.IsValid()) {
            NotifyError("Invalid restore options", 102);
            return false;
        }
        for (const auto& t : targets) {
            if (t.targetPath.empty()) {
                NotifyError("Restore target has empty target path", 103);
                return false;
            }
        }
        return true;
    }

    // ========================================================================
    // RESTORE LOGIC
    // ========================================================================

    std::string Restore(const std::string& backupId,
                        const std::vector<RestoreTarget>& targets,
                        const RestoreOptions& options)
    {
        if (m_status != RestoreModuleStatus::Ready &&
            m_status != RestoreModuleStatus::Restoring) {
            NotifyError("RestoreManager is not initialized", 104);
            return {};
        }

        if (!ValidateRestoreInputs(backupId, targets, options)) {
            return {};
        }

        // Enforce concurrent restore limit
        {
            std::shared_lock lock(m_mutex);
            if (m_activeRestores.size() >= RestoreConstants::MAX_CONCURRENT_RESTORES) {
                NotifyError("Maximum concurrent restores reached", 105);
                return {};
            }
        }

        std::string restoreId = GenerateId();
        if (restoreId.empty()) {
            NotifyError("Failed to generate restore ID", 106);
            return {};
        }

        auto cancelFlag = std::make_shared<std::atomic<bool>>(false);

        {
            std::unique_lock lock(m_mutex);
            RestoreProgress progress;
            progress.restoreId = restoreId;
            progress.status = RestoreStatus::Pending;
            progress.phase = "Initializing";
            m_activeRestores[restoreId] = progress;
            m_rollbackJournals[restoreId] = {};
            m_cancelFlags[restoreId] = cancelFlag;
        }

        // Launch tracked thread (NOT detached — safe lifetime management)
        std::thread worker([this, restoreId, backupId, targets, options, cancelFlag]() {
            PerformRestore(restoreId, backupId, targets, options, cancelFlag);
        });

        {
            std::unique_lock lock(m_mutex);
            m_workerThreads[restoreId] = std::move(worker);
        }

        m_status = RestoreModuleStatus::Restoring;
        return restoreId;
    }

    void PerformRestore(const std::string& restoreId,
                        const std::string& backupId,
                        const std::vector<RestoreTarget>& targets,
                        const RestoreOptions& options,
                        std::shared_ptr<std::atomic<bool>> cancelFlag)
    {
        SS_LOG_INFO(L"RestoreManager", L"Starting restore %hs from backup %hs",
                    restoreId.c_str(), backupId.c_str());

        const auto operationStart = std::chrono::system_clock::now();
        UpdateStatus(restoreId, RestoreStatus::InProgress, "Preparing");

        // Resolve vault and backup data directory
        auto vaultInfo = BackupManager::Instance().GetVaultInfo();
        const fs::path vaultPath = vaultInfo.path;

        if (vaultPath.empty()) {
            FinishRestore(restoreId, backupId, operationStart, RestoreStatus::Failed,
                          0, 0, 0, 0, {}, {"Vault path is not configured"});
            return;
        }

        const fs::path backupDataDir = vaultPath / backupId / "data";
        {
            std::error_code ec;
            if (!fs::exists(backupDataDir, ec) || ec) {
                std::string msg = "Backup data directory not found: " + backupDataDir.string();
                SS_LOG_ERROR(L"RestoreManager", L"%hs", msg.c_str());
                FinishRestore(restoreId, backupId, operationStart, RestoreStatus::Failed,
                              0, 0, 0, 0, {}, {msg});
                return;
            }
        }

        // Enumerate available backup files
        auto backupFiles = EnumerateBackupFiles(backupDataDir);
        if (backupFiles.empty()) {
            FinishRestore(restoreId, backupId, operationStart, RestoreStatus::Failed,
                          0, 0, 0, 0, {}, {"No files found in backup"});
            return;
        }

        // Build a filename->path map for fast lookup
        std::unordered_map<std::wstring, fs::path> backupFileMap;
        for (const auto& bf : backupFiles) {
            backupFileMap[bf.filename().wstring()] = bf;
        }

        const uint64_t totalFiles = static_cast<uint64_t>(backupFiles.size());
        UpdateProgress(restoreId, "Restoring", 0, 0, 0, totalFiles);

        uint64_t filesRestored = 0;
        uint64_t bytesRestored = 0;
        uint64_t filesSkipped = 0;
        uint64_t filesFailed = 0;
        std::vector<RestoreConflict> conflicts;
        std::vector<std::string> errors;

        // Process each target
        for (const auto& target : targets) {
            if (IsCancelledOrStopped(restoreId, cancelFlag)) break;

            const fs::path targetDir = target.targetPath;

            // Security: validate target path is not traversal
            if (!IsPathSafe(targetDir, targetDir.root_path())) {
                std::string msg = "Unsafe target path rejected: " + targetDir.string();
                SS_LOG_WARN(L"RestoreManager", L"%hs", msg.c_str());
                errors.push_back(msg);
                continue;
            }

            // Determine which backup files to restore for this target
            std::vector<const fs::path*> filesToRestore;
            if (!target.sourcePath.empty() && !target.isDirectory) {
                // Selective single-file restore: match by filename
                auto it = backupFileMap.find(target.sourcePath.filename().wstring());
                if (it != backupFileMap.end()) {
                    filesToRestore.push_back(&it->second);
                } else {
                    std::string msg = "File not found in backup: " + target.sourcePath.string();
                    errors.push_back(msg);
                    SS_LOG_WARN(L"RestoreManager", L"%hs", msg.c_str());
                }
            } else {
                // Full/directory restore: restore all backup files to target
                for (const auto& bf : backupFiles) {
                    filesToRestore.push_back(&bf);
                }
            }

            // Ensure target directory exists
            {
                Utils::FileUtils::Error dirErr;
                if (!Utils::FileUtils::CreateDirectories(targetDir.wstring(), &dirErr)) {
                    std::string msg = "Failed to create target directory: " + targetDir.string();
                    SS_LOG_ERROR(L"RestoreManager", L"%hs", msg.c_str());
                    errors.push_back(msg);
                    if (!options.continueOnError) break;
                    continue;
                }
            }

            // Restore each file
            for (const fs::path* srcFilePtr : filesToRestore) {
                if (IsCancelledOrStopped(restoreId, cancelFlag)) break;
                WaitIfPaused(restoreId, cancelFlag);
                if (IsCancelledOrStopped(restoreId, cancelFlag)) break;

                const fs::path& srcFile = *srcFilePtr;
                fs::path destPath = targetDir / srcFile.filename();

                // Security: re-validate final destination
                if (!IsPathSafe(destPath, targetDir)) {
                    std::string msg = "Path safety check failed for: " + destPath.string();
                    errors.push_back(msg);
                    filesFailed++;
                    continue;
                }

                // File callback — let caller filter
                {
                    BackupFileEntry entry;
                    entry.path = srcFile.filename();
                    std::error_code ec;
                    entry.size = fs::file_size(srcFile, ec);
                    if (!InvokeFileCallback(entry)) {
                        filesSkipped++;
                        continue;
                    }
                }

                // Conflict resolution
                Utils::FileUtils::Error existsErr;
                const bool targetExists = Utils::FileUtils::Exists(destPath.wstring(), &existsErr);
                if (targetExists) {
                    ConflictResolution resolution = options.conflictResolution;

                    if (resolution == ConflictResolution::OverwriteNewer ||
                        resolution == ConflictResolution::OverwriteOlder) {
                        resolution = ResolveTimestampConflict(srcFile, destPath, resolution);
                    }

                    if (resolution == ConflictResolution::Prompt) {
                        RestoreConflict conflict;
                        conflict.sourcePath = srcFile;
                        conflict.targetPath = destPath;
                        std::error_code ec;
                        conflict.sourceSize = fs::file_size(srcFile, ec);
                        conflict.targetSize = fs::file_size(destPath, ec);
                        resolution = InvokeConflictCallback(conflict);
                        conflict.resolution = resolution;
                        conflicts.push_back(conflict);
                    }

                    switch (resolution) {
                    case ConflictResolution::Skip:
                        filesSkipped++;
                        m_stats.filesSkipped++;
                        continue;
                    case ConflictResolution::KeepBoth: {
                        fs::path altPath = GenerateKeepBothPath(destPath);
                        if (altPath.empty()) {
                            errors.push_back("Failed to generate keep-both path for: " + destPath.string());
                            filesFailed++;
                            continue;
                        }
                        destPath = altPath;
                        break;
                    }
                    case ConflictResolution::Overwrite:
                    case ConflictResolution::OverwriteNewer:
                    case ConflictResolution::OverwriteOlder:
                        // Remove read-only attribute if needed
                        if (options.overwriteReadOnly) {
                            ClearReadOnlyAttribute(destPath);
                        }
                        break;
                    default:
                        break;
                    }
                }

                // Rollback journaling: backup existing file before overwrite
                if (options.createSnapshot) {
                    JournalOperation(restoreId, destPath, targetExists, vaultPath);
                }

                // Actual file copy (atomic via temp + rename)
                bool copySuccess = CopyFileAtomic(srcFile, destPath);
                if (!copySuccess) {
                    std::string msg = "Failed to restore file: " + destPath.string();
                    SS_LOG_ERROR(L"RestoreManager", L"%hs", msg.c_str());
                    errors.push_back(msg);
                    filesFailed++;
                    if (!options.continueOnError ||
                        (options.maxErrors > 0 && filesFailed >= options.maxErrors)) {
                        break;
                    }
                    continue;
                }

                // Post-copy verification
                if (options.verifyAfterRestore) {
                    std::string srcHash = ComputeFileHash(srcFile);
                    std::string dstHash = ComputeFileHash(destPath);
                    if (srcHash.empty() || dstHash.empty() || srcHash != dstHash) {
                        std::string msg = "Integrity verification failed for: " + destPath.string();
                        SS_LOG_ERROR(L"RestoreManager", L"%hs", msg.c_str());
                        errors.push_back(msg);
                        filesFailed++;
                        // Attempt to clean up the bad restore
                        Utils::FileUtils::Error rmErr;
                        Utils::FileUtils::RemoveFile(destPath.wstring(), &rmErr);
                        if (!options.continueOnError) break;
                        continue;
                    }
                    m_stats.verificationsPerformed++;
                }

                // Restore file attributes/timestamps if requested
                if (static_cast<uint32_t>(options.metadataOptions) &
                    static_cast<uint32_t>(MetadataOption::Timestamps)) {
                    RestoreTimestamps(srcFile, destPath);
                }
                if (static_cast<uint32_t>(options.metadataOptions) &
                    static_cast<uint32_t>(MetadataOption::Attributes)) {
                    RestoreAttributes(srcFile, destPath);
                }

                filesRestored++;
                std::error_code ec;
                bytesRestored += fs::file_size(destPath, ec);

                // Update progress
                const uint64_t totalProcessed = filesRestored + filesSkipped + filesFailed;
                int pct = (totalFiles > 0)
                    ? static_cast<int>((totalProcessed * 100) / totalFiles)
                    : 0;
                pct = std::min(pct, 99);
                UpdateProgress(restoreId, "Restoring", pct,
                               filesRestored, bytesRestored, totalFiles);
            }

            if (!options.continueOnError && filesFailed > 0) break;
        }

        // Determine final status
        const bool wasCancelled = IsCancelledOrStopped(restoreId, cancelFlag);
        RestoreStatus finalStatus;
        if (wasCancelled) {
            finalStatus = RestoreStatus::Cancelled;
        } else if (filesFailed > 0 && filesRestored == 0) {
            finalStatus = RestoreStatus::Failed;
        } else if (filesFailed > 0) {
            finalStatus = RestoreStatus::Partial;
        } else {
            finalStatus = RestoreStatus::Completed;
        }

        FinishRestore(restoreId, backupId, operationStart, finalStatus,
                      filesRestored, bytesRestored, filesSkipped, filesFailed,
                      conflicts, errors);
    }

    void FinishRestore(const std::string& restoreId,
                       const std::string& backupId,
                       const SystemTimePoint& startTime,
                       RestoreStatus status,
                       uint64_t filesRestored,
                       uint64_t bytesRestored,
                       uint64_t filesSkipped,
                       uint64_t filesFailed,
                       const std::vector<RestoreConflict>& conflicts,
                       const std::vector<std::string>& errors)
    {
        const auto endTime = std::chrono::system_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);

        RestoreResult result;
        result.restoreId = restoreId;
        result.backupId = backupId;
        result.startTime = startTime;
        result.endTime = endTime;
        result.duration = duration;
        result.status = status;
        result.filesRestored = filesRestored;
        result.bytesRestored = bytesRestored;
        result.filesSkipped = filesSkipped;
        result.filesFailed = filesFailed;
        result.conflicts = conflicts;
        result.errors = errors;
        result.verificationPassed = (filesFailed == 0 && !errors.empty() == false);

        // Update statistics
        m_stats.totalRestores++;
        if (status == RestoreStatus::Completed) {
            m_stats.successfulRestores++;
        } else if (status == RestoreStatus::Failed) {
            m_stats.failedRestores++;
        }
        m_stats.totalFilesRestored += filesRestored;
        m_stats.totalBytesRestored += bytesRestored;
        m_stats.conflictsResolved += static_cast<uint64_t>(conflicts.size());

        const std::string statusName(GetRestoreStatusName(status));
        UpdateStatus(restoreId, status, statusName);
        UpdateProgress(restoreId, statusName, 100, filesRestored, bytesRestored, filesRestored + filesSkipped + filesFailed);

        {
            std::unique_lock lock(m_mutex);
            m_results[restoreId] = result;
            m_activeRestores.erase(restoreId);
            m_cancelFlags.erase(restoreId);

            // Keep rollback journal for completed/partial restores so user can undo.
            // Clear for failed/cancelled if no files were restored.
            if (status == RestoreStatus::Failed ||
                (status == RestoreStatus::Cancelled && filesRestored == 0)) {
                m_rollbackJournals.erase(restoreId);
            }

            // Reclaim the thread handle (it's about to exit)
            auto threadIt = m_workerThreads.find(restoreId);
            if (threadIt != m_workerThreads.end()) {
                if (threadIt->second.joinable()) {
                    threadIt->second.detach();  // Safe: we're inside this thread
                }
                m_workerThreads.erase(threadIt);
            }

            // Update module status if no more active restores
            if (m_activeRestores.empty() && m_status == RestoreModuleStatus::Restoring) {
                m_status = RestoreModuleStatus::Ready;
            }
        }

        SS_LOG_INFO(L"RestoreManager", L"Restore %hs finished: status=%hs files=%llu errors=%zu",
                    restoreId.c_str(), statusName.c_str(),
                    static_cast<unsigned long long>(filesRestored), errors.size());

        NotifyCompletion(result);
    }

    // ========================================================================
    // FILE OPERATIONS
    // ========================================================================

    [[nodiscard]] bool CopyFileAtomic(const fs::path& src, const fs::path& dest) {
        try {
            // Write to temp file first, then atomically rename
            fs::path tempDest = dest;
            tempDest += L".ss_restore_tmp";

            std::error_code ec;
            fs::copy_file(src, tempDest, fs::copy_options::overwrite_existing, ec);
            if (ec) {
                SS_LOG_ERROR(L"RestoreManager", L"copy_file failed: %hs -> %ls (ec=%d)",
                             src.string().c_str(), tempDest.c_str(), ec.value());
                fs::remove(tempDest, ec);
                return false;
            }

            // Atomic rename (on NTFS, rename within same volume is atomic)
            fs::rename(tempDest, dest, ec);
            if (ec) {
                // Fallback: if rename fails (cross-volume), try direct overwrite
                fs::copy_file(tempDest, dest, fs::copy_options::overwrite_existing, ec);
                fs::remove(tempDest, ec);
                if (ec) {
                    SS_LOG_ERROR(L"RestoreManager", L"Failed atomic restore to %ls",
                                 dest.c_str());
                    return false;
                }
            }
            return true;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"RestoreManager", L"Exception during file copy: %hs", e.what());
            return false;
        }
    }

    void ClearReadOnlyAttribute(const fs::path& path) {
        try {
            DWORD attrs = ::GetFileAttributesW(path.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY)) {
                ::SetFileAttributesW(path.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
            }
        } catch (...) {}
    }

    void RestoreTimestamps(const fs::path& src, const fs::path& dest) {
        FILETIME creation{}, lastAccess{}, lastWrite{};
        Utils::FileUtils::Error err;
        if (Utils::FileUtils::GetTimes(src.wstring(), creation, lastAccess, lastWrite, &err)) {
            HANDLE hDest = ::CreateFileW(dest.c_str(), FILE_WRITE_ATTRIBUTES,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hDest != INVALID_HANDLE_VALUE) {
                ::SetFileTime(hDest, &creation, &lastAccess, &lastWrite);
                ::CloseHandle(hDest);
            }
        }
    }

    void RestoreAttributes(const fs::path& src, const fs::path& dest) {
        DWORD attrs = ::GetFileAttributesW(src.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            ::SetFileAttributesW(dest.c_str(), attrs);
        }
    }

    [[nodiscard]] ConflictResolution ResolveTimestampConflict(
        const fs::path& src, const fs::path& dest, ConflictResolution policy)
    {
        try {
            std::error_code ec;
            auto srcTime = fs::last_write_time(src, ec);
            if (ec) return ConflictResolution::Skip;
            auto dstTime = fs::last_write_time(dest, ec);
            if (ec) return ConflictResolution::Overwrite;

            if (policy == ConflictResolution::OverwriteNewer) {
                return (srcTime > dstTime) ? ConflictResolution::Overwrite
                                           : ConflictResolution::Skip;
            }
            if (policy == ConflictResolution::OverwriteOlder) {
                return (srcTime < dstTime) ? ConflictResolution::Overwrite
                                           : ConflictResolution::Skip;
            }
        } catch (...) {}
        return ConflictResolution::Skip;
    }

    // ========================================================================
    // ROLLBACK JOURNALING
    // ========================================================================

    void JournalOperation(const std::string& restoreId, const fs::path& destPath,
                          bool existedBefore, const fs::path& vaultPath)
    {
        std::unique_lock lock(m_mutex);
        auto jIt = m_rollbackJournals.find(restoreId);
        if (jIt == m_rollbackJournals.end()) return;

        // Cap journal size to prevent unbounded memory growth
        if (jIt->second.size() >= kMaxRollbackJournalEntries) {
            SS_LOG_WARN(L"RestoreManager", L"Rollback journal limit reached for %hs", restoreId.c_str());
            return;
        }

        FileOperation op;
        op.path = destPath;

        if (existedBefore) {
            op.type = FileOperation::Overwritten;
            // Save a pre-overwrite copy so rollback can restore original
            try {
                fs::path rollbackDir = vaultPath / ".rollback" / restoreId;
                std::error_code ec;
                fs::create_directories(rollbackDir, ec);
                if (!ec) {
                    fs::path backupCopy = rollbackDir / (destPath.filename().wstring()
                        + L"." + std::to_wstring(jIt->second.size()));
                    fs::copy_file(destPath, backupCopy, fs::copy_options::overwrite_existing, ec);
                    if (!ec) {
                        op.backupCopyPath = backupCopy;
                    } else {
                        SS_LOG_WARN(L"RestoreManager", L"Could not backup file for rollback: %ls",
                                    destPath.c_str());
                    }
                }
            } catch (const std::exception& e) {
                SS_LOG_WARN(L"RestoreManager", L"Rollback journal backup failed: %hs", e.what());
            }
        } else {
            op.type = FileOperation::Created;
        }

        jIt->second.push_back(op);
    }

    // ========================================================================
    // PAUSE / CANCEL SUPPORT
    // ========================================================================

    [[nodiscard]] bool IsCancelledOrStopped(
        const std::string& restoreId,
        const std::shared_ptr<std::atomic<bool>>& cancelFlag) const
    {
        if (m_shutdownRequested.load(std::memory_order_acquire)) return true;
        if (cancelFlag && cancelFlag->load(std::memory_order_acquire)) return true;

        std::shared_lock lock(m_mutex);
        auto it = m_activeRestores.find(restoreId);
        if (it != m_activeRestores.end() &&
            it->second.status == RestoreStatus::Cancelled) {
            return true;
        }
        return false;
    }

    void WaitIfPaused(const std::string& restoreId,
                      const std::shared_ptr<std::atomic<bool>>& cancelFlag)
    {
        std::unique_lock lock(m_mutex);
        auto it = m_activeRestores.find(restoreId);
        if (it == m_activeRestores.end() || it->second.status != RestoreStatus::Paused) {
            return;
        }

        SS_LOG_INFO(L"RestoreManager", L"Restore paused: %hs", restoreId.c_str());

        m_cv.wait(lock, [this, &restoreId, &cancelFlag] {
            if (m_shutdownRequested.load(std::memory_order_acquire)) return true;
            if (cancelFlag && cancelFlag->load(std::memory_order_acquire)) return true;
            auto it2 = m_activeRestores.find(restoreId);
            return it2 == m_activeRestores.end() ||
                   it2->second.status != RestoreStatus::Paused;
        });

        SS_LOG_INFO(L"RestoreManager", L"Restore resumed/cancelled: %hs", restoreId.c_str());
    }

    // ========================================================================
    // CALLBACK INVOCATION
    // ========================================================================

    [[nodiscard]] ConflictResolution InvokeConflictCallback(const RestoreConflict& conflict) {
        // Snapshot callbacks under lock, invoke outside
        std::vector<RestoreConflictCallback> cbs;
        {
            std::shared_lock lock(m_callbackMutex);
            cbs = m_conflictCallbacks;
        }
        if (!cbs.empty()) {
            try {
                return cbs.back()(conflict);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"RestoreManager", L"Conflict callback threw: %hs", e.what());
            }
        }
        return ConflictResolution::Skip;
    }

    [[nodiscard]] bool InvokeFileCallback(const BackupFileEntry& entry) {
        std::vector<RestoreFileCallback> cbs;
        {
            std::shared_lock lock(m_callbackMutex);
            cbs = m_fileCallbacks;
        }
        for (const auto& cb : cbs) {
            try {
                if (!cb(entry)) return false;
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"RestoreManager", L"File callback threw: %hs", e.what());
            }
        }
        return true;
    }

    void UpdateStatus(const std::string& restoreId, RestoreStatus status,
                      const std::string& phase)
    {
        std::unique_lock lock(m_mutex);
        auto it = m_activeRestores.find(restoreId);
        if (it != m_activeRestores.end()) {
            it->second.status = status;
            it->second.phase = phase;
        }
    }

    void UpdateProgress(const std::string& restoreId, const std::string& phase,
                        int percent, uint64_t processed, uint64_t bytes, uint64_t total)
    {
        RestoreProgress snapshot;
        {
            std::unique_lock lock(m_mutex);
            auto it = m_activeRestores.find(restoreId);
            if (it == m_activeRestores.end()) return;
            auto& rp = it->second;
            rp.phase = phase;
            rp.percentComplete = std::clamp(percent, 0, 100);
            rp.filesRestored = processed;
            rp.bytesRestored = bytes;
            rp.totalFiles = total;
            snapshot = rp;
        }
        NotifyProgress(snapshot);
    }

    // ========================================================================
    // PAUSE / RESUME / CANCEL
    // ========================================================================

    bool Pause(const std::string& restoreId) {
        std::unique_lock lock(m_mutex);
        auto it = m_activeRestores.find(restoreId);
        if (it != m_activeRestores.end() &&
            it->second.status == RestoreStatus::InProgress) {
            it->second.status = RestoreStatus::Paused;
            it->second.phase = "Paused";
            SS_LOG_INFO(L"RestoreManager", L"Pause requested for %hs", restoreId.c_str());
            return true;
        }
        return false;
    }

    bool Resume(const std::string& restoreId) {
        std::unique_lock lock(m_mutex);
        auto it = m_activeRestores.find(restoreId);
        if (it != m_activeRestores.end() &&
            it->second.status == RestoreStatus::Paused) {
            it->second.status = RestoreStatus::InProgress;
            it->second.phase = "Resuming";
            m_cv.notify_all();
            SS_LOG_INFO(L"RestoreManager", L"Resume requested for %hs", restoreId.c_str());
            return true;
        }
        return false;
    }

    bool Cancel(const std::string& restoreId) {
        std::unique_lock lock(m_mutex);
        auto it = m_activeRestores.find(restoreId);
        if (it == m_activeRestores.end()) return false;

        it->second.status = RestoreStatus::Cancelled;
        auto flagIt = m_cancelFlags.find(restoreId);
        if (flagIt != m_cancelFlags.end()) {
            flagIt->second->store(true, std::memory_order_release);
        }
        m_cv.notify_all();
        SS_LOG_INFO(L"RestoreManager", L"Cancel requested for %hs", restoreId.c_str());
        return true;
    }

    // ========================================================================
    // NOTIFICATIONS (callbacks invoked outside locks)
    // ========================================================================

    void NotifyProgress(const RestoreProgress& p) {
        std::vector<RestoreProgressCallback> cbs;
        {
            std::shared_lock lock(m_callbackMutex);
            cbs = m_progressCallbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(p); } catch (...) {}
        }
    }

    void NotifyCompletion(const RestoreResult& r) {
        std::vector<RestoreCompletionCallback> cbs;
        {
            std::shared_lock lock(m_callbackMutex);
            cbs = m_completionCallbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(r); } catch (...) {}
        }
    }

    void NotifyError(const std::string& msg, int code) {
        SS_LOG_ERROR(L"RestoreManager", L"[%d] %hs", code, msg.c_str());
        std::vector<RestoreErrorCallback> cbs;
        {
            std::shared_lock lock(m_callbackMutex);
            cbs = m_errorCallbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(msg, code); } catch (...) {}
        }
    }
};

// ============================================================================
// RESTORE MANAGER PUBLIC API
// ============================================================================

RestoreManager& RestoreManager::Instance() noexcept {
    static RestoreManager instance;
    return instance;
}

bool RestoreManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

RestoreManager::RestoreManager() : m_impl(std::make_unique<RestoreManagerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

RestoreManager::~RestoreManager() {
    Shutdown();
    s_instanceCreated.store(false, std::memory_order_release);
}

bool RestoreManager::Initialize() {
    return m_impl->Initialize();
}

void RestoreManager::Shutdown() {
    m_impl->ShutdownInternal();
}

bool RestoreManager::IsInitialized() const noexcept {
    auto status = m_impl->m_status.load(std::memory_order_acquire);
    return status == RestoreModuleStatus::Ready || status == RestoreModuleStatus::Restoring;
}

RestoreModuleStatus RestoreManager::GetStatus() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire);
}

bool RestoreManager::Restore(const std::wstring& backupId, const std::wstring& targetPath) {
    if (backupId.empty() || targetPath.empty()) {
        SS_LOG_ERROR(L"RestoreManager", L"Restore called with empty backupId or targetPath");
        return false;
    }
    RestoreTarget target;
    target.targetPath = targetPath;
    target.isDirectory = true;
    return !Restore(Utils::StringUtils::ToNarrow(backupId), {target}).empty();
}

std::string RestoreManager::Restore(const std::string& backupId,
                                    const std::vector<RestoreTarget>& targets,
                                    const RestoreOptions& options) {
    return m_impl->Restore(backupId, targets, options);
}

bool RestoreManager::RestoreFile(const std::string& backupId,
                                 const fs::path& sourcePath,
                                 const fs::path& targetPath,
                                 const RestoreOptions& options) {
    if (sourcePath.empty() || targetPath.empty()) {
        SS_LOG_ERROR(L"RestoreManager", L"RestoreFile called with empty source or target path");
        return false;
    }
    RestoreTarget target;
    target.sourcePath = sourcePath;
    target.targetPath = targetPath.parent_path().empty() ? targetPath : targetPath.parent_path();
    target.isDirectory = false;
    return !m_impl->Restore(backupId, {target}, options).empty();
}

bool RestoreManager::CancelRestore(const std::string& restoreId) {
    return m_impl->Cancel(restoreId);
}

bool RestoreManager::PauseRestore(const std::string& restoreId) {
    return m_impl->Pause(restoreId);
}

bool RestoreManager::ResumeRestore(const std::string& restoreId) {
    return m_impl->Resume(restoreId);
}

std::optional<RestoreProgress> RestoreManager::GetProgress(const std::string& restoreId) {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_activeRestores.find(restoreId);
    if (it != m_impl->m_activeRestores.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<RestoreResult> RestoreManager::GetResult(const std::string& restoreId) {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_results.find(restoreId);
    if (it != m_impl->m_results.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<std::string> RestoreManager::GetActiveRestores() {
    std::shared_lock lock(m_impl->m_mutex);
    std::vector<std::string> ids;
    ids.reserve(m_impl->m_activeRestores.size());
    for (const auto& [id, _] : m_impl->m_activeRestores) {
        ids.push_back(id);
    }
    return ids;
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

void RestoreManager::RegisterProgressCallback(RestoreProgressCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallbacks.push_back(std::move(callback));
}

void RestoreManager::RegisterCompletionCallback(RestoreCompletionCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_completionCallbacks.push_back(std::move(callback));
}

void RestoreManager::RegisterConflictCallback(RestoreConflictCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_conflictCallbacks.push_back(std::move(callback));
}

void RestoreManager::RegisterFileCallback(RestoreFileCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_fileCallbacks.push_back(std::move(callback));
}

void RestoreManager::RegisterErrorCallback(RestoreErrorCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void RestoreManager::UnregisterCallbacks() {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallbacks.clear();
    m_impl->m_completionCallbacks.clear();
    m_impl->m_conflictCallbacks.clear();
    m_impl->m_fileCallbacks.clear();
    m_impl->m_errorCallbacks.clear();
}

// ============================================================================
// STATISTICS
// ============================================================================

RestoreStatistics RestoreManager::GetStatistics() const {
    // Atomics are individually thread-safe; no mutex needed for snapshot reads
    RestoreStatistics s;
    s.totalRestores       = m_impl->m_stats.totalRestores.load(std::memory_order_relaxed);
    s.successfulRestores  = m_impl->m_stats.successfulRestores.load(std::memory_order_relaxed);
    s.failedRestores      = m_impl->m_stats.failedRestores.load(std::memory_order_relaxed);
    s.totalFilesRestored  = m_impl->m_stats.totalFilesRestored.load(std::memory_order_relaxed);
    s.totalBytesRestored  = m_impl->m_stats.totalBytesRestored.load(std::memory_order_relaxed);
    s.conflictsResolved   = m_impl->m_stats.conflictsResolved.load(std::memory_order_relaxed);
    s.filesSkipped        = m_impl->m_stats.filesSkipped.load(std::memory_order_relaxed);
    s.aclsRestored        = m_impl->m_stats.aclsRestored.load(std::memory_order_relaxed);
    s.verificationsPerformed = m_impl->m_stats.verificationsPerformed.load(std::memory_order_relaxed);
    s.rollbacksPerformed  = m_impl->m_stats.rollbacksPerformed.load(std::memory_order_relaxed);
    s.startTime           = m_impl->m_stats.startTime;
    return s;
}

void RestoreManager::ResetStatistics() {
    m_impl->m_stats.Reset();
}

// ============================================================================
// POINT-IN-TIME RESTORE
// ============================================================================

std::string RestoreManager::RestoreToPointInTime(const SystemTimePoint& ts,
                                                  const std::vector<RestoreTarget>& t,
                                                  const RestoreOptions& o) {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"RestoreManager", L"Not initialized for point-in-time restore");
        return {};
    }

    auto backups = BackupManager::Instance().GetBackupPointsDetailed();
    if (backups.empty()) {
        SS_LOG_ERROR(L"RestoreManager", L"No backups available for point-in-time restore");
        return {};
    }

    // Sort descending by end time, pick first backup completed at-or-before ts
    std::sort(backups.begin(), backups.end(), [](const BackupPoint& a, const BackupPoint& b) {
        return a.endTime > b.endTime;
    });

    std::string selectedBackupId;
    for (const auto& bp : backups) {
        if (bp.status == BackupStatus::Completed && bp.endTime <= ts) {
            selectedBackupId = bp.backupId;
            break;
        }
    }

    if (selectedBackupId.empty()) {
        SS_LOG_ERROR(L"RestoreManager", L"No completed backup found at or before specified time");
        return {};
    }

    SS_LOG_INFO(L"RestoreManager", L"Point-in-time restore using backup %hs",
                selectedBackupId.c_str());
    return Restore(selectedBackupId, t, o);
}

std::vector<BackupFileEntry> RestoreManager::GetFileVersions(const fs::path& filePath) {
    std::vector<BackupFileEntry> versions;

    if (filePath.empty()) return versions;

    auto vaultInfo = BackupManager::Instance().GetVaultInfo();
    if (vaultInfo.path.empty()) return versions;

    auto backups = BackupManager::Instance().GetBackupPointsDetailed();
    const std::wstring targetFilename = filePath.filename().wstring();

    for (const auto& bp : backups) {
        if (bp.status != BackupStatus::Completed) continue;

        fs::path backupDataDir = vaultInfo.path / bp.backupId / "data";
        std::error_code ec;
        if (!fs::exists(backupDataDir, ec) || ec) continue;

        // Search for matching filename in this backup's data dir
        for (const auto& entry : fs::directory_iterator(backupDataDir, ec)) {
            if (ec) break;
            if (!entry.is_regular_file()) continue;

            // Match by filename (BackupManager flattens structure)
            std::wstring entryName = entry.path().filename().wstring();
            if (entryName == targetFilename ||
                entryName.find(filePath.stem().wstring()) == 0) {
                BackupFileEntry bfe;
                bfe.path = entry.path().filename();
                bfe.isDirectory = false;
                bfe.size = entry.file_size(ec);
                bfe.modifiedTime = bp.endTime;
                bfe.hash = ComputeFileHash(entry.path());
                versions.push_back(std::move(bfe));
                break;
            }
        }
    }

    return versions;
}

bool RestoreManager::RestoreFileVersion(const fs::path& filePath,
                                        const SystemTimePoint& versionTimestamp,
                                        const fs::path& targetPath) {
    if (filePath.empty() || targetPath.empty()) {
        SS_LOG_ERROR(L"RestoreManager", L"RestoreFileVersion called with empty paths");
        return false;
    }

    auto backups = BackupManager::Instance().GetBackupPointsDetailed();
    std::string targetBackupId;

    for (const auto& bp : backups) {
        if (bp.status == BackupStatus::Completed && bp.endTime == versionTimestamp) {
            targetBackupId = bp.backupId;
            break;
        }
    }

    if (targetBackupId.empty()) {
        SS_LOG_ERROR(L"RestoreManager", L"No backup found matching version timestamp");
        return false;
    }

    RestoreTarget target;
    target.sourcePath = filePath;
    target.targetPath = targetPath.parent_path().empty() ? targetPath : targetPath.parent_path();
    target.isDirectory = false;

    RestoreOptions opts;
    opts.mode = RestoreMode::Selective;
    opts.conflictResolution = ConflictResolution::Overwrite;

    return !Restore(targetBackupId, {target}, opts).empty();
}

// ============================================================================
// BROWSE BACKUP
// ============================================================================

std::vector<BackupFileEntry> RestoreManager::ListBackupFiles(const std::string& backupId,
                                                              const fs::path& directory) {
    std::vector<BackupFileEntry> entries;

    if (!IsValidBackupId(backupId)) {
        SS_LOG_ERROR(L"RestoreManager", L"Invalid backup ID in ListBackupFiles");
        return entries;
    }

    auto vaultInfo = BackupManager::Instance().GetVaultInfo();
    if (vaultInfo.path.empty()) return entries;

    fs::path backupDataDir = vaultInfo.path / backupId / "data";
    std::error_code ec;
    if (!fs::exists(backupDataDir, ec) || ec) return entries;

    for (const auto& entry : fs::directory_iterator(backupDataDir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;

        // If a directory filter is provided, match against it
        if (!directory.empty()) {
            std::wstring entryName = entry.path().filename().wstring();
            std::wstring filter = directory.filename().wstring();
            if (!filter.empty() && entryName.find(filter) == std::wstring::npos) {
                continue;
            }
        }

        BackupFileEntry bfe;
        bfe.path = entry.path().filename();
        bfe.isDirectory = false;
        bfe.size = entry.file_size(ec);
        bfe.compressedSize = bfe.size;  // No compression in current BackupManager
        entries.push_back(std::move(bfe));
    }

    return entries;
}

std::vector<BackupFileEntry> RestoreManager::SearchBackupFiles(const std::string& backupId,
                                                                const std::string& pattern) {
    if (pattern.empty()) return ListBackupFiles(backupId);

    auto allFiles = ListBackupFiles(backupId);
    std::vector<BackupFileEntry> matches;

    // Simple substring match (case-insensitive)
    std::string lowerPattern = pattern;
    std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (auto& entry : allFiles) {
        std::string name = entry.path.string();
        std::string lowerName = name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lowerName.find(lowerPattern) != std::string::npos) {
            matches.push_back(std::move(entry));
        }
    }
    return matches;
}

std::vector<uint8_t> RestoreManager::PreviewFile(const std::string& backupId,
                                                  const fs::path& filePath,
                                                  size_t maxBytes) {
    if (!IsValidBackupId(backupId) || filePath.empty()) return {};

    // Cap maxBytes to prevent excessive memory allocation
    constexpr size_t kMaxPreview = 16 * 1024 * 1024;  // 16MB
    maxBytes = std::min(maxBytes, kMaxPreview);

    auto vaultInfo = BackupManager::Instance().GetVaultInfo();
    if (vaultInfo.path.empty()) return {};

    fs::path fullPath = vaultInfo.path / backupId / "data" / filePath.filename();
    std::error_code ec;
    if (!fs::exists(fullPath, ec) || ec) return {};

    uint64_t fileSize = fs::file_size(fullPath, ec);
    if (ec) return {};

    size_t readSize = static_cast<size_t>(std::min(static_cast<uint64_t>(maxBytes), fileSize));

    std::vector<uint8_t> buffer(readSize);
    std::ifstream ifs(fullPath, std::ios::binary);
    if (!ifs) return {};

    ifs.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(readSize));
    auto actualRead = ifs.gcount();
    buffer.resize(static_cast<size_t>(actualRead));
    return buffer;
}

// ============================================================================
// VERIFICATION
// ============================================================================

bool RestoreManager::VerifyRestore(const std::string& restoreId) {
    auto resultOpt = GetResult(restoreId);
    if (!resultOpt) {
        SS_LOG_ERROR(L"RestoreManager", L"VerifyRestore: no result for %hs", restoreId.c_str());
        return false;
    }

    const auto& result = *resultOpt;
    if (result.status != RestoreStatus::Completed &&
        result.status != RestoreStatus::Partial) {
        SS_LOG_ERROR(L"RestoreManager", L"VerifyRestore: restore %hs did not complete successfully",
                     restoreId.c_str());
        return false;
    }

    // Verify each file that was journaled
    std::shared_lock lock(m_impl->m_mutex);
    auto jIt = m_impl->m_rollbackJournals.find(restoreId);
    if (jIt == m_impl->m_rollbackJournals.end()) {
        SS_LOG_WARN(L"RestoreManager", L"VerifyRestore: no journal found for %hs", restoreId.c_str());
        return result.filesFailed == 0;
    }

    uint64_t verified = 0;
    uint64_t verifyFailed = 0;
    for (const auto& op : jIt->second) {
        std::error_code ec;
        if (!fs::exists(op.path, ec) || ec) {
            SS_LOG_ERROR(L"RestoreManager", L"Verify: restored file missing: %ls",
                         op.path.c_str());
            verifyFailed++;
            continue;
        }
        // File exists — basic integrity check
        if (fs::file_size(op.path, ec) == 0 && ec) {
            verifyFailed++;
            continue;
        }
        verified++;
    }

    m_impl->m_stats.verificationsPerformed++;
    SS_LOG_INFO(L"RestoreManager", L"VerifyRestore %hs: %llu verified, %llu failed",
                restoreId.c_str(),
                static_cast<unsigned long long>(verified),
                static_cast<unsigned long long>(verifyFailed));
    return verifyFailed == 0;
}

bool RestoreManager::VerifyFileIntegrity(const fs::path& filePath,
                                          const std::string& expectedHash) {
    if (filePath.empty() || expectedHash.empty()) {
        SS_LOG_ERROR(L"RestoreManager", L"VerifyFileIntegrity: empty path or hash");
        return false;
    }

    std::error_code ec;
    if (!fs::exists(filePath, ec) || ec) {
        SS_LOG_ERROR(L"RestoreManager", L"VerifyFileIntegrity: file not found: %ls",
                     filePath.c_str());
        return false;
    }

    std::string calculatedHash = ComputeFileHash(filePath);
    if (calculatedHash.empty()) {
        SS_LOG_ERROR(L"RestoreManager", L"Failed to compute hash for: %ls",
                     filePath.c_str());
        return false;
    }

    // Constant-time comparison to prevent timing side-channels
    if (calculatedHash.size() != expectedHash.size()) return false;
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < calculatedHash.size(); ++i) {
        diff |= static_cast<unsigned char>(calculatedHash[i]) ^
                static_cast<unsigned char>(expectedHash[i]);
    }
    return diff == 0;
}

// ============================================================================
// ROLLBACK
// ============================================================================

bool RestoreManager::RollbackRestore(const std::string& restoreId) {
    std::unique_lock lock(m_impl->m_mutex);
    auto jIt = m_impl->m_rollbackJournals.find(restoreId);
    if (jIt == m_impl->m_rollbackJournals.end() || jIt->second.empty()) {
        SS_LOG_WARN(L"RestoreManager", L"No rollback journal for %hs", restoreId.c_str());
        return false;
    }

    auto& journal = jIt->second;
    SS_LOG_INFO(L"RestoreManager", L"Rolling back restore %hs (%zu operations)",
                restoreId.c_str(), journal.size());

    uint64_t rollbackSuccess = 0;
    uint64_t rollbackFailed = 0;

    // Process in reverse order (LIFO)
    while (!journal.empty()) {
        auto op = journal.back();
        journal.pop_back();

        Utils::FileUtils::Error err;
        try {
            if (op.type == RestoreManagerImpl::FileOperation::Created) {
                // Undo creation → delete the file we created
                if (Utils::FileUtils::RemoveFile(op.path.wstring(), &err)) {
                    rollbackSuccess++;
                } else {
                    SS_LOG_ERROR(L"RestoreManager", L"Rollback: failed to remove created file: %ls",
                                 op.path.c_str());
                    rollbackFailed++;
                }
            } else if (op.type == RestoreManagerImpl::FileOperation::Overwritten) {
                // Undo overwrite → restore from pre-overwrite backup
                if (!op.backupCopyPath.empty()) {
                    std::error_code ec;
                    fs::copy_file(op.backupCopyPath, op.path,
                                  fs::copy_options::overwrite_existing, ec);
                    if (!ec) {
                        fs::remove(op.backupCopyPath, ec);
                        rollbackSuccess++;
                    } else {
                        SS_LOG_ERROR(L"RestoreManager",
                                     L"Rollback: failed to restore original: %ls",
                                     op.path.c_str());
                        rollbackFailed++;
                    }
                } else {
                    SS_LOG_WARN(L"RestoreManager",
                                L"Rollback: no backup copy for overwritten file: %ls",
                                op.path.c_str());
                    rollbackFailed++;
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"RestoreManager", L"Rollback exception for %ls: %hs",
                         op.path.c_str(), e.what());
            rollbackFailed++;
        }
    }

    // Clean up rollback temp directory
    auto vaultInfo = BackupManager::Instance().GetVaultInfo();
    if (!vaultInfo.path.empty()) {
        std::error_code ec;
        fs::remove_all(vaultInfo.path / ".rollback" / restoreId, ec);
    }

    m_impl->m_rollbackJournals.erase(jIt);
    m_impl->m_stats.rollbacksPerformed++;

    SS_LOG_INFO(L"RestoreManager", L"Rollback %hs complete: %llu ok, %llu failed",
                restoreId.c_str(),
                static_cast<unsigned long long>(rollbackSuccess),
                static_cast<unsigned long long>(rollbackFailed));
    return rollbackFailed == 0;
}

bool RestoreManager::IsRollbackAvailable(const std::string& restoreId) const {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_rollbackJournals.find(restoreId);
    return it != m_impl->m_rollbackJournals.end() && !it->second.empty();
}

// ============================================================================
// SELF-TEST & VERSION
// ============================================================================

bool RestoreManager::SelfTest() {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"RestoreManager", L"SelfTest: not initialized");
        return false;
    }

    // Verify UUID generation
    std::string testId = GenerateRestoreId();
    if (testId.empty() || testId.size() < 8) {
        SS_LOG_ERROR(L"RestoreManager", L"SelfTest: UUID generation failed");
        return false;
    }

    // Verify backup ID validation
    if (!IsValidBackupId(testId)) {
        SS_LOG_ERROR(L"RestoreManager", L"SelfTest: ID validation rejected valid UUID");
        return false;
    }
    if (IsValidBackupId("../../etc/passwd")) {
        SS_LOG_ERROR(L"RestoreManager", L"SelfTest: ID validation accepted path traversal");
        return false;
    }

    // Verify BackupManager connectivity
    if (!BackupManager::HasInstance()) {
        SS_LOG_WARN(L"RestoreManager", L"SelfTest: BackupManager not available");
    }

    SS_LOG_INFO(L"RestoreManager", L"SelfTest passed");
    return true;
}

std::string RestoreManager::GetVersionString() noexcept {
    return std::to_string(RestoreConstants::VERSION_MAJOR) + "." +
           std::to_string(RestoreConstants::VERSION_MINOR) + "." +
           std::to_string(RestoreConstants::VERSION_PATCH);
}

// ============================================================================
// JSON SERIALIZATION
// ============================================================================

std::string RestoreTarget::ToJson() const {
    Utils::JSON::Json j;
    j["sourcePath"] = sourcePath.string();
    j["targetPath"] = targetPath.string();
    j["isDirectory"] = isDirectory;
    j["recursive"] = recursive;
    j["includePatterns"] = includePatterns;
    j["excludePatterns"] = excludePatterns;
    return j.dump();
}

std::string RestoreConflict::ToJson() const {
    Utils::JSON::Json j;
    j["sourcePath"] = sourcePath.string();
    j["targetPath"] = targetPath.string();
    j["sourceSize"] = sourceSize;
    j["targetSize"] = targetSize;
    j["resolution"] = static_cast<int>(resolution);
    return j.dump();
}

std::string BackupFileEntry::ToJson() const {
    Utils::JSON::Json j;
    j["path"] = path.string();
    j["isDirectory"] = isDirectory;
    j["size"] = size;
    j["compressedSize"] = compressedSize;
    j["attributes"] = attributes;
    j["hash"] = hash;
    j["hasACLs"] = hasACLs;
    j["hasADS"] = hasADS;
    return j.dump();
}

std::string RestoreProgress::ToJson() const {
    Utils::JSON::Json j;
    j["restoreId"] = restoreId;
    j["status"] = static_cast<int>(status);
    j["phase"] = phase;
    j["currentFile"] = currentFile.string();
    j["percentComplete"] = percentComplete;
    j["filesRestored"] = filesRestored;
    j["totalFiles"] = totalFiles;
    j["bytesRestored"] = bytesRestored;
    j["totalBytes"] = totalBytes;
    j["filesSkipped"] = filesSkipped;
    j["filesFailed"] = filesFailed;
    j["conflictsEncountered"] = conflictsEncountered;
    j["transferRate"] = transferRate;
    j["estimatedTimeRemaining"] = estimatedTimeRemaining;
    j["errors"] = errors;
    return j.dump();
}

std::string RestoreResult::ToJson() const {
    Utils::JSON::Json j;
    j["restoreId"] = restoreId;
    j["backupId"] = backupId;
    j["status"] = static_cast<int>(status);
    j["startTime"] = std::chrono::duration_cast<std::chrono::seconds>(
        startTime.time_since_epoch()).count();
    j["endTime"] = std::chrono::duration_cast<std::chrono::seconds>(
        endTime.time_since_epoch()).count();
    j["duration"] = duration.count();
    j["filesRestored"] = filesRestored;
    j["bytesRestored"] = bytesRestored;
    j["filesSkipped"] = filesSkipped;
    j["filesFailed"] = filesFailed;
    j["verificationPassed"] = verificationPassed;
    j["errors"] = errors;

    Utils::JSON::Json jConflicts = Utils::JSON::Json::array();
    for (const auto& c : conflicts) {
        jConflicts.push_back(Utils::JSON::Json::parse(c.ToJson()));
    }
    j["conflicts"] = jConflicts;
    return j.dump();
}

std::string RestoreStatistics::ToJson() const {
    Utils::JSON::Json j;
    j["totalRestores"] = totalRestores.load(std::memory_order_relaxed);
    j["successfulRestores"] = successfulRestores.load(std::memory_order_relaxed);
    j["failedRestores"] = failedRestores.load(std::memory_order_relaxed);
    j["totalFilesRestored"] = totalFilesRestored.load(std::memory_order_relaxed);
    j["totalBytesRestored"] = totalBytesRestored.load(std::memory_order_relaxed);
    j["conflictsResolved"] = conflictsResolved.load(std::memory_order_relaxed);
    j["filesSkipped"] = filesSkipped.load(std::memory_order_relaxed);
    j["aclsRestored"] = aclsRestored.load(std::memory_order_relaxed);
    j["verificationsPerformed"] = verificationsPerformed.load(std::memory_order_relaxed);
    j["rollbacksPerformed"] = rollbacksPerformed.load(std::memory_order_relaxed);
    return j.dump();
}

void RestoreStatistics::Reset() noexcept {
    totalRestores = 0;
    successfulRestores = 0;
    failedRestores = 0;
    totalFilesRestored = 0;
    totalBytesRestored = 0;
    conflictsResolved = 0;
    filesSkipped = 0;
    aclsRestored = 0;
    verificationsPerformed = 0;
    rollbacksPerformed = 0;
    startTime = Clock::now();
}

bool RestoreOptions::IsValid() const noexcept {
    if (maxErrors == 0 && !continueOnError) return true;
    if (mode > RestoreMode::BareMetal) return false;
    if (conflictResolution > ConflictResolution::Prompt) return false;
    return true;
}

// ============================================================================
// FREE FUNCTIONS
// ============================================================================

std::string_view GetRestoreModeName(RestoreMode mode) noexcept {
    switch (mode) {
    case RestoreMode::Full:         return "Full";
    case RestoreMode::Selective:    return "Selective";
    case RestoreMode::Directory:    return "Directory";
    case RestoreMode::PointInTime:  return "PointInTime";
    case RestoreMode::BareMetal:    return "BareMetal";
    default:                        return "Unknown";
    }
}

std::string_view GetConflictResolutionName(ConflictResolution resolution) noexcept {
    switch (resolution) {
    case ConflictResolution::Overwrite:       return "Overwrite";
    case ConflictResolution::KeepBoth:        return "KeepBoth";
    case ConflictResolution::Skip:            return "Skip";
    case ConflictResolution::OverwriteNewer:  return "OverwriteNewer";
    case ConflictResolution::OverwriteOlder:  return "OverwriteOlder";
    case ConflictResolution::Prompt:          return "Prompt";
    default:                                  return "Unknown";
    }
}

std::string_view GetRestoreStatusName(RestoreStatus status) noexcept {
    switch (status) {
    case RestoreStatus::Pending:      return "Pending";
    case RestoreStatus::InProgress:   return "InProgress";
    case RestoreStatus::Completed:    return "Completed";
    case RestoreStatus::Failed:       return "Failed";
    case RestoreStatus::Cancelled:    return "Cancelled";
    case RestoreStatus::Partial:      return "Partial";
    case RestoreStatus::Verifying:    return "Verifying";
    case RestoreStatus::RollingBack:  return "RollingBack";
    case RestoreStatus::Paused:       return "Paused";
    default:                          return "Unknown";
    }
}

std::string GenerateRestoreId() {
    return GenerateId();
}

bool IsNewer(const SystemTimePoint& a, const SystemTimePoint& b) {
    return a > b;
}

}  // namespace Backup
}  // namespace ShadowStrike

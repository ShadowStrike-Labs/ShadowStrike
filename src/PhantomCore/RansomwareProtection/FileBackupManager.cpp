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
 * ShadowStrike NGAV - FILE BACKUP MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file FileBackupManager.cpp
 * @brief Enterprise-grade JIT backup system implementation
 *
 * ARCHITECTURE:
 * - PIMPL pattern for ABI stability
 * - Meyers singleton for thread-safe instance management
 * - shared_mutex for concurrent read/write access
 * - Hybrid storage (RAM + Disk) with intelligent tiering
 *
 * SECURITY:
 * - SHA-256 cryptographic hashing via Utils::HashUtils
 * - Atomic writes (temp-file + rename) via Utils::FileUtils
 * - Integrity verification before every restore
 * - Path traversal protection via Utils::FileUtils::NormalizePath
 * - CSPRNG backup IDs via Utils::CryptoUtils::SecureRandom
 * - Non-obvious backup directory with restrictive attributes
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
#include "FileBackupManager.hpp"

// ============================================================================
// ADDITIONAL INCLUDES
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"

// Cross-module wiring
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"

#include <filesystem>
#include <algorithm>
#include <thread>
#include <condition_variable>

namespace fs = std::filesystem;

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

namespace {
    constexpr const wchar_t* kLogCategory = L"Backup";
    constexpr const wchar_t* kBackupSubDirName = L"rtpdb";

    // RAII wrapper for Win32 HANDLE
    struct HandleCloser {
        void operator()(HANDLE h) const noexcept {
            if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
        }
    };
    using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleCloser>;

    [[nodiscard]] std::string GenerateBackupId() {
        using namespace ShadowStrike;
        Utils::CryptoUtils::SecureRandom rng;
        auto bytes = rng.Generate(16);
        if (!bytes.empty()) {
            return Utils::HashUtils::ToHexLower(bytes.data(), bytes.size());
        }
        LARGE_INTEGER qpc{};
        ::QueryPerformanceCounter(&qpc);
        auto tid = ::GetCurrentThreadId();
        std::array<uint8_t, 16> fb{};
        std::memcpy(fb.data(), &qpc.QuadPart, 8);
        std::memcpy(fb.data() + 8, &tid, 4);
        return ShadowStrike::Utils::HashUtils::ToHexLower(fb.data(), fb.size());
    }

    [[nodiscard]] bool ComputeBufferHash(
        const void* data, size_t len,
        ShadowStrike::Ransomware::Hash256& outHash) noexcept
    {
        using namespace ShadowStrike;
        std::vector<uint8_t> hashOut;
        if (!Utils::HashUtils::Compute(
                Utils::HashUtils::Algorithm::SHA256, data, len, hashOut)) {
            return false;
        }
        if (hashOut.size() != 32) return false;
        std::memcpy(outHash.data(), hashOut.data(), 32);
        return true;
    }

    [[nodiscard]] bool HashEqual(
        const ShadowStrike::Ransomware::Hash256& a,
        const ShadowStrike::Ransomware::Hash256& b) noexcept
    {
        return ShadowStrike::Utils::HashUtils::Equal(a.data(), b.data(), 32);
    }

    [[nodiscard]] std::wstring NormalizePolicyPath(std::wstring_view path) {
        if (path.empty()) {
            return {};
        }

        std::wstring normalized(path);
        std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
        std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                       [](wchar_t ch) { return static_cast<wchar_t>(::towlower(ch)); });

        while (normalized.size() > 3 && !normalized.empty() && normalized.back() == L'\\') {
            normalized.pop_back();
        }

        return normalized;
    }

    [[nodiscard]] std::wstring NormalizeDirectoryPrefix(std::wstring_view directory) {
        std::wstring normalized = NormalizePolicyPath(directory);
        if (!normalized.empty() && normalized.back() != L'\\') {
            normalized.push_back(L'\\');
        }
        return normalized;
    }

    [[nodiscard]] bool HasDirectoryPrefix(std::wstring_view normalizedPath,
                                          std::wstring_view normalizedDirectory) {
        if (normalizedPath.empty() || normalizedDirectory.empty() ||
            normalizedPath.size() < normalizedDirectory.size()) {
            return false;
        }

        return normalizedPath.compare(0, normalizedDirectory.size(), normalizedDirectory) == 0;
    }

    [[nodiscard]] bool MatchesExtensionList(std::wstring_view extension,
                                            const std::vector<std::wstring>& filterList) {
        for (const auto& filter : filterList) {
            if (extension == NormalizePolicyPath(filter)) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool IsPathAllowedByPolicy(
        std::wstring_view normalizedPath,
        const ShadowStrike::Ransomware::BackupPolicy& policy)
    {
        auto dotPos = normalizedPath.find_last_of(L'.');
        if (dotPos != std::wstring::npos) {
            const std::wstring extension(normalizedPath.substr(dotPos));
            if (MatchesExtensionList(extension, policy.excludeExtensions)) {
                return false;
            }

            if (!policy.includeExtensions.empty() &&
                !MatchesExtensionList(extension, policy.includeExtensions)) {
                return false;
            }
        } else if (!policy.includeExtensions.empty()) {
            return false;
        }

        if (!policy.includeDirectories.empty()) {
            bool matchedIncludeDirectory = false;
            for (const auto& directory : policy.includeDirectories) {
                const auto normalizedDirectory = NormalizeDirectoryPrefix(directory);
                if (!normalizedDirectory.empty() &&
                    HasDirectoryPrefix(normalizedPath, normalizedDirectory)) {
                    matchedIncludeDirectory = true;
                    break;
                }
            }

            if (!matchedIncludeDirectory) {
                return false;
            }
        }

        for (const auto& directory : policy.excludeDirectories) {
            const auto normalizedDirectory = NormalizeDirectoryPrefix(directory);
            if (!normalizedDirectory.empty() &&
                HasDirectoryPrefix(normalizedPath, normalizedDirectory)) {
                return false;
            }
        }

        return true;
    }

    [[nodiscard]] uint64_t FileTimeToUint64(const FILETIME& ft) noexcept {
        return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    }

    [[nodiscard]] FILETIME Uint64ToFileTime(uint64_t val) noexcept {
        FILETIME ft{};
        ft.dwLowDateTime  = static_cast<DWORD>(val);
        ft.dwHighDateTime = static_cast<DWORD>(val >> 32);
        return ft;
    }
} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike::Ransomware {

class FileBackupManagerImpl final {
public:
    FileBackupManagerImpl() = default;
    ~FileBackupManagerImpl() { Shutdown(); }

    FileBackupManagerImpl(const FileBackupManagerImpl&) = delete;
    FileBackupManagerImpl& operator=(const FileBackupManagerImpl&) = delete;
    FileBackupManagerImpl(FileBackupManagerImpl&&) = delete;
    FileBackupManagerImpl& operator=(FileBackupManagerImpl&&) = delete;

    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    FileBackupManagerConfiguration m_config;
    BackupStatistics m_stats;

    std::unordered_map<std::string, BackupEntry> m_backups;
    std::unordered_map<uint32_t, std::vector<std::string>> m_processBackups;
    std::unordered_map<std::wstring, std::string> m_pathIndex;

    std::atomic<uint64_t> m_currentRamUsage{0};
    std::atomic<uint64_t> m_currentDiskUsage{0};

    std::atomic<bool> m_running{false};
    std::thread m_cleanupThread;
    std::mutex m_shutdownMutex;
    std::condition_variable m_shutdownCv;

    std::wstring m_resolvedCacheDir;

    BackupCompleteCallback m_backupCompleteCallback;
    RestoreCompleteCallback m_restoreCompleteCallback;
    BackupProgressCallback m_progressCallback;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    void Shutdown() {
        m_running.store(false, std::memory_order_release);
        m_shutdownCv.notify_all();
        if (m_cleanupThread.joinable()) {
            m_cleanupThread.join();
        }
        std::unique_lock lock(m_mutex);
        for (auto& [id, entry] : m_backups) {
            entry.memoryData.reset();
        }
        m_backups.clear();
        m_processBackups.clear();
        m_pathIndex.clear();
        m_currentRamUsage.store(0, std::memory_order_relaxed);
    }

    [[nodiscard]] bool InitializeCacheDirectory() {
        std::wstring baseDir = m_config.cacheDirectory;
        if (baseDir.empty()) {
            baseDir = Utils::SystemUtils::ExpandEnv(L"%ProgramData%");
            if (baseDir.empty()) {
                SS_LOG_ERROR(kLogCategory, L"Cannot resolve ProgramData path");
                return false;
            }
            baseDir += L"\\ShadowStrike\\";
            baseDir += kBackupSubDirName;
        }
        auto normalized = Utils::FileUtils::NormalizePath(baseDir);
        if (normalized.empty()) {
            SS_LOG_ERROR(kLogCategory, L"Failed to normalize cache path: %ls", baseDir.c_str());
            return false;
        }
        Utils::FileUtils::Error dirErr{};
        if (!Utils::FileUtils::CreateDirectories(normalized, &dirErr)) {
            SS_LOG_ERROR(kLogCategory, L"Failed to create cache dir: %ls (Win32: %u)",
                normalized.c_str(), dirErr.win32);
            return false;
        }
        ::SetFileAttributesW(normalized.c_str(),
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
        m_resolvedCacheDir = std::move(normalized);
        SS_LOG_DEBUG(kLogCategory, L"Backup cache: %ls", m_resolvedCacheDir.c_str());
        return true;
    }

    // ========================================================================
    // PATH VALIDATION
    // ========================================================================

    [[nodiscard]] bool ValidatePath(const std::wstring& path) const {
        if (path.empty()) return false;
        auto normalized = Utils::FileUtils::NormalizePath(path, true);
        if (normalized.empty()) return false;
        if (!m_resolvedCacheDir.empty()) {
            Utils::FileUtils::Error err{};
            if (Utils::FileUtils::IsPathUnderRoot(normalized, m_resolvedCacheDir, true, &err)) {
                SS_LOG_WARN(kLogCategory, L"Rejecting cache-internal path: %ls", path.c_str());
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool IsPathExcluded(const std::wstring& path, const BackupPolicy& policy) const {
        const std::wstring normalizedPath = NormalizePolicyPath(path);
        if (normalizedPath.empty()) {
            return true;
        }

        return !IsPathAllowedByPolicy(normalizedPath, policy);
    }

    // ========================================================================
    // ENTRY CREATION
    // ========================================================================

    [[nodiscard]] BackupEntry CreateBackupEntry(
        const std::wstring& filePath, uint32_t pid, const BackupPolicy& policy)
    {
        BackupEntry entry;
        entry.backupId = GenerateBackupId();
        entry.originalPath = filePath;
        entry.modifyingPid = pid;
        entry.timestamp = std::chrono::system_clock::now();
        entry.expirationTime = Clock::now() + std::chrono::seconds(policy.retentionSecs);

        Utils::FileUtils::FileStat stat{};
        Utils::FileUtils::Error statErr{};
        if (!Utils::FileUtils::Stat(filePath, stat, &statErr)) {
            SS_LOG_ERROR(kLogCategory, L"Stat failed: %ls (Win32: %u)", filePath.c_str(), statErr.win32);
            entry.status = BackupStatus::Failed;
            return entry;
        }
        if (!stat.exists || stat.isDirectory) {
            SS_LOG_WARN(kLogCategory, L"File missing or is directory: %ls", filePath.c_str());
            entry.status = BackupStatus::Failed;
            return entry;
        }
        entry.originalSize = stat.size;
        entry.originalAttributes = stat.attributes;
        entry.originalCreationTime = FileTimeToUint64(stat.creation);
        entry.originalModificationTime = FileTimeToUint64(stat.lastWrite);

        if (entry.originalSize <= policy.ramThreshold &&
            (m_currentRamUsage.load(std::memory_order_relaxed) + entry.originalSize) <= m_config.maxRamCacheSize) {
            entry.storageType = BackupStorageType::RAM;
        } else {
            entry.storageType = BackupStorageType::Disk;
        }
        return entry;
    }

    // ========================================================================
    // BACKUP EXECUTION
    // ========================================================================

    void CleanupFailedBackupFile(const std::wstring& path) {
        if (!path.empty()) {
            (void)::SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
            (void)Utils::FileUtils::RemoveFile(path);
        }
    }

    void PerformBackup(BackupEntry& entry) {
        try {
            entry.status = BackupStatus::InProgress;

            std::vector<std::byte> fileContent;
            Utils::FileUtils::Error readErr{};
            if (!Utils::FileUtils::ReadAllBytes(entry.originalPath, fileContent, &readErr)) {
                SS_LOG_ERROR(kLogCategory, L"Read failed: %ls (Win32: %u)",
                    entry.originalPath.c_str(), readErr.win32);
                throw std::runtime_error("Failed to read source file");
            }
            entry.originalSize = fileContent.size();

            if (!ComputeBufferHash(fileContent.data(), fileContent.size(), entry.originalHash)) {
                throw std::runtime_error("Content hash computation failed");
            }

            if (entry.storageType == BackupStorageType::RAM) {
                auto memData = std::make_shared<std::vector<uint8_t>>(fileContent.size());
                if (!fileContent.empty()) {
                    std::memcpy(memData->data(), fileContent.data(), fileContent.size());
                }
                entry.memoryData = std::move(memData);
                entry.backupHash = entry.originalHash;
                entry.backupSize = fileContent.size();
                m_currentRamUsage.fetch_add(entry.backupSize, std::memory_order_relaxed);
            } else {
                std::wstring fname = Utils::StringUtils::ToWide(entry.backupId) + L".bak";
                entry.backupPath = (fs::path(m_resolvedCacheDir) / fname).wstring();

                Utils::FileUtils::Error writeErr{};
                if (!Utils::FileUtils::WriteAllBytesAtomic(
                        entry.backupPath, fileContent.data(), fileContent.size(), &writeErr)) {
                    SS_LOG_ERROR(kLogCategory, L"Atomic write failed: %ls (Win32: %u)",
                        entry.backupPath.c_str(), writeErr.win32);
                    throw std::runtime_error("Atomic backup write failed");
                }
                ::SetFileAttributesW(entry.backupPath.c_str(),
                    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM |
                    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_READONLY);

                Hash256 verifyHash{};
                if (!Utils::FileUtils::ComputeFileSHA256(entry.backupPath, verifyHash)) {
                    CleanupFailedBackupFile(entry.backupPath);
                    throw std::runtime_error("Backup verification hash failed");
                }
                if (!HashEqual(entry.originalHash, verifyHash)) {
                    CleanupFailedBackupFile(entry.backupPath);
                    SS_LOG_FATAL(kLogCategory, L"BACKUP HASH MISMATCH after write: %ls",
                        entry.backupPath.c_str());
                    throw std::runtime_error("Backup hash mismatch - possible disk corruption");
                }
                entry.backupHash = verifyHash;
                entry.backupSize = fileContent.size();
                m_currentDiskUsage.fetch_add(entry.backupSize, std::memory_order_relaxed);
            }

            entry.status = BackupStatus::Completed;
            m_stats.filesBackedUp.fetch_add(1, std::memory_order_relaxed);
            m_stats.bytesBackedUp.fetch_add(entry.originalSize, std::memory_order_relaxed);
            m_stats.activeBackups.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(kLogCategory, L"JIT backup [%hs] PID=%u %ls (%llu bytes, %hs)",
                entry.backupId.c_str(), entry.modifyingPid, entry.originalPath.c_str(),
                static_cast<unsigned long long>(entry.originalSize),
                entry.storageType == BackupStorageType::RAM ? "RAM" : "Disk");

        } catch (const std::exception& e) {
            entry.status = BackupStatus::Failed;
            m_stats.backupFailures.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_ERROR(kLogCategory, L"Backup failed: %ls - %hs",
                entry.originalPath.c_str(), e.what());
        }
    }

    // ========================================================================
    // RESTORE EXECUTION
    // ========================================================================

    void RestoreTimestamps(const BackupEntry& entry) {
        if (entry.originalCreationTime == 0 && entry.originalModificationTime == 0) return;
        UniqueHandle hFile(::CreateFileW(
            entry.originalPath.c_str(), FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!hFile || hFile.get() == INVALID_HANDLE_VALUE) return;
        FILETIME creation = Uint64ToFileTime(entry.originalCreationTime);
        FILETIME lastWrite = Uint64ToFileTime(entry.originalModificationTime);
        ::SetFileTime(hFile.get(),
            entry.originalCreationTime != 0 ? &creation : nullptr,
            nullptr,
            entry.originalModificationTime != 0 ? &lastWrite : nullptr);
    }

    [[nodiscard]] RestoreResult RestoreFileInternal(const BackupEntry& entry) {
        RestoreResult result;
        result.originalPath = entry.originalPath;
        result.backupId = entry.backupId;

        try {
            auto start = Clock::now();

            if (entry.storageType == BackupStorageType::RAM) {
                if (!entry.memoryData || entry.memoryData->empty()) {
                    throw std::runtime_error("RAM backup data missing");
                }
                Hash256 memHash{};
                if (!ComputeBufferHash(entry.memoryData->data(),
                        entry.memoryData->size(), memHash)) {
                    result.status = RestoreStatus::Corrupted;
                    result.errorMessage = "RAM backup hash computation failed";
                    m_stats.restoreFailures.fetch_add(1, std::memory_order_relaxed);
                    return result;
                }
                if (!HashEqual(memHash, entry.originalHash)) {
                    result.status = RestoreStatus::Corrupted;
                    result.errorMessage = "RAM backup integrity check failed";
                    SS_LOG_FATAL(kLogCategory, L"RAM INTEGRITY FAILURE: %ls",
                        entry.originalPath.c_str());
                    m_stats.restoreFailures.fetch_add(1, std::memory_order_relaxed);
                    return result;
                }
                Utils::FileUtils::Error writeErr{};
                if (!Utils::FileUtils::WriteAllBytesAtomic(entry.originalPath,
                        reinterpret_cast<const std::byte*>(entry.memoryData->data()),
                        entry.memoryData->size(), &writeErr)) {
                    SS_LOG_ERROR(kLogCategory, L"Atomic restore write failed: %ls (Win32: %u)",
                        entry.originalPath.c_str(), writeErr.win32);
                    throw std::runtime_error("Atomic restore write failed");
                }
                result.bytesRestored = entry.memoryData->size();
                result.integrityVerified = true;

            } else {
                if (entry.backupPath.empty() || !Utils::FileUtils::Exists(entry.backupPath)) {
                    throw std::runtime_error("Backup file missing from disk");
                }
                Hash256 diskHash{};
                if (!Utils::FileUtils::ComputeFileSHA256(entry.backupPath, diskHash)) {
                    result.status = RestoreStatus::Corrupted;
                    result.errorMessage = "Backup hash computation failed";
                    m_stats.restoreFailures.fetch_add(1, std::memory_order_relaxed);
                    return result;
                }
                if (!HashEqual(diskHash, entry.backupHash)) {
                    result.status = RestoreStatus::Corrupted;
                    result.errorMessage = "Backup tampered or corrupted - hash mismatch";
                    SS_LOG_FATAL(kLogCategory, L"BACKUP TAMPERING DETECTED: %ls",
                        entry.backupPath.c_str());
                    m_stats.restoreFailures.fetch_add(1, std::memory_order_relaxed);
                    return result;
                }
                std::vector<std::byte> backupContent;
                Utils::FileUtils::Error readErr{};
                if (!Utils::FileUtils::ReadAllBytes(entry.backupPath, backupContent, &readErr)) {
                    throw std::runtime_error("Failed to read backup file");
                }
                Utils::FileUtils::Error writeErr{};
                if (!Utils::FileUtils::WriteAllBytesAtomic(entry.originalPath,
                        backupContent.data(), backupContent.size(), &writeErr)) {
                    SS_LOG_ERROR(kLogCategory, L"Atomic restore write failed: %ls (Win32: %u)",
                        entry.originalPath.c_str(), writeErr.win32);
                    throw std::runtime_error("Atomic restore write failed");
                }
                result.bytesRestored = backupContent.size();
                result.integrityVerified = true;
            }

            if (entry.originalAttributes != 0) {
                ::SetFileAttributesW(entry.originalPath.c_str(), entry.originalAttributes);
            }
            RestoreTimestamps(entry);

            result.status = RestoreStatus::Success;
            result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now() - start).count();
            m_stats.filesRestored.fetch_add(1, std::memory_order_relaxed);
            m_stats.bytesRestored.fetch_add(result.bytesRestored, std::memory_order_relaxed);

            SS_LOG_INFO(kLogCategory, L"Restored: %ls [%hs] (%llu bytes, %llu ms)",
                entry.originalPath.c_str(), entry.backupId.c_str(),
                static_cast<unsigned long long>(result.bytesRestored),
                static_cast<unsigned long long>(result.durationMs));

        } catch (const std::exception& e) {
            result.status = RestoreStatus::Failed;
            result.errorMessage = e.what();
            m_stats.restoreFailures.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_ERROR(kLogCategory, L"Restore failed: %ls - %hs",
                entry.originalPath.c_str(), e.what());
        }
        return result;
    }

    // ========================================================================
    // DELETE / CLEANUP
    // ========================================================================

    void DeleteBackupUnlocked(const std::string& backupId) {
        auto it = m_backups.find(backupId);
        if (it == m_backups.end()) return;
        auto& entry = it->second;

        if (entry.storageType == BackupStorageType::RAM) {
            auto current = m_currentRamUsage.load(std::memory_order_relaxed);
            m_currentRamUsage.store(
                (entry.backupSize <= current) ? current - entry.backupSize : 0,
                std::memory_order_relaxed);
            entry.memoryData.reset();
        } else if (entry.storageType == BackupStorageType::Disk && !entry.backupPath.empty()) {
            (void)::SetFileAttributesW(entry.backupPath.c_str(), FILE_ATTRIBUTE_NORMAL);
            (void)Utils::FileUtils::RemoveFile(entry.backupPath);
            auto current = m_currentDiskUsage.load(std::memory_order_relaxed);
            m_currentDiskUsage.store(
                (entry.backupSize <= current) ? current - entry.backupSize : 0,
                std::memory_order_relaxed);
        }

        auto procIt = m_processBackups.find(entry.modifyingPid);
        if (procIt != m_processBackups.end()) {
            auto& ids = procIt->second;
            ids.erase(std::remove(ids.begin(), ids.end(), backupId), ids.end());
            if (ids.empty()) m_processBackups.erase(procIt);
        }

        auto pathIt = m_pathIndex.find(entry.originalPath);
        if (pathIt != m_pathIndex.end() && pathIt->second == backupId) {
            m_pathIndex.erase(pathIt);
        }

        if (entry.status == BackupStatus::Completed) {
            auto cur = m_stats.activeBackups.load(std::memory_order_relaxed);
            if (cur > 0) m_stats.activeBackups.fetch_sub(1, std::memory_order_relaxed);
        }
        m_backups.erase(it);
    }

    void CleanupThreadFunc() {
        SS_LOG_DEBUG(kLogCategory, L"Backup cleanup thread started");
        while (m_running.load(std::memory_order_acquire)) {
            try {
                auto now = Clock::now();
                std::vector<std::string> expiredIds;
                {
                    std::shared_lock lock(m_mutex);
                    for (const auto& [id, entry] : m_backups) {
                        if (entry.status == BackupStatus::Completed && now >= entry.expirationTime) {
                            expiredIds.push_back(id);
                        }
                    }
                }
                if (!expiredIds.empty()) {
                    std::unique_lock lock(m_mutex);
                    for (const auto& id : expiredIds) {
                        DeleteBackupUnlocked(id);
                    }
                    m_stats.filesCommitted.fetch_add(expiredIds.size(), std::memory_order_relaxed);
                    SS_LOG_INFO(kLogCategory, L"Cleaned up %zu expired backups", expiredIds.size());
                }
            } catch (const std::exception& e) {
                SS_LOG_ERROR(kLogCategory, L"Cleanup error: %hs", e.what());
            }

            std::unique_lock shutdownLock(m_shutdownMutex);
            m_shutdownCv.wait_for(shutdownLock,
                std::chrono::seconds(m_config.cleanupIntervalSecs),
                [this] { return !m_running.load(std::memory_order_acquire); });
        }
        SS_LOG_DEBUG(kLogCategory, L"Backup cleanup thread exiting");
    }

    void EvictOldest(uint64_t bytesNeeded) {
        struct Candidate { std::string id; TimePoint expiration; uint64_t size; };
        std::vector<Candidate> candidates;
        for (const auto& [id, entry] : m_backups) {
            if (entry.status == BackupStatus::Completed) {
                candidates.push_back({id, entry.expirationTime, entry.backupSize});
            }
        }
        std::sort(candidates.begin(), candidates.end(),
            [](const Candidate& a, const Candidate& b) { return a.expiration < b.expiration; });
        uint64_t freed = 0;
        for (const auto& c : candidates) {
            if (freed >= bytesNeeded) break;
            freed += c.size;
            DeleteBackupUnlocked(c.id);
        }
        if (freed > 0) {
            SS_LOG_INFO(kLogCategory, L"Evicted backups: freed %llu bytes (needed %llu)",
                static_cast<unsigned long long>(freed),
                static_cast<unsigned long long>(bytesNeeded));
        }
    }
};
// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> FileBackupManager::s_instanceCreated{false};

[[nodiscard]] FileBackupManager& FileBackupManager::Instance() noexcept {
    static FileBackupManager instance;
    return instance;
}

[[nodiscard]] bool FileBackupManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

FileBackupManager::FileBackupManager()
    : m_impl(std::make_unique<FileBackupManagerImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    SS_LOG_INFO(kLogCategory, L"FileBackupManager singleton created");
}

FileBackupManager::~FileBackupManager() {
    try {
        Shutdown();
        SS_LOG_INFO(kLogCategory, L"FileBackupManager singleton destroyed");
    } catch (...) {}
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

[[nodiscard]] bool FileBackupManager::Initialize(
    const FileBackupManagerConfiguration& config)
{
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status != ModuleStatus::Uninitialized &&
            m_impl->m_status != ModuleStatus::Stopped) {
            SS_LOG_WARN(kLogCategory, L"FileBackupManager already initialized (status=%u)",
                static_cast<unsigned>(m_impl->m_status.load()));
            return false;
        }

        m_impl->m_status = ModuleStatus::Initializing;

        if (!config.IsValid()) {
            SS_LOG_ERROR(kLogCategory, L"Invalid FileBackupManager configuration");
            m_impl->m_status = ModuleStatus::Error;
            return false;
        }

        m_impl->m_config = config;
        m_impl->m_stats.Reset();

        lock.unlock();
        if (!m_impl->InitializeCacheDirectory()) {
            m_impl->m_status = ModuleStatus::Error;
            return false;
        }
        lock.lock();

        if (config.autoCleanup) {
            m_impl->m_running.store(true, std::memory_order_release);
            m_impl->m_cleanupThread = std::thread(
                &FileBackupManagerImpl::CleanupThreadFunc, m_impl.get());
        }

        m_impl->m_status = ModuleStatus::Running;
        SS_LOG_INFO(kLogCategory, L"FileBackupManager initialized (RAM=%llu MB, Disk=%llu GB)",
            static_cast<unsigned long long>(config.maxRamCacheSize / (1024 * 1024)),
            static_cast<unsigned long long>(config.maxDiskCacheSize / (1024ULL * 1024 * 1024)));
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCategory, L"Initialization failed: %hs", e.what());
        m_impl->m_status = ModuleStatus::Error;
        return false;
    }
}

void FileBackupManager::Shutdown() {
    m_impl->Shutdown();
    m_impl->m_status = ModuleStatus::Stopped;
}

[[nodiscard]] bool FileBackupManager::IsInitialized() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire) == ModuleStatus::Running;
}

[[nodiscard]] ModuleStatus FileBackupManager::GetStatus() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire);
}

// ============================================================================
// BACKUP OPERATIONS
// ============================================================================

[[nodiscard]] bool FileBackupManager::BackupFile(const std::wstring& filePath, uint32_t pid) {
    return BackupFileEx(filePath, pid, m_impl->m_config.defaultPolicy).has_value();
}

[[nodiscard]] std::optional<std::string> FileBackupManager::BackupFileEx(
    std::wstring_view filePath, uint32_t pid, const BackupPolicy& policy)
{
    if (m_impl->m_status.load(std::memory_order_acquire) != ModuleStatus::Running) {
        return std::nullopt;
    }
    if (!m_impl->m_config.enabled || !policy.enabled) {
        return std::nullopt;
    }

    std::wstring path(filePath);

    if (!m_impl->ValidatePath(path)) {
        SS_LOG_WARN(kLogCategory, L"Path validation rejected: %ls", path.c_str());
        return std::nullopt;
    }
    if (m_impl->IsPathExcluded(path, policy)) {
        return std::nullopt;
    }

    {
        std::shared_lock lock(m_impl->m_mutex);
        auto it = m_impl->m_processBackups.find(pid);
        if (it != m_impl->m_processBackups.end() &&
            it->second.size() >= BackupConstants::MAX_BACKUPS_PER_PROCESS) {
            SS_LOG_WARN(kLogCategory, L"Backup limit reached for PID %u (%zu backups)",
                pid, it->second.size());
            return std::nullopt;
        }
    }

    auto entry = m_impl->CreateBackupEntry(path, pid, policy);
    if (entry.status == BackupStatus::Failed) {
        return std::nullopt;
    }

    if (entry.originalSize > policy.maxFileSize) {
        SS_LOG_DEBUG(kLogCategory, L"File too large for backup: %ls (%llu bytes)",
            path.c_str(), static_cast<unsigned long long>(entry.originalSize));
        return std::nullopt;
    }

    if (entry.storageType == BackupStorageType::Disk) {
        uint64_t projected = m_impl->m_currentDiskUsage.load(std::memory_order_relaxed) + entry.originalSize;
        if (projected > m_impl->m_config.maxDiskCacheSize) {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->EvictOldest(entry.originalSize);
        }
        projected = m_impl->m_currentDiskUsage.load(std::memory_order_relaxed) + entry.originalSize;
        if (projected > m_impl->m_config.maxDiskCacheSize) {
            SS_LOG_WARN(kLogCategory, L"Disk quota exceeded, cannot backup: %ls", path.c_str());
            return std::nullopt;
        }
    }

    m_impl->PerformBackup(entry);

    if (entry.status != BackupStatus::Completed) {
        return std::nullopt;
    }

    std::string backupId = entry.backupId;
    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_backups.emplace(backupId, std::move(entry));
        m_impl->m_processBackups[pid].push_back(backupId);
        m_impl->m_pathIndex[path] = backupId;
    }

    BackupCompleteCallback cb;
    BackupEntry entryCopy;
    bool fireCallback = false;
    {
        std::shared_lock lock(m_impl->m_mutex);
        cb = m_impl->m_backupCompleteCallback;
        if (cb) {
            auto it = m_impl->m_backups.find(backupId);
            if (it != m_impl->m_backups.end()) {
                entryCopy = it->second;
                fireCallback = true;
            }
        }
    }
    if (fireCallback) {
        try { cb(entryCopy); } catch (...) {}
    }

    return backupId;
}

[[nodiscard]] std::optional<std::string> FileBackupManager::BackupFileTo(
    std::wstring_view filePath, uint32_t pid, BackupStorageType storage)
{
    BackupPolicy policy = m_impl->m_config.defaultPolicy;
    policy.preferredStorage = storage;
    if (storage == BackupStorageType::RAM) {
        policy.ramThreshold = UINT64_MAX;
    } else {
        policy.ramThreshold = 0;
    }
    return BackupFileEx(filePath, pid, policy);
}

[[nodiscard]] bool FileBackupManager::IsBackedUp(std::wstring_view filePath, uint32_t pid) const {
    std::shared_lock lock(m_impl->m_mutex);
    auto procIt = m_impl->m_processBackups.find(pid);
    if (procIt == m_impl->m_processBackups.end()) return false;
    std::wstring path(filePath);
    for (const auto& id : procIt->second) {
        auto entIt = m_impl->m_backups.find(id);
        if (entIt != m_impl->m_backups.end() &&
            entIt->second.originalPath == path &&
            entIt->second.status == BackupStatus::Completed) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::optional<BackupEntry> FileBackupManager::GetBackup(
    std::wstring_view filePath, uint32_t pid) const
{
    std::shared_lock lock(m_impl->m_mutex);
    auto procIt = m_impl->m_processBackups.find(pid);
    if (procIt == m_impl->m_processBackups.end()) return std::nullopt;
    std::wstring path(filePath);
    for (const auto& id : procIt->second) {
        auto entIt = m_impl->m_backups.find(id);
        if (entIt != m_impl->m_backups.end() &&
            entIt->second.originalPath == path &&
            entIt->second.status == BackupStatus::Completed) {
            return entIt->second;
        }
    }
    return std::nullopt;
}
// ============================================================================
// RESTORATION
// ============================================================================

RollbackResult FileBackupManager::RollbackChanges(uint32_t pid) {
    RollbackResult result;
    result.pid = pid;
    auto start = Clock::now();

    std::vector<std::string> backupIds;
    {
        std::shared_lock lock(m_impl->m_mutex);
        auto it = m_impl->m_processBackups.find(pid);
        if (it != m_impl->m_processBackups.end()) {
            backupIds = it->second;
        }
    }
    result.filesAttempted = backupIds.size();

    std::unordered_map<std::wstring, BackupEntry> fileFirstBackup;
    {
        std::shared_lock lock(m_impl->m_mutex);
        for (const auto& id : backupIds) {
            auto it = m_impl->m_backups.find(id);
            if (it == m_impl->m_backups.end()) continue;
            if (it->second.status != BackupStatus::Completed) continue;
            const auto& p = it->second.originalPath;
            if (fileFirstBackup.find(p) == fileFirstBackup.end()) {
                fileFirstBackup.emplace(p, it->second);
            }
        }
    }

    for (auto& [path, entry] : fileFirstBackup) {
        RestoreResult restoreRes = m_impl->RestoreFileInternal(entry);
        if (restoreRes.status == RestoreStatus::Success) {
            result.filesRestored++;
            result.bytesRestored += restoreRes.bytesRestored;
        } else {
            result.filesFailed++;
        }
        result.results.push_back(std::move(restoreRes));
    }

    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start).count();

    if (result.filesFailed > 0) {
        SS_LOG_ERROR(kLogCategory, L"ROLLBACK PID=%u: %llu/%llu restored, %llu FAILED (%llu ms)",
            pid,
            static_cast<unsigned long long>(result.filesRestored),
            static_cast<unsigned long long>(result.filesAttempted),
            static_cast<unsigned long long>(result.filesFailed),
            static_cast<unsigned long long>(result.durationMs));
    } else {
        SS_LOG_INFO(kLogCategory, L"ROLLBACK PID=%u: %llu/%llu files restored (%llu ms)",
            pid,
            static_cast<unsigned long long>(result.filesRestored),
            static_cast<unsigned long long>(result.filesAttempted),
            static_cast<unsigned long long>(result.durationMs));
    }

    // === Cross-module wiring: alert + telemetry on rollback ===
    ReportRollbackToAlertSystem(pid, result);
    ReportBackupTelemetry("ransomware_rollback", {
        {"pid", std::to_string(pid)},
        {"filesAttempted", std::to_string(result.filesAttempted)},
        {"filesRestored", std::to_string(result.filesRestored)},
        {"filesFailed", std::to_string(result.filesFailed)},
        {"bytesRestored", std::to_string(result.bytesRestored)},
        {"durationMs", std::to_string(result.durationMs)}
    });

    RestoreCompleteCallback cb;
    {
        std::shared_lock lock(m_impl->m_mutex);
        cb = m_impl->m_restoreCompleteCallback;
    }
    if (cb) {
        for (const auto& r : result.results) {
            try { cb(r); } catch (...) {}
        }
    }
    return result;
}

[[nodiscard]] RestoreResult FileBackupManager::RestoreFile(const std::string& backupId) {
    BackupEntry entryCopy;
    {
        std::shared_lock lock(m_impl->m_mutex);
        auto it = m_impl->m_backups.find(backupId);
        if (it == m_impl->m_backups.end()) {
            RestoreResult result;
            result.status = RestoreStatus::NotFound;
            result.errorMessage = "Backup ID not found";
            return result;
        }
        entryCopy = it->second;
    }
    return m_impl->RestoreFileInternal(entryCopy);
}

[[nodiscard]] RestoreResult FileBackupManager::RestoreFile(std::wstring_view filePath, uint32_t pid) {
    auto backup = GetBackup(filePath, pid);
    if (backup) {
        return m_impl->RestoreFileInternal(*backup);
    }
    RestoreResult result;
    result.originalPath = std::wstring(filePath);
    result.status = RestoreStatus::NotFound;
    result.errorMessage = "No backup found for this file and process";
    return result;
}

[[nodiscard]] std::vector<RestoreResult> FileBackupManager::RestoreFiles(
    std::span<const std::string> backupIds)
{
    std::vector<RestoreResult> results;
    results.reserve(backupIds.size());
    for (const auto& id : backupIds) {
        results.push_back(RestoreFile(id));
    }
    return results;
}

// ============================================================================
// COMMIT
// ============================================================================

void FileBackupManager::CommitChanges(uint32_t pid) {
    std::vector<std::string> idsToCommit;
    {
        std::shared_lock lock(m_impl->m_mutex);
        auto it = m_impl->m_processBackups.find(pid);
        if (it != m_impl->m_processBackups.end()) {
            idsToCommit = it->second;
        }
    }
    if (!idsToCommit.empty()) {
        std::unique_lock lock(m_impl->m_mutex);
        for (const auto& id : idsToCommit) {
            m_impl->DeleteBackupUnlocked(id);
        }
        m_impl->m_stats.filesCommitted.fetch_add(idsToCommit.size(), std::memory_order_relaxed);
    }
    SS_LOG_INFO(kLogCategory, L"Committed %zu changes for PID %u", idsToCommit.size(), pid);
}

void FileBackupManager::CommitBackup(const std::string& backupId) {
    std::unique_lock lock(m_impl->m_mutex);
    if (m_impl->m_backups.find(backupId) == m_impl->m_backups.end()) {
        return;
    }
    m_impl->DeleteBackupUnlocked(backupId);
    m_impl->m_stats.filesCommitted.fetch_add(1, std::memory_order_relaxed);
}

void FileBackupManager::CommitExpired() {
    auto now = Clock::now();
    std::vector<std::string> expiredIds;
    {
        std::shared_lock lock(m_impl->m_mutex);
        for (const auto& [id, entry] : m_impl->m_backups) {
            if (entry.status == BackupStatus::Completed && now >= entry.expirationTime) {
                expiredIds.push_back(id);
            }
        }
    }
    if (!expiredIds.empty()) {
        std::unique_lock lock(m_impl->m_mutex);
        for (const auto& id : expiredIds) {
            m_impl->DeleteBackupUnlocked(id);
        }
        m_impl->m_stats.filesCommitted.fetch_add(expiredIds.size(), std::memory_order_relaxed);
        SS_LOG_INFO(kLogCategory, L"Committed %zu expired backups", expiredIds.size());
    }
}

// ============================================================================
// QUERIES
// ============================================================================

[[nodiscard]] std::vector<BackupEntry> FileBackupManager::GetBackupsForProcess(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_mutex);
    std::vector<BackupEntry> result;
    auto it = m_impl->m_processBackups.find(pid);
    if (it != m_impl->m_processBackups.end()) {
        result.reserve(it->second.size());
        for (const auto& id : it->second) {
            auto entIt = m_impl->m_backups.find(id);
            if (entIt != m_impl->m_backups.end()) {
                result.push_back(entIt->second);
            }
        }
    }
    return result;
}

[[nodiscard]] std::vector<BackupEntry> FileBackupManager::GetActiveBackups() const {
    std::shared_lock lock(m_impl->m_mutex);
    std::vector<BackupEntry> result;
    result.reserve(m_impl->m_backups.size());
    for (const auto& [id, entry] : m_impl->m_backups) {
        if (entry.status == BackupStatus::Completed) {
            result.push_back(entry);
        }
    }
    return result;
}

[[nodiscard]] size_t FileBackupManager::GetBackupCount(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_processBackups.find(pid);
    return (it != m_impl->m_processBackups.end()) ? it->second.size() : 0;
}

[[nodiscard]] size_t FileBackupManager::GetTotalBackupCount() const noexcept {
    return m_impl->m_stats.activeBackups.load(std::memory_order_relaxed);
}

// ============================================================================
// STORAGE MANAGEMENT
// ============================================================================

[[nodiscard]] uint64_t FileBackupManager::GetRamCacheUsage() const noexcept {
    return m_impl->m_currentRamUsage.load(std::memory_order_relaxed);
}

[[nodiscard]] uint64_t FileBackupManager::GetDiskCacheUsage() const noexcept {
    return m_impl->m_currentDiskUsage.load(std::memory_order_relaxed);
}

void FileBackupManager::Cleanup() {
    CommitExpired();
}

void FileBackupManager::FreeSpace(uint64_t bytesNeeded) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->EvictOldest(bytesNeeded);
}

// ============================================================================
// CALLBACKS
// ============================================================================

void FileBackupManager::SetBackupCompleteCallback(BackupCompleteCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_backupCompleteCallback = std::move(callback);
}

void FileBackupManager::SetRestoreCompleteCallback(RestoreCompleteCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_restoreCompleteCallback = std::move(callback);
}

void FileBackupManager::SetProgressCallback(BackupProgressCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_progressCallback = std::move(callback);
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] BackupStatisticsSnapshot FileBackupManager::GetStatistics() const {
    BackupStatisticsSnapshot snap;
    snap.filesBackedUp = m_impl->m_stats.filesBackedUp.load(std::memory_order_relaxed);
    snap.filesRestored = m_impl->m_stats.filesRestored.load(std::memory_order_relaxed);
    snap.filesCommitted = m_impl->m_stats.filesCommitted.load(std::memory_order_relaxed);
    snap.backupFailures = m_impl->m_stats.backupFailures.load(std::memory_order_relaxed);
    snap.restoreFailures = m_impl->m_stats.restoreFailures.load(std::memory_order_relaxed);
    snap.bytesBackedUp = m_impl->m_stats.bytesBackedUp.load(std::memory_order_relaxed);
    snap.bytesRestored = m_impl->m_stats.bytesRestored.load(std::memory_order_relaxed);
    snap.currentRamUsage = m_impl->m_currentRamUsage.load(std::memory_order_relaxed);
    snap.currentDiskUsage = m_impl->m_currentDiskUsage.load(std::memory_order_relaxed);
    snap.activeBackups = m_impl->m_stats.activeBackups.load(std::memory_order_relaxed);
    {
        std::shared_lock lock(m_impl->m_mutex);
        snap.startTime = m_impl->m_stats.startTime;
    }
    return snap;
}

void FileBackupManager::ResetStatistics() {
    m_impl->m_stats.Reset();
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_stats.startTime = Clock::now();
}
// ============================================================================
// UTILITY
// ============================================================================

[[nodiscard]] bool FileBackupManager::SelfTest() {
    SS_LOG_INFO(kLogCategory, L"Running FileBackupManager self-test...");
    try {
        bool wasRunning = (m_impl->m_status.load() == ModuleStatus::Running);
        if (!wasRunning) {
            FileBackupManagerConfiguration testConfig;
            testConfig.enabled = true;
            testConfig.maxRamCacheSize = 1024 * 1024;
            testConfig.autoCleanup = false;
            if (!Initialize(testConfig)) {
                SS_LOG_ERROR(kLogCategory, L"Self-test: init failed");
                return false;
            }
        }

        std::wstring testDir = Utils::SystemUtils::ExpandEnv(L"%TEMP%");
        if (testDir.empty()) testDir = L"C:\\Windows\\Temp";
        std::wstring testPath = testDir + L"\\ss_selftest_" +
            Utils::StringUtils::ToWide(GenerateBackupId().substr(0, 8)) + L".tmp";

        const std::string testContent = "ShadowStrike FileBackupManager Self-Test Content v3";
        {
            Utils::FileUtils::Error err{};
            if (!Utils::FileUtils::WriteAllBytesAtomic(testPath,
                    reinterpret_cast<const std::byte*>(testContent.data()),
                    testContent.size(), &err)) {
                SS_LOG_ERROR(kLogCategory, L"Self-test: create test file failed");
                return false;
            }
        }

        constexpr uint32_t kTestPid = 0xFFFFFFFE;
        if (!BackupFile(testPath, kTestPid)) {
            (void)Utils::FileUtils::RemoveFile(testPath);
            SS_LOG_ERROR(kLogCategory, L"Self-test: BackupFile failed");
            return false;
        }
        if (!IsBackedUp(testPath, kTestPid)) {
            (void)Utils::FileUtils::RemoveFile(testPath);
            SS_LOG_ERROR(kLogCategory, L"Self-test: IsBackedUp check failed");
            return false;
        }

        {
            const std::string corrupted = "ENCRYPTED_BY_RANSOMWARE";
            (void)Utils::FileUtils::WriteAllBytesAtomic(testPath,
                reinterpret_cast<const std::byte*>(corrupted.data()),
                corrupted.size());
        }

        auto restoreRes = RestoreFile(testPath, kTestPid);
        if (restoreRes.status != RestoreStatus::Success) {
            (void)Utils::FileUtils::RemoveFile(testPath);
            SS_LOG_ERROR(kLogCategory, L"Self-test: restore failed");
            return false;
        }
        if (!restoreRes.integrityVerified) {
            (void)Utils::FileUtils::RemoveFile(testPath);
            SS_LOG_ERROR(kLogCategory, L"Self-test: integrity not verified");
            return false;
        }

        std::vector<std::byte> readBack;
        (void)Utils::FileUtils::ReadAllBytes(testPath, readBack);
        if (readBack.size() != testContent.size() ||
            std::memcmp(readBack.data(), testContent.data(), testContent.size()) != 0) {
            (void)Utils::FileUtils::RemoveFile(testPath);
            SS_LOG_ERROR(kLogCategory, L"Self-test: content verification FAILED");
            return false;
        }

        CommitChanges(kTestPid);
        (void)Utils::FileUtils::RemoveFile(testPath);
        if (!wasRunning) Shutdown();

        SS_LOG_INFO(kLogCategory, L"Self-test PASSED");
        return true;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCategory, L"Self-test exception: %hs", e.what());
        return false;
    }
}

[[nodiscard]] std::string FileBackupManager::GetVersionString() noexcept {
    return std::to_string(BackupConstants::VERSION_MAJOR) + "." +
           std::to_string(BackupConstants::VERSION_MINOR) + "." +
           std::to_string(BackupConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string BackupEntry::ToJson() const {
    using ShadowStrike::Utils::JSON::Json;
    Json j = Json::object();
    j["backupId"] = backupId;
    j["originalPath"] = Utils::StringUtils::ToNarrow(originalPath);
    j["backupPath"] = Utils::StringUtils::ToNarrow(backupPath);
    j["originalSize"] = originalSize;
    j["backupSize"] = backupSize;
    j["modifyingPid"] = modifyingPid;
    j["storageType"] = static_cast<int>(storageType);
    j["status"] = static_cast<int>(status);
    j["originalHash"] = Utils::HashUtils::ToHexLower(originalHash.data(), originalHash.size());
    j["backupHash"] = Utils::HashUtils::ToHexLower(backupHash.data(), backupHash.size());
    return j.dump(2);
}

[[nodiscard]] std::string RestoreResult::ToJson() const {
    using ShadowStrike::Utils::JSON::Json;
    Json j = Json::object();
    j["originalPath"] = Utils::StringUtils::ToNarrow(originalPath);
    j["backupId"] = backupId;
    j["status"] = static_cast<int>(status);
    j["durationMs"] = durationMs;
    j["bytesRestored"] = bytesRestored;
    j["integrityVerified"] = integrityVerified;
    if (!errorMessage.empty()) j["error"] = errorMessage;
    return j.dump(2);
}

[[nodiscard]] std::string RollbackResult::ToJson() const {
    using ShadowStrike::Utils::JSON::Json;
    Json j = Json::object();
    j["pid"] = pid;
    j["filesAttempted"] = filesAttempted;
    j["filesRestored"] = filesRestored;
    j["filesFailed"] = filesFailed;
    j["bytesRestored"] = bytesRestored;
    j["durationMs"] = durationMs;
    return j.dump(2);
}

void BackupStatistics::Reset() noexcept {
    filesBackedUp.store(0, std::memory_order_relaxed);
    filesRestored.store(0, std::memory_order_relaxed);
    filesCommitted.store(0, std::memory_order_relaxed);
    backupFailures.store(0, std::memory_order_relaxed);
    restoreFailures.store(0, std::memory_order_relaxed);
    bytesBackedUp.store(0, std::memory_order_relaxed);
    bytesRestored.store(0, std::memory_order_relaxed);
    currentRamUsage.store(0, std::memory_order_relaxed);
    currentDiskUsage.store(0, std::memory_order_relaxed);
    activeBackups.store(0, std::memory_order_relaxed);
}

[[nodiscard]] std::string BackupStatistics::ToJson() const {
    using ShadowStrike::Utils::JSON::Json;
    Json j = Json::object();
    j["filesBackedUp"] = filesBackedUp.load(std::memory_order_relaxed);
    j["filesRestored"] = filesRestored.load(std::memory_order_relaxed);
    j["filesCommitted"] = filesCommitted.load(std::memory_order_relaxed);
    j["backupFailures"] = backupFailures.load(std::memory_order_relaxed);
    j["restoreFailures"] = restoreFailures.load(std::memory_order_relaxed);
    j["bytesBackedUp"] = bytesBackedUp.load(std::memory_order_relaxed);
    j["bytesRestored"] = bytesRestored.load(std::memory_order_relaxed);
    j["activeBackups"] = activeBackups.load(std::memory_order_relaxed);
    j["ramUsage"] = currentRamUsage.load(std::memory_order_relaxed);
    j["diskUsage"] = currentDiskUsage.load(std::memory_order_relaxed);
    return j.dump(2);
}

[[nodiscard]] std::string BackupStatisticsSnapshot::ToJson() const {
    using ShadowStrike::Utils::JSON::Json;
    Json j = Json::object();
    j["filesBackedUp"] = filesBackedUp;
    j["filesRestored"] = filesRestored;
    j["filesCommitted"] = filesCommitted;
    j["backupFailures"] = backupFailures;
    j["restoreFailures"] = restoreFailures;
    j["bytesBackedUp"] = bytesBackedUp;
    j["bytesRestored"] = bytesRestored;
    j["activeBackups"] = activeBackups;
    j["ramUsage"] = currentRamUsage;
    j["diskUsage"] = currentDiskUsage;
    auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = static_cast<uint64_t>(uptimeMs > 0 ? uptimeMs / 1000 : 0);
    return j.dump(2);
}

[[nodiscard]] bool FileBackupManagerConfiguration::IsValid() const noexcept {
    if (maxRamCacheSize > BackupConstants::MAX_RAM_CACHE_SIZE * 2) return false;
    if (maxDiskCacheSize > BackupConstants::MAX_DISK_CACHE_SIZE * 4) return false;
    if (cleanupIntervalSecs == 0 || cleanupIntervalSecs > 86400) return false;
    return true;
}

[[nodiscard]] bool BackupPolicy::ShouldBackup(std::wstring_view filePath, uint64_t fileSize) const {
    if (!enabled) return false;
    if (fileSize > maxFileSize) return false;
    if (fileSize == 0) return false;

    const std::wstring normalizedPath = NormalizePolicyPath(filePath);
    if (normalizedPath.empty()) return false;

    return IsPathAllowedByPolicy(normalizedPath, *this);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetStorageTypeName(BackupStorageType type) noexcept {
    switch (type) {
        case BackupStorageType::RAM:       return "RAM";
        case BackupStorageType::Disk:      return "Disk";
        case BackupStorageType::Encrypted: return "Encrypted";
        case BackupStorageType::VSS:       return "VSS";
        case BackupStorageType::Network:   return "Network";
        default:                           return "Unknown";
    }
}

[[nodiscard]] std::string_view GetBackupStatusName(BackupStatus status) noexcept {
    switch (status) {
        case BackupStatus::Pending:    return "Pending";
        case BackupStatus::InProgress: return "InProgress";
        case BackupStatus::Completed:  return "Completed";
        case BackupStatus::Failed:     return "Failed";
        case BackupStatus::Restored:   return "Restored";
        case BackupStatus::Committed:  return "Committed";
        case BackupStatus::Expired:    return "Expired";
        default:                       return "Unknown";
    }
}

[[nodiscard]] std::string_view GetRestoreStatusName(RestoreStatus status) noexcept {
    switch (status) {
        case RestoreStatus::Success:        return "Success";
        case RestoreStatus::PartialSuccess: return "PartialSuccess";
        case RestoreStatus::Failed:         return "Failed";
        case RestoreStatus::NotFound:       return "NotFound";
        case RestoreStatus::Corrupted:      return "Corrupted";
        case RestoreStatus::InUse:          return "InUse";
        case RestoreStatus::AccessDenied:   return "AccessDenied";
        default:                            return "Unknown";
    }
}

// ============================================================================
// KERNEL BRIDGE IMPLEMENTATIONS
// ============================================================================

void FileBackupManager::OnKernelProcessNotify(
    uint32_t pid, uint32_t parentPid,
    std::wstring_view imagePath, bool isCreate)
{
    if (!IsInitialized()) return;

    if (!isCreate) {
        // Process exit: commit backups for this PID (process exited normally)
        size_t count = GetBackupCount(pid);
        if (count > 0) {
            SS_LOG_DEBUG(kLogCategory,
                L"[KernelBridge] PID %u exited with %zu active backups — committing",
                pid, count);
            CommitChanges(pid);
        }
        return;
    }

    // Process creation: no backup action needed at this stage.
    // Backups are demand-driven via BackupFile() when file modifications are intercepted.
    (void)parentPid;
    (void)imagePath;
}

void FileBackupManager::OnKernelImageLoad(
    uint32_t pid, std::wstring_view imagePath, uintptr_t imageBase)
{
    (void)imageBase;
    if (!IsInitialized()) return;

    // If a DLL is loaded into a process with active backups, log for forensic awareness.
    size_t count = GetBackupCount(pid);
    if (count > 0) {
        SS_LOG_TRACE(kLogCategory,
            L"[KernelBridge] Image load in backed-up PID %u: %.*s",
            pid, static_cast<int>(imagePath.size()), imagePath.data());
    }
}

[[nodiscard]] bool FileBackupManager::RequestKernelProcessBlock(
    uint32_t pid, std::wstring_view reason)
{
    using Communication::IPCManager;
    if (!IPCManager::HasInstance() || !IPCManager::Instance().IsFilterPortConnected()) {
        SS_LOG_WARN(kLogCategory,
            L"[KernelBridge] Cannot block PID %u — kernel IPC not connected", pid);
        return false;
    }

#pragma pack(push, 1)
    struct KernelBlockRequest {
        uint32_t msgType = 0x30;   // BLOCK_PROCESS
        uint32_t targetPid = 0;
        wchar_t  reason[256]{};
    };
#pragma pack(pop)

    KernelBlockRequest req;
    req.targetPid = pid;
    if (!reason.empty()) {
        wcsncpy_s(req.reason, 256, reason.data(),
                  std::min<size_t>(reason.size(), 255));
    }

    bool sent = IPCManager::Instance().SendToKernel(&req, sizeof(req));
    if (!sent) {
        SS_LOG_ERROR(kLogCategory,
            L"[KernelBridge] Failed to send block request for PID %u", pid);
    }
    return sent;
}

// ============================================================================
// CROSS-MODULE WIRING IMPLEMENTATIONS
// ============================================================================

void FileBackupManager::ReportRollbackToAlertSystem(
    uint32_t pid, const RollbackResult& result)
{
    using Communication::AlertSystem;
    if (!AlertSystem::HasInstance()) return;

    auto severity = (result.filesFailed > 0)
        ? Communication::AlertSeverity::Critical
        : Communication::AlertSeverity::High;

    std::string title = "Ransomware rollback for PID " + std::to_string(pid);
    std::string detail = "Restored " + std::to_string(result.filesRestored) + "/" +
                         std::to_string(result.filesAttempted) + " files (" +
                         std::to_string(result.bytesRestored) + " bytes) in " +
                         std::to_string(result.durationMs) + "ms";
    if (result.filesFailed > 0) {
        detail += " — " + std::to_string(result.filesFailed) + " FAILED";
    }

    (void)AlertSystem::Instance().RaiseAlert(
        severity,
        Communication::AlertType::ThreatDetection,
        "FileBackupManager",
        title,
        detail);
}

void FileBackupManager::ReportBackupTelemetry(
    const std::string& eventName,
    const std::map<std::string, std::string>& fields)
{
    using Communication::TelemetryCollector;
    if (!TelemetryCollector::HasInstance()) return;

    TelemetryCollector::Instance().RecordCustom(eventName, fields);
}

}  // namespace ShadowStrike::Ransomware

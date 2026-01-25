/**
 * ============================================================================
 * ShadowStrike Ransomware Protection - FILE BACKUP MANAGER (The Time Machine)
 * ============================================================================
 *
 * @file FileBackupManager.hpp
 * @brief Just-In-Time (JIT) backup system for suspicious modifications.
 *
 * When a process exhibits "Suspicious but not Confirmed" behavior, we cannot
 * simply block it (False Positive risk). Instead, we:
 * 1. Pause the write operation.
 * 2. Quickly copy the *original* file to a secure cache (RAM or Protected Folder).
 * 3. Allow the write.
 * 4. If the process is later confirmed as Ransomware, we restore from cache.
 * 5. If the process exits cleanly, we discard the cache.
 *
 * This enables "Rollback" functionality.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/FileUtils.hpp"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>

namespace ShadowStrike {
    namespace Ransomware {

        struct BackupEntry {
            std::wstring originalPath;
            std::wstring backupPath;
            uint64_t fileSize;
            uint32_t modifyingPid;
            std::chrono::system_clock::time_point timestamp;
        };

        class FileBackupManager {
        public:
            static FileBackupManager& Instance();

            bool Initialize();

            /**
             * @brief Create a JIT backup of a file before it is modified.
             * @param filePath The file about to be changed.
             * @param pid The process requesting the change.
             * @return True if backup successful.
             */
            bool BackupFile(const std::wstring& filePath, uint32_t pid);

            /**
             * @brief Restore all files modified by a specific process.
             * Called after Ransomware detection.
             */
            void RollbackChanges(uint32_t pid);

            /**
             * @brief Commit changes (delete backups) for a safe process.
             */
            void CommitChanges(uint32_t pid);

        private:
            FileBackupManager() = default;
            ~FileBackupManager() = default;

            // Disable copy
            FileBackupManager(const FileBackupManager&) = delete;
            FileBackupManager& operator=(const FileBackupManager&) = delete;

            // ========================================================================
            // STORAGE
            // ========================================================================

            std::wstring m_cacheDirectory; // Hidden system folder
            
            std::mutex m_backupMutex;
            // Map PID -> List of Backups
            std::map<uint32_t, std::vector<BackupEntry>> m_pendingBackups;
        };

    } // namespace Ransomware
} // namespace ShadowStrike

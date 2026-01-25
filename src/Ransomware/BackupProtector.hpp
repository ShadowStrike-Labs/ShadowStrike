/**
 * ============================================================================
 * ShadowStrike Ransomware Protection - BACKUP PROTECTOR (The Last Line)
 * ============================================================================
 *
 * @file BackupProtector.hpp
 * @brief Protection for Volume Shadow Copies (VSS) and Backup Files.
 *
 * Ransomware almost always tries to delete backups before encrypting files.
 * Command: `vssadmin.exe Delete Shadows /All /Quiet`
 * Command: `wbadmin.exe DELETE SYSTEMSTATEBACKUP`
 * Command: `bcdedit.exe /set {default} recoveryenabled No`
 *
 * This module blocks these specific administrative commands and protects
 * known backup extensions (.bkf, .vhd, .tib).
 *
 * Integrations:
 * - **Core::Process::ProcessMonitor**: To identify `vssadmin.exe` execution.
 * - **Core::Registry::RegistryMonitor**: To block disabling of VSS service.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Core/Process/ProcessMonitor.hpp"
#include <string>
#include <vector>
#include <unordered_set>

namespace ShadowStrike {
    namespace Ransomware {

        class BackupProtector {
        public:
            static BackupProtector& Instance();

            /**
             * @brief Initialize protections.
             * Sets up process creation callbacks to intercept admin tools.
             */
            bool Initialize();

            /**
             * @brief Analyze a process creation attempt.
             * Returns TRUE if the process is a backup destruction tool.
             */
            bool IsDestructiveTool(
                const std::wstring& imagePath, 
                const std::wstring& commandLine
            );

            /**
             * @brief Check if a file access is targeting a protected backup file.
             */
            bool IsProtectedBackupFile(const std::wstring& filePath);

        private:
            BackupProtector() = default;
            ~BackupProtector() = default;

            // Disable copy
            BackupProtector(const BackupProtector&) = delete;
            BackupProtector& operator=(const BackupProtector&) = delete;

            // List of dangerous tools (vssadmin, wbadmin, bcdedit, wmic)
            std::unordered_set<std::wstring> m_dangerousTools;
            
            // List of backup extensions (.bak, .vhd, .tibx)
            std::unordered_set<std::wstring> m_protectedExtensions;
        };

    } // namespace Ransomware
} // namespace ShadowStrike

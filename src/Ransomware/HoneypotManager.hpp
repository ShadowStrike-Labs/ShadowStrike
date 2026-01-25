/**
 * ============================================================================
 * ShadowStrike Ransomware Protection - HONEYPOT MANAGER (The Trap)
 * ============================================================================
 *
 * @file HoneypotManager.hpp
 * @brief Management of decoy files (Honeyfiles) to trap ransomware.
 *
 * This module strategically places fake files (e.g., "Passwords.txt", "Budget.xlsx")
 * in user directories. Legitimate users never touch these files (they are hidden or
 * obscure). Any process that modifies or deletes them is, by definition, malicious.
 *
 * Capabilities:
 * 1. Strategic Placement: Documents, Desktop, Pictures, and Root drives.
 * 2. File Generation: Uses `Utils::FileUtils` to create realistic-looking headers.
 * 3. Monitoring: Registers `FileWatcher` callbacks specifically for these paths.
 * 4. Stealth: Marks files as Hidden/System to avoid annoying the user.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/FileUtils.hpp"
#include <vector>
#include <string>
#include <mutex>

namespace ShadowStrike {
    namespace Ransomware {

        struct HoneyFile {
            std::wstring path;
            std::wstring originalName; // For regeneration
            bool isDirectory;
        };

        class HoneypotManager {
        public:
            static HoneypotManager& Instance();

            /**
             * @brief Deploys honeyfiles to strategic locations.
             * Should be called on service start.
             */
            bool DeployTraps();

            /**
             * @brief Removes all honeyfiles (cleanup).
             */
            void RemoveTraps();

            /**
             * @brief Check if a given path is a known honeyfile.
             * Fast lookup called by FileSystem Filter.
             */
            bool IsTrap(const std::wstring& filePath);

            /**
             * @brief Regenerate a trap if it was deleted (Persistence).
             */
            void RegenerateTrap(const std::wstring& filePath);

        private:
            HoneypotManager() = default;
            ~HoneypotManager() = default;

            // Disable copy
            HoneypotManager(const HoneypotManager&) = delete;
            HoneypotManager& operator=(const HoneypotManager&) = delete;

            // ========================================================================
            // INTERNAL LOGIC
            // ========================================================================

            void CreateDecoyFile(const std::wstring& path, const std::string& type);
            
            std::mutex m_trapMutex;
            std::vector<HoneyFile> m_activeTraps;
        };

    } // namespace Ransomware
} // namespace ShadowStrike

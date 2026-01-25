/**
 * ============================================================================
 * ShadowStrike Ransomware Protection - DETECTOR (The Guardian)
 * ============================================================================
 *
 * @file RansomwareDetector.hpp
 * @brief Real-time heuristics engine specifically for crypto-ransomware.
 *
 * This module sits on top of the File System Filter events. It maintains a
 * rolling window of IO statistics for every active process to detect:
 * 1. High-Entropy Writes: Detecting encryption (encrypted data looks random).
 * 2. Rapid File Renaming: Detecting extension changes (.docx -> .locked).
 * 3. Bulk Deletion: Detecting mass deletion of user data.
 * 4. Decoy Access: Detecting access to Honeypot files.
 *
 * Integrations:
 * - **Core::Engine::BehaviorAnalyzer**: Sends alerts to the central brain.
 * - **Core::FileSystem::FileWatcher**: Receives file events.
 * - **Utils::CryptoUtils**: Calculates Shannon Entropy of written buffers.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Core/Process/ProcessMonitor.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <atomic>

namespace ShadowStrike {
    namespace Ransomware {

        struct IOStats {
            uint32_t writeCount = 0;
            uint32_t renameCount = 0;
            uint32_t deleteCount = 0;
            uint32_t highEntropyWrites = 0; // Entropy > 7.5
            std::vector<std::wstring> affectedExtensions;
            std::chrono::steady_clock::time_point firstActivity;
            std::chrono::steady_clock::time_point lastActivity;
        };

        class RansomwareDetector {
        public:
            static RansomwareDetector& Instance();

            bool Initialize();
            void Shutdown();

            /**
             * @brief Analyze a file write operation BEFORE it happens (Pre-Write).
             * @param pid Process ID.
             * @param buffer Data being written.
             * @param filePath Target file.
             * @return True if operation should be BLOCKED.
             */
            bool AnalyzeWrite(
                uint32_t pid,
                const std::vector<uint8_t>& buffer,
                const std::wstring& filePath
            );

            /**
             * @brief Analyze a file rename operation.
             * e.g., "Resume.docx" -> "Resume.docx.crypt"
             */
            bool AnalyzeRename(
                uint32_t pid,
                const std::wstring& oldPath,
                const std::wstring& newPath
            );

            /**
             * @brief Called when a Honeyfile is touched.
             * Immediate BLOCK + KILL verdict.
             */
            void OnHoneypotTouched(uint32_t pid, const std::wstring& filePath);

        private:
            RansomwareDetector() = default;
            ~RansomwareDetector() = default;

            // Disable copy
            RansomwareDetector(const RansomwareDetector&) = delete;
            RansomwareDetector& operator=(const RansomwareDetector&) = delete;

            // ========================================================================
            // INTERNAL LOGIC
            // ========================================================================

            // Thresholds
            const double ENTROPY_THRESHOLD = 7.5;
            const uint32_t MAX_RAPID_WRITES = 10; // Files per second
            const std::chrono::seconds TIME_WINDOW{ 5 };

            std::mutex m_statsMutex;
            std::map<uint32_t, IOStats> m_processStats;

            // Helper: Is this file type typically high entropy? (e.g. .zip, .jpg)
            bool IsCompressedType(const std::wstring& filePath);
        };

    } // namespace Ransomware
} // namespace ShadowStrike

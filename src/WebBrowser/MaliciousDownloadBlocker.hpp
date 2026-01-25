/**
 * ============================================================================
 * ShadowStrike WebBrowser - DOWNLOAD BLOCKER (The Inspector)
 * ============================================================================
 *
 * @file MaliciousDownloadBlocker.hpp
 * @brief Automatic scanning of files downloaded via browser.
 *
 * Monitors download directories (Downloads, Desktop).
 * Uses `ScanEngine` to analyze files before the user opens them.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Core/Engine/ScanEngine.hpp"
#include <string>

namespace ShadowStrike {
    namespace WebBrowser {

        class MaliciousDownloadBlocker {
        public:
            static MaliciousDownloadBlocker& Instance();

            /**
             * @brief Called when a file is completed downloading.
             * @param filePath Path to the downloaded file.
             * @param sourceUrl Origin of the file (for reputational check).
             */
            void OnDownloadComplete(const std::wstring& filePath, const std::string& sourceUrl);

        private:
            MaliciousDownloadBlocker() = default;
        };

    } // namespace WebBrowser
} // namespace ShadowStrike

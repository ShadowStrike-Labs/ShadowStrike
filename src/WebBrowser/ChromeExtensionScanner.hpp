/**
 * ============================================================================
 * ShadowStrike WebBrowser - CHROME EXTENSION SCANNER (The Auditor)
 * ============================================================================
 *
 * @file ChromeExtensionScanner.hpp
 * @brief Analysis of Chrome and Chromium-based browser extensions.
 *
 * Scans `C:\Users\...\AppData\Local\Google\Chrome\User Data\Default\Extensions`.
 * Looks for extensions with excessive permissions (tabs, cookies, webRequest)
 * and matches them against known malicious eklentiler.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace WebBrowser {

        struct ExtensionInfo {
            std::string id;
            std::string name;
            std::string version;
            std::vector<std::string> permissions;
            bool isSideloaded;
            bool isMalicious;
        };

        class ChromeExtensionScanner {
        public:
            static ChromeExtensionScanner& Instance();

            /**
             * @brief Scan all extensions for all user profiles.
             */
            std::vector<ExtensionInfo> ScanAll();

            /**
             * @brief Analyze a specific extension folder.
             */
            ExtensionInfo AnalyzeFolder(const std::wstring& path);

        private:
            ChromeExtensionScanner() = default;
        };

    } // namespace WebBrowser
} // namespace ShadowStrike

/**
 * ============================================================================
 * ShadowStrike WebBrowser - FIREFOX ADDON SCANNER (The Auditor)
 * ============================================================================
 *
 * @file FirefoxAddonScanner.hpp
 * @brief Analysis of Mozilla Firefox Add-ons (.xpi files).
 *
 * Scans Firefox profiles for malicious add-ons. Similar to Chrome scanner
 * but parses manifest.json inside XPI (Zip) archives.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "ChromeExtensionScanner.hpp" // Reuse ExtensionInfo
#include <string>
#include <vector>

namespace ShadowStrike {
    namespace WebBrowser {

        class FirefoxAddonScanner {
        public:
            static FirefoxAddonScanner& Instance();

            std::vector<ExtensionInfo> ScanAll();

        private:
            FirefoxAddonScanner() = default;
        };

    } // namespace WebBrowser
} // namespace ShadowStrike

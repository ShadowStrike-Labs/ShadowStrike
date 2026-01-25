/**
 * ============================================================================
 * ShadowStrike Privacy - PRIVACY CLEANER (The Janitor)
 * ============================================================================
 *
 * @file PrivacyCleaner.hpp
 * @brief Secure removal of digital footprints.
 *
 * Capabilities:
 * 1. Browser Cleanup: Cookies, Cache, History for all major browsers.
 * 2. System Cleanup: Recent files, Thumbnail cache, TEMP folders.
 * 3. Secure Erase: Uses `Utils::FileUtils::SecureEraseFile` to overwrite data.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/FileUtils.hpp"
#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Privacy {

        class PrivacyCleaner {
        public:
            static PrivacyCleaner& Instance();

            /**
             * @brief Perform a full system privacy scan.
             */
            void CleanAll();

            /**
             * @brief Clear data for a specific browser.
             */
            void CleanBrowser(const std::wstring& browserName);

        private:
            PrivacyCleaner() = default;
        };

    } // namespace Privacy
} // namespace ShadowStrike

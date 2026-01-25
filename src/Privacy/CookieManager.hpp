/**
 * ============================================================================
 * ShadowStrike Privacy - COOKIE MANAGER (The Baker)
 * ============================================================================
 *
 * @file CookieManager.hpp
 * @brief Management and filtering of HTTP cookies.
 *
 * Capabilities:
 * 1. Tracking Block: Automatically deletes known advertising cookies.
 * 2. Supercookie Detection: Identifying Flash and Silverlight LSOs.
 * 3. Whitelisting: Preserving login sessions for trusted sites.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Privacy {

        struct BrowserCookie {
            std::string domain;
            std::string name;
            std::string path;
            bool isSecure;
            bool isTracking;
        };

        class CookieManager {
        public:
            static CookieManager& Instance();

            /**
             * @brief Enumerate all cookies from browser databases.
             */
            std::vector<BrowserCookie> GetAllCookies();

            /**
             * @brief Remove tracking cookies for all users.
             */
            void PurgeTrackers();

        private:
            CookieManager() = default;
        };

    } // namespace Privacy
} // namespace ShadowStrike

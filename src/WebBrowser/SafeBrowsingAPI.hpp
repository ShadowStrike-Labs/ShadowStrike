/**
 * ============================================================================
 * ShadowStrike WebBrowser - SAFE BROWSING API (The Interconnector)
 * ============================================================================
 *
 * @file SafeBrowsingAPI.hpp
 * @brief Integration with 3rd-party reputation APIs (Google, Microsoft).
 *
 * This module allows ShadowStrike to query external threat intelligence feeds
 * for real-time URL reputation.
 *
 * Capabilities:
 * 1. Google Safe Browsing API v4 support.
 * 2. Microsoft SmartScreen fallback.
 * 3. Local Caching: Avoid duplicate API calls for performance.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/NetworkUtils.hpp"
#include <string>
#include <vector>

namespace ShadowStrike {
    namespace WebBrowser {

        class SafeBrowsingAPI {
        public:
            static SafeBrowsingAPI& Instance();

            /**
             * @brief Initialize with API Keys.
             */
            void Initialize(const std::string& googleApiKey);

            /**
             * @brief Query external APIs for URL risk.
             */
            bool IsUrlMalicious(const std::string& url);

        private:
            SafeBrowsingAPI() = default;
            std::string m_apiKey;
        };

    } // namespace WebBrowser
} // namespace ShadowStrike

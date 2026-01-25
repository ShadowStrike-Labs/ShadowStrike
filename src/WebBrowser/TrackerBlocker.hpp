/**
 * ============================================================================
 * ShadowStrike WebBrowser - TRACKER BLOCKER (The Privacy Guard)
 * ============================================================================
 *
 * @file TrackerBlocker.hpp
 * @brief Prevention of online tracking and fingerprinting.
 *
 * Capabilities:
 * 1. Cookie Management: Removing 3rd-party tracking cookies.
 * 2. Fingerprint Protection: Masking user-agent and canvas signatures.
 * 3. Beacon Blocking: Detecting invisible tracking pixels.
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

        class TrackerBlocker {
        public:
            static TrackerBlocker& Instance();

            /**
             * @brief Identify tracking pixels in HTTP response.
             */
            bool IsTrackingPixel(const std::vector<uint8_t>& buffer);

            /**
             * @brief Provide a generic User-Agent to prevent fingerprinting.
             */
            std::string GetSafeUserAgent();

        private:
            TrackerBlocker() = default;
        };

    } // namespace WebBrowser
} // namespace ShadowStrike

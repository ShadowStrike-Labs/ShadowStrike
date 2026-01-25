/**
 * ============================================================================
 * ShadowStrike WebBrowser - AD BLOCKER (The Filter)
 * ============================================================================
 *
 * @file AdBlocker.hpp
 * @brief DNS and URL based ad blocking.
 *
 * Capabilities:
 * 1. Cosmetic Filtering: Hiding ad elements (via extension).
 * 2. Network Filtering: Blocking tracking domains (EasyList).
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_set>

namespace ShadowStrike {
    namespace WebBrowser {

        class AdBlocker {
        public:
            static AdBlocker& Instance();

            bool Initialize();

            /**
             * @brief Check if a URL belongs to an ad network.
             */
            bool ShouldBlock(const std::string& url);

        private:
            AdBlocker() = default;
            std::unordered_set<std::string> m_adDomains;
        };

    } // namespace WebBrowser
} // namespace ShadowStrike

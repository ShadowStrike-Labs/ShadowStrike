/**
 * ============================================================================
 * ShadowStrike WebBrowser - BROWSER PROTECTION (The Navigator)
 * ============================================================================
 *
 * @file BrowserProtection.hpp
 * @brief Central controller for web browser security features.
 *
 * Integrations:
 * - **Core::Network::URLAnalyzer**: For blocking domains.
 * - **Core::FileSystem::FileWatcher**: For scanning downloads.
 * - **Native Messaging**: For communicating with our Browser Extension.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Core/Network/URLAnalyzer.hpp"
#include <string>
#include <vector>

namespace ShadowStrike {
    namespace WebBrowser {

        enum class BrowserType {
            Chrome,
            Edge,
            Firefox,
            Brave,
            Opera,
            Unknown
        };

        class BrowserProtection {
        public:
            static BrowserProtection& Instance();

            bool Initialize();

            /**
             * @brief Handle a navigation event (from Extension or Network Filter).
             */
            void OnNavigate(const std::string& url, uint32_t pid);

            /**
             * @brief Enforce "Secure Search" (Force Google SafeSearch).
             */
            bool EnforceSafeSearch(bool enable);

            /**
             * @brief Detect running browsers.
             */
            std::vector<uint32_t> GetBrowserPids();

        private:
            BrowserProtection() = default;
        };

    } // namespace WebBrowser
} // namespace ShadowStrike

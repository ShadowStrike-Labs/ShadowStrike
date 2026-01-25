/**
 * ============================================================================
 * ShadowStrike Communication - NOTIFICATION MANAGER (The Messenger)
 * ============================================================================
 *
 * @file NotificationManager.hpp
 * @brief Management of user-facing UI notifications.
 *
 * Capabilities:
 * 1. Windows Toast: Using standard Windows notification center.
 * 2. Custom Popups: Displaying high-priority threat alerts.
 * 3. Quiet Mode: Postponing notifications during gaming or meetings.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Communication {

        enum class NotificationLevel { Info, Warning, Critical };

        class NotificationManager {
        public:
            static NotificationManager& Instance();

            /**
             * @brief Show a standard notification to the user.
             */
            void Show(const std::wstring& title, const std::wstring& message, NotificationLevel level);

            /**
             * @brief Show a "Threat Blocked" alert with action buttons.
             */
            void ShowThreatAlert(const std::wstring& threatName, const std::wstring& filePath);

        private:
            NotificationManager() = default;
        };

    } // namespace Communication
} // namespace ShadowStrike

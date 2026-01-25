/**
 * ============================================================================
 * ShadowStrike Configuration - SETTINGS MANAGER (The User Interface)
 * ============================================================================
 *
 * @file SettingsManager.hpp
 * @brief Management of local user preferences.
 *
 * Handles non-critical settings such as UI theme, language, notification
 * frequency, and schedule times.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Config {

        enum class Theme { Light, Dark, System };

        struct UserSettings {
            Theme theme;
            std::string language;
            bool enableNotifications;
            bool startWithWindows;
        };

        class SettingsManager {
        public:
            static SettingsManager& Instance();

            /**
             * @brief Load settings from the local profile.
             */
            UserSettings Load();

            /**
             * @brief Save settings to the local profile.
             */
            void Save(const UserSettings& settings);

        private:
            SettingsManager() = default;
        };

    } // namespace Config
} // namespace ShadowStrike

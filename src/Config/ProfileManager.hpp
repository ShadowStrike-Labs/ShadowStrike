/**
 * ============================================================================
 * ShadowStrike Configuration - PROFILE MANAGER (The Switcher)
 * ============================================================================
 *
 * @file ProfileManager.hpp
 * @brief Management of different operating profiles (e.g. Server, Workstation).
 *
 * Capabilities:
 * 1. Role-Based: Automatically adjusts sensitivity based on detected machine role.
 * 2. High-Availability: Switches to a "Safety" profile if the DB is corrupted.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Config {

        enum class SystemProfile {
            Standard,
            Server,
            Developer,      // Fewer file system blocks
            LockedDown,     // High sensitivity
            Gaming          // Performance focus
        };

        class ProfileManager {
        public:
            static ProfileManager& Instance();

            /**
             * @brief Set the active system profile.
             */
            void SetActiveProfile(SystemProfile profile);

            SystemProfile GetActiveProfile() const { return m_currentProfile; }

        private:
            ProfileManager() = default;
            SystemProfile m_currentProfile = SystemProfile::Standard;
        };

    } // namespace Config
} // namespace ShadowStrike

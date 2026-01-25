/**
 * ============================================================================
 * ShadowStrike GameMode - PROCESS DETECTOR (The Referee)
 * ============================================================================
 *
 * @file GameProcessDetector.hpp
 * @brief Logic for identifying running games and launchers.
 *
 * Capabilities:
 * 1. Launcher Detection: Steam, Origin, Epic, GOG, Battle.net.
 * 2. Fullscreen Detection: Monitoring window state of foreground process.
 * 3. Known DB: List of 10,000+ game executable names.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Core/Process/ProcessMonitor.hpp"
#include <string>
#include <unordered_set>

namespace ShadowStrike {
    namespace GameMode {

        class GameProcessDetector {
        public:
            static GameProcessDetector& Instance();

            /**
             * @brief Initialize with a list of known game process names.
             */
            bool Initialize();

            /**
             * @brief Check if a PID belongs to a known game.
             */
            bool IsGameProcess(uint32_t pid);

            /**
             * @brief Check if the current foreground window is in Fullscreen mode.
             */
            bool IsForegroundFullscreen();

        private:
            GameProcessDetector() = default;
            std::unordered_set<std::wstring> m_gameExecutables;
        };

    } // namespace GameMode
} // namespace ShadowStrike
